use bytes::{Buf, BytesMut};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, RwLock},
};

use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::{ServerConfig, Session};
use tokio_rustls::{server::TlsStream as RustlsStream, TlsAcceptor};
use tokio_util::codec::Decoder;

use socket2::{Domain, Socket, Type};

use crate::{
    copy_bidirectional::copy_bidirectional,
    header::{MaybeSocketAddr, TrojanDecoder, UdpAssociate, UdpAssociateDecoder},
    usermg::User,
    Error, Result, DEFAULT_BUFFER_SIZE,
};
use std::{
    collections::HashMap,
    io::{Error as IoError, Result as IoResult},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use trust_dns_resolver::TokioAsyncResolver;

use once_cell::sync::Lazy;

type TlsStream = RustlsStream<TcpStream>;

static UNSPECIFIED: Lazy<SocketAddr> =
    Lazy::new(|| SocketAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));

/// send a bad request to `$s` and close it immediately.
macro_rules! bad_request {
    ($s:ident) => {
        $s.write_all(b"HTTP/1.1 400 bad request\r\nconnection: closed\r\n\r\nbad request")
            .await?;
        $s.flush().await?;
        $s.shutdown().await?;
    };
}

macro_rules! resolve {
    ($addr:expr,$resolver:expr) => {
        match $addr {
            MaybeSocketAddr::SocketAddr(ref addr) => *addr,
            MaybeSocketAddr::HostAndPort(host, port) => {
                crate::resolver::resolve(host.clone(), *port, $resolver)
                    .await?
                    .ok_or(trust_dns_resolver::error::ResolveError::from(format!(
                        "no addresses returned ,host: {}",
                        host
                    )))?
            }
        }
    };
}

pub struct Forwarder {
    /// available users
    users: Arc<RwLock<HashMap<Box<[u8]>, User>>>,
    /// tokio DNS resolver
    resolver: Arc<TokioAsyncResolver>,
    /// common UDP socket
    udp_socket: Arc<UdpSocket>,
    /// current exchanging UDP group
    udp_pairs: Arc<Mutex<HashMap<SocketAddrV6, (WriteHalf<TlsStream>, u64)>>>,
}

impl Forwarder {
    pub fn new(
        users: Arc<RwLock<HashMap<Box<[u8]>, User>>>,
        resolver: Arc<TokioAsyncResolver>,
        udp_socket: Arc<UdpSocket>,
    ) -> Self {
        Forwarder {
            users,
            resolver,
            udp_socket,
            udp_pairs: Default::default(),
        }
    }

    pub async fn run_server(&self, listen_addr: SocketAddr, config: ServerConfig) -> Result<()> {
        let udp_transfer_to_downstream_fut =
            udp_transfer_to_downstream(self.udp_socket.clone(), self.udp_pairs.clone());
        tokio::spawn(async {
            udp_transfer_to_downstream_fut.await.unwrap();
            std::process::exit(1);
        });
        let ipv6 = to_ipv6_address(&listen_addr);
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let socket = Socket::new(Domain::ipv6(), Type::stream(), None)?;
        socket.set_only_v6(false)?;
        socket.set_nonblocking(true)?;
        socket.set_read_timeout(Some(Duration::from_secs(60)))?;
        socket.set_write_timeout(Some(Duration::from_secs(60)))?;
        socket.set_linger(Some(Duration::from_secs(10)))?;
        socket.bind(&ipv6.into())?;
        socket.listen(128)?;
        let listener = TcpListener::from_std(socket.into_tcp_listener())?;
        while let Ok((inbound, src)) = listener.accept().await {
            info!("accepting new connection from {:?}", src);
            let fut = transfer(
                src,
                inbound,
                acceptor.clone(),
                self.users.clone(),
                self.resolver.clone(),
                self.udp_socket.clone(),
                self.udp_pairs.clone(),
            );
            tokio::spawn(async move {
                if let Err(err) = fut.await {
                    error!("transfer error: {:?}", err);
                }
            });
        }
        Ok(())
    }
}

#[inline]
fn to_ipv6_address(addr: &SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V4(ref a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
        SocketAddr::V6(ref a) => *a,
    }
}

async fn transfer(
    src: SocketAddr,
    inbound: TcpStream,
    acceptor: TlsAcceptor,
    users: Arc<RwLock<HashMap<Box<[u8]>, User>>>,
    resolver: Arc<TokioAsyncResolver>,
    udp_socket: Arc<UdpSocket>,
    udp_pairs: Arc<Mutex<HashMap<SocketAddrV6, (WriteHalf<TlsStream>, u64)>>>,
) -> Result<()> {
    let mut stream = timeout(
        Duration::from_secs(5),
        acceptor.accept_with(inbound, |s| {
            s.set_buffer_limit(DEFAULT_BUFFER_SIZE);
        }),
    )
    .await
    .map_err(|_| {
        IoError::new(
            std::io::ErrorKind::TimedOut,
            format!("inbound: {} tls handshake timeout within 5 sec", src),
        )
    })??;
    let mut buf = bytes::BytesMut::with_capacity(1024);
    loop {
        let n = timeout(Duration::from_secs(5), stream.read_buf(&mut buf))
            .await
            .map_err(|_| {
                IoError::new(
                    std::io::ErrorKind::TimedOut,
                    format!("inbound: {} read timeout within 5 sec", src),
                )
            })??;
        if n == 0 {
            bad_request!(stream);
            break;
        }
        match TrojanDecoder.decode(&mut buf) {
            Ok(Some(header)) => {
                if !users.read().await.contains_key(&header.password) {
                    bad_request!(stream);
                    break;
                }
                let addr = resolve!(&header.addr, resolver.clone());
                let (upload, download) = if header.udp_associate {
                    let (read_half, write_half) = split(stream);
                    let cached = {
                        if addr == *UNSPECIFIED {
                            Some(write_half)
                        } else {
                            let addr = to_ipv6_address(&addr);
                            let mut udp_pairs = udp_pairs.lock().await;
                            if udp_pairs.contains_key(&addr) {
                                Some(write_half)
                            } else {
                                udp_pairs.insert(addr, (write_half, 0));
                                None
                            }
                        }
                    };
                    if let Some(write_half) = cached {
                        udp_bitransfer(src, read_half, write_half, buf, resolver).await?
                    } else {
                        let upload =
                            udp_transfer_to_upstream(read_half, addr, udp_socket, buf, resolver)
                                .await;
                        let mut guard = udp_pairs.lock().await;
                        let addr = to_ipv6_address(&addr);
                        let pair = guard.remove(&addr);
                        if let Some((mut write_half, download)) = pair {
                            write_half.flush().await?;
                            write_half.shutdown().await?;
                            (upload?, download)
                        } else {
                            unreachable!()
                        }
                    }
                } else {
                    // let outbound = TcpStream::connect(&addr).await?;
                    let domain_type = if addr.is_ipv4() {
                        Domain::ipv4()
                    } else {
                        Domain::ipv6()
                    };
                    let socket = Socket::new(domain_type, Type::stream(), None)?;
                    socket.set_read_timeout(Some(Duration::from_secs(60)))?;
                    socket.set_write_timeout(Some(Duration::from_secs(60)))?;
                    socket.set_linger(Some(Duration::from_secs(10)))?;
                    socket.connect_timeout(&addr.into(), Duration::from_secs(5))?;
                    socket.set_nonblocking(true)?;
                    let outbound = TcpStream::from_std(socket.into_tcp_stream())?;
                    tcp_bitransfer(stream, outbound, buf).await?
                };
                info!(
                    "src: {} <=> dst: {} ,upload: {}bytes,download: {}bytes",
                    src, header.addr, upload, download
                );
                if let Some(user) = users.write().await.get_mut(&header.password) {
                    user.upload += upload;
                    user.download += download;
                }
                break;
            }
            Ok(None) => {}
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                bad_request!(stream);
                break;
            }
            Err(e) => {
                stream.shutdown().await?;
                return Err(Error::Io(e));
            }
        }
    }
    Ok(())
}

async fn udp_transfer_to_upstream(
    mut inbound: ReadHalf<TlsStream>,
    addr: SocketAddr,
    outbound: Arc<UdpSocket>,
    mut buf: BytesMut,
    resolver: Arc<TokioAsyncResolver>,
) -> Result<u64> {
    let mut upload = 0;
    loop {
        while let Some(frame) = UdpAssociateDecoder.decode(&mut buf)? {
            let addr = resolve!(&frame.addr, resolver.clone());
            upload += outbound.send_to(&frame.payload, addr).await?;
        }
        if let Ok(r) = timeout(Duration::from_secs(60), inbound.read_buf(&mut buf)).await {
            if r? == 0 {
                while let Some(frame) = UdpAssociateDecoder.decode_eof(&mut buf)? {
                    let addr = resolve!(&frame.addr, resolver.clone());
                    upload += outbound.send_to(&frame.payload, addr).await?;
                }
                break;
            }
        } else {
            info!("udp relay timeout for inbound side, dst :{}", addr);
            break;
        }
    }
    Ok(upload as u64)
}

async fn udp_transfer_to_downstream(
    udp_socket: Arc<UdpSocket>,
    udp_pairs: Arc<Mutex<HashMap<SocketAddrV6, (WriteHalf<TlsStream>, u64)>>>,
) -> IoResult<()> {
    let mut buf = vec![0; 2048].into_boxed_slice();
    loop {
        let (len, dst) = udp_socket.recv_from(&mut buf).await?;
        let us: Vec<u8> = UdpAssociate::new(dst, &buf[..len]).into();
        {
            let mut is_err = false;
            let mut guard = udp_pairs.lock().await;
            let dst = to_ipv6_address(&dst);
            if let Some((write_half, download)) = guard.get_mut(&dst) {
                if let Err(e) = write_half.write_all(&us).await {
                    error!("udp transfer to downstream error: {}", e);
                    is_err = true;
                } else {
                    *download += len as u64;
                }
            }
            if is_err {
                guard.remove(&dst);
            }
        }
    }
}

/// UDP bi-directional transmission through two futures
async fn udp_bitransfer(
    src: SocketAddr,
    mut ri: ReadHalf<TlsStream>,
    mut wi: WriteHalf<TlsStream>,
    mut buf: BytesMut,
    resolver: Arc<TokioAsyncResolver>,
) -> Result<(u64, u64)> {
    let (mut upload, mut download) = (0, 0);
    let outbound = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(
        Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))
    .await?;
    let client_to_server = async {
        loop {
            while let Some(frame) = UdpAssociateDecoder.decode(&mut buf)? {
                let addr = resolve!(&frame.addr, resolver.clone());
                upload += outbound.send_to(&frame.payload, addr).await?;
            }
            if let Ok(r) = timeout(Duration::from_secs(60), ri.read_buf(&mut buf)).await {
                if r? == 0 {
                    while let Some(frame) = UdpAssociateDecoder.decode_eof(&mut buf)? {
                        let addr = resolve!(&frame.addr, resolver.clone());
                        upload += outbound.send_to(&frame.payload, addr).await?;
                    }
                    break;
                }
            } else {
                info!("udp bitransfer timeout, src: {}", src);
                break;
            }
        }
        Ok(()) as Result<()>
    };
    let server_to_client = async {
        let mut buf = vec![0; 2048].into_boxed_slice();
        loop {
            let (len, dst) = outbound.recv_from(&mut buf).await?;
            if len == 0 {
                wi.shutdown().await?;
                break;
            }
            let us: Vec<u8> = UdpAssociate::new(dst, &buf[..len]).into();
            wi.write_all(&us).await?;
            download += us.len();
        }
        wi.flush().await?;
        wi.shutdown().await?;
        Ok(()) as Result<()>
    };
    let r = tokio::select! {
        r = client_to_server =>r,
        r = server_to_client =>r,
    };
    if let Err(e) = r {
        error!("udp bitransfer error: {} ,src: {}", e, src);
    }
    Ok((upload as u64, download as u64))
}

async fn tcp_bitransfer(
    mut inbound: TlsStream,
    mut outbound: TcpStream,
    buf: BytesMut,
) -> IoResult<(u64, u64)> {
    let remaining = buf.remaining();
    if remaining > 0 {
        // flushing remaining buffer
        outbound.write_all(buf.chunk()).await?;
    }
    let (upload, download) = copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok((upload + remaining as u64, download))
}

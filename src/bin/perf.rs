
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use futures::TryFutureExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use bytes::BufMut;

use argh::FromArgs;

use trojan_lite::hex_hash;

use tokio_rustls::{
    rustls::{
        Certificate, ClientConfig, RootCertStore, ServerCertVerified, ServerCertVerifier, Session,
        TLSError,
    },
    webpki::DNSNameRef,
    TlsConnector,
};

///trojan perf util
#[derive(FromArgs)]
struct Options {
    /// trojan server addr
    #[argh(positional)]
    trojan_server_addr: SocketAddr,

    /// thread
    #[argh(option, short = 't', default = "4")]
    thread: u8,

    /// test user
    #[argh(option, short = 'u')]
    user: String,
}

fn generate_trojan_header(addr: SocketAddr, user: &str) -> Vec<u8> {
    let mut buf = Vec::from(hex_hash(user));
    buf.put(&b"\r\n"[..]);
    buf.put_u8(1);
    match addr {
        SocketAddr::V4(x) => {
            buf.put_u8(b'\x01');
            buf.put_slice(&x.ip().octets());
            buf.put_slice(&x.port().to_be_bytes());
        }
        SocketAddr::V6(x) => {
            buf.put_u8(b'\x04');
            buf.put_slice(&x.ip().octets());
            buf.put_slice(&x.port().to_be_bytes());
        }
    };
    buf.put(&b"\r\n"[..]);
    buf
}

pub struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        _presented_certs: &[Certificate],
        _dns_name: DNSNameRef,
        _ocsp_response: &[u8],
    ) -> std::result::Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}

async fn do_send_until_error(addr: SocketAddr, header: Vec<u8>) -> io::Result<()> {
    let bytes = vec![0; 4096].into_boxed_slice();
    let mut config = ClientConfig::new();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(&addr).await?;
    let domain = DNSNameRef::try_from_ascii_str("localhost")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;
    let mut stream = connector
        .connect_with(domain, stream, |c| {
            c.set_buffer_limit(4096 * 2);
        })
        .await
        .unwrap();
    stream.write_all(&header).await?;
    while let Ok(_) = stream.write(&bytes).await {}
    Ok(())
}

async fn do_recv(target_addr: SocketAddr, amt: Arc<AtomicUsize>) -> io::Result<()> {
    let listener = TcpListener::bind(target_addr).await?;
    while let Ok((mut socket, addr)) = listener.accept().await {
        println!("accept :{}", addr);
        let amt = amt.clone();
        tokio::task::spawn(async move {
            let mut buf = [0; 4096 * 2];
            while let Ok(n) = socket.read(&mut buf).await {
                if n != 0 {
                    amt.fetch_add(n, Ordering::SeqCst);
                }
            }
        });
    }
    Ok(())
}

async fn perf(
    threads: u8,
    addr: SocketAddr,
    target_addr: SocketAddr,
    user: &str,
    amt: Arc<AtomicUsize>,
) -> io::Result<()> {
    let header = generate_trojan_header(target_addr, user);
    let do_recv = do_recv(target_addr, amt).map_err(|e| {
        eprint!("{}", e);
        std::process::exit(1);
    });
    tokio::task::spawn(do_recv);

    for _ in 0..threads {
        let header = header.clone();
        let do_send_until_error = do_send_until_error(addr, header).map_err(|e| {
            eprint!("{}", e);
            std::process::exit(1);
        });
        tokio::task::spawn(do_send_until_error);
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let opts: Options = argh::from_env();
    let addr = "127.0.0.1:28078".parse().unwrap();
    let amt = Arc::new(AtomicUsize::default());
    let dummy = amt.clone();
    if let Err(e) = perf(
        opts.thread,
        opts.trojan_server_addr,
        addr,
        &opts.user,
        dummy,
    )
    .await
    {
        eprint!("{}", e)
    }
    let mut slepper = tokio::time::sleep(std::time::Duration::from_secs(1));
    let start = std::time::Instant::now();
    loop {
        slepper.await;
        let i = amt.load(Ordering::SeqCst);
        println!(
            "{}M/s",
            i / 1024 / 1024 / start.elapsed().as_secs() as usize
        );
        slepper = tokio::time::sleep(std::time::Duration::from_secs(1));
    }
}
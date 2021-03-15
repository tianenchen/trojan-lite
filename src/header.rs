use std::{
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::Decoder;

/*

+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+

where Trojan Request is a SOCKS5-like request:

+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+

where:

    o  CMD
        o  CONNECT X'01'
        o  UDP ASSOCIATE X'03'
    o  ATYP address type of following address
        o  IP V4 address: X'01'
        o  DOMAINNAME: X'03'
        o  IP V6 address: X'04'
    o  DST.ADDR desired destination address
    o  DST.PORT desired destination port in network octet order

If the connection is a UDP ASSOCIATE, then each UDP packet has the following format:

+------+----------+----------+--------+---------+----------+
| ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
+------+----------+----------+--------+---------+----------+
|  1   | Variable |    2     |   2    | X'0D0A' | Variable |
+------+----------+----------+--------+---------+----------+

*/

#[derive(Debug, PartialEq)]
pub struct SocksHeader {
    atyp: u8,
    addr: Vec<u8>,
    port: u16,
}

macro_rules! aquire {
    ($src:ident,$n:expr) => {
        if $src.len() < $n {
            $src.reserve($n - $src.len());
            return Ok(None);
        }
    };
}

macro_rules! socks_addr {
    ($src:ident,$p:ident) => {
        match $src[$p] {
            0x01 => {
                aquire!($src, $p + 7);
                let port = u16::from_be_bytes([$src[$p + 5], $src[$p + 6]]);
                let addr = SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new($src[$p + 1], $src[$p + 2], $src[$p + 3], $src[$p + 4]),
                    port,
                ));
                $p += 7;
                addr.into()
            }
            0x03 => {
                aquire!($src, $p + 2);
                let len = $src[$p + 1] as usize;
                aquire!($src, $p + 2 + len);
                let data = $src[$p + 2..$p + 2 + len].to_vec();
                let port = u16::from_be_bytes([$src[$p + 2 + len], $src[$p + 3 + len]]);
                let domain = String::from_utf8(data).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.utf8_error())
                })?;
                $p += 4 + len;
                (domain, port).into()
                // if let Some(addr) = (domain.clone(), port).to_socket_addrs()?.next() {
                //     info!("resolve: {} - {:?}", domain, addr);
                //     addr.into()
                // } else {
                //     return Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable));
                // }
            }
            0x04 => {
                aquire!($src, $p + 19);
                let mut ipv6_bytes = [0u8; 16];
                ipv6_bytes.copy_from_slice(&$src[$p + 1..$p + 17]);
                let ipv6 = Ipv6Addr::from(ipv6_bytes);
                let port = u16::from_be_bytes([$src[$p + 17], $src[$p + 18]]);
                let addr = SocketAddr::V6(SocketAddrV6::new(ipv6, port, 0, 0));
                $p += 19;
                addr.into()
            }
            _ => {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
        }
    };
}

macro_rules! line_break {
    ($src:ident,$n:expr) => {
        if $src[$n] != b'\x0D' || $src[$n + 1] != b'\x0A' {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
    };
}
#[derive(Debug, PartialEq)]
pub enum MaybeSocketAddr {
    SocketAddr(SocketAddr),
    HostAndPort(String, u16),
}

impl fmt::Display for MaybeSocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaybeSocketAddr::SocketAddr(addr) => write!(f, "{}", addr),
            MaybeSocketAddr::HostAndPort(host, port) => write!(f, "{}:{}", host, port),
        }
    }
}

impl From<SocketAddr> for MaybeSocketAddr {
    fn from(addr: SocketAddr) -> Self {
        MaybeSocketAddr::SocketAddr(addr)
    }
}

impl From<(String, u16)> for MaybeSocketAddr {
    fn from(domain_and_port: (String, u16)) -> Self {
        MaybeSocketAddr::HostAndPort(domain_and_port.0, domain_and_port.1)
    }
}

pub struct TrojanHeader {
    pub password: Box<[u8]>,
    pub udp_associate: bool,
    pub addr: MaybeSocketAddr,
}

pub struct TrojanDecoder;

impl Decoder for TrojanDecoder {
    type Error = io::Error;
    type Item = TrojanHeader;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        aquire!(src, 59);
        let password = src[..56].to_owned().into_boxed_slice();
        line_break!(src, 56);
        let udp_associate = src[58] == 0x03;
        let mut p = 59;
        let addr = socks_addr!(src, p);
        aquire!(src, p + 2);
        line_break!(src, p);
        src.advance(p + 2);
        Ok(Some(TrojanHeader {
            password,
            udp_associate,
            addr,
        }))
    }
}

#[derive(Debug, PartialEq)]
pub struct UdpAssociate<T> {
    pub addr: MaybeSocketAddr,
    pub payload: T,
}

impl<'a> Into<Vec<u8>> for UdpAssociate<&'a [u8]> {
    fn into(self) -> Vec<u8> {
        let Self { addr, payload } = self;
        let mut buf = vec![];
        match addr {
            MaybeSocketAddr::SocketAddr(SocketAddr::V4(x)) => {
                buf.put_u8(b'\x01');
                buf.put_slice(&x.ip().octets());
                buf.put_slice(&x.port().to_be_bytes());
            }
            MaybeSocketAddr::SocketAddr(SocketAddr::V6(x)) => {
                buf.put_u8(b'\x04');
                buf.put_slice(&x.ip().octets());
                buf.put_slice(&x.port().to_be_bytes());
            }
            _ => unreachable!(),
        };
        buf.put_u16(payload.len() as u16);
        buf.put(&b"\r\n"[..]);
        buf.put_slice(&payload);
        buf
    }
}

impl<'a> UdpAssociate<&'a [u8]> {
    pub fn new(addr: SocketAddr, payload: &'a [u8]) -> Self {
        UdpAssociate {
            addr: addr.into(),
            payload,
        }
    }
}

pub struct UdpAssociateDecoder;

impl Decoder for UdpAssociateDecoder {
    type Error = io::Error;
    type Item = UdpAssociate<Vec<u8>>;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut p = 0;
        aquire!(src, 1);
        let addr = socks_addr!(src, p);
        aquire!(src, p + 2);
        let len = u16::from_be_bytes([src[p], src[p + 1]]) as usize;
        aquire!(src, p + 4 + len);
        line_break!(src, p + 2);
        let payload = src[p + 4..p + 4 + len].to_vec();
        src.advance(p + 4 + len);
        Ok(Some(UdpAssociate { addr, payload }))
    }
}

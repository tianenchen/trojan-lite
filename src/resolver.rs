use crate::header::MaybeSocketAddr;
use crate::Result;

pub use resolver::resolve;
#[cfg(feature = "dns-over-tls")]
pub mod resolver {
    use super::*;
    use std::fmt::Display;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use trust_dns_resolver::{error::ResolveResult, IntoName, TokioAsyncResolver, TryParseIp};

    async fn try_resolve<N: IntoName + Display + TryParseIp + Clone + 'static>(
        host: N,
        port: u16,
        resolver: Arc<TokioAsyncResolver>,
    ) -> ResolveResult<Option<SocketAddr>> {
        let result = resolver
            .lookup_ip(host.clone())
            .await?
            .into_iter()
            .map(move |ip| SocketAddr::new(ip, port))
            .next();
        if let Some(ref r) = result {
            info!("resolve: {} -> {:?}", host, r.ip());
        }
        return Ok(result);
    }
    pub async fn resolve(
        addr: &MaybeSocketAddr,
        resolver: Arc<TokioAsyncResolver>,
    ) -> Result<Option<SocketAddr>> {
        match addr {
            MaybeSocketAddr::SocketAddr(ref addr) => Ok(Some(*addr)),
            MaybeSocketAddr::HostAndPort(host, port) => try_resolve(host.clone(), *port, resolver)
                .await
                .map_err(|_| {
                    crate::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        format!("resolve host: {} error", host),
                    ))
                }),
        }
    }
}

#[cfg(not(feature = "dns-over-tls"))]
pub mod resolver {
    use super::*;
    use std::net::{SocketAddr, ToSocketAddrs};

    pub fn try_resolve(host: &str, port: u16) -> crate::Result<Option<SocketAddr>> {
        if let Some(addr) = (host, port).to_socket_addrs()?.next() {
            info!("resolve: {} -> {:?}", host, addr.ip());
            Ok(Some(addr))
        } else {
            Ok(None)
        }
    }

    pub fn resolve(addr: &MaybeSocketAddr) -> Result<Option<SocketAddr>> {
        match addr {
            MaybeSocketAddr::SocketAddr(ref addr) => Ok(Some(*addr)),
            MaybeSocketAddr::HostAndPort(host, port) => try_resolve(&host, *port).map_err(|_| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    format!("resolve host: {} error", host),
                ))
            }),
        }
    }
}
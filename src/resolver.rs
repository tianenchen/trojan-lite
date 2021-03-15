use std::fmt::Display;
use std::net::SocketAddr;
use std::sync::Arc;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::{IntoName, TryParseIp};

pub async fn resolve<N: IntoName + Display + TryParseIp + Clone + 'static>(
    host: N,
    port: u16,
    resolver: Arc<TokioAsyncResolver>,
) -> crate::Result<Option<SocketAddr>> {
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

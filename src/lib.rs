#[macro_use]
extern crate log;

mod forward;
mod header;
mod resolver;
#[cfg(feature = "user-management")]
mod usermg;
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    path::{Path, PathBuf},
    sync::Arc,
};

use sha2::Digest;

use thiserror::Error;
use tokio::{net::UdpSocket, runtime, sync::RwLock};

#[cfg(feature = "dns-over-tls")]
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, Certificate, NoClientAuth,
    PrivateKey, RootCertStore, ServerConfig,
};

pub const DEFAULT_BUFFER_SIZE: usize = 2 * 4096;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "user-management")]
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

#[cfg(feature = "user-management")]
pub use usermg::User;

#[cfg(not(feature = "user-management"))]
#[derive(Clone, PartialEq)]
pub struct User {
    pub pswd: String,
    pub upload: u64,
    pub download: u64,
}

macro_rules! key {
    ($e:expr,$p:ident) => {
        let reader = &mut BufReader::new(File::open($p)?);
        if let Ok(mut keys) = $e(reader) {
            if !keys.is_empty() {
                return Ok(keys.remove(0));
            }
        }
    };
}
fn load_keys(path: &Path) -> io::Result<PrivateKey> {
    key!(pkcs8_private_keys, path);
    key!(rsa_private_keys, path);
    Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}

macro_rules! users {
    ($users:expr) => {
        Arc::new(RwLock::new(
            $users
                .iter()
                .map(|u| {
                    (
                        hex_hash(u),
                        User {
                            pswd: u.to_owned(),
                            upload: 0,
                            download: 0,
                        },
                    )
                })
                .collect(),
        ))
    };
}

#[macro_export]
macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

#[inline]
pub fn hex_hash(content: &str) -> Box<[u8]> {
    let mut bytes = [0u8; 56];
    hex::encode_to_slice(&sha2::Sha224::digest(content.as_bytes())[..], &mut bytes)
        .unwrap_or_default();
    Box::new(bytes)
}

pub fn run_server(
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    auth: Option<PathBuf>,
    require_auth: bool,
    users: Vec<String>,
    #[cfg(feature = "user-management")] mng_addr: Option<SocketAddr>,
    #[cfg(feature = "multi-threaded")] threads: Option<usize>,
) -> Result<()> {
    let certs = load_certs(&cert)?;
    let key = load_keys(&key)?;

    let verifier = if let Some(auth) = auth {
        let roots = load_certs(&auth)?;
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(&root).unwrap();
        }
        if require_auth {
            AllowAnyAuthenticatedClient::new(client_auth_roots)
        } else {
            AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots)
        }
    } else {
        NoClientAuth::new()
    };
    let mut config = ServerConfig::new(verifier);
    config
        .set_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let users: Arc<RwLock<HashMap<Box<[u8]>, User>>> = users!(users);
    #[cfg(feature = "dns-over-tls")]
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default())
        .expect("build 'TokioAsyncResolver' fail");
    #[cfg(feature = "multi-threaded")]
    let mut builder = {
        let mut builder = runtime::Builder::new_multi_thread();
        if let Some(threads) = threads {
            builder.worker_threads(threads);
        }
        builder
    };
    #[cfg(not(feature = "multi-threaded"))]
    let mut builder = runtime::Builder::new_current_thread();
    let runtime = builder.enable_all().build()?;
    runtime.block_on(async {
        let udp_socket = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            0,
            0,
            0,
        )))
        .await?;
        // let udp_socket = UdpSocket::from_std(socket.into_udp_socket())?;
        debug!("udp socket bind: {}", udp_socket.local_addr().unwrap());
        let forwarder = forward::Forwarder::new(
            users.clone(),
            #[cfg(feature = "dns-over-tls")]
            Arc::new(resolver),
            Arc::new(udp_socket),
        );
        let forwarder_fut = forwarder.run_server(addr, config);
        #[cfg(feature = "user-management")]
        if let Some(mng_addr) = mng_addr {
            let mngsvr_fut = usermg::run_server(mng_addr, users);
            tokio::try_join!(forwarder_fut, mngsvr_fut).map(|_| ())
        } else {
            forwarder_fut.await
        }
        #[cfg(not(feature = "user-management"))]
        forwarder_fut.await
    })?;
    Ok(())
}
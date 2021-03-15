use argh::FromArgs;

use env_logger;
use log::error;

use std::{net::SocketAddr, path::PathBuf};

///trojan implementation
#[derive(FromArgs)]
struct Options {
    /// bind addr
    #[argh(positional)]
    addr: SocketAddr,

    /// user management service bind addr
    #[argh(option, short = 'm')]
    mng_addr: Option<SocketAddr>,

    /// read server certificates from CERTFILE. This should contain PEM-format certificates in the right order (the first certificate should certify KEYFILE, the last should be a root CA).
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// read private key from KEYFILE.  This should be a RSA private key or PKCS8-encoded private key, in PEM format.
    #[argh(option, short = 'k')]
    key: PathBuf,

    /// enable client authentication, and accept certificates signed by those roots provided in CERTFILE.
    #[argh(option, short = 'a')]
    auth: Option<PathBuf>,

    /// send a fatal alert if the client does not complete client authentication.
    #[argh(switch, short = 'r')]
    require_auth: bool,

    /// numbers of worker threads
    #[cfg(feature = "multi-threaded")]
    #[argh(option, short = 't')]
    threads: Option<usize>,

    /// users
    #[argh(positional, short = 'u')]
    users: Vec<String>,
}

fn main() {
    env_logger::init();
    let opts: Options = argh::from_env();
    let Options {
        addr,
        mng_addr,
        cert,
        key,
        auth,
        require_auth,
        users,
        ..
    } = opts;
    if let Err(e) = trojan_lite::run_server(
        addr,
        mng_addr,
        cert,
        key,
        auth,
        require_auth,
        users,
        #[cfg(feature = "multi-threaded")]
        opts.threads,
    ) {
        error!("{}", e);
        std::process::exit(1);
    }
}

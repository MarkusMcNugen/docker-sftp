//! The listener: TLS 1.3 with a certificate from /config/webui/tls, or plain
//! HTTP for connections from WEBUI_TRUSTED_PROXIES only.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sftp_webui::net;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, TryAcquireError};
use tokio_rustls::TlsAcceptor;
use tower::Service;

use crate::app::{self, App, Peer};
use crate::config::Config;
use crate::log;

const TLS_DIR: &str = "/config/webui/tls";
const MAX_CONNECTIONS: usize = 256;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The most a request's line and headers may take; bodies are capped
/// separately at the same size.
const MAX_HEAD: usize = 64 * 1024;

fn hostname() -> String {
    match std::fs::read_to_string("/etc/hostname") {
        Ok(h) if !h.trim().is_empty() => h.trim().to_string(),
        Ok(_) => "localhost".into(),
        Err(e) => {
            log(&format!("cannot read /etc/hostname ({e}); the certificate names localhost only"));
            "localhost".into()
        }
    }
}

/// Loads cert.pem and key.pem from `tls_dir`, generating a self-signed pair
/// when neither exists. Prints the certificate's SHA-256 fingerprint either
/// way.
fn tls_config(tls_dir: &str) -> Result<rustls::ServerConfig> {
    let dir = Path::new(tls_dir);
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {}
        (false, false) => {
            std::fs::create_dir_all(dir).with_context(|| format!("cannot create {tls_dir}"))?;
            let names = vec![hostname(), "localhost".to_string()];
            let generated = rcgen::generate_simple_self_signed(names).context("cannot generate a certificate")?;
            write_private(&key_path, generated.signing_key.serialize_pem().as_bytes())?;
            std::fs::write(&cert_path, generated.cert.pem()).with_context(|| format!("cannot write {}", cert_path.display()))?;
            log(&format!("generated a self-signed certificate in {tls_dir}"));
        }
        _ => bail!("{tls_dir} must hold both cert.pem and key.pem, or neither"),
    }
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cert_path)
        .with_context(|| format!("cannot read {}", cert_path.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("{} is not a PEM certificate chain", cert_path.display()))?;
    let Some(first) = certs.first() else {
        bail!("{} holds no certificate", cert_path.display());
    };
    let fingerprint = crate::auth::sha256_hex(first.as_ref());
    let pairs: Vec<String> = fingerprint.as_bytes().chunks(2).map(|c| String::from_utf8_lossy(c).to_uppercase()).collect();
    log(&format!("TLS certificate SHA-256 fingerprint {}", pairs.join(":")));
    let key = PrivateKeyDer::from_pem_file(&key_path).with_context(|| format!("{} is not a PEM private key", key_path.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("cannot set up TLS 1.3")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("the certificate and key do not match")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(data).with_context(|| format!("cannot write {}", path.display()))
}

pub async fn bind(port: u16) -> Result<TcpListener> {
    match TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)).await {
        Ok(l) => Ok(l),
        Err(six) => {
            log(&format!("cannot listen on IPv6 ({six}); listening on IPv4 only"));
            TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
                .await
                .with_context(|| format!("cannot listen on port {port}"))
        }
    }
}

/// TLS from the certificate in `tls_dir`, or None for plain HTTP, which
/// only the trusted proxies are then served.
pub fn acceptor(config: &Config, tls_dir: &str) -> Result<Option<TlsAcceptor>> {
    if config.plain_http {
        log("serving plain HTTP to the trusted proxies only");
        return Ok(None);
    }
    Ok(Some(TlsAcceptor::from(Arc::new(tls_config(tls_dir)?))))
}

pub async fn run(config: Config) -> Result<()> {
    let acceptor = acceptor(&config, TLS_DIR)?;
    let port = config.port;
    let app = Arc::new(App::new(config)?);
    let router = app::router(Arc::clone(&app));
    let listener = bind(port).await?;
    log(&format!("listening on port {port}"));
    app.announce_setup();
    accept_loop(listener, acceptor, router, app.config.trusted_proxies.clone()).await
}

/// Serves each connection on its own task, at most MAX_CONNECTIONS at once.
/// Without TLS, only `trusted_proxies` are served.
pub async fn accept_loop(
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
    router: axum::Router,
    trusted_proxies: Vec<net::Network>,
) -> Result<()> {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                log(&format!("accept failed: {e}"));
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let permit = match Arc::clone(&limit).try_acquire_owned() {
            Ok(p) => p,
            Err(TryAcquireError::NoPermits) => continue,
            Err(TryAcquireError::Closed) => bail!("the connection limit closed"),
        };
        let peer_ip = net::canonical(peer.ip());
        if acceptor.is_none() && !net::any_contains(&trusted_proxies, peer_ip) {
            continue;
        }
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let held = permit;
            if let Err(e) = connection(tcp, peer_ip, acceptor, router).await {
                log(&format!("connection from {peer_ip}: {e:#}"));
            }
            drop(held);
        });
    }
}

async fn connection(tcp: TcpStream, peer: IpAddr, acceptor: Option<TlsAcceptor>, router: axum::Router) -> Result<()> {
    tcp.set_nodelay(true).context("cannot set TCP_NODELAY")?;
    let service = hyper::service::service_fn(move |mut request: hyper::Request<Incoming>| {
        request.extensions_mut().insert(Peer(peer));
        let mut router = router.clone();
        async move { router.call(request).await }
    });
    let mut http = hyper::server::conn::http1::Builder::new();
    http.timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT).max_buf_size(MAX_HEAD);
    match acceptor {
        Some(acceptor) => {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => bail!("TLS handshake failed: {e}"),
                Err(elapsed) => bail!("TLS handshake took too long: {elapsed}"),
            };
            http.serve_connection(TokioIo::new(tls), service).await.context("HTTP error")
        }
        None => http.serve_connection(TokioIo::new(tcp), service).await.context("HTTP error"),
    }
}

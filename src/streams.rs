use tower::Service;
use tokio::net::{TcpStream, UnixStream};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use http::Uri;
use hyper_util::client::legacy::connect::{HttpConnector, Connection, Connected};
use hyper_util::rt::TokioIo;
use tokio::io::ReadBuf;

#[derive(Clone, Debug)]
pub enum AnyConnector {
    Http(HttpConnector),
    /// TLS to whatever the URI names, for proxying to an `https://` upstream.
    Https(std::sync::Arc<rustls::ClientConfig>),
    FixedTcp(String),
    FixedUnix(String),
}

/// Trust for upstream certificates, taken from the system store so that an administrator's own CA
/// works without webcentral knowing about it. Built once: reading the store costs a syscall per
/// certificate.
pub fn upstream_tls() -> std::sync::Arc<rustls::ClientConfig> {
    use std::sync::{Arc, OnceLock};
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            let found = rustls_native_certs::load_native_certs();
            for cert in found.certs {
                let _ = roots.add(cert);
            }
            if roots.is_empty() {
                eprintln!("No system CA certificates found; proxying to https:// will fail");
            }
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

impl Service<Uri> for AnyConnector {
    type Response = AnyStream;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            AnyConnector::Http(c) => c.poll_ready(cx).map_err(|e| e.into()),
            AnyConnector::Https(_) => Poll::Ready(Ok(())),
            AnyConnector::FixedTcp(_) => Poll::Ready(Ok(())),
            AnyConnector::FixedUnix(_) => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        match self {
            AnyConnector::Http(c) => {
                let fut = c.call(req);
                Box::pin(async move {
                    let stream = fut.await?;
                    Ok(AnyStream::Http(stream))
                })
            }
            AnyConnector::Https(config) => {
                let config = config.clone();
                Box::pin(async move {
                    let host = req
                        .host()
                        .ok_or("an https target must name a host")?
                        .to_string();
                    let port = req.port_u16().unwrap_or(443);
                    let tcp = TcpStream::connect((host.as_str(), port)).await?;
                    // The name is verified against the certificate, so a proxied upstream is
                    // authenticated rather than merely encrypted.
                    let name = rustls::pki_types::ServerName::try_from(host)?;
                    let tls = tokio_rustls::TlsConnector::from(config).connect(name, tcp).await?;
                    Ok(AnyStream::Tls(Box::new(TokioIo::new(tls))))
                })
            }
            AnyConnector::FixedTcp(addr) => {
                let addr = addr.clone();
                Box::pin(async move {
                    let stream = TcpStream::connect(addr).await?;
                    Ok(AnyStream::Tcp(TokioIo::new(stream)))
                })
            }
            AnyConnector::FixedUnix(path) => {
                let path = path.clone();
                Box::pin(async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok(AnyStream::Unix(TokioIo::new(stream)))
                })
            }
        }
    }
}

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

pub enum AnyStream {
    Http(TokioIo<TcpStream>),
    // Boxed: a TLS session is far larger than the other variants, and every stream would
    // otherwise be sized for it.
    Tls(Box<TokioIo<TlsStream>>),
    Tcp(TokioIo<TcpStream>),
    Unix(TokioIo<UnixStream>),
}

impl AnyStream {
    pub fn into_tokio(self) -> AnyTokioStream {
        match self {
            AnyStream::Http(s) => AnyTokioStream::Http(s.into_inner()),
            AnyStream::Tls(s) => AnyTokioStream::Tls(Box::new(s.into_inner())),
            AnyStream::Tcp(s) => AnyTokioStream::Tcp(s.into_inner()),
            AnyStream::Unix(s) => AnyTokioStream::Unix(s.into_inner()),
        }
    }
}

impl Connection for AnyStream {
    fn connected(&self) -> Connected {
        match self {
            AnyStream::Http(s) => s.connected(),
            AnyStream::Tls(_) => Connected::new(),
            AnyStream::Tcp(s) => s.connected(),
            AnyStream::Unix(_) => Connected::new(),
        }
    }
}

impl hyper::rt::Read for AnyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyStream::Http(s) => Pin::new(s).poll_read(cx, buf),
            AnyStream::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
            AnyStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            AnyStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for AnyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            AnyStream::Http(s) => Pin::new(s).poll_write(cx, buf),
            AnyStream::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
            AnyStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            AnyStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyStream::Http(s) => Pin::new(s).poll_flush(cx),
            AnyStream::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
            AnyStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            AnyStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyStream::Http(s) => Pin::new(s).poll_shutdown(cx),
            AnyStream::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
            AnyStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            AnyStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub enum AnyTokioStream {
    Http(TcpStream),
    Tls(Box<TlsStream>),
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl tokio::io::AsyncRead for AnyTokioStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            AnyTokioStream::Http(s) => Pin::new(s).poll_read(cx, buf),
            AnyTokioStream::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
            AnyTokioStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            AnyTokioStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for AnyTokioStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            AnyTokioStream::Http(s) => Pin::new(s).poll_write(cx, buf),
            AnyTokioStream::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
            AnyTokioStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            AnyTokioStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyTokioStream::Http(s) => Pin::new(s).poll_flush(cx),
            AnyTokioStream::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
            AnyTokioStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            AnyTokioStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyTokioStream::Http(s) => Pin::new(s).poll_shutdown(cx),
            AnyTokioStream::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
            AnyTokioStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            AnyTokioStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

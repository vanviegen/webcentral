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
    FixedTcp(String),
    FixedUnix(String),
}

impl Service<Uri> for AnyConnector {
    type Response = AnyStream;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            AnyConnector::Http(c) => c.poll_ready(cx).map_err(|e| e.into()),
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

pub enum AnyStream {
    Http(TokioIo<TcpStream>),
    Tcp(TokioIo<TcpStream>),
    Unix(TokioIo<UnixStream>),
}

impl AnyStream {
    pub fn into_tokio(self) -> AnyTokioStream {
        match self {
            AnyStream::Http(s) => AnyTokioStream::Http(s.into_inner()),
            AnyStream::Tcp(s) => AnyTokioStream::Tcp(s.into_inner()),
            AnyStream::Unix(s) => AnyTokioStream::Unix(s.into_inner()),
        }
    }
}

impl Connection for AnyStream {
    fn connected(&self) -> Connected {
        match self {
            AnyStream::Http(s) => s.connected(),
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
            AnyStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            AnyStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyStream::Http(s) => Pin::new(s).poll_flush(cx),
            AnyStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            AnyStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyStream::Http(s) => Pin::new(s).poll_shutdown(cx),
            AnyStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            AnyStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub enum AnyTokioStream {
    Http(TcpStream),
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
            AnyTokioStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            AnyTokioStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyTokioStream::Http(s) => Pin::new(s).poll_flush(cx),
            AnyTokioStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            AnyTokioStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyTokioStream::Http(s) => Pin::new(s).poll_shutdown(cx),
            AnyTokioStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            AnyTokioStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

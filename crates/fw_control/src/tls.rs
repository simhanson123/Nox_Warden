//! A separate, bounded TLS listener for enrollment and authenticated device reads.
//! Client identity comes only from the verified TLS certificate, never headers.
use axum::{extract::connect_info::Connected, serve::IncomingStream};
use fw_enrollment::ControllerPki;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::Sleep,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
    server::TlsStream,
};

#[derive(Clone, Debug)]
pub struct TlsPeer {
    address: SocketAddr,
    pub(crate) certificate_fingerprint: Option<String>,
}
impl TlsPeer {
    pub(crate) fn is_loopback(&self) -> bool {
        self.address.ip().is_loopback()
    }
}

pub struct EnrollmentListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    connections: Arc<Semaphore>,
    handshakes: JoinSet<Option<(BoundedTlsConnection, TlsPeer)>>,
}

impl EnrollmentListener {
    pub async fn bind(
        address: SocketAddr,
        pki: &ControllerPki,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if !address.ip().is_loopback() {
            return Err("the development enrollment listener must bind to loopback".into());
        }
        let ca = pki.authority.ca_certificate_pem();
        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(ca.as_bytes()) {
            roots.add(certificate?)?;
        }
        if roots.is_empty() {
            return Err("enrollment trust roots are unavailable".into());
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        // Initial enrollment has a one-use token and no client certificate yet.
        // Any certificate that IS presented must pass chain/time/client-EKU checks.
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .allow_unauthenticated()
        .build()?;
        let certificates = CertificateDer::pem_slice_iter(pki.server_certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_slice(pki.server_private_key_pem.as_bytes())?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            connections: Arc::new(Semaphore::new(64)),
            handshakes: JoinSet::new(),
        })
    }

    pub fn local_socket_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

pub struct BoundedTlsConnection {
    stream: TlsStream<TcpStream>,
    deadline: Pin<Box<Sleep>>,
    _permit: OwnedSemaphorePermit,
}

impl BoundedTlsConnection {
    fn timed_out(&mut self, cx: &mut Context<'_>) -> bool {
        self.deadline.as_mut().poll(cx).is_ready()
    }
}
fn connection_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "enrollment connection lifetime exceeded",
    )
}
impl AsyncRead for BoundedTlsConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.timed_out(cx) {
            return Poll::Ready(Err(connection_timeout()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for BoundedTlsConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.timed_out(cx) {
            return Poll::Ready(Err(connection_timeout()));
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.timed_out(cx) {
            return Poll::Ready(Err(connection_timeout()));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl axum::serve::Listener for EnrollmentListener {
    type Io = BoundedTlsConnection;
    type Addr = TlsPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                biased;
                completed = self.handshakes.join_next(), if !self.handshakes.is_empty() => {
                    if let Some(Ok(Some(connection))) = completed { return connection; }
                }
                accepted = self.listener.accept() => {
                    let (stream, address) = match accepted {
                        Ok(connection) => connection,
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let Ok(permit) = self.connections.clone().try_acquire_owned() else {
                        // No unauthenticated socket can create an unbounded task queue.
                        drop(stream);
                        continue;
                    };
                    let acceptor = self.acceptor.clone();
                    self.handshakes.spawn(async move {
                        let accepted = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await;
                        let Ok(Ok(stream)) = accepted else { return None };
                        let certificate_fingerprint = stream.get_ref().1.peer_certificates()
                            .and_then(|certificates| certificates.first())
                            .map(|certificate| fw_contracts::hash_bytes(certificate.as_ref()));
                        Some((BoundedTlsConnection {
                            stream,
                            deadline: Box::pin(tokio::time::sleep(Duration::from_secs(60))),
                            _permit: permit,
                        }, TlsPeer { address, certificate_fingerprint }))
                    });
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(TlsPeer {
            address: self.listener.local_addr()?,
            certificate_fingerprint: None,
        })
    }
}

impl Connected<IncomingStream<'_, EnrollmentListener>> for TlsPeer {
    fn connect_info(stream: IncomingStream<'_, EnrollmentListener>) -> Self {
        stream.remote_addr().clone()
    }
}

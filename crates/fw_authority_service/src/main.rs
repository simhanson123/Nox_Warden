//! Explicit local startup only. No default database, profile or generated key.
use fw_authority_service::Service;
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{path::Path, sync::Arc, time::Duration};

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!(
            "Authority review service refused startup or stopped. Verify private configuration, preprovisioned credentials, distinct loopback origins and available port."
        );
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 || args[1] != "--config" || args[3] != "--session-key-file" {
        return Err("usage: fw_authority_service --config <private-config.json> --session-key-file <private-32-byte-key>".into());
    }
    let service = Service::from_files(Path::new(&args[2]), Path::new(&args[4]))?;
    let address = service.loopback_address()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let router = service.router();
    let connections = Arc::new(tokio::sync::Semaphore::new(64));
    eprintln!(
        "Authority review is listening on its configured loopback origin. No signer or host enforcement is enabled."
    );
    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let service = TowerToHyperService::new(router.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let mut http = http1::Builder::new();
            http.keep_alive(false)
                .max_headers(48)
                .max_buf_size(16384)
                .header_read_timeout(Duration::from_secs(5))
                .timer(TokioTimer::new());
            let _ = tokio::time::timeout(
                Duration::from_secs(30),
                http.serve_connection(TokioIo::new(stream), service),
            )
            .await;
        });
    }
}

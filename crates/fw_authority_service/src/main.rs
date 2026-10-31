//! Explicit local startup only. No default database, profile or generated key.
use fw_authority_service::{Service, StartupError, StartupStage};
use std::path::Path;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), StartupError> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 || args[1] != "--config" || args[3] != "--session-key-file" {
        return Err(StartupError::new(StartupStage::Arguments));
    }
    let service = Service::from_files(Path::new(&args[2]), Path::new(&args[4]))?;
    let address = service
        .loopback_address()
        .map_err(|_| StartupError::new(StartupStage::Origin))?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|_| StartupError::new(StartupStage::Bind))?;
    eprintln!(
        "Authority review is listening on its configured loopback origin. No signer or host enforcement is enabled."
    );
    service
        .serve(listener)
        .await
        .map_err(|_| StartupError::new(StartupStage::Listener))?;
    Ok(())
}

//! Offline compiler adapter used by the isolated native lab. Never executes nft.
use fw_backend_linux::{compile, CompileContext};
use fw_domain::Policy;
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    context: CompileContext,
    policies: Vec<Policy>,
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin().take(65_537).read_to_end(&mut bytes)?;
    let request: Input = fw_contracts::parse_strict(&bytes)?;
    let artifact = compile(&request.policies, &request.context)?;
    serde_json::to_writer(std::io::stdout(), &artifact)?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

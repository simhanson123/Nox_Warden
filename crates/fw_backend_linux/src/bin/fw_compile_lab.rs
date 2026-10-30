//! Offline compiler adapter used by the isolated native lab. Never executes nft.
//! `verify-readback` assumes a trusted original compiler artifact, trusted
//! observation time and UTC nft capture. It checks bounded correspondence only;
//! it does not authenticate the artifact or reconstruct its desired policy hash.
use fw_backend_linux::{compile, verify_readback, Artifact, Comparison, CompileContext};
use fw_domain::Policy;
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    context: CompileContext,
    policies: Vec<Policy>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadbackInput {
    artifact: Artifact,
    readback: serde_json::Value,
    observed_at_unix: i64,
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let verify = match arguments.as_slice() {
        [] => false,
        [command] if command == "verify-readback" => true,
        _ => return Err("usage: fw_compile_lab [verify-readback]".into()),
    };
    let limit = if verify {
        1024 * 1024
    } else {
        fw_contracts::MAX_BODY_BYTES
    };
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if verify {
        let request: ReadbackInput = fw_contracts::parse_strict_with_limit(&bytes, limit)?;
        let result = verify_readback(
            &request.artifact,
            &request.readback,
            request.observed_at_unix,
        );
        serde_json::to_writer(std::io::stdout(), &result)?;
        Ok(match result.comparison {
            Comparison::Match => 0,
            Comparison::Mismatch => 1,
            Comparison::Unknown => 2,
        })
    } else {
        let request: Input = fw_contracts::parse_strict(&bytes)?;
        let artifact = compile(&request.policies, &request.context)?;
        serde_json::to_writer(std::io::stdout(), &artifact)?;
        Ok(0)
    }
}
fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    };
    std::process::exit(code);
}

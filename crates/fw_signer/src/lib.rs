//! Independent, purpose-limited local policy signer. Production prerequisites
//! are resolved by the authority store; process isolation never supplies them.
use serde::{Deserialize, Serialize};
use std::ffi::OsString;

#[cfg(target_os = "linux")]
mod linux;

pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Arguments,
    Unsupported,
    Identity,
    Config,
    Key,
    Database,
    Socket,
    Peer,
    Protocol,
    Authority,
    Delivery,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::Arguments => "ARGUMENTS_REJECTED",
            Self::Unsupported => "PLATFORM_UNSUPPORTED",
            Self::Identity => "IDENTITY_REJECTED",
            Self::Config => "CONFIG_REJECTED",
            Self::Key => "KEY_REJECTED",
            Self::Database => "DATABASE_REJECTED",
            Self::Socket => "SOCKET_REJECTED",
            Self::Peer => "PEER_REJECTED",
            Self::Protocol => "PROTOCOL_REJECTED",
            Self::Authority => "AUTHORITY_UNAVAILABLE",
            Self::Delivery => "DELIVERY_FAILED",
        };
        write!(f, "SIGNER_{code}")
    }
}
impl std::error::Error for Failure {}
pub type Result<T> = std::result::Result<T, Failure>;

/// Administrator-owned configuration is never accepted over the socket. The
/// signer and controller must be different, non-root operating-system users.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: String,
    pub signer_uid: u32,
    pub controller_uid: u32,
    pub org_id: String,
    pub project_id: String,
    pub database_path: String,
    pub key_file: String,
    pub key_id: String,
    pub socket_path: String,
    pub webauthn_origin: String,
}

/// Neither payloads, actor names, filesystem paths nor PASS assertions are IPC
/// inputs. A signing request identifies an already retained immutable job.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum Request {
    #[serde(rename = "status")]
    Status {
        schema_version: String,
        request_id: String,
    },
    #[serde(rename = "sign_job")]
    SignJob {
        schema_version: String,
        request_id: String,
        job_id: String,
        expected_claim_generation: String,
    },
    #[serde(rename = "authorize_bootstrap")]
    AuthorizeBootstrap {
        schema_version: String,
        request_id: String,
        manifest_id: String,
    },
}
impl Request {
    fn validate(&self) -> Result<&str> {
        let (schema, id) = match self {
            Self::Status {
                schema_version,
                request_id,
            } => (schema_version, request_id),
            Self::AuthorizeBootstrap {
                schema_version,
                request_id,
                manifest_id,
            } => {
                canonical_uuid(manifest_id)?;
                (schema_version, request_id)
            }
            Self::SignJob {
                schema_version,
                request_id,
                job_id,
                expected_claim_generation,
            } => {
                canonical_uuid(job_id)?;
                let counter = expected_claim_generation
                    .parse::<u64>()
                    .map_err(|_| Failure::Protocol)?;
                if counter.to_string() != *expected_claim_generation {
                    return Err(Failure::Protocol);
                }
                (schema_version, request_id)
            }
        };
        canonical_uuid(id)?;
        if schema != "fw.signer-request/v1" {
            return Err(Failure::Protocol);
        }
        Ok(id)
    }
}
fn canonical_uuid(input: &str) -> Result<()> {
    let id = uuid::Uuid::parse_str(input).map_err(|_| Failure::Protocol)?;
    if id.to_string() != input {
        return Err(Failure::Protocol);
    }
    Ok(())
}

pub fn parse_request(bytes: &[u8]) -> Result<Request> {
    let request: Request = fw_contracts::parse_strict_with_limit(bytes, MAX_REQUEST_BYTES)
        .map_err(|_| Failure::Protocol)?;
    request.validate()?;
    Ok(request)
}

pub fn run(args: Vec<OsString>) -> Result<()> {
    if args.len() != 3 || args[1] != "--config" {
        return Err(Failure::Arguments);
    }
    #[cfg(target_os = "linux")]
    return linux::serve(std::path::Path::new(&args[2]));
    #[cfg(not(target_os = "linux"))]
    Err(Failure::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipc_is_closed_and_never_accepts_grant_bytes_or_identity() {
        let good = br#"{"operation":"status","schema_version":"fw.signer-request/v1","request_id":"00000000-0000-4000-8000-000000000001"}"#;
        assert!(parse_request(good).is_ok());
        for input in [
            String::from_utf8(good.to_vec())
                .unwrap()
                .replace("\"operation\"", "\"actor\":\"owner\",\"operation\""),
            String::from_utf8(good.to_vec())
                .unwrap()
                .replace("\"operation\"", "\"payload\":{},\"operation\""),
            String::from_utf8(good.to_vec())
                .unwrap()
                .replace("\"status\"", "\"status\",\"operation\":\"status\""),
        ] {
            assert_eq!(
                parse_request(input.as_bytes()).unwrap_err(),
                Failure::Protocol
            );
        }
        assert_eq!(
            parse_request(&vec![b' '; MAX_REQUEST_BYTES + 1]).unwrap_err(),
            Failure::Protocol
        );
    }
}

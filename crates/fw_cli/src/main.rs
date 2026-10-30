use serde_json::{Value, json};
use std::{error::Error, path::PathBuf};
fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" {
        println!(
            "fw_cli <health|status|requests|operations|audit|capabilities>\nEnvironment: FW_API_URL (default http://127.0.0.1:8787), FW_SESSION_FILE (0600 JSON with cookie).\nThis development client never changes the host firewall. Use the local UI bootstrap to authenticate."
        );
        return Ok(());
    }
    let base = std::env::var("FW_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".into());
    validate_base(&base)?;
    let route = match args[0].as_str() {
        "health" => "/healthz",
        "status" => "/api/v1/status",
        "requests" => "/api/v1/access-requests",
        "operations" => "/api/v1/operations",
        "audit" => "/api/v1/audit/events",
        "capabilities" => "/api/v1/capabilities",
        _ => return Err("unknown command; see --help".into()),
    };
    let agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .build()
        .new_agent();
    let mut req = agent.get(format!("{}{route}", base.trim_end_matches('/')));
    if args[0] != "health" {
        let path = PathBuf::from(
            std::env::var("FW_SESSION_FILE")
                .map_err(|_| "FW_SESSION_FILE is required for authenticated reads")?,
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
                return Err("session file must have permissions 0600".into());
            }
        }
        let session: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let cookie = session["cookie"].as_str().ok_or("session cookie missing")?;
        req = req.header("Cookie", cookie);
    }
    let response: Value = req.call()?.body_mut().read_json()?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", json!({"error":e.to_string()}));
        std::process::exit(1);
    }
}

fn validate_base(base: &str) -> Result<(), Box<dyn Error>> {
    let uri: ureq::http::Uri = base.parse()?;
    let authority = uri.authority().ok_or("API authority missing")?;
    let local = uri.scheme_str() == Some("http") && uri.host() == Some("127.0.0.1");
    if authority.as_str().contains('@')
        || uri.query().is_some()
        || !["", "/"].contains(&uri.path())
        || !(local || uri.scheme_str() == Some("https"))
    {
        return Err(
            "API must be an HTTPS origin or loopback HTTP origin without credentials".into(),
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origin_validation_rejects_credential_confusion() {
        for bad in [
            "http://127.0.0.1:8787@evil.example",
            "http://example.com",
            "https://user:pass@example.com",
            "https://example.com/path",
            "https://example.com/?query=yes",
        ] {
            assert!(validate_base(bad).is_err(), "{bad}");
        }
        assert!(validate_base("http://127.0.0.1:8787").is_ok());
        assert!(validate_base("https://firewall.example").is_ok());
    }
}

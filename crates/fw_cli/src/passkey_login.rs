//! Browser-mediated CLI login. The request URL includes an encrypted ticket;
//! the matching display code is printed separately. The polling secret and
//! session stay in memory or the existing private session file.
use super::*;
use std::time::Instant;

struct CliRequest {
    id: String,
    uri: String,
    code: String,
    poll_token: String,
    ticket: String,
}

fn request_fields(base: &str, body: &Value) -> Result<CliRequest> {
    let data = &body["data"];
    let id = data["request_id"]
        .as_str()
        .ok_or("invalid CLI login response")?;
    if !Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id) {
        return Err("invalid CLI login request identifier".into());
    }
    let uri = data["verification_uri"]
        .as_str()
        .ok_or("invalid CLI login response")?;
    let ticket = data["request_ticket"]
        .as_str()
        .filter(|value| {
            value.len() <= 2048
                && value.strip_prefix("cli1.").is_some_and(|encoded| {
                    !encoded.is_empty()
                        && encoded.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                        })
                })
        })
        .ok_or("invalid CLI request ticket")?;
    if uri != format!("{base}/cli-login/{id}#ticket={ticket}") {
        return Err("CLI login URL does not match the configured controller".into());
    }
    let code = data["user_code"]
        .as_str()
        .filter(|v| {
            v.len() == 8
                && v.bytes()
                    .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
        })
        .ok_or("invalid CLI login display code")?;
    let token = data["poll_token"]
        .as_str()
        .filter(|v| token_value(v))
        .ok_or("invalid CLI login response")?;
    Ok(CliRequest {
        id: id.into(),
        uri: uri.into(),
        code: code.into(),
        poll_token: token.into(),
        ticket: ticket.into(),
    })
}

pub(super) fn login(base: &str, session_path: &Path) -> Result<()> {
    let client = agent();
    let mut response = client
        .post(format!("{base}/api/v1/auth/cli/requests"))
        .header("Origin", base)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/json")
        .send_json(json!({}))
        .map_err(request_error)?;
    if response.status() != 201 {
        return Err("unexpected CLI login response".into());
    }
    let body: Value = response
        .body_mut()
        .with_config()
        .limit(65_536)
        .read_json()
        .map_err(|_| "invalid CLI login response")?;
    let CliRequest {
        id,
        uri,
        code,
        poll_token,
        ticket,
    } = request_fields(base, &body)?;
    eprintln!("Open this controller page in your browser: {uri}");
    eprintln!("Enter this code and approve CLI login: {code}");
    eprintln!("Waiting up to five minutes for passkey authorization.");
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(300) {
        let mut response = client
            .post(format!("{base}/api/v1/auth/cli/requests/{id}/exchange"))
            .header("Origin", base)
            .header("Idempotency-Key", Uuid::new_v4().to_string())
            .header("Content-Type", "application/json")
            .send_json(json!({"poll_token":poll_token,"request_ticket":ticket}))
            .map_err(request_error)?;
        if response.status() == 202 {
            let body: Value = response
                .body_mut()
                .with_config()
                .limit(65_536)
                .read_json()
                .map_err(|_| "invalid CLI polling response")?;
            if body["data"]["state"] != "pending" {
                return Err("unexpected CLI polling state".into());
            }
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        if response.status() != 200 {
            return Err("unexpected CLI authentication response".into());
        }
        let cookies = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().map(str::to_owned))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| "invalid CLI session cookie")?;
        let body: Value = response
            .body_mut()
            .with_config()
            .limit(65_536)
            .read_json()
            .map_err(|_| "invalid CLI session response")?;
        if body["data"]["authentication_method"] != "passkey" {
            return Err("CLI login did not use passkey authentication".into());
        }
        let session = session_from_response(base, &cookies, &body)?;
        write_private_file(session_path, &serde_json::to_vec(&session)?)?;
        return Ok(());
    }
    Err("CLI login expired; run login again to create a new request".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_login_response_cannot_redirect_or_print_untrusted_text() {
        let origin = "http://localhost:8787";
        let id = Uuid::new_v4();
        let ticket = "cli1.test_encoded_ticket";
        let mut body = json!({"data":{
            "request_id":id,"request_ticket":ticket,"verification_uri":format!("{origin}/cli-login/{id}#ticket={ticket}"),
            "user_code":"A123BC45","poll_token":"a".repeat(64)
        }});
        assert!(request_fields(origin, &body).is_ok());
        body["data"]["verification_uri"] = "https://untrusted.example/login".into();
        assert!(request_fields(origin, &body).is_err());
        body["data"]["verification_uri"] =
            format!("{origin}/cli-login/{id}#ticket={ticket}").into();
        body["data"]["user_code"] = "A123\nX45".into();
        assert!(request_fields(origin, &body).is_err());
        body["data"]["user_code"] = "A123BC45".into();
        body["data"]["poll_token"] = "short".into();
        assert!(request_fields(origin, &body).is_err());
        body["data"]["poll_token"] = "a".repeat(64).into();
        for invalid in [
            "".into(),
            "cli1.".into(),
            "cli1.hello\nworld".into(),
            "cli1.a?b=c".into(),
            format!("cli1.{}", "x".repeat(2044)),
        ] {
            body["data"]["request_ticket"] = Value::String(invalid.clone());
            body["data"]["verification_uri"] =
                format!("{origin}/cli-login/{id}#ticket={invalid}").into();
            assert!(request_fields(origin, &body).is_err());
        }
        body["data"]["request_ticket"] = ticket.into();
        body["data"]["verification_uri"] =
            format!("{origin}/cli-login/{id}?ticket={ticket}").into();
        assert!(request_fields(origin, &body).is_err());
    }
}

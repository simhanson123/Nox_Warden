//! Local-owner authentication only. These ceremonies do not approve policies or
//! provide an independent signer's authority. Raw WebAuthn proof stays in storage.
use super::*;
use fw_store::passkeys::{
    PasskeyAuthority, PasskeyChallenge, PasskeyChallengeInput, VerifiedPasskey,
};
use fw_webauthn::{
    AuthenticationResponse, AuthenticationState, Credential, RegistrationResponse,
    RegistrationState,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistrationStart {
    name: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationStart {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationFinish {
    ceremony_id: String,
    credential: RegistrationResponse,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationFinish {
    ceremony_id: String,
    credential: AuthenticationResponse,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

fn auth_envelope(data: Value) -> Value {
    let mut value = envelope(data);
    value["actions"] = json!([]);
    value
}

fn engine(s: &AppState) -> Result<&fw_webauthn::WebAuthn, Problem> {
    s.webauthn.as_ref().ok_or(Problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "PASSKEY_ORIGIN_UNSUPPORTED",
    ))
}
fn cookie<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    h.get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| part.trim().strip_prefix(&prefix))
}
fn session_binding(session: &Session) -> String {
    fw_contracts::hash_bytes(session.id.as_bytes())
}
fn flow_binding(h: &HeaderMap) -> Result<String, Problem> {
    let value = cookie(h, "fw_auth")
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(Problem(
            StatusCode::UNAUTHORIZED,
            "PASSKEY_BROWSER_BINDING_REQUIRED",
        ))?;
    Ok(fw_contracts::hash_bytes(value.as_bytes()))
}
fn write_headers<'a>(s: &AppState, h: &'a HeaderMap) -> Result<&'a str, Problem> {
    if header(h, "origin")? != s.origin {
        return Err(Problem(StatusCode::FORBIDDEN, "ORIGIN_REJECTED"));
    }
    let key = header(h, "idempotency-key")?;
    if !uuid(key) {
        return Err(bad("IDEMPOTENCY_KEY_INVALID"));
    }
    if header(h, "content-type")?.split(';').next() != Some("application/json") {
        return Err(Problem(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON_REQUIRED"));
    }
    Ok(key)
}
fn ceremony_limit(s: &AppState) -> Result<(), Problem> {
    let at = now();
    let mut login = s.login.lock().map_err(|_| unavailable())?;
    if at < login.ceremony_window || at - login.ceremony_window >= 60 {
        login.ceremony_window = at;
        login.ceremony_attempts = 0;
    }
    if login.ceremony_attempts >= 120 {
        return Err(Problem(
            StatusCode::TOO_MANY_REQUESTS,
            "PASSKEY_RATE_LIMITED",
        ));
    }
    login.ceremony_attempts += 1;
    Ok(())
}
fn map_passkey(error: fw_store::StoreError) -> Problem {
    use fw_store::StoreError::*;
    match error {
        Conflict("PASSKEY_PROOF_REJECTED") => {
            Problem(StatusCode::UNAUTHORIZED, "PASSKEY_VERIFICATION_FAILED")
        }
        Conflict(
            "PASSKEY_FRESH_AUTHENTICATION_REQUIRED"
            | "PASSKEY_AUTHENTICATION_REQUIRED"
            | "PASSKEY_AUTHORIZATION_REQUIRED",
        ) => Problem(StatusCode::FORBIDDEN, "PASSKEY_REAUTHENTICATION_REQUIRED"),
        Conflict("PASSKEY_LAST_CREDENTIAL") => {
            Problem(StatusCode::CONFLICT, "LAST_PASSKEY_REQUIRED")
        }
        Conflict("PASSKEY_CHALLENGE_LIMIT" | "PASSKEY_CHALLENGE_LOCKED") => {
            Problem(StatusCode::TOO_MANY_REQUESTS, "PASSKEY_RATE_LIMITED")
        }
        Conflict(code) => Problem(StatusCode::CONFLICT, code),
        other => map_store(other),
    }
}
fn public_challenge(challenge: PasskeyChallenge) -> Result<Response, Problem> {
    let options = challenge.options.get("publicKey").ok_or_else(unavailable)?;
    Ok(
        axum::Json(auth_envelope(json!({"ceremony_id":challenge.challenge_id,
        "public_key":options,"expires_at":timestamp(challenge.expires_at)})))
        .into_response(),
    )
}
fn credentials(s: &AppState) -> Result<Vec<Credential>, Problem> {
    s.store
        .list_passkeys(&s.tenant, PRINCIPAL)
        .map_err(map_passkey)?
        .into_iter()
        .filter(|c| c.revoked_at.is_none())
        .map(|c| {
            let value: Credential =
                serde_json::from_value(c.credential).map_err(|_| unavailable())?;
            if value.id() != c.credential_id || value.principal_id() != PRINCIPAL {
                return Err(unavailable());
            }
            Ok(value)
        })
        .collect()
}
fn proof_error() -> fw_store::StoreError {
    fw_store::StoreError::Conflict("PASSKEY_PROOF_REJECTED")
}
fn remove_session(s: &AppState, h: &HeaderMap) -> Result<(), Problem> {
    if let Some(token) = cookie(h, "fw_session") {
        s.login
            .lock()
            .map_err(|_| unavailable())?
            .sessions
            .remove(&hash(token));
    }
    Ok(())
}
fn clear_cookie(response: &mut Response, name: &str) {
    response.headers_mut().append(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        ))
        .unwrap(),
    );
}

async fn status(State(s): State<Arc<AppState>>) -> ApiResult {
    let enrolled = s
        .store
        .passkey_owner_enrolled(&s.tenant, PRINCIPAL)
        .map_err(map_passkey)?;
    let login = s.login.lock().map_err(|_| unavailable())?;
    Ok(axum::Json(auth_envelope(json!({"passkey_available":s.webauthn.is_some(),
        "passkey_unavailable_reason":if s.webauthn.is_some(){Value::Null}else{json!("PASSKEY_ORIGIN_UNSUPPORTED")},
        "owner_enrolled":enrolled,"bootstrap_available":!enrolled && !login.consumed && now()<login.expires && login.failures<10,
        "rp_id":s.webauthn.as_ref().map(|w|w.rp_id()),"origin":s.origin}))).into_response())
}
async fn list(State(s): State<Arc<AppState>>, h: HeaderMap) -> ApiResult {
    let session = s.auth(&h, false)?;
    let rows: Vec<_> = s.store.list_passkeys(&s.tenant, PRINCIPAL).map_err(map_passkey)?.into_iter().map(|c| json!({
        "id":c.credential_id,"name":c.name,"created_at":timestamp(c.created_at),
        "last_used_at":c.last_used_at.map(timestamp),"revoked_at":c.revoked_at.map(timestamp),
        "verified_at":c.verified_at.map(timestamp),"current":session.credential_id.as_deref()==Some(&c.credential_id)
    })).collect();
    Ok(axum::Json(auth_envelope(json!({"credentials":rows,"fresh_authentication_required":session.passkey_authority(now()).is_err()}))).into_response())
}
async fn registration_options(State(s): State<Arc<AppState>>, h: HeaderMap, b: Bytes) -> ApiResult {
    let session = s.auth(&h, true)?;
    let key = write_headers(&s, &h)?;
    let input: RegistrationStart =
        fw_contracts::parse_strict(&b).map_err(|_| bad("INVALID_JSON"))?;
    let authority = if session.credential_id.is_some() {
        session.passkey_authority(now())?
    } else {
        PasskeyAuthority::Bootstrap
    };
    let ceremony = engine(&s)?
        .begin_registration(PRINCIPAL, "Local owner", &credentials(&s)?)
        .map_err(|_| bad("PASSKEY_REGISTRATION_INVALID"))?;
    let saved = s
        .store
        .begin_passkey_challenge(
            &s.tenant,
            PRINCIPAL,
            &PasskeyChallengeInput {
                kind: "registration".into(),
                session_binding: session_binding(&session),
                authority: Some(authority),
                name: Some(input.name.clone()),
                request: serde_json::to_value(input).map_err(|_| unavailable())?,
                options: ceremony.options,
                state: serde_json::to_value(ceremony.state).map_err(|_| unavailable())?,
            },
            key,
            now(),
        )
        .map_err(map_passkey)?;
    public_challenge(saved)
}
async fn registration_complete(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    b: Bytes,
) -> ApiResult {
    let session = s.auth(&h, true)?;
    let key = write_headers(&s, &h)?;
    let input: RegistrationFinish =
        fw_contracts::parse_strict(&b).map_err(|_| bad("INVALID_JSON"))?;
    if !uuid(&input.ceremony_id) {
        return Err(bad("CEREMONY_ID_INVALID"));
    }
    let webauthn = engine(&s)?;
    let proof = serde_json::to_value(&input.credential).map_err(|_| unavailable())?;
    let result = s
        .store
        .finish_passkey_challenge(
            &s.tenant,
            PRINCIPAL,
            &input.ceremony_id,
            "registration",
            &session_binding(&session),
            &proof,
            key,
            now(),
            |challenge, _current| {
                let state: RegistrationState =
                    serde_json::from_value(challenge.state.clone()).map_err(|_| proof_error())?;
                let credential = webauthn
                    .finish_registration(&state, &input.credential)
                    .map_err(|_| proof_error())?;
                if credential.principal_id() != PRINCIPAL {
                    return Err(proof_error());
                }
                Ok(VerifiedPasskey {
                    credential_id: credential.id(),
                    credential: serde_json::to_value(credential).map_err(|_| proof_error())?,
                })
            },
        )
        .map_err(map_passkey)?;
    if result.replayed {
        return Err(Problem(StatusCode::CONFLICT, "CEREMONY_ALREADY_USED"));
    }
    remove_session(&s, &h)?;
    let mut response = axum::Json(auth_envelope(json!({"registered":true,"credential_id":result.credential_id,"authentication_required":true}))).into_response();
    clear_cookie(&mut response, "fw_session");
    Ok(response)
}
async fn login_options(State(s): State<Arc<AppState>>, h: HeaderMap, b: Bytes) -> ApiResult {
    let key = write_headers(&s, &h)?;
    ceremony_limit(&s)?;
    let input: AuthenticationStart =
        fw_contracts::parse_strict(&b).map_err(|_| bad("INVALID_JSON"))?;
    let mut candidates = credentials(&s)?;
    if let Some(id) = &input.credential_id {
        candidates.retain(|c| &c.id() == id);
    }
    let ceremony = engine(&s)?
        .begin_authentication(PRINCIPAL, &candidates)
        .map_err(|_| Problem(StatusCode::CONFLICT, "PASSKEY_UNAVAILABLE"))?;
    let token = cookie(&h, "fw_auth")
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned)
        .unwrap_or_else(random_token);
    let saved = s
        .store
        .begin_passkey_challenge(
            &s.tenant,
            PRINCIPAL,
            &PasskeyChallengeInput {
                kind: "authentication".into(),
                session_binding: fw_contracts::hash_bytes(token.as_bytes()),
                authority: None,
                name: None,
                request: serde_json::to_value(input).map_err(|_| unavailable())?,
                options: ceremony.options,
                state: serde_json::to_value(ceremony.state).map_err(|_| unavailable())?,
            },
            key,
            now(),
        )
        .map_err(map_passkey)?;
    let mut response = public_challenge(saved)?;
    response.headers_mut().append(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "fw_auth={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=300"
        ))
        .unwrap(),
    );
    Ok(response)
}
async fn login_complete(State(s): State<Arc<AppState>>, h: HeaderMap, b: Bytes) -> ApiResult {
    let key = write_headers(&s, &h)?;
    ceremony_limit(&s)?;
    let binding = flow_binding(&h)?;
    let input: AuthenticationFinish =
        fw_contracts::parse_strict(&b).map_err(|_| bad("INVALID_JSON"))?;
    if !uuid(&input.ceremony_id) {
        return Err(bad("CEREMONY_ID_INVALID"));
    }
    let webauthn = engine(&s)?;
    let proof = serde_json::to_value(&input.credential).map_err(|_| unavailable())?;
    let authenticated_at = now();
    let result = s
        .store
        .finish_passkey_challenge(
            &s.tenant,
            PRINCIPAL,
            &input.ceremony_id,
            "authentication",
            &binding,
            &proof,
            key,
            authenticated_at,
            |challenge, current| {
                let state: AuthenticationState =
                    serde_json::from_value(challenge.state.clone()).map_err(|_| proof_error())?;
                let current = current
                    .iter()
                    .find(|c| c.credential_id == input.credential.id && c.revoked_at.is_none())
                    .ok_or_else(proof_error)?;
                let current: Credential = serde_json::from_value(current.credential.clone())
                    .map_err(|_| proof_error())?;
                let credential = webauthn
                    .finish_authentication(&state, &input.credential, &current)
                    .map_err(|_| proof_error())?;
                if credential.principal_id() != PRINCIPAL {
                    return Err(proof_error());
                }
                Ok(VerifiedPasskey {
                    credential_id: credential.id(),
                    credential: serde_json::to_value(credential).map_err(|_| proof_error())?,
                })
            },
        )
        .map_err(map_passkey)?;
    if result.replayed {
        return Err(Problem(StatusCode::CONFLICT, "CEREMONY_ALREADY_USED"));
    }
    let (token, session) = s.issue_passkey_session(
        &result.credential_id,
        cookie(&h, "fw_session"),
        authenticated_at,
    )?;
    let mut response = axum::Json(envelope(session_data(&s, &session)?)).into_response();
    response.headers_mut().append(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "fw_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"
        ))
        .unwrap(),
    );
    clear_cookie(&mut response, "fw_auth");
    Ok(response)
}
async fn revoke(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    Path(id): Path<String>,
    b: Bytes,
) -> ApiResult {
    let session = s.auth(&h, true)?;
    let key = write_headers(&s, &h)?;
    let _: Empty = fw_contracts::parse_strict(&b).map_err(|_| bad("INVALID_JSON"))?;
    let authority = session.passkey_authority(now())?;
    s.store
        .revoke_passkey(&s.tenant, PRINCIPAL, &id, &authority, key, now())
        .map_err(map_passkey)?;
    let mut response =
        axum::Json(auth_envelope(json!({"revoked":true,"credential_id":id}))).into_response();
    if session.credential_id.as_deref() == Some(&id) {
        remove_session(&s, &h)?;
        clear_cookie(&mut response, "fw_session");
    }
    Ok(response)
}
async fn logout(State(s): State<Arc<AppState>>, h: HeaderMap, b: Bytes) -> ApiResult {
    write_headers(&s, &h)?;
    let _: Empty = fw_contracts::parse_strict(&b).map_err(|_| bad("INVALID_JSON"))?;
    // In particular, a localhost service that obtained only the port-shared
    // cookie must not invalidate another application's authenticated session.
    s.auth(&h, true)?;
    remove_session(&s, &h)?;
    let mut response = axum::Json(auth_envelope(json!({"authenticated":false}))).into_response();
    clear_cookie(&mut response, "fw_session");
    clear_cookie(&mut response, "fw_auth");
    Ok(response)
}
pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/status", get(status))
        .route("/auth/passkeys", get(list))
        .route(
            "/auth/passkeys/registration/options",
            post(registration_options),
        )
        .route(
            "/auth/passkeys/registration/complete",
            post(registration_complete),
        )
        .route("/auth/passkeys/login/options", post(login_options))
        .route("/auth/passkeys/login/complete", post(login_complete))
        .route("/auth/passkeys/{id}/revocations", post(revoke))
        .route("/auth/logout", post(logout))
}

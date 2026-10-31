//! Browser-authorized, one-use transfer of a local CLI session. The polling
//! secret is never a URL parameter and never reaches the browser UI.
use crate::*;

const LIFETIME: i64 = 300;
const MAX_REQUESTS: usize = 16;

struct CliRequest {
    user_code: String,
    poll_hash: [u8; 32],
    expires: i64,
    approval: Option<CliApproval>,
    consumed: bool,
    failures: u8,
}

struct CliApproval {
    credential_id: String,
    authenticated_at: i64,
    session_id: String,
}

#[derive(Default)]
pub(crate) struct CliLoginState {
    requests: HashMap<String, CliRequest>,
    creation_keys: HashMap<String, i64>,
}

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/cli/requests", post(create))
        .route("/auth/cli/requests/{id}", get(view))
        .route("/auth/cli/requests/{id}/authorize", post(authorize))
        .route("/auth/cli/requests/{id}/exchange", post(exchange))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorize {
    user_code: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    poll_token: String,
}

fn public_envelope(data: Value) -> Value {
    let mut value = envelope(data);
    value["actions"] = json!([]);
    value
}

fn input<T: serde::de::DeserializeOwned>(
    s: &AppState,
    h: &HeaderMap,
    b: &[u8],
) -> Result<T, Problem> {
    if header(h, "origin")? != s.origin {
        return Err(Problem(StatusCode::FORBIDDEN, "ORIGIN_REJECTED"));
    }
    if !uuid(header(h, "idempotency-key")?) {
        return Err(bad("IDEMPOTENCY_KEY_INVALID"));
    }
    if header(h, "content-type")?.split(';').next() != Some("application/json") {
        return Err(Problem(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON_REQUIRED"));
    }
    fw_contracts::parse_strict(b).map_err(|_| bad("INVALID_JSON"))
}

fn request<'a>(
    state: &'a mut CliLoginState,
    id: &str,
    at: i64,
) -> Result<&'a mut CliRequest, Problem> {
    if !uuid(id) {
        return Err(bad("CLI_REQUEST_INVALID"));
    }
    let r = state
        .requests
        .get_mut(id)
        .ok_or(Problem(StatusCode::NOT_FOUND, "CLI_LOGIN_NOT_FOUND"))?;
    if at >= r.expires {
        return Err(Problem(StatusCode::GONE, "CLI_LOGIN_EXPIRED"));
    }
    Ok(r)
}

async fn create(State(s): State<Arc<AppState>>, h: HeaderMap, b: Bytes) -> ApiResult {
    let _: Empty = input(&s, &h, &b)?;
    if !s.origin.starts_with("http://localhost:")
        || !s
            .store
            .passkey_owner_enrolled(&s.tenant, PRINCIPAL)
            .map_err(map_store)?
    {
        return Err(Problem(StatusCode::CONFLICT, "PASSKEY_LOGIN_REQUIRED"));
    }
    let at = now();
    let key = header(&h, "idempotency-key")?;
    let mut state = s.cli_login.lock().map_err(|_| unavailable())?;
    state.requests.retain(|_, r| r.expires > at);
    state.creation_keys.retain(|_, expiry| *expiry > at);
    // Authentication exchanges are one-use. Never regenerate a bearer secret
    // from a replayed creation request after the original response was lost.
    if state.creation_keys.contains_key(key) {
        return Err(Problem(StatusCode::CONFLICT, "CLI_REQUEST_ALREADY_CREATED"));
    }
    if state.requests.len() >= MAX_REQUESTS {
        return Err(Problem(StatusCode::TOO_MANY_REQUESTS, "CLI_LOGIN_LIMIT"));
    }
    let id = Uuid::new_v4().to_string();
    let token = random_token();
    let code = Uuid::new_v4().simple().to_string()[..8].to_ascii_uppercase();
    s.store
        .record_passkey_cli_event(&s.tenant, PRINCIPAL, &id, "cli_login_requested", at)
        .map_err(map_store)?;
    state.requests.insert(
        id.clone(),
        CliRequest {
            user_code: code.clone(),
            poll_hash: hash(&token),
            expires: at + LIFETIME,
            approval: None,
            consumed: false,
            failures: 0,
        },
    );
    state.creation_keys.insert(key.to_owned(), at + LIFETIME);
    Ok((
        StatusCode::CREATED,
        axum::Json(public_envelope(json!({
            "request_id":id,"user_code":code,"poll_token":token,
            "verification_uri":format!("{}/cli-login/{id}",s.origin),
            "expires_at":timestamp(at+LIFETIME),"poll_interval_seconds":2
        }))),
    )
        .into_response())
}

async fn view(State(s): State<Arc<AppState>>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    s.auth(&h, false)?;
    let mut state = s.cli_login.lock().map_err(|_| unavailable())?;
    let r = request(&mut state, &id, now())?;
    Ok(axum::Json(envelope(json!({
        "request_id":id,"user_code":r.user_code,"expires_at":timestamp(r.expires),
        "state":if r.consumed {"consumed"} else if r.approval.is_some() {"approved"} else {"pending"},
        "api_origin":s.origin
    }))).into_response())
}

async fn authorize(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    Path(id): Path<String>,
    b: Bytes,
) -> ApiResult {
    let input: Authorize = input(&s, &h, &b)?;
    let session = s.auth(&h, true)?;
    let at = now();
    session.passkey_authority(at)?;
    let credential = session.credential_id.as_ref().ok_or(Problem(
        StatusCode::FORBIDDEN,
        "PASSKEY_REAUTHENTICATION_REQUIRED",
    ))?;
    let mut state = s.cli_login.lock().map_err(|_| unavailable())?;
    let r = request(&mut state, &id, at)?;
    if r.consumed || r.failures >= 5 {
        return Err(Problem(StatusCode::CONFLICT, "CLI_LOGIN_UNAVAILABLE"));
    }
    if !bool::from(hash(&input.user_code).ct_eq(&hash(&r.user_code))) {
        r.failures += 1;
        return Err(Problem(StatusCode::FORBIDDEN, "CLI_CODE_MISMATCH"));
    }
    if r.approval.is_none() {
        s.store
            .record_passkey_cli_event(&s.tenant, PRINCIPAL, &id, "cli_login_approved", at)
            .map_err(map_store)?;
        r.approval = Some(CliApproval {
            credential_id: credential.clone(),
            authenticated_at: session.authenticated_at,
            session_id: session.id,
        });
    }
    Ok(axum::Json(envelope(
        json!({"request_id":id,"state":"approved","expires_at":timestamp(r.expires)}),
    ))
    .into_response())
}

async fn exchange(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    Path(id): Path<String>,
    b: Bytes,
) -> ApiResult {
    let input: Exchange = input(&s, &h, &b)?;
    let at = now();
    let mut state = s.cli_login.lock().map_err(|_| unavailable())?;
    let r = request(&mut state, &id, at)?;
    if !bool::from(hash(&input.poll_token).ct_eq(&r.poll_hash)) {
        return Err(Problem(StatusCode::UNAUTHORIZED, "CLI_POLL_SECRET_INVALID"));
    }
    if r.consumed {
        return Err(Problem(StatusCode::CONFLICT, "CLI_LOGIN_ALREADY_USED"));
    }
    let Some(approval) = &r.approval else {
        return Ok((
            StatusCode::ACCEPTED,
            axum::Json(public_envelope(json!({"state":"pending"}))),
        )
            .into_response());
    };
    // Preserve the actual WebAuthn authentication time. Exchanging a CLI token
    // must not refresh the ability to enroll or revoke another credential.
    if approval.authenticated_at > at || at - approval.authenticated_at >= LIFETIME {
        return Err(Problem(
            StatusCode::FORBIDDEN,
            "PASSKEY_REAUTHENTICATION_REQUIRED",
        ));
    }
    // Logging out or replacing the authorizing browser session cancels a
    // handoff that has not yet been exchanged. A captured polling secret must
    // not bring that session back after logout.
    let live_authorizer = s
        .login
        .lock()
        .map_err(|_| unavailable())?
        .sessions
        .values()
        .any(|session| {
            session.id == approval.session_id
                && session.expires > at
                && session.credential_id.as_deref() == Some(&approval.credential_id)
                && session.authenticated_at == approval.authenticated_at
        });
    if !live_authorizer {
        return Err(Problem(
            StatusCode::UNAUTHORIZED,
            "CLI_AUTHORIZER_SESSION_ENDED",
        ));
    }
    let (token, session) =
        s.issue_passkey_session(&approval.credential_id, None, approval.authenticated_at)?;
    if let Err(error) =
        s.store
            .record_passkey_cli_event(&s.tenant, PRINCIPAL, &id, "cli_login_exchanged", at)
    {
        s.login
            .lock()
            .map_err(|_| unavailable())?
            .sessions
            .remove(&hash(&token));
        return Err(map_store(error));
    }
    r.consumed = true;
    let mut response = axum::Json(envelope(session_data(&s, &session)?)).into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "fw_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"
        ))
        .map_err(|_| unavailable())?,
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use fw_store::passkeys::{PasskeyAuthority, PasskeyChallengeInput, VerifiedPasskey};

    // These trusted store callbacks are state-machine fixtures, not a WebAuthn
    // verifier. The separate browser smoke exercises real signed assertions.
    fn credential(s: &AppState, id: &str, authorizer: Option<&str>, at: i64) {
        for kind in ["registration", "authentication"] {
            let binding = fw_contracts::hash_bytes(b"CLI state-machine fixture");
            let authority = if kind == "authentication" {
                None
            } else {
                Some(
                    authorizer.map_or(PasskeyAuthority::Bootstrap, |credential_id| {
                        PasskeyAuthority::Passkey {
                            credential_id: credential_id.into(),
                            authenticated_at: at,
                        }
                    }),
                )
            };
            let challenge = s
                .store
                .begin_passkey_challenge(
                    &s.tenant,
                    PRINCIPAL,
                    &PasskeyChallengeInput {
                        kind: kind.into(),
                        session_binding: binding.clone(),
                        authority,
                        name: (kind == "registration").then(|| "CLI test key".into()),
                        request: json!({"test_only":true}),
                        options: json!({"test_only":true}),
                        state: json!({"test_only":true}),
                    },
                    &Uuid::new_v4().to_string(),
                    at,
                )
                .unwrap();
            s.store
                .finish_passkey_challenge(
                    &s.tenant,
                    PRINCIPAL,
                    &challenge.challenge_id,
                    kind,
                    &binding,
                    &json!({"test_only":true}),
                    &Uuid::new_v4().to_string(),
                    at,
                    |_, _| {
                        Ok(VerifiedPasskey {
                            credential_id: id.into(),
                            credential: json!({"test_only":true}),
                        })
                    },
                )
                .unwrap();
        }
    }
    fn setup() -> Arc<AppState> {
        let s = Arc::new(
            AppState::new(
                Store::in_memory().unwrap(),
                "http://localhost:8787".into(),
                "test-console",
            )
            .unwrap(),
        );
        credential(&s, "first-key", None, now());
        s
    }
    fn headers(s: &AppState, session: Option<(&str, &Session)>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("origin", s.origin.parse().unwrap());
        h.insert("content-type", "application/json".parse().unwrap());
        h.insert(
            "idempotency-key",
            Uuid::new_v4().to_string().parse().unwrap(),
        );
        if let Some((token, session)) = session {
            h.insert("cookie", format!("fw_session={token}").parse().unwrap());
            h.insert("x-csrf-token", session.csrf.parse().unwrap());
        }
        h
    }
    fn bytes(v: Value) -> Bytes {
        Bytes::from(serde_json::to_vec(&v).unwrap())
    }
    async fn data(response: Response) -> Value {
        serde_json::from_slice::<Value>(&to_bytes(response.into_body(), 65536).await.unwrap())
            .unwrap()["data"]
            .clone()
    }
    async fn flow(s: &Arc<AppState>) -> Value {
        data(
            create(State(s.clone()), headers(s, None), bytes(json!({})))
                .await
                .unwrap(),
        )
        .await
    }
    async fn approve(s: &Arc<AppState>, f: &Value, token: &str, session: &Session) -> ApiResult {
        authorize(
            State(s.clone()),
            headers(s, Some((token, session))),
            Path(f["request_id"].as_str().unwrap().into()),
            bytes(json!({"user_code":f["user_code"]})),
        )
        .await
    }
    async fn poll(s: &Arc<AppState>, f: &Value) -> ApiResult {
        exchange(
            State(s.clone()),
            headers(s, None),
            Path(f["request_id"].as_str().unwrap().into()),
            bytes(json!({"poll_token":f["poll_token"]})),
        )
        .await
    }
    #[tokio::test]
    async fn cli_handoff_requires_fresh_explicit_authorization_and_one_use_secret() {
        let s = setup();
        let f = flow(&s).await;
        assert_eq!(poll(&s, &f).await.unwrap().status(), StatusCode::ACCEPTED);
        let (token, session) = s.issue_passkey_session("first-key", None, now()).unwrap();
        let bad = authorize(
            State(s.clone()),
            headers(&s, Some((&token, &session))),
            Path(f["request_id"].as_str().unwrap().into()),
            bytes(json!({"user_code":"WRONG"})),
        )
        .await;
        assert!(matches!(
            bad,
            Err(Problem(StatusCode::FORBIDDEN, "CLI_CODE_MISMATCH"))
        ));
        approve(&s, &f, &token, &session).await.unwrap();
        let mut wrong = f.clone();
        wrong["poll_token"] = "wrong".into();
        assert!(matches!(
            poll(&s, &wrong).await,
            Err(Problem(StatusCode::UNAUTHORIZED, "CLI_POLL_SECRET_INVALID"))
        ));
        let count = s.login.lock().unwrap().sessions.len();
        let (a, b) = tokio::join!(poll(&s, &f), poll(&s, &f));
        assert!(a.is_ok() ^ b.is_ok());
        assert_eq!(s.login.lock().unwrap().sessions.len(), count + 1);
        let result = data(a.or(b).unwrap()).await;
        assert_eq!(result["authenticated_at"], session.authenticated_at);
        assert_eq!(result["authentication_method"], "passkey");
    }
    #[tokio::test]
    async fn ended_browser_session_or_revoked_credential_blocks_pending_handoff() {
        let s = setup();
        let at = now();
        credential(&s, "second-key", Some("first-key"), at);
        let (token, session) = s.issue_passkey_session("first-key", None, at).unwrap();
        let f = flow(&s).await;
        approve(&s, &f, &token, &session).await.unwrap();
        s.login.lock().unwrap().sessions.remove(&hash(&token));
        assert!(matches!(
            poll(&s, &f).await,
            Err(Problem(
                StatusCode::UNAUTHORIZED,
                "CLI_AUTHORIZER_SESSION_ENDED"
            ))
        ));
        let (token, session) = s.issue_passkey_session("first-key", None, at).unwrap();
        let f = flow(&s).await;
        approve(&s, &f, &token, &session).await.unwrap();
        s.store
            .revoke_passkey(
                &s.tenant,
                PRINCIPAL,
                "first-key",
                &PasskeyAuthority::Passkey {
                    credential_id: "second-key".into(),
                    authenticated_at: at,
                },
                &Uuid::new_v4().to_string(),
                at,
            )
            .unwrap();
        assert!(matches!(
            poll(&s, &f).await,
            Err(Problem(StatusCode::UNAUTHORIZED, "PASSKEY_SESSION_REVOKED"))
        ));
    }
    #[tokio::test]
    async fn expired_requests_and_stale_or_future_authentication_cannot_issue_sessions() {
        let s = setup();
        let at = now();
        for authentication_time in [at - 300, at + 300] {
            let (token, session) = s
                .issue_passkey_session("first-key", None, authentication_time)
                .unwrap();
            let f = flow(&s).await;
            let failure = approve(&s, &f, &token, &session).await.unwrap_err();
            if authentication_time > at {
                assert_eq!(failure.0, StatusCode::UNAUTHORIZED);
            } else {
                assert_eq!(failure.0, StatusCode::FORBIDDEN);
                assert_eq!(failure.1, "PASSKEY_REAUTHENTICATION_REQUIRED");
            }
        }
        let f = flow(&s).await;
        s.cli_login
            .lock()
            .unwrap()
            .requests
            .get_mut(f["request_id"].as_str().unwrap())
            .unwrap()
            .expires = at;
        assert!(matches!(
            poll(&s, &f).await,
            Err(Problem(StatusCode::GONE, "CLI_LOGIN_EXPIRED"))
        ));
    }

    #[tokio::test]
    async fn cli_handoff_is_reachable_at_the_public_api_route() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let s = setup();
        let app = crate::router(s.clone(), "/tmp/fw-absent-web".into());
        let mut request = Request::post("/api/v1/auth/cli/requests")
            .body(Body::from("{}"))
            .unwrap();
        *request.headers_mut() = headers(&s, None);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let f = data(response).await;
        assert_eq!(
            f["verification_uri"],
            format!(
                "{}/cli-login/{}",
                s.origin,
                f["request_id"].as_str().unwrap()
            )
        );
    }
}

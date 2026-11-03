//! Browser-authorized, one-use transfer of a local CLI session. The polling
//! secret is never a URL parameter and never reaches the browser UI.
use crate::*;

#[path = "cli_ticket.rs"]
mod ticket;

const LIFETIME: i64 = 300;
const MAX_REQUESTS: usize = 16;

struct CliRequest {
    ticket_hash: [u8; 32],
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
    tickets: Option<ticket::Tickets>,
    requests: HashMap<String, CliRequest>,
    clock: Option<CliClock>,
    #[cfg(test)]
    exchange_probe: Option<Arc<ExchangeProbe>>,
}

struct CliClock {
    anchor: std::time::Instant,
    anchor_wall: i64,
    high_water: i64,
}

#[cfg(test)]
struct ExchangeProbe {
    validated: std::sync::Barrier,
    proceed: std::sync::Barrier,
}

impl CliLoginState {
    fn observe_time(&mut self, at: i64) -> Result<(), Problem> {
        let clock = self.clock.get_or_insert_with(|| CliClock {
            anchor: std::time::Instant::now(),
            anchor_wall: at,
            high_water: at,
        });
        let elapsed = i64::try_from(clock.anchor.elapsed().as_secs()).map_err(|_| unavailable())?;
        let monotonic_floor = clock
            .anchor_wall
            .checked_add(elapsed)
            .ok_or_else(unavailable)?;
        clock.high_water = clock.high_water.max(at).max(monotonic_floor);
        if at < clock.high_water {
            return Err(Problem(StatusCode::CONFLICT, "CLI_CLOCK_UNCERTAIN"));
        }
        Ok(())
    }
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
    request_ticket: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    poll_token: String,
    request_ticket: String,
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

fn ticket_claims(
    s: &AppState,
    state: &CliLoginState,
    token: &str,
    id: &str,
    at: i64,
) -> Result<ticket::Claims, Problem> {
    if !uuid(id) {
        return Err(bad("CLI_REQUEST_INVALID"));
    }
    let claims = state
        .tickets
        .as_ref()
        .ok_or(bad("CLI_REQUEST_TICKET_INVALID"))?
        .open(token, &s.origin, id, at)
        .map_err(ticket_error)?;
    if let Some(request) = state.requests.get(id)
        && (!bool::from(request.ticket_hash.ct_eq(&hash(token)))
            || request.expires != claims.expires_at)
    {
        return Err(bad("CLI_REQUEST_TICKET_INVALID"));
    }
    Ok(claims)
}

fn ticket_error(error: ticket::Error) -> Problem {
    match error {
        ticket::Error::Invalid => bad("CLI_REQUEST_TICKET_INVALID"),
        ticket::Error::Expired => Problem(StatusCode::GONE, "CLI_LOGIN_EXPIRED"),
        ticket::Error::Internal => unavailable(),
    }
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
    let mut state = s.cli_login.lock().map_err(|_| unavailable())?;
    let at = now();
    state.observe_time(at)?;
    if state.tickets.is_none() {
        state.tickets = Some(ticket::Tickets::new().map_err(ticket_error)?);
    }
    let id = Uuid::new_v4().to_string();
    let token = random_token();
    let code = Uuid::new_v4().simple().to_string()[..8].to_ascii_uppercase();
    // No public pending slot, replay tombstone or durable audit row. A repeated
    // creation key gets an unrelated request, never an earlier bearer secret.
    let (request_ticket, claims) = state
        .tickets
        .as_mut()
        .ok_or_else(unavailable)?
        .issue(&s.origin, id.clone(), hash(&code), hash(&token), at)
        .map_err(ticket_error)?;
    Ok((
        StatusCode::CREATED,
        axum::Json(public_envelope(json!({
            "request_id":id,"request_ticket":request_ticket,"user_code":code,"poll_token":token,
            "verification_uri":format!("{}/cli-login/{id}#ticket={request_ticket}",s.origin),
            "expires_at":timestamp(claims.expires_at),"poll_interval_seconds":2
        }))),
    )
        .into_response())
}

async fn view(State(s): State<Arc<AppState>>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    s.auth(&h, false)?;
    let mut state = s.cli_login.lock().map_err(|_| unavailable())?;
    let at = now();
    state.observe_time(at)?;
    let claims = ticket_claims(&s, &state, header(&h, "x-cli-request-ticket")?, &id, at)?;
    let r = state.requests.get(&id);
    Ok(axum::Json(envelope(json!({
        // The confirmation code is returned only to the initiating terminal.
        // Returning it here would let a URL recipient copy it from the page
        // without having started the CLI request they are about to approve.
        "request_id":id,"expires_at":timestamp(claims.expires_at),
        "state":if r.is_some_and(|r|r.consumed) {"consumed"} else if r.is_some_and(|r|r.approval.is_some()) {"approved"} else {"pending"},
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
    let at = now();
    session.passkey_authority(at)?;
    state.observe_time(at)?;
    let claims = ticket_claims(&s, &state, &input.request_ticket, &id, at)?;
    // Only a currently verified, fresh direct browser session can consume this
    // budget. Anonymous issue/view/poll cannot evict or fill protected entries.
    state.requests.retain(|_, r| r.expires > at);
    if !state.requests.contains_key(&id) && state.requests.len() >= MAX_REQUESTS {
        return Err(Problem(StatusCode::TOO_MANY_REQUESTS, "CLI_LOGIN_LIMIT"));
    }
    let r = state
        .requests
        .entry(id.clone())
        .or_insert_with(|| CliRequest {
            ticket_hash: hash(&input.request_ticket),
            expires: claims.expires_at,
            approval: None,
            consumed: false,
            failures: 0,
        });
    if r.consumed || r.failures >= 5 {
        return Err(Problem(StatusCode::CONFLICT, "CLI_LOGIN_UNAVAILABLE"));
    }
    if !bool::from(hash(&input.user_code).ct_eq(&claims.code_hash)) {
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
    let mut state = s.cli_login.lock().map_err(|_| unavailable())?;
    let at = now();
    state.observe_time(at)?;
    let claims = ticket_claims(&s, &state, &input.request_ticket, &id, at)?;
    if !bool::from(hash(&input.poll_token).ct_eq(&claims.poll_hash)) {
        return Err(Problem(StatusCode::UNAUTHORIZED, "CLI_POLL_SECRET_INVALID"));
    }
    #[cfg(test)]
    let exchange_probe = state.exchange_probe.clone();
    let Some(r) = state.requests.get_mut(&id) else {
        return Ok((
            StatusCode::ACCEPTED,
            axum::Json(public_envelope(json!({"state":"pending"}))),
        )
            .into_response());
    };
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
    // Preserve the actual authentication time for handoff freshness and session
    // lifetime. CLI provenance never conveys browser credential-management or
    // further CLI-authorization authority, even during this fresh interval.
    if approval.authenticated_at > at || at - approval.authenticated_at >= LIFETIME {
        return Err(Problem(
            StatusCode::FORBIDDEN,
            "PASSKEY_REAUTHENTICATION_REQUIRED",
        ));
    }
    // Logging out or replacing the authorizing browser session cancels a
    // handoff that has not yet been exchanged. A captured polling secret must
    // not bring that session back after logout.
    // Lock order is CLI state -> session registry -> short store operation.
    // Other session paths release store guards before acquiring this registry;
    // none hold the registry while acquiring CLI state.
    let mut login = s.login.lock().map_err(|_| unavailable())?;
    let live_authorizer = login.sessions.values().any(|session| {
        session.id == approval.session_id
            && session.kind == SessionKind::BrowserPasskey
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
    #[cfg(test)]
    if let Some(probe) = exchange_probe {
        probe.validated.wait();
        probe.proceed.wait();
    }
    s.store
        .active_passkey(&s.tenant, PRINCIPAL, &approval.credential_id)
        .map_err(|_| Problem(StatusCode::UNAUTHORIZED, "PASSKEY_SESSION_REVOKED"))?;
    s.store
        .record_passkey_cli_event(&s.tenant, PRINCIPAL, &id, "cli_login_exchanged", at)
        .map_err(map_store)?;
    let (token, session) = AppState::insert_credential_session(
        &mut login,
        SessionKind::Cli,
        &approval.credential_id,
        None,
        approval.authenticated_at,
    );
    r.consumed = true;
    drop(login);
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
                            authenticated_at: authentication_time(s, credential_id),
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
    fn authentication_time(s: &AppState, id: &str) -> i64 {
        s.store
            .active_passkey(&s.tenant, PRINCIPAL, id)
            .unwrap()
            .last_used_at
            .unwrap()
    }
    fn browser_session(s: &AppState, id: &str) -> (String, Session) {
        // Session authority must retain the store fixture's actual authentication
        // time, even when setup and the HTTP operation cross a clock second.
        s.issue_passkey_session(id, None, authentication_time(s, id))
            .unwrap()
    }
    fn setup() -> Arc<AppState> {
        setup_at(now())
    }
    fn setup_at(at: i64) -> Arc<AppState> {
        let s = Arc::new(
            AppState::new(
                Store::in_memory().unwrap(),
                "http://localhost:8787".into(),
                "test-console",
            )
            .unwrap(),
        );
        credential(&s, "first-key", None, at);
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
    fn view_headers(s: &AppState, f: &Value, token: &str, session: &Session) -> HeaderMap {
        let mut h = headers(s, Some((token, session)));
        h.insert(
            "x-cli-request-ticket",
            f["request_ticket"].as_str().unwrap().parse().unwrap(),
        );
        h
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
            bytes(json!({"user_code":f["user_code"],"request_ticket":f["request_ticket"]})),
        )
        .await
    }
    async fn poll(s: &Arc<AppState>, f: &Value) -> ApiResult {
        exchange(
            State(s.clone()),
            headers(s, None),
            Path(f["request_id"].as_str().unwrap().into()),
            bytes(json!({"poll_token":f["poll_token"],"request_ticket":f["request_ticket"]})),
        )
        .await
    }
    async fn delegated_session(s: &Arc<AppState>) -> (String, Session) {
        let (browser_token, browser) = browser_session(s, "first-key");
        let request = flow(s).await;
        approve(s, &request, &browser_token, &browser)
            .await
            .unwrap();
        let response = poll(s, &request).await.unwrap();
        let token = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("fw_session=")
            .unwrap()
            .to_owned();
        let session = s.login.lock().unwrap().sessions[&hash(&token)].clone();
        (token, session)
    }
    async fn route_post(
        s: &Arc<AppState>,
        token: &str,
        session: &Session,
        path: &str,
        body: Value,
    ) -> Response {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let app = crate::router(s.clone(), "/tmp/fw-absent-web".into());
        let mut request = Request::post(path)
            .body(Body::from(body.to_string()))
            .unwrap();
        *request.headers_mut() = headers(s, Some((token, session)));
        // These client claims cannot promote server-owned session provenance.
        request
            .headers_mut()
            .insert("x-session-kind", "browser_passkey".parse().unwrap());
        request
            .headers_mut()
            .insert("x-authentication-method", "passkey".parse().unwrap());
        app.oneshot(request).await.unwrap()
    }
    #[tokio::test]
    async fn delegated_cli_session_cannot_authorize_another_terminal() {
        let s = setup();
        let (token, session) = delegated_session(&s).await;
        let next = flow(&s).await;
        let response = route_post(
            &s,
            &token,
            &session,
            &format!(
                "/api/v1/auth/cli/requests/{}/authorize",
                next["request_id"].as_str().unwrap()
            ),
            json!({"user_code":next["user_code"],"request_ticket":next["request_ticket"]}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            poll(&s, &next).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
        assert!(
            s.auth(&headers(&s, Some((&token, &session))), false)
                .is_ok()
        );
    }
    #[tokio::test]
    async fn delegated_cli_session_cannot_revoke_or_register_owner_credentials() {
        let s = setup();
        credential(&s, "second-key", Some("first-key"), now());
        let (token, session) = delegated_session(&s).await;
        // Revoke is a real mutation that succeeded before provenance separation.
        for (path, body) in [
            ("/api/v1/auth/passkeys/second-key/revocations", json!({})),
            (
                "/api/v1/auth/passkeys/registration/options",
                json!({"name":"Injected owner"}),
            ),
            // Completion must reject CLI authority before parsing/proof processing,
            // even if a caller skips the registration-options endpoint entirely.
            ("/api/v1/auth/passkeys/registration/complete", json!({})),
        ] {
            let response = route_post(&s, &token, &session, path, body).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
            let result: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap())
                    .unwrap();
            assert_eq!(result["detail"], "BROWSER_PASSKEY_REQUIRED");
        }
        assert!(
            s.store
                .active_passkey(&s.tenant, PRINCIPAL, "second-key")
                .is_ok()
        );
        assert_eq!(
            s.store.list_passkeys(&s.tenant, PRINCIPAL).unwrap().len(),
            2
        );
    }
    #[tokio::test]
    async fn delegated_cli_access_ends_on_logout_expiry_or_credential_revocation() {
        for ending in ["logout", "expiry", "revocation"] {
            let s = setup();
            credential(&s, "second-key", Some("first-key"), now());
            let (token, session) = delegated_session(&s).await;
            let (browser_token, browser) = browser_session(&s, "second-key");
            let h = headers(&s, Some((&token, &session)));
            assert!(s.auth(&h, false).is_ok());
            assert!(s.auth(&h, true).is_ok());
            match ending {
                "logout" => {
                    let response =
                        route_post(&s, &token, &session, "/api/v1/auth/logout", json!({})).await;
                    assert_eq!(response.status(), StatusCode::OK);
                }
                "expiry" => {
                    s.login
                        .lock()
                        .unwrap()
                        .sessions
                        .get_mut(&hash(&token))
                        .unwrap()
                        .expires = now();
                }
                "revocation" => {
                    let response = route_post(
                        &s,
                        &browser_token,
                        &browser,
                        "/api/v1/auth/passkeys/first-key/revocations",
                        json!({}),
                    )
                    .await;
                    assert_eq!(response.status(), StatusCode::OK);
                }
                _ => unreachable!(),
            }
            assert!(
                matches!(s.auth(&h, false), Err(Problem(StatusCode::UNAUTHORIZED, _))),
                "{ending}"
            );
            // Ending the delegated session cannot end an independent browser session.
            assert!(
                s.auth(&headers(&s, Some((&browser_token, &browser))), false)
                    .is_ok()
            );
        }
    }
    #[tokio::test]
    async fn revocation_fixture_retains_authentication_time_across_clock_seconds() {
        // Both values are recent and in the past; only the timestamp matching
        // the persisted authentication may authorize this owner mutation.
        let at = now() - 2;
        let s = setup_at(at);
        credential(&s, "second-key", Some("first-key"), at);
        let (cli_token, cli_session) = delegated_session(&s).await;
        let (token, session) = s.issue_passkey_session("second-key", None, at + 1).unwrap();
        let denied = route_post(
            &s,
            &token,
            &session,
            "/api/v1/auth/passkeys/first-key/revocations",
            json!({}),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let problem: Value =
            serde_json::from_slice(&to_bytes(denied.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(problem["detail"], "PASSKEY_REAUTHENTICATION_REQUIRED");
        assert!(
            s.auth(&headers(&s, Some((&cli_token, &cli_session))), false)
                .is_ok()
        );

        let (token, session) = browser_session(&s, "second-key");
        assert_eq!(session.authenticated_at, at);
        let accepted = route_post(
            &s,
            &token,
            &session,
            "/api/v1/auth/passkeys/first-key/revocations",
            json!({}),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);
        assert!(matches!(
            s.auth(&headers(&s, Some((&cli_token, &cli_session))), false),
            Err(Problem(StatusCode::UNAUTHORIZED, _))
        ));
    }
    #[tokio::test]
    async fn browser_request_view_never_discloses_the_terminal_confirmation_code() {
        let s = setup();
        let f = flow(&s).await;
        let (token, session) = browser_session(&s, "first-key");
        let viewed = data(
            view(
                State(s.clone()),
                view_headers(&s, &f, &token, &session),
                Path(f["request_id"].as_str().unwrap().into()),
            )
            .await
            .unwrap(),
        )
        .await;
        assert!(viewed.get("user_code").is_none());
        assert!(viewed.get("poll_token").is_none());
        let serialized = serde_json::to_string(&viewed).unwrap();
        assert!(!serialized.contains(f["user_code"].as_str().unwrap()));
        assert!(!serialized.contains(f["poll_token"].as_str().unwrap()));
        assert_eq!(viewed["state"], "pending");
        assert_eq!(poll(&s, &f).await.unwrap().status(), StatusCode::ACCEPTED);
        assert!(
            !f["verification_uri"]
                .as_str()
                .unwrap()
                .contains(f["user_code"].as_str().unwrap())
        );
        assert!(
            !f["verification_uri"]
                .as_str()
                .unwrap()
                .contains(f["poll_token"].as_str().unwrap())
        );
    }
    #[tokio::test]
    async fn cli_handoff_requires_fresh_explicit_authorization_and_one_use_secret() {
        let s = setup();
        let f = flow(&s).await;
        assert_eq!(poll(&s, &f).await.unwrap().status(), StatusCode::ACCEPTED);
        let unauthenticated = authorize(
            State(s.clone()),
            headers(&s, None),
            Path(f["request_id"].as_str().unwrap().into()),
            bytes(json!({"user_code":f["user_code"],"request_ticket":f["request_ticket"]})),
        )
        .await;
        assert!(matches!(
            unauthenticated,
            Err(Problem(StatusCode::UNAUTHORIZED, "AUTHENTICATION_REQUIRED"))
        ));
        assert_eq!(poll(&s, &f).await.unwrap().status(), StatusCode::ACCEPTED);
        let (token, session) = browser_session(&s, "first-key");
        let missing = authorize(
            State(s.clone()),
            headers(&s, Some((&token, &session))),
            Path(f["request_id"].as_str().unwrap().into()),
            bytes(json!({})),
        )
        .await;
        assert!(matches!(
            missing,
            Err(Problem(StatusCode::BAD_REQUEST, "INVALID_JSON"))
        ));
        assert_eq!(poll(&s, &f).await.unwrap().status(), StatusCode::ACCEPTED);
        let bad = authorize(
            State(s.clone()),
            headers(&s, Some((&token, &session))),
            Path(f["request_id"].as_str().unwrap().into()),
            bytes(json!({"user_code":"WRONG","request_ticket":f["request_ticket"]})),
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
        let (token, session) = browser_session(&s, "first-key");
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
        let (token, session) = browser_session(&s, "first-key");
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
                // Request/approval audit events may cross a clock second after
                // the authentication time captured above. Revocation uses the
                // current operation time, preserving the monotonic audit head.
                now(),
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
        let mut f = flow(&s).await;
        let (expired_ticket, _) = s
            .cli_login
            .lock()
            .unwrap()
            .tickets
            .as_mut()
            .unwrap()
            .issue(
                &s.origin,
                f["request_id"].as_str().unwrap().into(),
                hash(f["user_code"].as_str().unwrap()),
                hash(f["poll_token"].as_str().unwrap()),
                at - LIFETIME,
            )
            .unwrap();
        f["request_ticket"] = expired_ticket.into();
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
                "{}/cli-login/{}#ticket={}",
                s.origin,
                f["request_id"].as_str().unwrap(),
                f["request_ticket"].as_str().unwrap()
            )
        );
    }

    #[tokio::test]
    async fn anonymous_initiation_flood_preserves_earlier_request_without_state_or_audit_growth() {
        let s = setup();
        let f = flow(&s).await;
        let before = s.store.count_audit(&s.tenant, 0).unwrap();
        for _ in 0..1005 {
            flow(&s).await;
        }
        assert!(s.cli_login.lock().unwrap().requests.is_empty());
        assert_eq!(s.store.count_audit(&s.tenant, 0).unwrap(), before);
        assert_eq!(poll(&s, &f).await.unwrap().status(), StatusCode::ACCEPTED);
        assert!(s.cli_login.lock().unwrap().requests.is_empty());
        let (token, session) = browser_session(&s, "first-key");
        approve(&s, &f, &token, &session).await.unwrap();
        assert_eq!(poll(&s, &f).await.unwrap().status(), StatusCode::OK);
        assert_eq!(s.store.count_audit(&s.tenant, 0).unwrap(), before + 2);
        for _ in 0..32 {
            flow(&s).await;
        }
        assert!(matches!(
            poll(&s, &f).await,
            Err(Problem(StatusCode::CONFLICT, "CLI_LOGIN_ALREADY_USED"))
        ));
        assert_eq!(s.cli_login.lock().unwrap().requests.len(), 1);
    }

    #[tokio::test]
    async fn creation_retry_never_recovers_previous_ticket_or_bearer_secret() {
        let s = setup();
        let h = headers(&s, None);
        let first = data(
            create(State(s.clone()), h.clone(), bytes(json!({})))
                .await
                .unwrap(),
        )
        .await;
        let retry = data(create(State(s.clone()), h, bytes(json!({}))).await.unwrap()).await;
        for field in ["request_id", "request_ticket", "poll_token"] {
            assert_ne!(first[field], retry[field], "{field}");
        }
        // Both independently created requests are still usable; a retry neither
        // replaces the earlier request nor reissues any earlier polling secret.
        assert_eq!(
            poll(&s, &first).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            poll(&s, &retry).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
    }

    #[tokio::test]
    async fn ticket_url_alone_and_cross_request_secrets_cannot_authorize_or_exchange() {
        let s = setup();
        let first = flow(&s).await;
        let second = flow(&s).await;
        let (token, session) = browser_session(&s, "first-key");
        let viewed = data(
            view(
                State(s.clone()),
                view_headers(&s, &first, &token, &session),
                Path(first["request_id"].as_str().unwrap().into()),
            )
            .await
            .unwrap(),
        )
        .await;
        assert!(viewed.get("request_ticket").is_none());
        assert!(viewed.get("user_code").is_none());
        assert!(viewed.get("poll_token").is_none());
        assert!(s.cli_login.lock().unwrap().requests.is_empty());
        let mut mixed = first.clone();
        mixed["request_ticket"] = second["request_ticket"].clone();
        assert!(matches!(
            poll(&s, &mixed).await,
            Err(Problem(
                StatusCode::BAD_REQUEST,
                "CLI_REQUEST_TICKET_INVALID"
            ))
        ));
        assert!(matches!(
            approve(&s, &mixed, &token, &session).await,
            Err(Problem(
                StatusCode::BAD_REQUEST,
                "CLI_REQUEST_TICKET_INVALID"
            ))
        ));
        assert!(s.cli_login.lock().unwrap().requests.is_empty());
        mixed = first.clone();
        mixed["poll_token"] = second["poll_token"].clone();
        assert!(matches!(
            poll(&s, &mixed).await,
            Err(Problem(StatusCode::UNAUTHORIZED, "CLI_POLL_SECRET_INVALID"))
        ));
        mixed = first.clone();
        mixed["request_ticket"] = "cli1.invalid".into();
        assert!(poll(&s, &mixed).await.is_err());
        assert!(matches!(
            view(
                State(s.clone()),
                headers(&s, Some((&token, &session))),
                Path(first["request_id"].as_str().unwrap().into())
            )
            .await,
            Err(Problem(StatusCode::BAD_REQUEST, "HEADER_REQUIRED"))
        ));
    }

    #[tokio::test]
    async fn protected_wrong_code_attempts_remain_bounded_and_cannot_be_reset_by_public_creation() {
        let s = setup();
        let f = flow(&s).await;
        let (token, session) = browser_session(&s, "first-key");
        let mut wrong = f.clone();
        wrong["user_code"] = "WRONG".into();
        for _ in 0..5 {
            assert!(matches!(
                approve(&s, &wrong, &token, &session).await,
                Err(Problem(StatusCode::FORBIDDEN, "CLI_CODE_MISMATCH"))
            ));
        }
        for _ in 0..32 {
            flow(&s).await;
        }
        assert!(matches!(
            approve(&s, &f, &token, &session).await,
            Err(Problem(StatusCode::CONFLICT, "CLI_LOGIN_UNAVAILABLE"))
        ));
        assert_eq!(poll(&s, &f).await.unwrap().status(), StatusCode::ACCEPTED);
        assert_eq!(s.cli_login.lock().unwrap().requests.len(), 1);
    }

    #[tokio::test]
    async fn protected_capacity_cannot_be_filled_or_evicted_without_fresh_browser_authority() {
        let s = setup();
        let (token, session) = browser_session(&s, "first-key");
        let mut approved = Vec::new();
        for _ in 0..MAX_REQUESTS {
            let f = flow(&s).await;
            approve(&s, &f, &token, &session).await.unwrap();
            approved.push(f);
        }
        // Public initiation remains available even when the owner has filled
        // the protected budget. It cannot clear earlier approval/tombstones.
        let extra = flow(&s).await;
        assert!(matches!(
            approve(&s, &extra, &token, &session).await,
            Err(Problem(StatusCode::TOO_MANY_REQUESTS, "CLI_LOGIN_LIMIT"))
        ));
        assert_eq!(s.cli_login.lock().unwrap().requests.len(), MAX_REQUESTS);
        assert_eq!(
            poll(&s, &approved[0]).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(matches!(
            approve(&s, &extra, &token, &session).await,
            Err(Problem(StatusCode::TOO_MANY_REQUESTS, "CLI_LOGIN_LIMIT"))
        ));
        // The next authenticated admission reaps genuinely expired entries.
        for request in s.cli_login.lock().unwrap().requests.values_mut() {
            request.expires = now();
        }
        approve(&s, &extra, &token, &session).await.unwrap();
        assert_eq!(s.cli_login.lock().unwrap().requests.len(), 1);
    }

    #[tokio::test]
    async fn mandatory_audit_failure_never_approves_or_leaves_an_issued_cli_session() {
        for stage in ["approval", "exchange"] {
            let s = setup();
            let f = flow(&s).await;
            let (token, session) = browser_session(&s, "first-key");
            if stage == "exchange" {
                approve(&s, &f, &token, &session).await.unwrap();
            }
            // A real monotonic audit-head failure, not a bypass of the store's
            // write path. Future chronology makes the next current-time append
            // fail; no sleeps or production failure hooks are needed.
            s.store
                .record_passkey_cli_event(
                    &s.tenant,
                    PRINCIPAL,
                    &Uuid::new_v4().to_string(),
                    "cli_login_approved",
                    now() + 60,
                )
                .unwrap();
            let audit_count = s.store.count_audit(&s.tenant, 0).unwrap();
            let session_count = s.login.lock().unwrap().sessions.len();
            if stage == "approval" {
                assert!(approve(&s, &f, &token, &session).await.is_err());
                assert_eq!(poll(&s, &f).await.unwrap().status(), StatusCode::ACCEPTED);
            } else {
                assert!(poll(&s, &f).await.is_err());
            }
            assert_eq!(s.store.count_audit(&s.tenant, 0).unwrap(), audit_count);
            assert_eq!(s.login.lock().unwrap().sessions.len(), session_count);
            let state = s.cli_login.lock().unwrap();
            let request = &state.requests[f["request_id"].as_str().unwrap()];
            assert!(!request.consumed);
            assert_eq!(request.approval.is_some(), stage == "exchange");
        }
    }

    #[tokio::test]
    async fn expiry_pruning_and_clock_rollback_cannot_restore_consumption_or_code_attempts() {
        for consumed in [false, true] {
            let s = setup();
            let f = flow(&s).await;
            let (token, session) = browser_session(&s, "first-key");
            if consumed {
                approve(&s, &f, &token, &session).await.unwrap();
                poll(&s, &f).await.unwrap();
            } else {
                let mut wrong = f.clone();
                wrong["user_code"] = "WRONG".into();
                for _ in 0..5 {
                    assert!(approve(&s, &wrong, &token, &session).await.is_err());
                }
            }
            {
                let mut state = s.cli_login.lock().unwrap();
                let expiry = state.requests[f["request_id"].as_str().unwrap()].expires;
                state.observe_time(expiry).unwrap();
                state.requests.retain(|_, request| request.expires > expiry);
                assert!(state.requests.is_empty());
            }
            // Returning wall time to the old ticket's interval must not turn a
            // pruned consumed/failed-code request back into a pending request.
            assert!(matches!(
                poll(&s, &f).await,
                Err(Problem(StatusCode::CONFLICT, "CLI_CLOCK_UNCERTAIN"))
            ));
            assert!(matches!(
                approve(&s, &f, &token, &session).await,
                Err(Problem(StatusCode::CONFLICT, "CLI_CLOCK_UNCERTAIN"))
            ));
            assert!(s.cli_login.lock().unwrap().requests.is_empty());
        }
    }

    #[test]
    fn monotonic_elapsed_time_prevents_idle_ticket_extension_after_clock_rollback() {
        let mut state = CliLoginState::default();
        state.observe_time(1000).unwrap();
        state.clock.as_mut().unwrap().anchor -= std::time::Duration::from_secs(301);
        assert!(matches!(
            state.observe_time(1001),
            Err(Problem(StatusCode::CONFLICT, "CLI_CLOCK_UNCERTAIN"))
        ));
        assert!(state.clock.as_ref().unwrap().high_water >= 1301);
    }

    #[tokio::test]
    async fn concurrent_logout_cannot_complete_between_authorizer_check_and_session_insertion() {
        let s = setup();
        let f = flow(&s).await;
        let (token, session) = browser_session(&s, "first-key");
        approve(&s, &f, &token, &session).await.unwrap();
        let probe = Arc::new(ExchangeProbe {
            validated: std::sync::Barrier::new(2),
            proceed: std::sync::Barrier::new(2),
        });
        s.cli_login.lock().unwrap().exchange_probe = Some(probe.clone());
        let exchange_state = s.clone();
        let exchange_request = f.clone();
        let exchanging = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(poll(&exchange_state, &exchange_request))
                .unwrap()
        });
        probe.validated.wait();
        // This probe is after live-authorizer validation. The same registry
        // guard still excludes logout/replacement until audit+insertion commit.
        assert!(matches!(
            s.login.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        let logout_state = s.clone();
        let logout_token = token.clone();
        let logout_session = session.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let logging_out = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let response = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(route_post(
                    &logout_state,
                    &logout_token,
                    &logout_session,
                    "/api/v1/auth/logout",
                    json!({}),
                ));
            finished_tx.send(response.status()).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            finished_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        probe.proceed.wait();
        assert_eq!(exchanging.join().unwrap().status(), StatusCode::OK);
        logging_out.join().unwrap();
        assert_eq!(finished_rx.recv().unwrap(), StatusCode::OK);
        assert!(!s.login.lock().unwrap().sessions.contains_key(&hash(&token)));
        assert_eq!(
            s.login
                .lock()
                .unwrap()
                .sessions
                .values()
                .filter(|session| session.kind == SessionKind::Cli)
                .count(),
            1
        );
        assert!(matches!(
            poll(&s, &f).await,
            Err(Problem(StatusCode::CONFLICT, "CLI_LOGIN_ALREADY_USED"))
        ));
    }
}

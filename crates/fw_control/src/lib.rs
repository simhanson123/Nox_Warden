//! Loopback-only development control plane. No route can dispatch native changes.
mod audit;
mod audit_cursor;
mod bootstrap_file;
mod cli_auth;
mod collection_cursor;
mod collections;
mod enrollment;
mod login_ticket;
mod passkeys;
mod registry;
pub mod tls;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::DateTime;
use fw_store::{Store, Tenant};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

pub const ORG: &str = "00000000-0000-4000-8000-000000000001";
pub const PROJECT: &str = "00000000-0000-4000-8000-000000000002";
pub const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000003";
const SESSION_SECONDS: i64 = 28800;
#[derive(Clone)]
struct Session {
    id: String,
    csrf: String,
    expires: i64,
    authenticated_at: i64,
    credential_id: Option<String>,
}
struct LoginState {
    token_hash: [u8; 32],
    expires: i64,
    consumed: bool,
    failures: u32,
    failure_window: std::time::Instant,
    sessions: HashMap<[u8; 32], Session>,
}
pub struct AppState {
    pub store: Store,
    tenant: Tenant,
    origin: String,
    login: Mutex<LoginState>,
    enrollment: Option<Arc<enrollment::EnrollmentRuntime>>,
    webauthn: Option<fw_webauthn::WebAuthn>,
    cli_login: Mutex<cli_auth::CliLoginState>,
    denial_audit: Mutex<audit::DenialState>,
    audit_cursor_key: [u8; 32],
    login_tickets: login_ticket::LoginTickets,
    bootstrap_file: Option<bootstrap_file::BootstrapFile>,
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}
fn hash(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}
fn timestamp(t: i64) -> String {
    DateTime::from_timestamp(t, 0)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
fn envelope(data: Value) -> Value {
    json!({"data":data,"server_time":timestamp(now()),"revision":1,"actions":[{"action_id":"requests.create","allowed":true,"reason_code":null},{"action_id":"registry.assets.write","allowed":true,"reason_code":null},{"action_id":"registry.services.write","allowed":true,"reason_code":null}],"freshness":{"observed_at":timestamp(now()),"stale_after_seconds":30,"stale":false,"source":"controller"},"next_cursor":null})
}
#[derive(Debug)]
struct Problem(StatusCode, &'static str);
impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let code = match self.0 {
            StatusCode::UNAUTHORIZED => "UNAUTHENTICATED",
            StatusCode::FORBIDDEN => "FORBIDDEN",
            StatusCode::NOT_FOUND => "NOT_FOUND",
            StatusCode::PRECONDITION_REQUIRED => "PRECONDITION_REQUIRED",
            StatusCode::PRECONDITION_FAILED => "REVISION_CONFLICT",
            StatusCode::SERVICE_UNAVAILABLE => "TEMPORARILY_UNAVAILABLE",
            StatusCode::TOO_MANY_REQUESTS => "RATE_LIMITED",
            StatusCode::PAYLOAD_TOO_LARGE => "RESULT_TOO_LARGE",
            StatusCode::GONE if self.1 == "CURSOR_EXPIRED" => "CURSOR_EXPIRED",
            StatusCode::CONFLICT if self.1 == "IDEMPOTENCY_CONFLICT" => "IDEMPOTENCY_CONFLICT",
            StatusCode::CONFLICT => "REVISION_CONFLICT",
            _ if self.1 == "CAPABILITY_UNVERIFIED" => "UNSUPPORTED_PROFILE",
            _ if self.1 == "RESULT_TOO_LARGE" => "RESULT_TOO_LARGE",
            _ => "INVALID_INPUT",
        };
        let mut response = (self.0,axum::Json(json!({"type":"urn:f:problem:v1","title":self.1,"status":self.0.as_u16(),"code":code,"detail":self.1,"request_id":Uuid::new_v4(),"retryable":self.0==StatusCode::SERVICE_UNAVAILABLE,"field_errors":[]}))).into_response();
        if self.0 == StatusCode::TOO_MANY_REQUESTS && self.1 == "BOOTSTRAP_RATE_LIMITED" {
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from_static("60"));
        }
        response
    }
}
type ApiResult = Result<Response, Problem>;
fn bad(code: &'static str) -> Problem {
    Problem(StatusCode::BAD_REQUEST, code)
}
fn unavailable() -> Problem {
    Problem(StatusCode::SERVICE_UNAVAILABLE, "STORAGE_UNAVAILABLE")
}
fn uuid(s: &str) -> bool {
    Uuid::parse_str(s).is_ok_and(|u| u.to_string() == s)
}
fn header<'a>(h: &'a HeaderMap, name: &str) -> Result<&'a str, Problem> {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| bad("HEADER_REQUIRED"))
}
impl Session {
    fn passkey_authority(&self, at: i64) -> Result<fw_store::passkeys::PasskeyAuthority, Problem> {
        let id = self.credential_id.as_ref().ok_or(Problem(
            StatusCode::FORBIDDEN,
            "PASSKEY_REAUTHENTICATION_REQUIRED",
        ))?;
        if self.authenticated_at > at || at - self.authenticated_at >= 300 {
            return Err(Problem(
                StatusCode::FORBIDDEN,
                "PASSKEY_REAUTHENTICATION_REQUIRED",
            ));
        }
        Ok(fw_store::passkeys::PasskeyAuthority::Passkey {
            credential_id: id.clone(),
            authenticated_at: self.authenticated_at,
        })
    }
}
fn session_data(s: &AppState, session: &Session) -> Result<Value, Problem> {
    Ok(
        json!({"authenticated":true,"principal_id":PRINCIPAL,"org_id":ORG,
        "project_id":PROJECT,"csrf_token":session.csrf,"profile":"local-development",
        "authentication_method":if session.credential_id.is_some(){"passkey"}else{"bootstrap"},
        "authenticated_at":session.authenticated_at,"credential_id":session.credential_id,
        "owner_enrolled":s.store.passkey_owner_enrolled(&s.tenant, PRINCIPAL).map_err(map_store)?}),
    )
}
impl LoginState {
    fn consume_bootstrap(&mut self, candidate: &str, at: i64) -> Result<(), Problem> {
        if self.consumed || at >= self.expires {
            return Err(Problem(StatusCode::UNAUTHORIZED, "BOOTSTRAP_INVALID"));
        }
        // A valid high-entropy console token remains usable during a failed-
        // attempt cooldown; an anonymous caller cannot permanently lock it out.
        if bool::from(hash(candidate).ct_eq(&self.token_hash)) {
            self.consumed = true;
            self.token_hash.fill(0);
            return Ok(());
        }
        if self.failure_window.elapsed() >= std::time::Duration::from_secs(60) {
            self.failures = 0;
            self.failure_window = std::time::Instant::now();
        }
        if self.failures >= 10 {
            return Err(Problem(
                StatusCode::TOO_MANY_REQUESTS,
                "BOOTSTRAP_RATE_LIMITED",
            ));
        }
        self.failures += 1;
        Err(Problem(StatusCode::UNAUTHORIZED, "BOOTSTRAP_INVALID"))
    }
}
impl AppState {
    /// Configure only the token file created by the local console startup path.
    /// Request bodies cannot select a filesystem path.
    pub fn with_bootstrap_token_file(mut self, path: std::path::PathBuf) -> std::io::Result<Self> {
        self.bootstrap_file = Some(bootstrap_file::BootstrapFile::open(path)?);
        Ok(self)
    }
    pub fn new(
        store: Store,
        origin: String,
        token: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tenant = Tenant::new(ORG, PROJECT)?;
        store.ensure_tenant(ORG, PROJECT, "Local development", now())?;
        store.ensure_principal(&tenant, PRINCIPAL, "human", now())?;
        let enrolled = store.passkey_owner_enrolled(&tenant, PRINCIPAL)?;
        let webauthn = fw_webauthn::WebAuthn::new(&origin).ok();
        let mut audit_cursor_key = [0u8; 32];
        openssl::rand::rand_bytes(&mut audit_cursor_key)?;
        Ok(Self {
            store,
            tenant,
            origin,
            login: Mutex::new(LoginState {
                token_hash: hash(token),
                expires: now() + 600,
                consumed: enrolled,
                failures: 0,
                failure_window: std::time::Instant::now(),
                sessions: HashMap::new(),
            }),
            enrollment: None,
            webauthn,
            cli_login: Mutex::new(cli_auth::CliLoginState::default()),
            denial_audit: Mutex::new(audit::DenialState::default()),
            audit_cursor_key,
            login_tickets: login_ticket::LoginTickets::new()?,
            bootstrap_file: None,
        })
    }
    /// Configure a separate enrollment listener after its TLS material is validated.
    /// Transport registration does not enable native dispatch or create policy authority.
    pub fn with_enrollment(mut self, authority: fw_enrollment::CertificateAuthority) -> Self {
        self.enrollment = Some(Arc::new(enrollment::EnrollmentRuntime::new(authority)));
        self
    }
    fn issue_passkey_session(
        &self,
        credential_id: &str,
        previous_token: Option<&str>,
        at: i64,
    ) -> Result<(String, Session), Problem> {
        self.store
            .active_passkey(&self.tenant, PRINCIPAL, credential_id)
            .map_err(|_| Problem(StatusCode::UNAUTHORIZED, "PASSKEY_SESSION_REVOKED"))?;
        let mut login = self.login.lock().map_err(|_| unavailable())?;
        login.sessions.retain(|_, session| session.expires > at);
        if let Some(token) = previous_token {
            login.sessions.remove(&hash(token));
        }
        if login.sessions.len() >= 64 {
            let oldest = login
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.authenticated_at)
                .map(|(k, _)| *k);
            if let Some(key) = oldest {
                login.sessions.remove(&key);
            }
        }
        let token = random_token();
        let session = Session {
            id: Uuid::new_v4().to_string(),
            csrf: random_token(),
            expires: at + SESSION_SECONDS,
            authenticated_at: at,
            credential_id: Some(credential_id.into()),
        };
        login.sessions.insert(hash(&token), session.clone());
        Ok((token, session))
    }
    fn auth(&self, h: &HeaderMap, write: bool) -> Result<Session, Problem> {
        let result = self.auth_inner(h, write);
        if let Err(ref reason) = result {
            let explicit_session =
                h.get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|cookies| {
                        cookies
                            .split(';')
                            .any(|p| p.trim().starts_with("fw_session="))
                    });
            // Anonymous page-load probes are expected and do not append a
            // persistent denial. Explicit credentials and writes are sampled.
            if write || explicit_session || h.contains_key("authorization") {
                self.record_authentication_denial(reason.1);
            }
        }
        result
    }
    fn auth_inner(&self, h: &HeaderMap, write: bool) -> Result<Session, Problem> {
        let cookies = header(h, "cookie")
            .map_err(|_| Problem(StatusCode::UNAUTHORIZED, "AUTHENTICATION_REQUIRED"))?;
        let token = cookies
            .split(';')
            .find_map(|p| p.trim().strip_prefix("fw_session="))
            .ok_or(Problem(StatusCode::UNAUTHORIZED, "AUTHENTICATION_REQUIRED"))?;
        let mut login = self.login.lock().map_err(|_| unavailable())?;
        login.sessions.retain(|_, s| s.expires > now());
        let session = login
            .sessions
            .get(&hash(token))
            .filter(|s| s.expires > now() && s.authenticated_at <= now())
            .cloned()
            .ok_or(Problem(StatusCode::UNAUTHORIZED, "SESSION_EXPIRED"))?;
        drop(login);
        // Cookies are scoped to a host, not a port. Another localhost service
        // can receive a bootstrap cookie just as it can a passkey cookie. Every
        // session therefore requires the independently returned proof, even for
        // reads. Cookie-only introspection must never disclose that proof.
        h.get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .filter(|value| bool::from(value.as_bytes().ct_eq(session.csrf.as_bytes())))
            .ok_or(Problem(StatusCode::UNAUTHORIZED, "SESSION_PROOF_REQUIRED"))?;
        if let Some(id) = &session.credential_id {
            self.store
                .active_passkey(&self.tenant, PRINCIPAL, id)
                .map_err(|_| Problem(StatusCode::UNAUTHORIZED, "PASSKEY_SESSION_REVOKED"))?;
        } else if self
            .store
            .passkey_owner_enrolled(&self.tenant, PRINCIPAL)
            .map_err(map_store)?
        {
            return Err(Problem(
                StatusCode::UNAUTHORIZED,
                "PASSKEY_AUTHENTICATION_REQUIRED",
            ));
        }
        if write {
            if header(h, "origin")? != self.origin {
                return Err(Problem(StatusCode::FORBIDDEN, "ORIGIN_REJECTED"));
            }
            let csrf = header(h, "x-csrf-token")?;
            if !bool::from(csrf.as_bytes().ct_eq(session.csrf.as_bytes())) {
                return Err(Problem(StatusCode::FORBIDDEN, "CSRF_REJECTED"));
            }
            if !uuid(header(h, "idempotency-key")?) {
                return Err(bad("IDEMPOTENCY_KEY_INVALID"));
            }
        }
        Ok(session)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    token: String,
}
async fn bootstrap(State(s): State<Arc<AppState>>, h: HeaderMap, b: Bytes) -> ApiResult {
    let result = bootstrap_inner(State(s.clone()), h, b).await;
    if let Err(reason) = &result {
        s.record_authentication_denial(reason.1);
    }
    result
}
async fn bootstrap_inner(State(s): State<Arc<AppState>>, h: HeaderMap, b: Bytes) -> ApiResult {
    if header(&h, "origin")? != s.origin {
        return Err(Problem(StatusCode::FORBIDDEN, "ORIGIN_REJECTED"));
    }
    if !uuid(header(&h, "idempotency-key")?) {
        return Err(bad("IDEMPOTENCY_KEY_INVALID"));
    }
    let input: Bootstrap = fw_contracts::parse_strict(&b).map_err(|_| bad("INVALID_JSON"))?;
    if s.store
        .passkey_owner_enrolled(&s.tenant, PRINCIPAL)
        .map_err(map_store)?
    {
        return Err(Problem(
            StatusCode::UNAUTHORIZED,
            "PASSKEY_AUTHENTICATION_REQUIRED",
        ));
    }
    let mut login = s.login.lock().map_err(|_| unavailable())?;
    if let Err(reason) = login.consume_bootstrap(&input.token, now()) {
        drop(login);
        return Err(reason);
    }
    if s.bootstrap_file
        .as_ref()
        .is_some_and(|file| file.consume().is_err())
    {
        drop(login);
        return Err(Problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "BOOTSTRAP_TOKEN_CLEANUP_FAILED",
        ));
    }
    let token = random_token();
    let csrf = random_token();
    let session = Session {
        id: Uuid::new_v4().to_string(),
        csrf,
        expires: now() + SESSION_SECONDS,
        authenticated_at: now(),
        credential_id: None,
    };
    login.sessions.insert(hash(&token), session.clone());
    drop(login);
    let mut response = axum::Json(envelope(session_data(&s, &session)?)).into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "fw_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"
        ))
        .unwrap(),
    );
    Ok(response)
}
async fn session(State(s): State<Arc<AppState>>, h: HeaderMap) -> ApiResult {
    let session = s.auth(&h, false)?;
    Ok(axum::Json(envelope(session_data(&s, &session)?)).into_response())
}
async fn health() -> Response {
    axum::Json(json!({"status":"ok","service":"fw_control","version":env!("CARGO_PKG_VERSION")}))
        .into_response()
}
async fn status(State(s): State<Arc<AppState>>, h: HeaderMap) -> ApiResult {
    s.auth(&h, false)?;
    Ok(axum::Json(envelope(json!({"mode":"observe","enforcement":false,"version":env!("CARGO_PKG_VERSION"),"profile":"local-development","telemetry_enabled":false,"ai_enabled":false,"native_dispatch_enabled":false,"platforms":[{"platform":"linux","backend":"nftables","status":"unverified"},{"platform":"windows","backend":"windows_wfp","status":"unsupported"},{"platform":"macos","backend":"macos_network_extension","status":"unsupported"}]}))).into_response())
}
async fn capabilities(State(s): State<Arc<AppState>>, h: HeaderMap) -> ApiResult {
    s.auth(&h, false)?;
    let mut unsupported = vec![
        "oidc",
        "policy-approval",
        "authority-bootstrap",
        "certificate-renewal",
        "native-deployment",
        "postgresql-runtime",
    ];
    if s.webauthn.is_none() {
        unsupported.push("webauthn");
    }
    Ok(axum::Json(envelope(json!({"schema_version":"f.development-capabilities/v1","profile":"local-development","native_enforcement":"unverified","dispatch_allowed":false,"supported_api":["access-requests.create","access-requests.read","operations.read","audit.read"],"passkey_authentication":s.webauthn.is_some(),"transport_enrollment":if s.enrollment.is_some(){"available"}else{"disabled"},"unsupported":unsupported,"telemetry_enabled":false}))).into_response())
}
async fn empty(State(s): State<Arc<AppState>>, h: HeaderMap) -> ApiResult {
    s.auth(&h, false)?;
    Ok(axum::Json(envelope(json!([]))).into_response())
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessRequest {
    schema_version: String,
    idempotency_key: String,
    workflow_id: String,
    workload_binding_id: String,
    source_asset_ids: Vec<String>,
    destination_asset_ids: Vec<String>,
    service_id: String,
    lease_seconds: u64,
    purpose: String,
}
impl AccessRequest {
    fn validate(&self, key: &str) -> Result<(), Problem> {
        fn ids(v: &[String]) -> bool {
            !v.is_empty()
                && v.len() <= 16
                && v.iter().all(|x| uuid(x))
                && v.iter().collect::<HashSet<_>>().len() == v.len()
        }
        if self.schema_version != "f.access-request/v1"
            || self.idempotency_key != key
            || !uuid(&self.workload_binding_id)
            || !ids(&self.source_asset_ids)
            || !ids(&self.destination_asset_ids)
            || !(60..=86400).contains(&self.lease_seconds)
            || self.workflow_id.is_empty()
            || self.workflow_id.chars().count() > 128
            || self.service_id.is_empty()
            || self.service_id.chars().count() > 128
            || self.purpose.trim().is_empty()
            || self.purpose.chars().count() > 2000
        {
            return Err(Problem(StatusCode::UNPROCESSABLE_ENTITY, "REQUEST_INVALID"));
        }
        Ok(())
    }
}
async fn requests(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    Query(q): Query<collections::ListQuery>,
) -> ApiResult {
    let session = s.auth(&h, false)?;
    Ok(axum::Json(collections::page(
        &s,
        &session,
        q,
        fw_store::collections::CollectionKind::Requests,
        "/api/v1/access-requests",
    )?)
    .into_response())
}
async fn create_request(State(s): State<Arc<AppState>>, h: HeaderMap, b: Bytes) -> ApiResult {
    s.auth(&h, true)?;
    if header(&h, "content-type")?.split(';').next() != Some("application/json") {
        return Err(Problem(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON_REQUIRED"));
    }
    let mut input: AccessRequest =
        fw_contracts::parse_strict(&b).map_err(|_| bad("INVALID_JSON"))?;
    let key = header(&h, "idempotency-key")?;
    input.validate(key)?;
    input.source_asset_ids.sort();
    input.destination_asset_ids.sort();
    input.workflow_id = input.workflow_id.nfc().collect();
    input.service_id = input.service_id.nfc().collect();
    input.purpose = input.purpose.nfc().collect();
    let body = serde_json::to_value(input).map_err(|_| bad("INVALID_JSON"))?;
    let submission = s
        .store
        .submit_unenrolled_request(&s.tenant, PRINCIPAL, "access_request", &body, key, now())
        .map_err(map_store)?;
    Ok((StatusCode::ACCEPTED,axum::Json(envelope(json!({"operation_id":submission.operation.operation_id,"resource_kind":"request","resource_id":submission.request.request_id,"state":"queued","retry_after_seconds":5})))).into_response())
}
fn map_store(e: fw_store::StoreError) -> Problem {
    use fw_store::StoreError::*;
    match e {
        IdempotencyConflict => Problem(StatusCode::CONFLICT, "IDEMPOTENCY_CONFLICT"),
        NotFound => Problem(StatusCode::NOT_FOUND, "NOT_FOUND"),
        PreconditionFailed | ClaimStale => Problem(StatusCode::CONFLICT, "STATE_CONFLICT"),
        InvalidInput(_) | Contract(_) | Domain(_) | Json(_) => bad("INVALID_INPUT"),
        _ => unavailable(),
    }
}
async fn request(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    s.auth(&h, false)?;
    if !uuid(&id) {
        return Err(bad("ID_INVALID"));
    }
    let row = s.store.get_request(&s.tenant, &id).map_err(map_store)?;
    let mut response = envelope(json!(row));
    response["revision"] = json!(row.revision);
    Ok(axum::Json(response).into_response())
}
async fn operations(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    Query(q): Query<collections::ListQuery>,
) -> ApiResult {
    let session = s.auth(&h, false)?;
    Ok(axum::Json(collections::page(
        &s,
        &session,
        q,
        fw_store::collections::CollectionKind::Operations,
        "/api/v1/operations",
    )?)
    .into_response())
}
async fn operation(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    s.auth(&h, false)?;
    let row = s.store.get_operation(&s.tenant, &id).map_err(map_store)?;
    let mut response = envelope(row.view());
    response["revision"] = json!(row.revision);
    Ok(axum::Json(response).into_response())
}
async fn audit(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    Query(q): Query<audit::AuditQuery>,
) -> ApiResult {
    let session = s.auth(&h, false)?;
    Ok(axum::Json(audit::page(&s, &session, q, "/api/v1/audit/events")?).into_response())
}
async fn blocked(State(s): State<Arc<AppState>>, h: HeaderMap) -> ApiResult {
    s.auth(&h, true)?;
    Err(Problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "CAPABILITY_UNVERIFIED",
    ))
}
async fn mcp(State(s): State<Arc<AppState>>, h: HeaderMap, b: Bytes) -> ApiResult {
    let session = s.auth(&h, true)?;
    let value = fw_contracts::parse_value(&b).map_err(|_| bad("INVALID_JSON"))?;
    let response = fw_mcp::dispatch(value, |name, args| match name {
        "get_capabilities" => Ok(envelope(
            json!({"dispatch_allowed":false,"native_enforcement":"unverified","profile":"local-development"}),
        )),
        "get_operation" => s
            .store
            .get_operation(&s.tenant, args["operation_id"].as_str().unwrap_or(""))
            .map(|v| {
                let mut response = envelope(v.view());
                response["revision"] = json!(v.revision);
                response
            })
            .map_err(|_| "NOT_FOUND"),
        "get_audit_events" => {
            let q = audit::AuditQuery {
                limit: args["limit"].as_u64().map(|n| n as usize),
                after_sequence: args["after_sequence"]
                    .as_str()
                    .map(|n| n.parse::<u64>())
                    .transpose()
                    .map_err(|_| "CURSOR_INVALID")?,
                cursor: args["cursor"].as_str().map(str::to_owned),
            };
            audit::page(&s, &session, q, "mcp:get_audit_events").map_err(|error| error.1)
        }
        _ => Err("TOOL_UNSUPPORTED"),
    });
    Ok(match response {
        Some(value) => axum::Json(value).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    })
}
async fn not_found() -> Problem {
    Problem(StatusCode::NOT_FOUND, "NOT_FOUND")
}
async fn response_boundary(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let api = request.uri().path().starts_with("/api/") || request.uri().path() == "/mcp";
    let response = next.run(request).await;
    if !api {
        return response;
    }
    let status = response.status();
    let (mut parts, body) = response.into_parts();
    parts.headers.insert(
        "x-request-id",
        HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
    );
    match axum::body::to_bytes(body, 262144).await {
        Ok(bytes) => {
            if status.is_client_error() && serde_json::from_slice::<Value>(&bytes).is_err() {
                return Problem(status, "INVALID_INPUT").into_response();
            }
            Response::from_parts(parts, axum::body::Body::from(bytes))
        }
        Err(_) => Problem(StatusCode::PAYLOAD_TOO_LARGE, "RESULT_TOO_LARGE").into_response(),
    }
}
pub fn router(state: Arc<AppState>, web_dir: std::path::PathBuf) -> Router {
    let api = Router::new()
        .merge(passkeys::routes())
        .merge(cli_auth::routes())
        .route("/session/bootstrap", post(bootstrap))
        .route("/session", get(session))
        .route("/status", get(status))
        .route("/capabilities", get(capabilities))
        .route("/access-requests", get(requests).post(create_request))
        .route("/access-requests/{id}", get(request))
        .route("/operations", get(operations))
        .route("/operations/{id}", get(operation))
        .route("/audit/events", get(audit))
        .route("/audit/denial-summaries/{id}", get(audit::denial_summary))
        .route("/targets", get(enrollment::list_targets))
        .route("/targets/{id}", get(enrollment::get_target))
        .route("/enrollment-tokens", post(enrollment::create_token))
        .route("/enrollments", get(enrollment::list_enrollments))
        .route("/enrollments/{id}/revoke", post(enrollment::revoke))
        .route("/policies", get(empty))
        .route(
            "/assets",
            get(registry::list_assets).post(registry::create_asset),
        )
        .route("/assets/{id}", get(registry::get_asset))
        .route("/assets/{id}/revisions", post(registry::revise_asset))
        .route(
            "/services",
            get(registry::list_services).post(registry::create_service),
        )
        .route("/services/{id}", get(registry::get_service))
        .route("/services/{id}/revisions", post(registry::revise_service))
        .route("/deployments", post(blocked))
        .route("/approvals/challenges", post(blocked))
        .route("/approvals/assertions", post(blocked))
        .fallback(not_found);
    let index = web_dir.join("index.html");
    Router::new()
    .route_service("/overview",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/requests",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/requests/new",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/requests/{id}",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/policies",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/targets",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/assets",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/assets/{id}",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/services",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/services/{id}",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/security",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/cli-login/{id}",tower_http::services::ServeFile::new(index.clone()))
    .route_service("/audit",tower_http::services::ServeFile::new(index))
    .route("/healthz",get(health)).route("/mcp",post(mcp)).nest("/api/v1",api).fallback_service(tower_http::services::ServeDir::new(web_dir)).layer(DefaultBodyLimit::max(65536)).layer(axum::middleware::from_fn(response_boundary)).layer(tower_http::set_header::SetResponseHeaderLayer::overriding(axum::http::header::CACHE_CONTROL,HeaderValue::from_static("no-store"))).layer(tower_http::set_header::SetResponseHeaderLayer::overriding(axum::http::header::X_CONTENT_TYPE_OPTIONS,HeaderValue::from_static("nosniff"))).layer(tower_http::set_header::SetResponseHeaderLayer::overriding(axum::http::header::CONTENT_SECURITY_POLICY,HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"))).with_state(state)
}
pub fn generate_token() -> String {
    random_token()
}
/// Only serve this router with the TLS listener and its verified ConnectInfo.
pub fn enrollment_router(state: Arc<AppState>) -> Router {
    enrollment::internal_router(state)
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use fw_store::passkeys::{PasskeyAuthority, PasskeyChallengeInput, VerifiedPasskey};
    use tower::ServiceExt;

    fn activated_session() -> (Arc<AppState>, String, Session) {
        let state = Arc::new(
            AppState::new(
                Store::in_memory().unwrap(),
                "http://localhost:8787".into(),
                "unit-bootstrap",
            )
            .unwrap(),
        );
        let at = now();
        let binding = fw_contracts::hash_bytes(b"unit session-boundary fixture");
        // Isolate session transport checks from cryptography. Actual signature
        // verification is exercised by fw_webauthn and the browser smoke.
        for kind in ["registration", "authentication"] {
            let input = PasskeyChallengeInput {
                kind: kind.into(),
                session_binding: binding.clone(),
                authority: (kind == "registration").then_some(PasskeyAuthority::Bootstrap),
                name: (kind == "registration").then_some("Unit fixture".into()),
                request: json!({}),
                options: json!({}),
                state: json!({}),
            };
            let challenge = state
                .store
                .begin_passkey_challenge(
                    &state.tenant,
                    PRINCIPAL,
                    &input,
                    &Uuid::new_v4().to_string(),
                    at,
                )
                .unwrap();
            state
                .store
                .finish_passkey_challenge(
                    &state.tenant,
                    PRINCIPAL,
                    &challenge.challenge_id,
                    kind,
                    &binding,
                    &json!({}),
                    &Uuid::new_v4().to_string(),
                    at,
                    |_, _| {
                        Ok(VerifiedPasskey {
                            credential_id: "dW5pdC1zZXNzaW9uLWtleQ".into(),
                            credential: json!({"unit_test":"opaque public credential"}),
                        })
                    },
                )
                .unwrap();
        }
        let (token, session) = state
            .issue_passkey_session("dW5pdC1zZXNzaW9uLWtleQ", None, at)
            .unwrap();
        (state, token, session)
    }

    #[tokio::test]
    async fn a_localhost_cookie_alone_cannot_read_or_invalidate_a_passkey_session() {
        let (state, token, session) = activated_session();
        let app = router(state, "/tmp/fw-session-test-web-absent".into());
        let cookie = format!("fw_session={token}");
        for path in [
            "/api/v1/session".to_owned(),
            "/api/v1/status".to_owned(),
            format!("/api/v1/auth/cli/requests/{}", Uuid::new_v4()),
        ] {
            for proof in [None, Some("incorrect-proof")] {
                let mut request = Request::get(&path).header("cookie", &cookie);
                if let Some(proof) = proof {
                    request = request.header("x-csrf-token", proof);
                }
                let response = app
                    .clone()
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
                assert!(!String::from_utf8_lossy(&bytes).contains(&session.csrf));
            }
        }
        let unauthorized_logout = app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/logout")
                    .header("origin", "http://localhost:8787")
                    .header("cookie", &cookie)
                    .header("content-type", "application/json")
                    .header("idempotency-key", Uuid::new_v4().to_string())
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized_logout.status(), StatusCode::UNAUTHORIZED);
        for path in ["/api/v1/session", "/api/v1/status"] {
            let response = app
                .clone()
                .oneshot(
                    Request::get(path)
                        .header("cookie", &cookie)
                        .header("x-csrf-token", &session.csrf)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/logout")
                    .header("origin", "http://localhost:8787")
                    .header("cookie", &cookie)
                    .header("x-csrf-token", &session.csrf)
                    .header("content-type", "application/json")
                    .header("idempotency-key", Uuid::new_v4().to_string())
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .oneshot(
                Request::get("/api/v1/session")
                    .header("cookie", cookie)
                    .header("x-csrf-token", &session.csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn a_session_authenticated_in_the_future_is_rejected() {
        let state = AppState::new(
            Store::in_memory().unwrap(),
            "http://localhost:8787".into(),
            "unit-bootstrap-token",
        )
        .unwrap();
        let token = "unit-session-token";
        let mut session = Session {
            id: Uuid::new_v4().to_string(),
            csrf: "unit-csrf".into(),
            expires: now() + SESSION_SECONDS,
            authenticated_at: now(),
            credential_id: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert("cookie", format!("fw_session={token}").parse().unwrap());
        headers.insert("x-csrf-token", session.csrf.parse().unwrap());
        state
            .login
            .lock()
            .unwrap()
            .sessions
            .insert(hash(token), session.clone());
        assert!(state.auth(&headers, false).is_ok());
        session.authenticated_at = now() + 60;
        state
            .login
            .lock()
            .unwrap()
            .sessions
            .insert(hash(token), session);
        assert!(matches!(
            state.auth(&headers, false),
            Err(Problem(StatusCode::UNAUTHORIZED, _))
        ));
    }
}

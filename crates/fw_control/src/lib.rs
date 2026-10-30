//! Loopback-only development control plane. No route can dispatch native changes.
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
    csrf: String,
    expires: i64,
}
struct LoginState {
    token_hash: [u8; 32],
    expires: i64,
    consumed: bool,
    failures: u32,
    sessions: HashMap<[u8; 32], Session>,
}
pub struct AppState {
    pub store: Store,
    tenant: Tenant,
    origin: String,
    login: Mutex<LoginState>,
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
    json!({"data":data,"server_time":timestamp(now()),"revision":1,"actions":[{"action_id":"requests.create","allowed":true,"reason_code":null}],"freshness":{"observed_at":timestamp(now()),"stale_after_seconds":30,"stale":false,"source":"controller"},"next_cursor":null})
}
#[derive(Debug)]
struct Problem(StatusCode, &'static str);
impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let code = match self.0 {
            StatusCode::UNAUTHORIZED => "UNAUTHENTICATED",
            StatusCode::FORBIDDEN => "FORBIDDEN",
            StatusCode::NOT_FOUND => "NOT_FOUND",
            StatusCode::SERVICE_UNAVAILABLE => "TEMPORARILY_UNAVAILABLE",
            StatusCode::TOO_MANY_REQUESTS => "RATE_LIMITED",
            StatusCode::PAYLOAD_TOO_LARGE => "RESULT_TOO_LARGE",
            StatusCode::CONFLICT if self.1 == "IDEMPOTENCY_CONFLICT" => "IDEMPOTENCY_CONFLICT",
            StatusCode::CONFLICT => "REVISION_CONFLICT",
            _ if self.1 == "CAPABILITY_UNVERIFIED" => "UNSUPPORTED_PROFILE",
            _ if self.1 == "RESULT_TOO_LARGE" => "RESULT_TOO_LARGE",
            _ => "INVALID_INPUT",
        };
        (self.0,axum::Json(json!({"type":"urn:f:problem:v1","title":self.1,"status":self.0.as_u16(),"code":code,"detail":self.1,"request_id":Uuid::new_v4(),"retryable":self.0==StatusCode::SERVICE_UNAVAILABLE,"field_errors":[]}))).into_response()
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
impl AppState {
    pub fn new(
        store: Store,
        origin: String,
        token: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tenant = Tenant::new(ORG, PROJECT)?;
        store.ensure_tenant(ORG, PROJECT, "Local development", now())?;
        store.ensure_principal(&tenant, PRINCIPAL, "human", now())?;
        Ok(Self {
            store,
            tenant,
            origin,
            login: Mutex::new(LoginState {
                token_hash: hash(token),
                expires: now() + 600,
                consumed: false,
                failures: 0,
                sessions: HashMap::new(),
            }),
        })
    }
    fn auth(&self, h: &HeaderMap, write: bool) -> Result<Session, Problem> {
        let result = self.auth_inner(h, write);
        if let Err(ref reason) = result {
            let _ = self
                .store
                .record_denied_action(&self.tenant, None, reason.1, now());
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
            .filter(|s| s.expires > now())
            .cloned()
            .ok_or(Problem(StatusCode::UNAUTHORIZED, "SESSION_EXPIRED"))?;
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
    if header(&h, "origin")? != s.origin {
        return Err(Problem(StatusCode::FORBIDDEN, "ORIGIN_REJECTED"));
    }
    if !uuid(header(&h, "idempotency-key")?) {
        return Err(bad("IDEMPOTENCY_KEY_INVALID"));
    }
    let input: Bootstrap = fw_contracts::parse_strict(&b).map_err(|_| bad("INVALID_JSON"))?;
    let mut login = s.login.lock().map_err(|_| unavailable())?;
    if login.failures >= 10 {
        return Err(Problem(StatusCode::TOO_MANY_REQUESTS, "BOOTSTRAP_LOCKED"));
    }
    if login.consumed
        || now() >= login.expires
        || !bool::from(hash(&input.token).ct_eq(&login.token_hash))
    {
        login.failures += 1;
        return Err(Problem(StatusCode::UNAUTHORIZED, "BOOTSTRAP_INVALID"));
    }
    login.consumed = true;
    let token = random_token();
    let csrf = random_token();
    login.sessions.insert(
        hash(&token),
        Session {
            csrf: csrf.clone(),
            expires: now() + SESSION_SECONDS,
        },
    );
    let mut response=axum::Json(envelope(json!({"authenticated":true,"principal_id":PRINCIPAL,"org_id":ORG,"project_id":PROJECT,"csrf_token":csrf,"profile":"local-development"}))).into_response();
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
    Ok(axum::Json(envelope(json!({"authenticated":true,"principal_id":PRINCIPAL,"org_id":ORG,"project_id":PROJECT,"csrf_token":session.csrf,"profile":"local-development"}))).into_response())
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
    Ok(axum::Json(envelope(json!({"schema_version":"f.development-capabilities/v1","profile":"local-development","native_enforcement":"unverified","dispatch_allowed":false,"supported_api":["access-requests.create","access-requests.read","operations.read","audit.read"],"unsupported":["oidc","webauthn","native-enrollment","native-deployment","postgresql-runtime"],"telemetry_enabled":false}))).into_response())
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
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    limit: Option<usize>,
    after_sequence: Option<u64>,
}
fn list_limit(q: &ListQuery) -> Result<usize, Problem> {
    let n = q.limit.unwrap_or(50);
    if n == 0 || n > 100 {
        Err(bad("PAGE_LIMIT_INVALID"))
    } else {
        Ok(n)
    }
}
async fn requests(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    Query(q): Query<ListQuery>,
) -> ApiResult {
    s.auth(&h, false)?;
    let limit = list_limit(&q)?;
    let rows = s
        .store
        .list_requests(&s.tenant, None, 100)
        .map_err(|_| unavailable())?;
    if s.store.count_requests(&s.tenant).map_err(map_store)? > limit as u64 {
        return Err(Problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "RESULT_TOO_LARGE",
        ));
    }
    Ok(axum::Json(envelope(json!(rows))).into_response())
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
async fn operations(State(s): State<Arc<AppState>>, h: HeaderMap) -> ApiResult {
    s.auth(&h, false)?;
    if s.store.count_operations(&s.tenant).map_err(map_store)? > 100 {
        return Err(Problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "RESULT_TOO_LARGE",
        ));
    }
    let rows = s
        .store
        .list_operations(&s.tenant, None, 100)
        .map_err(map_store)?;
    Ok(axum::Json(envelope(json!(
        rows.iter().map(|v| v.view()).collect::<Vec<_>>()
    )))
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
    Query(q): Query<ListQuery>,
) -> ApiResult {
    s.auth(&h, false)?;
    let limit = list_limit(&q)?;
    if s.store
        .count_audit(&s.tenant, q.after_sequence.unwrap_or(0))
        .map_err(map_store)?
        > limit as u64
    {
        return Err(Problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "RESULT_TOO_LARGE",
        ));
    }
    let rows = s
        .store
        .list_audit(&s.tenant, q.after_sequence.unwrap_or(0), limit)
        .map_err(map_store)?;
    Ok(axum::Json(envelope(json!(rows))).into_response())
}
async fn blocked(State(s): State<Arc<AppState>>, h: HeaderMap) -> ApiResult {
    s.auth(&h, true)?;
    Err(Problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "CAPABILITY_UNVERIFIED",
    ))
}
async fn mcp(State(s): State<Arc<AppState>>, h: HeaderMap, b: Bytes) -> ApiResult {
    s.auth(&h, true)?;
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
            if s.store
                .count_audit(&s.tenant, 0)
                .map_err(|_| "STORAGE_UNAVAILABLE")?
                > 50
            {
                return Err("RESULT_TOO_LARGE");
            }
            s.store
                .list_audit(&s.tenant, 0, 50)
                .map(|v| envelope(json!(v)))
                .map_err(|_| "STORAGE_UNAVAILABLE")
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
        .route("/session/bootstrap", post(bootstrap))
        .route("/session", get(session))
        .route("/status", get(status))
        .route("/capabilities", get(capabilities))
        .route("/access-requests", get(requests).post(create_request))
        .route("/access-requests/{id}", get(request))
        .route("/operations", get(operations))
        .route("/operations/{id}", get(operation))
        .route("/audit/events", get(audit))
        .route("/targets", get(empty))
        .route("/policies", get(empty))
        .route("/assets", get(empty))
        .route("/services", get(empty))
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
    .route_service("/audit",tower_http::services::ServeFile::new(index))
    .route("/healthz",get(health)).route("/mcp",post(mcp)).nest("/api/v1",api).fallback_service(tower_http::services::ServeDir::new(web_dir)).layer(DefaultBodyLimit::max(65536)).layer(axum::middleware::from_fn(response_boundary)).layer(tower_http::set_header::SetResponseHeaderLayer::overriding(axum::http::header::CACHE_CONTROL,HeaderValue::from_static("no-store"))).layer(tower_http::set_header::SetResponseHeaderLayer::overriding(axum::http::header::X_CONTENT_TYPE_OPTIONS,HeaderValue::from_static("nosniff"))).layer(tower_http::set_header::SetResponseHeaderLayer::overriding(axum::http::header::CONTENT_SECURITY_POLICY,HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"))).with_state(state)
}
pub fn generate_token() -> String {
    random_token()
}

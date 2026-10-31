//! Bounded, loopback-only review service for a separately provisioned authority.
//! No public enrollment, controller credential import, signer or host writes.
mod admission;
mod auth;
mod evidence;
mod files;
mod listener;
mod startup;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
pub use evidence::ReviewEvidence;
use fw_authority::{
    ApprovalDecision, ApprovalRole, AuthorityStore, AuthorityTenant, ReviewLogin, ReviewProfile,
};
use fw_contracts::parse_strict_with_limit;
use fw_webauthn::{AuthenticationResponse, WebAuthn};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use startup::at;
pub use startup::{StartupError, StartupStage};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;

const PREFIX: &str = "/authority/v1";
const COOKIE: &str = "__Host-fw_authority";
const MAX_SESSIONS: usize = 128;
const SESSION_SECONDS: i64 = 900;
const MAX_BODY: usize = 65536;
type Result<T> = std::result::Result<T, Failure>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProfile {
    pub org_id: String,
    pub project_id: String,
    pub principal_id: String,
    pub credential_id: String,
}
impl LocalProfile {
    fn tenant(&self) -> Result<AuthorityTenant> {
        AuthorityTenant::new(&self.org_id, &self.project_id).map_err(|_| Failure::Unauthorized)
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub origin: String,
    pub controller_origin: String,
    pub database: PathBuf,
    pub ui_directory: PathBuf,
    pub profiles: BTreeMap<String, LocalProfile>,
    /// Private administrator-selected files, keyed by immutable plan ID.
    pub review_evidence: BTreeMap<String, PathBuf>,
}
#[derive(Clone)]
pub struct Service {
    inner: Arc<Mutex<Runtime>>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    admission: Arc<admission::Admission>,
    origin: String,
    host: String,
}
struct Runtime {
    config: ServiceConfig,
    store: AuthorityStore,
    verifier: WebAuthn,
    key: [u8; 32],
    sessions: BTreeMap<String, Session>,
    assets: BTreeMap<String, (String, Vec<u8>)>,
    evidence: BTreeMap<String, ReviewEvidence>,
    envelope_key: auth::EnvelopeKeys,
    failure_samples: BTreeMap<String, i64>,
    next_session_serial: u64,
}
struct Session {
    serial: u64,
    csrf: String,
    issued_at: i64,
    expires_at: i64,
    identity: Option<(LocalProfile, i64)>,
    rate_start: i64,
    rate_count: u32,
}
#[derive(Debug)]
pub enum Failure {
    Unauthorized,
    Forbidden,
    Invalid,
    Conflict,
    Unavailable,
    Limited,
    ReviewUnavailable,
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let (status, error, reason) = match self {
            Self::Unauthorized => (401, "unauthorized", "AUTHENTICATION_REQUIRED"),
            Self::Forbidden => (403, "forbidden", "REQUEST_BOUNDARY_REJECTED"),
            Self::Invalid => (400, "invalid_request", "INVALID_REQUEST"),
            Self::Conflict => (409, "conflict", "AUTHORITY_STATE_CHANGED"),
            Self::Unavailable => (503, "unavailable", "AUTHORITY_UNAVAILABLE"),
            Self::Limited => (429, "unavailable", "RATE_LIMITED"),
            Self::ReviewUnavailable => (409, "conflict", "REVIEW_EVIDENCE_UNAVAILABLE"),
        };
        (
            StatusCode::from_u16(status).unwrap(),
            axum::Json(json!({"error":error,"reason":reason})),
        )
            .into_response()
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "authority service configuration or request rejected")
    }
}
impl std::error::Error for Failure {}
impl From<fw_authority::AuthorityError> for Failure {
    fn from(value: fw_authority::AuthorityError) -> Self {
        match value {
            fw_authority::AuthorityError::Storage(_) => Self::Unavailable,
            fw_authority::AuthorityError::Quota => Self::Limited,
            _ => Self::Conflict,
        }
    }
}
impl Service {
    /// Runtime key must be provided independently of controller configuration.
    /// Sessions and login proof state are private memory and die on restart.
    pub fn open(
        config: ServiceConfig,
        key: [u8; 32],
        clock: impl Fn() -> i64 + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::open_for_startup(config, key, clock).map_err(|error| error.failure)
    }
    fn open_for_startup(
        config: ServiceConfig,
        key: [u8; 32],
        clock: impl Fn() -> i64 + Send + Sync + 'static,
    ) -> std::result::Result<Self, StartupError> {
        at(StartupStage::Config, || {
            if !cfg!(unix)
                || config.profiles.is_empty()
                || config.profiles.len() > 32
                || config.review_evidence.len() > 100
            {
                return Err(Failure::Invalid);
            }
            Ok(())
        })?;
        if key == [0; 32] {
            return Err(StartupError::new(StartupStage::SessionKey));
        }
        let (verifier, host) = at(StartupStage::Origin, || {
            if config.origin == config.controller_origin
                || !config.origin.starts_with("http://localhost:")
            {
                return Err(Failure::Invalid);
            }
            let verifier = WebAuthn::new(&config.origin).map_err(|_| Failure::Invalid)?;
            WebAuthn::new(&config.controller_origin).map_err(|_| Failure::Invalid)?;
            let host = config
                .origin
                .strip_prefix("http://")
                .ok_or(Failure::Invalid)?
                .to_owned();
            if host
                .strip_prefix("localhost:")
                .and_then(|p| p.parse::<u16>().ok())
                .is_none_or(|p| p == 0)
            {
                return Err(Failure::Invalid);
            }
            Ok((verifier, host))
        })?;
        let mut store = at(StartupStage::Database, || {
            files::private_file(&config.database, false)?;
            if std::fs::metadata(&config.database)
                .map_err(|_| Failure::Invalid)?
                .len()
                == 0
            {
                return Err(Failure::Invalid);
            }
            AuthorityStore::open(&config.database).map_err(Failure::from)
        })?;
        let now = clock();
        at(StartupStage::Trust, || {
            for (alias, profile) in &config.profiles {
                if alias.is_empty()
                    || alias.len() > 64
                    || !alias
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
                {
                    return Err(Failure::Invalid);
                }
                let p = store
                    .review_profile(
                        &profile.tenant()?,
                        &profile.principal_id,
                        &profile.credential_id,
                        now,
                    )
                    .map_err(|_| Failure::Invalid)?;
                if p.state != "pending" && p.state != "active" {
                    return Err(Failure::Invalid);
                }
            }
            Ok(())
        })?;
        let assets = at(StartupStage::UiAssets, || {
            files::load_ui(&config.ui_directory)
        })?;
        let evidence = at(StartupStage::ReviewEvidence, || {
            let mut evidence = BTreeMap::new();
            for (id, path) in &config.review_evidence {
                if uuid::Uuid::parse_str(id).is_err() {
                    return Err(Failure::Invalid);
                }
                let bytes = files::read_private(path, 2 * 1024 * 1024)?;
                let bundle = parse_strict_with_limit::<ReviewEvidence>(&bytes, 2 * 1024 * 1024)
                    .map_err(|_| Failure::Invalid)?;
                evidence.insert(id.clone(), bundle);
            }
            Ok(evidence)
        })?;
        let origin = config.origin.clone();
        let envelope_key = at(StartupStage::RuntimeKey, || {
            let mut boot_nonce = [0; 32];
            openssl::rand::rand_bytes(&mut boot_nonce).map_err(|_| Failure::Unavailable)?;
            let hmac = PKey::hmac(&key).map_err(|_| Failure::Unavailable)?;
            let mut signer =
                Signer::new(MessageDigest::sha256(), &hmac).map_err(|_| Failure::Unavailable)?;
            signer
                .update(b"fw.authority-review/envelopes/v1")
                .map_err(|_| Failure::Unavailable)?;
            signer
                .update(&boot_nonce)
                .map_err(|_| Failure::Unavailable)?;
            signer
                .sign_to_vec()
                .map_err(|_| Failure::Unavailable)?
                .try_into()
                .map_err(|_| Failure::Unavailable)
        })?;
        let admission = Arc::new(at(StartupStage::Database, || {
            admission::Admission::new(&config.database, key)
        })?);
        Ok(Self {
            inner: Arc::new(Mutex::new(Runtime {
                config,
                store,
                verifier,
                key,
                sessions: BTreeMap::new(),
                assets,
                evidence,
                envelope_key: auth::EnvelopeKeys::new(envelope_key),
                failure_samples: BTreeMap::new(),
                next_session_serial: 0,
            })),
            clock: Arc::new(clock),
            admission,
            origin,
            host,
        })
    }
    pub fn from_files(
        config_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> std::result::Result<Self, StartupError> {
        let config = at(StartupStage::Config, || {
            parse_strict_with_limit(&files::read_private(config_path, 65536)?, 65536)
                .map_err(|_| Failure::Invalid)
        })?;
        let key = at(StartupStage::SessionKey, || {
            files::read_private(key_path, 32)?
                .try_into()
                .map_err(|_| Failure::Invalid)
        })?;
        Self::open_for_startup(config, key, || chrono::Utc::now().timestamp())
    }
    /// The origin is configured before binding; headers never select authority.
    pub fn loopback_address(&self) -> Result<std::net::SocketAddr> {
        let port = self
            .host
            .strip_prefix("localhost:")
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or(Failure::Invalid)?;
        Ok(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
    }
    pub fn router(self) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
}

fn one<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .map(|v| v.to_str().map_err(|_| Failure::Invalid))
        .transpose()?;
    if values.next().is_some() {
        return Err(Failure::Invalid);
    }
    Ok(first)
}
fn boundary(service: &Service, headers: &HeaderMap, api: bool, method: &str) -> Result<()> {
    if headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len())
        .sum::<usize>()
        > 8192
    {
        return Err(Failure::Invalid);
    }
    if one(headers, "host")? != Some(service.host.as_str()) {
        return Err(Failure::Forbidden);
    }
    let origin = one(headers, "origin")?;
    if origin.is_some_and(|v| v != service.origin)
        || (method == "POST" && origin != Some(service.origin.as_str()))
    {
        return Err(Failure::Forbidden);
    }
    if api && one(headers, "sec-fetch-site")?.is_some_and(|v| v != "same-origin" && v != "none") {
        return Err(Failure::Forbidden);
    }
    if one(headers, "authorization")?.is_some()
        || one(headers, "x-forwarded-host")?.is_some()
        || one(headers, "forwarded")?.is_some()
    {
        return Err(Failure::Forbidden);
    }
    Ok(())
}
async fn handle(State(service): State<Service>, request: Request) -> Response {
    let response = handle_inner(service, request)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    secure_headers(response)
}
async fn handle_inner(service: Service, request: Request) -> Result<Response> {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    if parts.uri.query().is_some() || parts.uri.scheme().is_some() || path.len() > 256 {
        return Err(Failure::Invalid);
    }
    let method = parts.method.as_str().to_owned();
    let api = path.starts_with(PREFIX);
    boundary(&service, &parts.headers, api, &method)?;
    if method != "GET" && method != "POST" {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    if method == "POST" && one(&parts.headers, "content-type")? != Some("application/json") {
        return Err(Failure::Invalid);
    }
    let permit = service
        .admission
        .reserve(
            &parts.headers,
            service.clock.clone(),
            parts.extensions.get::<listener::Phase>(),
        )
        .await?;
    let bytes = tokio::time::timeout(Duration::from_secs(3), to_bytes(body, MAX_BODY))
        .await
        .map_err(|_| Failure::Invalid)?
        .map_err(|_| Failure::Invalid)?;
    if method == "GET" && !bytes.is_empty() {
        return Err(Failure::Invalid);
    }
    // SQLite and cryptographic work never occupy the async reactor. Admission
    // is awaited to completion; a timeout must not imply a rolled-back decision.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut runtime = service.inner.lock().map_err(|_| Failure::Unavailable)?;
        // Queueing behind another database operation must not freeze freshness.
        let now = (service.clock)();
        let result = runtime.dispatch(&method, &path, &parts.headers, &bytes, now);
        service.admission.synchronize(&runtime.sessions)?;
        result
    })
    .await
    .map_err(|_| Failure::Unavailable)?
}
fn secure_headers(mut response: Response) -> Response {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-resource-policy", "same-origin"),
        ("cross-origin-opener-policy", "same-origin"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'",
        ),
        (
            "permissions-policy",
            "publickey-credentials-get=(self), publickey-credentials-create=()",
        ),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    response
}
fn random() -> Result<String> {
    let mut bytes = [0; 32];
    openssl::rand::rand_bytes(&mut bytes).map_err(|_| Failure::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn same(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    parse_strict_with_limit(bytes, MAX_BODY).map_err(|_| Failure::Invalid)
}
fn json_response(value: Value, cookie: Option<String>) -> Response {
    let Ok(bytes) = serde_json::to_vec(&value) else {
        return Failure::Unavailable.into_response();
    };
    if bytes.len() > 256 * 1024 {
        return Failure::Unavailable.into_response();
    }
    let mut response = ([("content-type", "application/json")], bytes).into_response();
    if let Some(cookie) = cookie {
        response.headers_mut().insert(
            "set-cookie",
            HeaderValue::from_str(&cookie).expect("generated cookie"),
        );
    }
    response
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthOptions {
    profile: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthVerify {
    ceremony_id: String,
    assertion: AuthenticationResponse,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    plan_id: String,
    plan_hash: String,
    requirements_hash: String,
    decision: ApprovalDecision,
    role: ApprovalRole,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionRequest {
    challenge_id: String,
    idempotency_key: String,
    assertion: AuthenticationResponse,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
impl Runtime {
    fn dispatch(
        &mut self,
        method: &str,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
        now: i64,
    ) -> Result<Response> {
        if !path.starts_with(PREFIX) {
            if method != "GET" {
                return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            let key = if path == "/" { "/index.html" } else { path };
            let (kind, bytes) = self.assets.get(key).ok_or(Failure::Invalid)?;
            return Ok(
                ([("content-type", kind.as_str())], Body::from(bytes.clone())).into_response(),
            );
        }
        if let Some(response) = self.auth_route(method, path, headers, body, now)? {
            return Ok(response);
        }
        let binding = self.session(headers, now)?;
        let id = binding.id.ok_or(Failure::Unauthorized)?;
        self.rate_authenticated(&id, now)?;
        let (identity, _) = self.authenticated(&id, now)?;
        let tenant = identity.tenant()?;
        if method == "GET" && path == "/authority/v1/plans" {
            let ids = self
                .store
                .review_plan_ids(&tenant, &identity.principal_id, now)?;
            let mut plans = Vec::new();
            for plan_id in ids {
                let detail =
                    self.store
                        .review_plan(&tenant, &identity.principal_id, &plan_id, now)?;
                plans.push(json!({"plan_id":plan_id,"plan_hash":detail.plan_hash,"change_kind":detail.plan["change_kind"],"valid_until":detail.plan["valid_until"]}));
            }
            return Ok(json_response(json!({"plans":plans}), None));
        }
        if method == "GET" && path.starts_with("/authority/v1/plans/") {
            let plan_id = path.trim_start_matches("/authority/v1/plans/");
            if uuid::Uuid::parse_str(plan_id).is_err() {
                return Err(Failure::Invalid);
            }
            let detail = self
                .store
                .review_plan(&tenant, &identity.principal_id, plan_id, now)?;
            let review = self
                .evidence
                .get(plan_id)
                .and_then(|e| e.verify(&detail.plan).ok());
            let mut value = serde_json::to_value(detail).map_err(|_| Failure::Unavailable)?;
            value["current_principal_decisions"] = self.store.review_decisions(
                &tenant,
                &identity.principal_id,
                plan_id,
                &self.verifier,
                now,
            )?;
            let (aggregation, current_set) =
                self.store
                    .approval_review_status(&tenant, plan_id, &self.verifier, now)?;
            value["aggregation"] =
                serde_json::to_value(aggregation).map_err(|_| Failure::Unavailable)?;
            value["current_approval_set"] = match current_set {
                Some(set) => {
                    json!({"content":set.content(),"hash":set.hash(),"valid_until":chrono::DateTime::from_timestamp(set.valid_until(),0).ok_or(Failure::Unavailable)?.format("%Y-%m-%dT%H:%M:%SZ").to_string()})
                }
                None => Value::Null,
            };
            value["review"] = review.unwrap_or_else(
                || json!({"available":false,"reason":"REVIEW_EVIDENCE_UNAVAILABLE"}),
            );
            return Ok(json_response(value, None));
        }
        if method == "POST" && path == "/authority/v1/approvals/challenges" {
            let request: ChallengeRequest = parse(body)?;
            let detail =
                self.store
                    .review_plan(&tenant, &identity.principal_id, &request.plan_id, now)?;
            if detail.plan_hash != request.plan_hash
                || detail.requirements_hash != request.requirements_hash
            {
                return Err(Failure::Conflict);
            }
            if request.decision == ApprovalDecision::Approve {
                self.evidence
                    .get(&request.plan_id)
                    .ok_or(Failure::ReviewUnavailable)?
                    .verify(&detail.plan)?;
            }
            let issued = self.store.issue_challenge(
                &tenant,
                &identity.principal_id,
                &identity.credential_id,
                &request.plan_id,
                request.role,
                request.decision,
                &self.verifier,
                now,
            )?;
            return Ok(json_response(
                json!({"challenge":issued.challenge,"options":issued.options}),
                None,
            ));
        }
        if method == "POST" && path == "/authority/v1/approvals/assertions" {
            let request: AssertionRequest = parse(body)?;
            let challenge = self.store.review_challenge(
                &tenant,
                &identity.principal_id,
                &identity.credential_id,
                &request.challenge_id,
            )?;
            if challenge.decision() == ApprovalDecision::Approve {
                let payload = serde_json::to_value(&challenge).map_err(|_| Failure::Unavailable)?;
                let plan_id = payload["subject"]["plan_ref"]["plan_id"]
                    .as_str()
                    .ok_or(Failure::Conflict)?;
                let detail =
                    self.store
                        .review_plan(&tenant, &identity.principal_id, plan_id, now)?;
                self.evidence
                    .get(plan_id)
                    .ok_or(Failure::ReviewUnavailable)?
                    .verify(&detail.plan)?;
            }
            let result = self.store.admit_decision(
                &tenant,
                &identity.principal_id,
                &request.challenge_id,
                &request.idempotency_key,
                &request.assertion,
                &self.verifier,
                now,
            )?;
            return Ok(json_response(
                json!({"approval":result.approval,"replayed":result.replayed,"aggregation":result.aggregation}),
                None,
            ));
        }
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}

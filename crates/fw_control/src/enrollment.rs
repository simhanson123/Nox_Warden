//! Token-bound transport registration. Registration never approves a policy.
use crate::{
    ApiResult, AppState, PRINCIPAL, Problem, bad, envelope, header, now, unavailable, uuid,
};
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use fw_enrollment::{CertificateAuthority, EnrollmentRequest, Issuance};
use fw_store::{
    StoreError,
    enrollment::{EnrollmentAttempt, EnrollmentIdentity},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

pub(crate) struct EnrollmentRuntime {
    authority: CertificateAuthority,
    in_flight: Arc<Semaphore>,
    rate: Mutex<(Instant, u32)>,
}
impl EnrollmentRuntime {
    pub(crate) fn new(authority: CertificateAuthority) -> Self {
        Self {
            authority,
            in_flight: Arc::new(Semaphore::new(4)),
            rate: Mutex::new((Instant::now(), 0)),
        }
    }
}

fn storage(error: StoreError) -> Problem {
    match error {
        StoreError::NotFound => Problem(StatusCode::NOT_FOUND, "NOT_FOUND"),
        StoreError::IdempotencyConflict => Problem(StatusCode::CONFLICT, "IDEMPOTENCY_CONFLICT"),
        StoreError::Conflict("ENROLLMENT_UNAVAILABLE") => {
            Problem(StatusCode::FORBIDDEN, "ENROLLMENT_UNAVAILABLE")
        }
        StoreError::Conflict("ENROLLMENT_EXPIRED") => {
            Problem(StatusCode::GONE, "ENROLLMENT_EXPIRED")
        }
        StoreError::Conflict(_) | StoreError::ClaimStale => {
            Problem(StatusCode::CONFLICT, "ENROLLMENT_CONFLICT")
        }
        StoreError::Retired => Problem(StatusCode::FORBIDDEN, "ENROLLMENT_REVOKED"),
        StoreError::PreconditionFailed => {
            Problem(StatusCode::PRECONDITION_FAILED, "REVISION_CONFLICT")
        }
        StoreError::InvalidInput("RESULT_TOO_LARGE") => {
            Problem(StatusCode::PAYLOAD_TOO_LARGE, "RESULT_TOO_LARGE")
        }
        StoreError::InvalidInput(_)
        | StoreError::Contract(_)
        | StoreError::Json(_)
        | StoreError::Domain(_) => bad("INVALID_ENROLLMENT"),
        _ => unavailable(),
    }
}
fn runtime(state: &AppState) -> Result<&EnrollmentRuntime, Problem> {
    state.enrollment.as_deref().ok_or(Problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "ENROLLMENT_DISABLED",
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenWrite {
    name: String,
    platform: String,
    expected_key_fingerprint: String,
    token_hash: String,
}
pub(crate) async fn create_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult {
    state.auth(&headers, true)?;
    runtime(&state)?;
    let input: TokenWrite = fw_contracts::parse_strict(&body).map_err(|_| bad("INVALID_JSON"))?;
    let value = json!({"name": input.name, "platform": input.platform,
        "expected_key_fingerprint": input.expected_key_fingerprint, "token_hash": input.token_hash});
    let result = state
        .store
        .create_enrollment_token(
            &state.tenant,
            PRINCIPAL,
            &value,
            header(&headers, "idempotency-key")?,
            now(),
        )
        .map_err(storage)?;
    let status = if result.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, axum::Json(envelope(result.value))).into_response())
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListQuery {
    limit: Option<usize>,
}
fn limit(query: &ListQuery) -> Result<usize, Problem> {
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(bad("LIMIT_INVALID"));
    }
    Ok(limit)
}
pub(crate) async fn list_enrollments(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult {
    state.auth(&headers, false)?;
    let limit = limit(&query)?;
    if state
        .store
        .count_enrollments(&state.tenant)
        .map_err(storage)?
        > limit as u64
    {
        return Err(Problem(StatusCode::PAYLOAD_TOO_LARGE, "RESULT_TOO_LARGE"));
    }
    let values = state
        .store
        .list_enrollments(&state.tenant, limit, now())
        .map_err(storage)?;
    Ok(axum::Json(envelope(json!(values))).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyWrite {}
pub(crate) async fn revoke(
    State(state): State<Arc<AppState>>,
    Path(target_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult {
    state.auth(&headers, true)?;
    if !uuid(&target_id) {
        return Err(bad("TARGET_ID_INVALID"));
    }
    let _: EmptyWrite = fw_contracts::parse_strict(&body).map_err(|_| bad("INVALID_JSON"))?;
    let value = state
        .store
        .revoke_enrollment(&state.tenant, PRINCIPAL, &target_id, now())
        .map_err(storage)?;
    Ok(axum::Json(envelope(value)).into_response())
}
pub(crate) async fn list_targets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult {
    state.auth(&headers, false)?;
    let limit = limit(&query)?;
    if state.store.count_targets(&state.tenant).map_err(storage)? > limit as u64 {
        return Err(Problem(StatusCode::PAYLOAD_TOO_LARGE, "RESULT_TOO_LARGE"));
    }
    let values = state
        .store
        .list_targets(&state.tenant, limit, now())
        .map_err(storage)?;
    Ok(axum::Json(envelope(json!(values))).into_response())
}
pub(crate) async fn get_target(
    State(state): State<Arc<AppState>>,
    Path(target_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult {
    state.auth(&headers, false)?;
    if !uuid(&target_id) {
        return Err(bad("TARGET_ID_INVALID"));
    }
    let value = state
        .store
        .get_target(&state.tenant, &target_id, now())
        .map_err(storage)?;
    Ok(axum::Json(envelope(value)).into_response())
}

async fn enroll(State(state): State<Arc<AppState>>, body: Bytes) -> ApiResult {
    let runtime = runtime(&state)?;
    let request: EnrollmentRequest =
        fw_contracts::parse_strict(&body).map_err(|_| bad("INVALID_JSON"))?;
    let csr =
        fw_enrollment::validate_request(&request).map_err(|_| bad("INVALID_CSR_OR_BINDING"))?;
    let attempt = EnrollmentAttempt {
        token_hash: fw_contracts::hash_bytes(request.token.as_bytes()),
        csr_hash: csr.csr_hash().into(),
        key_fingerprint: csr.key_fingerprint().into(),
        platform: request.platform.clone(),
        request_id: request.request_id.clone(),
        nonce: request.nonce.clone(),
        agent_version: request.agent_version.clone(),
    };
    let reservation = state
        .store
        .reserve_enrollment(&attempt, now())
        .map_err(storage)?;
    if let Some(response) = reservation.response {
        return Ok(axum::Json(response).into_response());
    }
    let response = runtime
        .authority
        .issue(
            &csr,
            &Issuance {
                request_id: reservation.request_id,
                org_id: reservation.tenant.org_id,
                project_id: reservation.tenant.project_id,
                target_id: reservation.target_id,
                job_id: reservation.job_id.clone(),
                issued_at: reservation.issued_at,
                authority_epoch: 0,
            },
        )
        .map_err(|_| {
            Problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "CERTIFICATE_ISSUANCE_UNAVAILABLE",
            )
        })?;
    // DER identity, rather than PEM formatting or CSR subject, keys runtime authentication.
    let certificate = tokio_rustls::rustls::pki_types::CertificateDer::from_pem_slice(
        response.certificate_chain_pem.as_bytes(),
    )
    .map_err(|_| unavailable())?;
    let fingerprint = fw_contracts::hash_bytes(certificate.as_ref());
    let response = serde_json::to_value(response).map_err(|_| unavailable())?;
    let value = state
        .store
        .complete_enrollment(&reservation.job_id, &fingerprint, &response, now())
        .map_err(storage)?;
    Ok(axum::Json(value).into_response())
}
fn authenticate_device(
    state: &AppState,
    peer: &crate::tls::TlsPeer,
) -> Result<EnrollmentIdentity, Problem> {
    let fingerprint = peer.certificate_fingerprint.as_deref().ok_or(Problem(
        StatusCode::UNAUTHORIZED,
        "CLIENT_CERTIFICATE_REQUIRED",
    ))?;
    state
        .store
        .authenticate_enrollment(fingerprint, now())
        .map_err(|_| Problem(StatusCode::FORBIDDEN, "DEVICE_AUTHENTICATION_REJECTED"))
}
fn device_envelope(value: Value) -> Value {
    let mut result = envelope(value);
    // A device certificate does not confer the human session's public-API actions.
    result["actions"] = json!([]);
    result
}
async fn capability(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<crate::tls::TlsPeer>,
    body: Bytes,
) -> ApiResult {
    let identity = authenticate_device(&state, &peer)?;
    let input: Value = fw_contracts::parse_strict(&body).map_err(|_| bad("INVALID_JSON"))?;
    let value = state
        .store
        .save_target_capability(&identity, &input, now())
        .map_err(storage)?;
    Ok(axum::Json(device_envelope(value)).into_response())
}
async fn device_status(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<crate::tls::TlsPeer>,
) -> ApiResult {
    let identity = authenticate_device(&state, &peer)?;
    let value = state
        .store
        .get_enrollment(&identity.tenant, &identity.target_id, now())
        .map_err(storage)?;
    Ok(axum::Json(device_envelope(value)).into_response())
}

async fn internal_boundary(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let runtime = match runtime(&state) {
        Ok(runtime) => runtime,
        Err(error) => return error.into_response(),
    };
    let Some(ConnectInfo(peer)) = request
        .extensions()
        .get::<ConnectInfo<crate::tls::TlsPeer>>()
    else {
        return Problem(StatusCode::UNAUTHORIZED, "TLS_CONNECTION_REQUIRED").into_response();
    };
    if !peer.is_loopback() {
        return Problem(StatusCode::FORBIDDEN, "LOOPBACK_REQUIRED").into_response();
    }
    if request.method() == axum::http::Method::POST
        && request
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v.split(';').next().map(str::trim) != Some("application/json"))
    {
        return Problem(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON_REQUIRED").into_response();
    }
    let Ok(_permit) = runtime.in_flight.clone().try_acquire_owned() else {
        return Problem(StatusCode::TOO_MANY_REQUESTS, "IN_FLIGHT_LIMIT").into_response();
    };
    {
        let Ok(mut rate) = runtime.rate.lock() else {
            return unavailable().into_response();
        };
        if rate.0.elapsed() >= Duration::from_secs(1) {
            *rate = (Instant::now(), 0);
        }
        if rate.1 >= 10 {
            return Problem(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED").into_response();
        }
        rate.1 += 1;
    }
    match tokio::time::timeout(Duration::from_secs(30), next.run(request)).await {
        Ok(response) => response,
        Err(_) => Problem(StatusCode::REQUEST_TIMEOUT, "REQUEST_TIMEOUT").into_response(),
    }
}
pub(crate) fn internal_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/internal/v1/enroll", post(enroll))
        .route("/internal/v1/capabilities", post(capability))
        .route("/internal/v1/device-status", get(device_status))
        .fallback(crate::not_found)
        .layer(DefaultBodyLimit::max(65_536))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            internal_boundary,
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            axum::http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .with_state(state)
}

use tokio_rustls::rustls::pki_types::pem::PemObject;

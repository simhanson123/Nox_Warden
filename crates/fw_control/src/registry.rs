//! Authenticated catalogue APIs. Manual records are never workload identity evidence.
use super::{ApiResult, AppState, PRINCIPAL, Problem, bad, envelope, header, now, uuid};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use fw_store::StoreError;
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AssetKind {
    Host,
    Vm,
    Namespace,
    Subnet,
    Gateway,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Isolation {
    Host,
    Vm,
    NetworkNamespace,
    Subnet,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Family {
    Ipv4,
    Ipv6,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Criticality {
    Normal,
    Critical,
    Management,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Provenance {
    Manual,
    EnrolledAgent,
    TrustedInventory,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RecordState {
    Active,
    Retired,
}

fn required_nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRef {
    store_id: String,
    object_hash: String,
    media_type: String,
    size_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetAddress {
    family: Family,
    cidr: String,
    #[serde(deserialize_with = "required_nullable")]
    interface: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetDefinition {
    name: String,
    asset_kind: AssetKind,
    owner_id: String,
    addresses: Vec<AssetAddress>,
    criticality: Criticality,
    isolation: Isolation,
    provenance: Provenance,
    #[serde(deserialize_with = "required_nullable")]
    source_evidence: Option<EvidenceRef>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetWrite {
    definition: AssetDefinition,
    state: RecordState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct PortRange {
    start: u16,
    end: u16,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase", deny_unknown_fields)]
enum Transport {
    Tcp {
        destination_ports: Vec<PortRange>,
    },
    Udp {
        destination_ports: Vec<PortRange>,
    },
    Icmp {
        #[serde(rename = "type")]
        icmp_type: u8,
        code: u8,
    },
    Icmpv6 {
        #[serde(rename = "type")]
        icmp_type: u8,
        code: u8,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceDefinition {
    name: String,
    owner_id: String,
    destination_asset_ids: Vec<String>,
    target_ids: Vec<String>,
    transport: Transport,
    description: String,
    criticality: Criticality,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceCreate {
    service_id: String,
    definition: ServiceDefinition,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceWrite {
    definition: ServiceDefinition,
    state: RecordState,
}

fn valid_text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.chars().count() <= max && !s.chars().any(|c| c == '\0')
}
fn valid_id_list(ids: &[String], max: usize) -> bool {
    !ids.is_empty()
        && ids.len() <= max
        && ids.iter().all(|s| uuid(s))
        && ids.iter().collect::<BTreeSet<_>>().len() == ids.len()
}
fn service_slug(s: &str) -> bool {
    let bytes = s.as_bytes();
    (1..=128).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(c))
}
fn invalid() -> Problem {
    Problem(StatusCode::UNPROCESSABLE_ENTITY, "REGISTRY_INVALID")
}
impl AssetWrite {
    fn validate(&self) -> Result<(), Problem> {
        let d = &self.definition;
        if !matches!(d.provenance, Provenance::Manual) || d.source_evidence.is_some() {
            return Err(Problem(
                StatusCode::FORBIDDEN,
                "TRUSTED_PROVENANCE_REQUIRES_ISSUER",
            ));
        }
        if !valid_text(&d.name, 128)
            || !uuid(&d.owner_id)
            || d.addresses.is_empty()
            || d.addresses.len() > 64
        {
            return Err(invalid());
        }
        for a in &d.addresses {
            if !valid_text(&a.cidr, 64) || a.interface.as_ref().is_some_and(|s| !valid_text(s, 128))
            {
                return Err(invalid());
            }
        }
        let addresses = d
            .addresses
            .iter()
            .map(|a| serde_json::to_string(a).expect("serializable address"))
            .collect::<BTreeSet<_>>();
        if addresses.len() != d.addresses.len() {
            return Err(invalid());
        }
        Ok(())
    }
}
impl ServiceDefinition {
    fn validate(&self) -> Result<(), Problem> {
        if !valid_text(&self.name, 128)
            || !uuid(&self.owner_id)
            || !valid_text(&self.description, 2048)
            || !valid_id_list(&self.destination_asset_ids, 64)
            || !valid_id_list(&self.target_ids, 16)
        {
            return Err(invalid());
        }
        if let Transport::Tcp { destination_ports } | Transport::Udp { destination_ports } =
            &self.transport
        {
            let mut ports = destination_ports.clone();
            ports.sort();
            if ports.is_empty()
                || ports.len() > 64
                || ports.iter().any(|p| p.start == 0 || p.start > p.end)
                || ports.windows(2).any(|p| p[0].end >= p[1].start)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
fn parse_body<T: DeserializeOwned>(headers: &HeaderMap, body: &[u8]) -> Result<T, Problem> {
    if header(headers, "content-type")?.split(';').next() != Some("application/json") {
        return Err(Problem(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON_REQUIRED"));
    }
    fw_contracts::parse_strict(body).map_err(|_| bad("INVALID_JSON"))
}
fn value<T: Serialize>(v: T) -> Result<Value, Problem> {
    serde_json::to_value(v).map_err(|_| bad("INVALID_JSON"))
}
fn store_error(error: StoreError) -> Problem {
    match error {
        StoreError::NotFound => Problem(StatusCode::NOT_FOUND, "NOT_FOUND"),
        StoreError::PreconditionFailed => {
            Problem(StatusCode::PRECONDITION_FAILED, "REVISION_CONFLICT")
        }
        StoreError::IdempotencyConflict => Problem(StatusCode::CONFLICT, "IDEMPOTENCY_CONFLICT"),
        StoreError::Conflict("RESULT_TOO_LARGE") => {
            Problem(StatusCode::UNPROCESSABLE_ENTITY, "RESULT_TOO_LARGE")
        }
        StoreError::Conflict(_) => Problem(StatusCode::CONFLICT, "REGISTRY_CONFLICT"),
        StoreError::Retired => Problem(StatusCode::GONE, "RESOURCE_RETIRED"),
        StoreError::InvalidInput(_)
        | StoreError::Domain(_)
        | StoreError::Contract(_)
        | StoreError::Json(_) => invalid(),
        _ => Problem(StatusCode::SERVICE_UNAVAILABLE, "STORAGE_UNAVAILABLE"),
    }
}
fn precondition(headers: &HeaderMap) -> Result<(i32, String), Problem> {
    let raw = headers
        .get("if-match")
        .ok_or(Problem(
            StatusCode::PRECONDITION_REQUIRED,
            "PRECONDITION_REQUIRED",
        ))?
        .to_str()
        .map_err(|_| bad("IF_MATCH_INVALID"))?;
    let inner = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| bad("IF_MATCH_INVALID"))?;
    let (rev, hash) = inner
        .strip_prefix("rev-")
        .and_then(|s| s.split_once('-'))
        .ok_or_else(|| bad("IF_MATCH_INVALID"))?;
    let number: i32 = rev.parse().map_err(|_| bad("IF_MATCH_INVALID"))?;
    if number < 1
        || rev != number.to_string()
        || hash.len() != 71
        || !hash.starts_with("sha256:")
        || !hash[7..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(bad("IF_MATCH_INVALID"));
    }
    Ok((number, hash.to_owned()))
}
fn registry_envelope(data: Value, kind: &str, revision: i32) -> Value {
    let mut result = envelope(data);
    result["revision"] = json!(revision);
    result["freshness"]["source"] = json!("registry");
    result["actions"] =
        json!([{"action_id":format!("registry.{kind}.write"),"allowed":true,"reason_code":null}]);
    result
}
fn object_response(object: Value, status: StatusCode, kind: &str) -> ApiResult {
    let revision = object["revision"]
        .as_i64()
        .filter(|n| *n > 0 && *n <= i32::MAX as i64)
        .ok_or(Problem(StatusCode::SERVICE_UNAVAILABLE, "STORAGE_INVALID"))?
        as i32;
    let hash = object["content_hash"]
        .as_str()
        .ok_or(Problem(StatusCode::SERVICE_UNAVAILABLE, "STORAGE_INVALID"))?;
    let etag = HeaderValue::from_str(&format!("\"rev-{revision}-{hash}\""))
        .map_err(|_| Problem(StatusCode::SERVICE_UNAVAILABLE, "STORAGE_INVALID"))?;
    let retired = object["state"] == "retired";
    let mut result = registry_envelope(object, kind, revision);
    if retired {
        result["actions"] = json!([{"action_id":format!("registry.{kind}.write"),"allowed":false,"reason_code":"RESOURCE_RETIRED"}]);
    }
    let mut response = (status, axum::Json(result)).into_response();
    response.headers_mut().insert("etag", etag);
    Ok(response)
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistryQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}
fn list_limit(query: &RegistryQuery) -> Result<usize, Problem> {
    if query.cursor.is_some() {
        return Err(bad("CURSOR_UNSUPPORTED"));
    }
    let limit = query.limit.unwrap_or(50);
    if limit == 0 || limit > 100 {
        return Err(bad("PAGE_LIMIT_INVALID"));
    }
    Ok(limit)
}
fn list_response(rows: Vec<Value>, kind: &str) -> ApiResult {
    let revision = rows
        .iter()
        .try_fold(1_i32, |sum, row| {
            let rev = i32::try_from(row["revision"].as_i64()?).ok()?;
            if rev <= 0 {
                return None;
            }
            sum.checked_add(rev)
        })
        .ok_or(Problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "REVISION_EXHAUSTED",
        ))?;
    Ok(axum::Json(registry_envelope(json!(rows), kind, revision)).into_response())
}
pub(super) async fn list_assets(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<RegistryQuery>,
) -> ApiResult {
    s.auth(&headers, false)?;
    let rows = s
        .store
        .list_assets(&s.tenant, list_limit(&query)?)
        .map_err(store_error)?;
    list_response(rows, "assets")
}
pub(super) async fn get_asset(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    s.auth(&headers, false)?;
    if !uuid(&id) {
        return Err(bad("ID_INVALID"));
    }
    object_response(
        s.store.get_asset(&s.tenant, &id).map_err(store_error)?,
        StatusCode::OK,
        "assets",
    )
}
pub(super) async fn create_asset(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult {
    s.auth(&headers, true)?;
    let input: AssetWrite = parse_body(&headers, &body)?;
    input.validate()?;
    let result = s
        .store
        .create_asset(
            &s.tenant,
            PRINCIPAL,
            &value(input)?,
            header(&headers, "idempotency-key")?,
            now(),
        )
        .map_err(store_error)?;
    object_response(result.value, StatusCode::CREATED, "assets")
}
pub(super) async fn revise_asset(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult {
    s.auth(&headers, true)?;
    if !uuid(&id) {
        return Err(bad("ID_INVALID"));
    }
    let (revision, hash) = precondition(&headers)?;
    let input: AssetWrite = parse_body(&headers, &body)?;
    input.validate()?;
    let result = s
        .store
        .revise_asset(
            &s.tenant,
            PRINCIPAL,
            &id,
            &value(input)?,
            revision,
            &hash,
            header(&headers, "idempotency-key")?,
            now(),
        )
        .map_err(store_error)?;
    object_response(result.value, StatusCode::CREATED, "assets")
}
pub(super) async fn list_services(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<RegistryQuery>,
) -> ApiResult {
    s.auth(&headers, false)?;
    let rows = s
        .store
        .list_services(&s.tenant, list_limit(&query)?)
        .map_err(store_error)?;
    list_response(rows, "services")
}
pub(super) async fn get_service(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    s.auth(&headers, false)?;
    if !service_slug(&id) {
        return Err(bad("ID_INVALID"));
    }
    object_response(
        s.store.get_service(&s.tenant, &id).map_err(store_error)?,
        StatusCode::OK,
        "services",
    )
}
pub(super) async fn create_service(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult {
    s.auth(&headers, true)?;
    let input: ServiceCreate = parse_body(&headers, &body)?;
    input.definition.validate()?;
    if !service_slug(&input.service_id) {
        return Err(invalid());
    }
    let result = s
        .store
        .create_service(
            &s.tenant,
            PRINCIPAL,
            &value(input)?,
            header(&headers, "idempotency-key")?,
            now(),
        )
        .map_err(store_error)?;
    object_response(result.value, StatusCode::CREATED, "services")
}
pub(super) async fn revise_service(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult {
    s.auth(&headers, true)?;
    if !service_slug(&id) {
        return Err(bad("ID_INVALID"));
    }
    let (revision, hash) = precondition(&headers)?;
    let input: ServiceWrite = parse_body(&headers, &body)?;
    input.definition.validate()?;
    let result = s
        .store
        .revise_service(
            &s.tenant,
            PRINCIPAL,
            &id,
            &value(input)?,
            revision,
            &hash,
            header(&headers, "idempotency-key")?,
            now(),
        )
        .map_err(store_error)?;
    object_response(result.value, StatusCode::CREATED, "services")
}

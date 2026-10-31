#[path = "support/authenticator.rs"]
mod authenticator;
#[path = "support/plans.rs"]
mod plans;
#[path = "../../fw_authority/tests/support/private_directory.rs"]
mod private_directory;
use authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use fw_authority::{ApprovalRole, AuthorityStore, AuthorityTenant};
use fw_authority_service::{LocalProfile, Service, ServiceConfig};
use fw_webauthn::WebAuthn;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const NOW: i64 = 1_700_000_000;
const ORG: &str = "22222222-2222-4222-8222-222222222222";
const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
const PLAN: &str = "44444444-4444-4444-8444-444444444444";
const OTHER: &str = "99999999-9999-4999-8999-999999999999";
const IDEMPOTENCY: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const IDEMPOTENCY_2: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn write_new_private_fixture(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(bytes).unwrap();
}

fn time(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn requirements() -> Value {
    json!({
        "schema_version": "f.approval-requirements/v1",
        "profile": "lab_owner", "minimum_humans": 1,
        "required_roles": ["owner"], "distinct_principals": true,
        "author_may_approve": true, "max_approval_age_seconds": 3600,
        "require_webauthn": true,
        "role_policy_hash": fw_contracts::hash_bytes(b"independently configured role policy")
    })
}

fn plan(requirements: &Value) -> Value {
    let hash = fw_contracts::hash_bytes(b"synthetic immutable plan evidence");
    let operations = json!([{
        "op": "remove_policy", "policy_id": OTHER, "expected_revision": 1,
        "expected_policy_hash": hash
    }]);
    let gates: Vec<Value> = [
        "schema",
        "identity",
        "scope",
        "quota",
        "semantic",
        "expiry",
        "capability",
        "baseline",
    ]
    .into_iter()
    .map(|gate| {
        json!({
            "gate_id": gate, "required": true, "result": "PASS", "evidence_hash": hash
        })
    })
    .collect();
    json!({
        "schema_version": "f.policy-change-plan/v1", "change_kind": "policy_change",
        "plan_id": PLAN, "request_id": OTHER, "request_revision": 1, "request_hash": hash,
        "org_id": ORG, "project_id": PROJECT, "target_id": OTHER, "principal_id": PRINCIPAL,
        "created_at": time(NOW), "valid_until": time(NOW + 3600),
        "request_patch_hash": fw_contracts::canonical_hash(&operations).unwrap(),
        "operations": operations,
        "baseline_hash": hash, "desired_state_hash": hash,
        "candidate_state_ref": {
            "store_id": "authority_test", "object_hash": hash,
            "media_type": "application/json", "size_bytes": 128
        },
        "source_snapshot_hash": hash, "target_capability_hash": hash,
        "guardrail_hash": hash, "compiler_hash": hash, "validator_hash": hash,
        "artifact_hash": hash, "validation_report_hash": hash,
        "effect_summary": {
            "relation": "restricting", "newly_allowed_region_hash": hash,
            "removed_region_hash": hash, "counterexample_hashes": [],
            "analysis_profile": "native-union-minus-deny/v1", "complete": true
        },
        "gates": gates,
        "approval_requirements_hash": fw_contracts::canonical_hash(requirements).unwrap(),
        "probe_spec_hash": hash, "authority_epoch": "1", "target_generation": "1",
        "confirm_timeout_seconds": 60,
        "rollback_authority": {
            "profile": "preserve-current-restrictions", "scope_bound_hash": hash,
            "baseline_hash": hash, "artifact_hash": hash, "valid_until": time(NOW + 3600)
        },
        "normalization_version": "f.normalize/nfc-v1"
    })
}

struct Fixture {
    _directory: tempfile::TempDir,
    db: std::path::PathBuf,
    config: ServiceConfig,
    key: Authenticator,
    credential_id: String,
    membership: String,
}
impl Fixture {
    fn new() -> Self {
        Self::configured(false)
    }
    fn configured(evidence: bool) -> Self {
        let directory = private_directory::private_directory();
        let db = directory.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&db).unwrap();
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let key = Authenticator::new(PRINCIPAL);
        let registration = verifier
            .begin_registration(PRINCIPAL, "Review fixture", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &key.registration(&registration.options),
            )
            .unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        store
            .provision_principal(
                &tenant,
                PRINCIPAL,
                "https://identity.example.test",
                "alice",
                NOW,
            )
            .unwrap();
        store
            .pin_credential(&tenant, &credential, NOW, NOW + 7200, NOW)
            .unwrap();
        let membership = store
            .grant_role(
                &tenant,
                PRINCIPAL,
                ApprovalRole::Owner,
                NOW,
                NOW + 7200,
                NOW,
            )
            .unwrap();
        let (admitted_plan, admitted_requirements, bundle) = plans::complete_plan(NOW);
        let bundle_path = directory.path().join("review.json");
        write_new_private_fixture(&bundle_path, &serde_json::to_vec(&bundle).unwrap());
        if evidence {
            store
                .register_plan(&tenant, &admitted_plan, &admitted_requirements, NOW)
                .unwrap();
        } else {
            store
                .register_plan(&tenant, &plan(&requirements()), &requirements(), NOW)
                .unwrap();
        }
        let ui = directory.path().join("ui");
        let mut directory_builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory_builder.mode(0o700);
        }
        directory_builder.recursive(false).create(&ui).unwrap();
        write_new_private_fixture(
            &ui.join("index.html"),
            b"<!doctype html><title>Authority review</title>",
        );
        let config = ServiceConfig {
            origin: ORIGIN.into(),
            controller_origin: "http://localhost:8799".into(),
            database: db.clone(),
            ui_directory: ui,
            profiles: BTreeMap::from([(
                "alice".into(),
                LocalProfile {
                    org_id: ORG.into(),
                    project_id: PROJECT.into(),
                    principal_id: PRINCIPAL.into(),
                    credential_id: credential.id(),
                },
            )]),
            review_evidence: if evidence {
                BTreeMap::from([(PLAN.into(), bundle_path)])
            } else {
                BTreeMap::new()
            },
        };
        Self {
            _directory: directory,
            db,
            config,
            key,
            credential_id: credential.id(),
            membership,
        }
    }
    async fn start(&self, now: i64) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let service = Service::open(self.config.clone(), [7; 32], move || now).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task =
            tokio::spawn(async move { axum::serve(listener, service.router()).await.unwrap() });
        (addr, task)
    }
}
struct Reply {
    status: u16,
    body: Value,
    cookie: Option<String>,
    raw: String,
}
async fn request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    body: Option<Value>,
    origin: &str,
) -> Reply {
    let data = body.map(|v| v.to_string()).unwrap_or_default();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost:8787\r\nOrigin: {origin}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        data.len()
    );
    if let Some(cookie) = cookie {
        head.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    if let Some(csrf) = csrf {
        head.push_str(&format!("X-Authority-CSRF: {csrf}\r\n"));
    }
    head.push_str("\r\n");
    head.push_str(&data);
    exchange(addr, &head).await
}
async fn exchange(addr: std::net::SocketAddr, head: &str) -> Reply {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();
    let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    let cookie = headers
        .lines()
        .find_map(|l| l.strip_prefix("set-cookie: "))
        .map(|s| s.split(';').next().unwrap().to_string());
    Reply {
        status,
        body: serde_json::from_str(body).unwrap_or(Value::Null),
        cookie,
        raw,
    }
}
async fn session(addr: std::net::SocketAddr) -> Reply {
    request(
        addr,
        "GET",
        "/authority/v1/session",
        None,
        None,
        None,
        ORIGIN,
    )
    .await
}
async fn login(f: &Fixture, addr: std::net::SocketAddr, counter: u32) -> Reply {
    let s = session(addr).await;
    assert_eq!(s.status, 200, "{}", s.raw);
    let options = request(
        addr,
        "POST",
        "/authority/v1/auth/options",
        s.cookie.as_deref(),
        s.body["csrf_token"].as_str(),
        Some(json!({"profile":"alice"})),
        ORIGIN,
    )
    .await;
    assert_eq!(options.status, 200, "{}", options.raw);
    request(addr,"POST","/authority/v1/auth/verify",s.cookie.as_deref(),s.body["csrf_token"].as_str(),Some(json!({"ceremony_id":options.body["ceremony_id"],"assertion":f.key.assertion(&options.body["options"],counter,0x05,ORIGIN)})),ORIGIN).await
}
#[tokio::test]
async fn http_requires_passkey_and_csrf_then_serves_immutable_authority_plan() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    let s = session(addr).await;
    assert_eq!(s.status, 200, "{}", s.raw);
    assert_eq!(s.body["authenticated"], false);
    assert!(s.raw.contains("HttpOnly"));
    assert!(s.raw.contains("SameSite=Strict"));
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            s.cookie.as_deref(),
            s.body["csrf_token"].as_str(),
            None,
            ORIGIN
        )
        .await
        .status,
        401
    );
    let auth = login(&f, addr, 1).await;
    assert_eq!(auth.status, 200, "{}", auth.raw);
    assert_eq!(auth.body["authenticated"], true);
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            auth.cookie.as_deref(),
            None,
            None,
            ORIGIN
        )
        .await
        .status,
        403
    );
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            None,
            "http://localhost:9999"
        )
        .await
        .status,
        403
    );
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(detail.status, 200, "{}", detail.raw);
    assert_eq!(detail.body["plan"], plan(&requirements()));
    assert_eq!(detail.body["review"]["available"], false);
    task.abort();
}
#[tokio::test]
async fn revoked_role_and_restart_invalidate_authenticated_sessions() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    assert_eq!(auth.status, 200, "{}", auth.raw);
    task.abort();
    let (addr, task) = f.start(NOW + 2).await;
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            None,
            ORIGIN
        )
        .await
        .status,
        401
    );
    let auth = login(&f, addr, 2).await;
    assert_eq!(auth.status, 200, "{}", auth.raw);
    let mut store = AuthorityStore::open(&f.db).unwrap();
    store
        .revoke_role(
            &AuthorityTenant::new(ORG, PROJECT).unwrap(),
            &f.membership,
            NOW + 2,
        )
        .unwrap();
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            None,
            ORIGIN
        )
        .await
        .status,
        401
    );
    task.abort();
    assert!(Service::open(f.config.clone(), [7; 32], || NOW + 3).is_err());
}

async fn challenge(
    addr: std::net::SocketAddr,
    auth: &Reply,
    detail: &Value,
    decision: &str,
) -> Reply {
    request(addr,"POST","/authority/v1/approvals/challenges",auth.cookie.as_deref(),auth.body["csrf_token"].as_str(),Some(json!({"plan_id":PLAN,"plan_hash":detail["plan_hash"],"requirements_hash":detail["requirements_hash"],"role":"owner","decision":decision})),ORIGIN).await
}
#[tokio::test]
async fn real_http_review_approve_requires_bound_evidence_and_retains_signature() {
    let f = Fixture::configured(true);
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    assert_eq!(auth.status, 200, "{}", auth.raw);
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(detail.body["review"]["available"], true, "{}", detail.raw);
    assert_eq!(
        detail.body["review"]["before"]["policies"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(detail.body["review"]["after"]["policies"], json!([]));
    let ceremony = challenge(addr, &auth, &detail.body, "approve").await;
    assert_eq!(ceremony.status, 200, "{}", ceremony.raw);
    let assertion = f.key.assertion(&ceremony.body["options"], 2, 0x05, ORIGIN);
    let body = json!({"challenge_id":ceremony.body["challenge"]["challenge_id"],"idempotency_key":IDEMPOTENCY,"assertion":assertion});
    let decision = request(
        addr,
        "POST",
        "/authority/v1/approvals/assertions",
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        Some(body.clone()),
        ORIGIN,
    )
    .await;
    assert_eq!(decision.status, 200, "{}", decision.raw);
    assert_eq!(decision.body["approval"]["decision"], "approve");
    let replay = request(
        addr,
        "POST",
        "/authority/v1/approvals/assertions",
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        Some(body),
        ORIGIN,
    )
    .await;
    assert_eq!(replay.status, 200, "{}", replay.raw);
    assert_eq!(replay.body["replayed"], true);
    assert_eq!(replay.body["approval"], decision.body["approval"]);
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(
        detail.body["current_principal_decisions"][0]["approval"],
        decision.body["approval"]
    );
    assert_eq!(
        detail.body["current_principal_decisions"][0]["current_valid"],
        true
    );
    task.abort();
    let (addr, task) = f.start(NOW + 2).await;
    let auth = login(&f, addr, 3).await;
    assert_eq!(auth.status, 200, "{}", auth.raw);
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(
        detail.body["current_principal_decisions"][0]["approval"],
        decision.body["approval"]
    );
    task.abort();
}
#[tokio::test]
async fn missing_evidence_blocks_approve_but_real_rejection_is_retained() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(
        challenge(addr, &auth, &detail.body, "approve").await.status,
        409
    );
    let ceremony = challenge(addr, &auth, &detail.body, "reject").await;
    assert_eq!(ceremony.status, 200, "{}", ceremony.raw);
    let bad = f.key.assertion(&ceremony.body["options"], 2, 0x01, ORIGIN);
    let body = json!({"challenge_id":ceremony.body["challenge"]["challenge_id"],"idempotency_key":IDEMPOTENCY,"assertion":bad});
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/approvals/assertions",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            Some(body),
            ORIGIN
        )
        .await
        .status,
        409
    );
    let proof = f.key.assertion(&ceremony.body["options"], 2, 0x05, ORIGIN);
    let body = json!({"challenge_id":ceremony.body["challenge"]["challenge_id"],"idempotency_key":IDEMPOTENCY,"assertion":proof});
    let decision = request(
        addr,
        "POST",
        "/authority/v1/approvals/assertions",
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        Some(body),
        ORIGIN,
    )
    .await;
    assert_eq!(decision.status, 200, "{}", decision.raw);
    assert_eq!(decision.body["approval"]["decision"], "reject");
    task.abort();
}

#[tokio::test]
async fn direct_library_challenge_cannot_bypass_http_review_evidence_gate() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let mut store = AuthorityStore::open(&f.db).unwrap();
    let issued = store
        .issue_challenge(
            &AuthorityTenant::new(ORG, PROJECT).unwrap(),
            PRINCIPAL,
            &f.credential_id,
            PLAN,
            ApprovalRole::Owner,
            fw_authority::ApprovalDecision::Approve,
            &WebAuthn::new(ORIGIN).unwrap(),
            NOW + 1,
        )
        .unwrap();
    let assertion = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let body = json!({"challenge_id":issued.challenge.challenge_id(),"idempotency_key":IDEMPOTENCY,"assertion":assertion});
    let response = request(
        addr,
        "POST",
        "/authority/v1/approvals/assertions",
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        Some(body),
        ORIGIN,
    )
    .await;
    assert_eq!(response.status, 409);
    assert_eq!(response.body["reason"], "REVIEW_EVIDENCE_UNAVAILABLE");
    task.abort();
}
#[tokio::test]
async fn current_credential_revocation_denies_plan_and_decision_access() {
    let f = Fixture::configured(true);
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    let ceremony = challenge(addr, &auth, &detail.body, "approve").await;
    assert_eq!(ceremony.status, 200);
    let mut store = AuthorityStore::open(&f.db).unwrap();
    store
        .revoke_credential(
            &AuthorityTenant::new(ORG, PROJECT).unwrap(),
            &f.credential_id,
            NOW + 1,
        )
        .unwrap();
    let body = json!({"challenge_id":ceremony.body["challenge"]["challenge_id"],"idempotency_key":IDEMPOTENCY,"assertion":f.key.assertion(&ceremony.body["options"],2,0x05,ORIGIN)});
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/approvals/assertions",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            Some(body),
            ORIGIN
        )
        .await
        .status,
        401
    );
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            None,
            ORIGIN
        )
        .await
        .status,
        401
    );
    task.abort();
}
#[tokio::test]
async fn hostile_origin_unknown_fields_and_cross_tenant_plan_never_authorize() {
    let f = Fixture::configured(true);
    let (addr, task) = f.start(NOW + 1).await;
    let anonymous = session(addr).await;
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/auth/options",
            anonymous.cookie.as_deref(),
            anonymous.body["csrf_token"].as_str(),
            Some(json!({"profile":"alice","role":"owner"})),
            ORIGIN
        )
        .await
        .status,
        400
    );
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/auth/options",
            anonymous.cookie.as_deref(),
            anonymous.body["csrf_token"].as_str(),
            Some(json!({"profile":"alice"})),
            "http://localhost:8799"
        )
        .await
        .status,
        403
    );
    let auth = login(&f, addr, 1).await;
    let mut store = AuthorityStore::open(&f.db).unwrap();
    let other_tenant = AuthorityTenant::new(ORG, OTHER).unwrap();
    store
        .provision_principal(
            &other_tenant,
            PRINCIPAL,
            "https://identity.example.test",
            "alice",
            NOW,
        )
        .unwrap();
    let (mut other_plan, requirements, _) = plans::complete_plan(NOW);
    other_plan["plan_id"] = json!(OTHER);
    other_plan["project_id"] = json!(OTHER);
    store
        .register_plan(&other_tenant, &other_plan, &requirements, NOW)
        .unwrap();
    let other = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{OTHER}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(other.status, 409);
    assert!(!other.raw.contains("plan_id"));
    let wrong = Authenticator::new(PRINCIPAL);
    let options = request(
        addr,
        "POST",
        "/authority/v1/auth/options",
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        Some(json!({"profile":"alice"})),
        ORIGIN,
    )
    .await;
    let body = json!({"ceremony_id":options.body["ceremony_id"],"assertion":wrong.assertion(&options.body["options"],2,0x05,ORIGIN)});
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/auth/verify",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            Some(body),
            ORIGIN
        )
        .await
        .status,
        401
    );
    task.abort();
}
#[tokio::test]
async fn changed_plan_hash_and_stale_authentication_snapshot_require_new_ceremonies() {
    let f = Fixture::configured(true);
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    let mut changed = detail.body.clone();
    changed["plan_hash"] = json!(fw_contracts::hash_bytes(b"attacker plan"));
    assert_eq!(
        challenge(addr, &auth, &changed, "approve").await.status,
        409
    );
    let ceremony = challenge(addr, &auth, &detail.body, "approve").await;
    assert_eq!(ceremony.status, 200);
    let second = login(&f, addr, 2).await;
    assert_eq!(second.status, 200);
    let body = json!({"challenge_id":ceremony.body["challenge"]["challenge_id"],"idempotency_key":IDEMPOTENCY_2,"assertion":f.key.assertion(&ceremony.body["options"],3,0x05,ORIGIN)});
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/approvals/assertions",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            Some(body),
            ORIGIN
        )
        .await
        .status,
        409
    );
    task.abort();
}
#[tokio::test]
async fn altered_evidence_disables_approval_and_configuration_cannot_create_trust() {
    let mut f = Fixture::configured(true);
    let path = f.config.review_evidence[PLAN].clone();
    let mut bundle: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    bundle["after"]["management_baseline_hash"] =
        json!(fw_contracts::hash_bytes(b"forged review content"));
    std::fs::write(path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(detail.body["review"]["available"], false);
    assert_eq!(
        challenge(addr, &auth, &detail.body, "approve").await.status,
        409
    );
    task.abort();
    f.config.database = f._directory.path().join("missing.sqlite3");
    assert!(Service::open(f.config.clone(), [7; 32], || NOW + 1).is_err());
    assert!(!f.config.database.exists());
    f.config.database = f.db.clone();
    f.config.controller_origin = ORIGIN.into();
    assert!(Service::open(f.config.clone(), [7; 32], || NOW + 1).is_err());
}

#[tokio::test]
async fn exact_host_duplicate_credentials_body_limits_and_logout_are_enforced() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let cookie = auth.cookie.as_ref().unwrap();
    let csrf = auth.body["csrf_token"].as_str().unwrap();
    for extra in [
        "Host: localhost:8787\r\nHost: attacker.invalid\r\n".to_string(),
        "Host: attacker.invalid\r\n".into(),
    ] {
        let wire = format!(
            "GET /authority/v1/session HTTP/1.1\r\n{extra}Origin: {ORIGIN}\r\nConnection: close\r\n\r\n"
        );
        assert!(exchange(addr, &wire).await.status >= 400);
    }
    let duplicated = format!(
        "GET /authority/v1/plans HTTP/1.1\r\nHost: localhost:8787\r\nOrigin: {ORIGIN}\r\nConnection: close\r\nCookie: {cookie}; {cookie}\r\nX-Authority-CSRF: {csrf}\r\n\r\n"
    );
    assert_eq!(exchange(addr, &duplicated).await.status, 400);
    let bootstrap_duplicates = duplicated
        .replace("/authority/v1/plans", "/authority/v1/session")
        .replace(&format!("X-Authority-CSRF: {csrf}\r\n"), "");
    assert_eq!(exchange(addr, &bootstrap_duplicates).await.status, 400);
    let duplicate_json = "{\"profile\":\"alice\",\"profile\":\"alice\"}";
    let wire = format!(
        "POST /authority/v1/auth/options HTTP/1.1\r\nHost: localhost:8787\r\nOrigin: {ORIGIN}\r\nConnection: close\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nX-Authority-CSRF: {csrf}\r\nContent-Length: {}\r\n\r\n{duplicate_json}",
        duplicate_json.len()
    );
    assert_eq!(exchange(addr, &wire).await.status, 400);
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/auth/options",
            Some(cookie),
            Some(csrf),
            Some(json!({"profile":"a".repeat(70000)})),
            ORIGIN
        )
        .await
        .status,
        400
    );
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans?token=never-accepted",
            Some(cookie),
            Some(csrf),
            None,
            ORIGIN
        )
        .await
        .status,
        400
    );
    let logout = request(
        addr,
        "POST",
        "/authority/v1/logout",
        Some(cookie),
        Some(csrf),
        Some(json!({})),
        ORIGIN,
    )
    .await;
    assert_eq!(logout.status, 200);
    assert_eq!(logout.body["authenticated"], false);
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            Some(cookie),
            Some(csrf),
            None,
            ORIGIN
        )
        .await
        .status,
        401
    );
    task.abort();
}
#[tokio::test]
async fn session_and_ceremony_absolute_expiries_are_checked_on_every_request() {
    use std::sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    };
    let f = Fixture::configured(true);
    let now = Arc::new(AtomicI64::new(NOW + 1));
    let clock = now.clone();
    let service = Service::open(f.config.clone(), [7; 32], move || {
        clock.load(Ordering::SeqCst)
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, service.router()).await.unwrap() });
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    let ceremony = challenge(addr, &auth, &detail.body, "approve").await;
    now.store(NOW + 302, Ordering::SeqCst);
    let body = json!({"challenge_id":ceremony.body["challenge"]["challenge_id"],"idempotency_key":IDEMPOTENCY,"assertion":f.key.assertion(&ceremony.body["options"],2,0x05,ORIGIN)});
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/approvals/assertions",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            Some(body),
            ORIGIN
        )
        .await
        .status,
        409
    );
    let options = request(
        addr,
        "POST",
        "/authority/v1/auth/options",
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        Some(json!({"profile":"alice"})),
        ORIGIN,
    )
    .await;
    now.store(NOW + 603, Ordering::SeqCst);
    let body = json!({"ceremony_id":options.body["ceremony_id"],"assertion":f.key.assertion(&options.body["options"],2,0x05,ORIGIN)});
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/auth/verify",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            Some(body),
            ORIGIN
        )
        .await
        .status,
        401
    );
    now.store(NOW + 902, Ordering::SeqCst);
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            None,
            ORIGIN
        )
        .await
        .status,
        401
    );
    task.abort();
}

#[tokio::test]
async fn queued_request_uses_current_clock_after_waiting_for_authority_work() {
    use std::sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    };
    let f = Fixture::configured(true);
    let now = Arc::new(AtomicI64::new(NOW + 1));
    let clock = now.clone();
    let service = Service::open(f.config.clone(), [7; 32], move || {
        clock.load(Ordering::SeqCst)
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, service.router()).await.unwrap() });
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    let db = rusqlite::Connection::open(&f.db).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let first_cookie = auth.cookie.clone();
    let first_csrf = auth.body["csrf_token"].as_str().unwrap().to_string();
    let body = json!({"plan_id":PLAN,"plan_hash":detail.body["plan_hash"],"requirements_hash":detail.body["requirements_hash"],"role":"owner","decision":"approve"});
    let first = tokio::spawn(async move {
        request(
            addr,
            "POST",
            "/authority/v1/approvals/challenges",
            first_cookie.as_deref(),
            Some(&first_csrf),
            Some(body),
            ORIGIN,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let second_cookie = auth.cookie.clone();
    let second_csrf = auth.body["csrf_token"].as_str().unwrap().to_string();
    let second = tokio::spawn(async move {
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            second_cookie.as_deref(),
            Some(&second_csrf),
            None,
            ORIGIN,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !first.is_finished(),
        "write must be waiting for SQLite lock"
    );
    assert!(
        !second.is_finished(),
        "read must be queued behind authority work"
    );
    now.store(NOW + 1000, Ordering::SeqCst);
    db.execute_batch("ROLLBACK").unwrap();
    first.await.unwrap();
    let late = second.await.unwrap();
    assert_eq!(late.status, 401, "queued session must expire: {}", late.raw);
    task.abort();
}

#[tokio::test]
async fn unauthenticated_session_flood_cannot_prevent_real_owner_login() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    for _ in 0..180 {
        let _ = session(addr).await;
    }
    let auth = login(&f, addr, 1).await;
    assert_eq!(
        auth.status, 200,
        "real owner must survive anonymous session flood: {}",
        auth.raw
    );
    task.abort();
}
#[tokio::test]
async fn unauthenticated_activation_options_cannot_exhaust_durable_key_capacity() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    for _ in 0..4 {
        let binding = session(addr).await;
        for _ in 0..10 {
            let _ = request(
                addr,
                "POST",
                "/authority/v1/auth/options",
                binding.cookie.as_deref(),
                binding.body["csrf_token"].as_str(),
                Some(json!({"profile":"alice"})),
                ORIGIN,
            )
            .await;
        }
    }
    let auth = login(&f, addr, 1).await;
    assert_eq!(
        auth.status, 200,
        "real possession proof must survive anonymous option flood: {}",
        auth.raw
    );
    let db = rusqlite::Connection::open(&f.db).unwrap();
    let pending: i64 = db
        .query_row(
            "SELECT count(*) FROM authority_activations WHERE consumed_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        pending, 0,
        "anonymous requests must not reserve durable key capacity"
    );
    task.abort();
}
#[tokio::test]
async fn unauthenticated_bootstrap_cannot_logout_cookie_owner_without_csrf() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let fresh = request(
        addr,
        "GET",
        "/authority/v1/session",
        auth.cookie.as_deref(),
        None,
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(fresh.status, 200);
    assert_eq!(fresh.body["authenticated"], false);
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            None,
            ORIGIN
        )
        .await
        .status,
        200
    );
    for _ in 0..180 {
        let _ = session(addr).await;
    }
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            None,
            ORIGIN
        )
        .await
        .status,
        200
    );
    task.abort();
}

#[tokio::test]
async fn invalid_login_proof_flood_has_bounded_audit_without_locking_owner_out() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let binding = session(addr).await;
    let options = request(
        addr,
        "POST",
        "/authority/v1/auth/options",
        binding.cookie.as_deref(),
        binding.body["csrf_token"].as_str(),
        Some(json!({"profile":"alice"})),
        ORIGIN,
    )
    .await;
    let invalid = json!({"ceremony_id":options.body["ceremony_id"],"assertion":f.key.assertion(&options.body["options"],2,0x01,ORIGIN)});
    for _ in 0..40 {
        assert_eq!(
            request(
                addr,
                "POST",
                "/authority/v1/auth/verify",
                binding.cookie.as_deref(),
                binding.body["csrf_token"].as_str(),
                Some(invalid.clone()),
                ORIGIN
            )
            .await
            .status,
            401
        );
    }
    let db = rusqlite::Connection::open(&f.db).unwrap();
    let failures: i64 = db
        .query_row(
            "SELECT count(*) FROM authority_audit WHERE kind='review_login_failed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        failures, 1,
        "public invalid proofs must not cause per-attempt persistent audit growth"
    );
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            None,
            ORIGIN
        )
        .await
        .status,
        200
    );
    let valid = json!({"ceremony_id":options.body["ceremony_id"],"assertion":f.key.assertion(&options.body["options"],2,0x05,ORIGIN)});
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/auth/verify",
            binding.cookie.as_deref(),
            binding.body["csrf_token"].as_str(),
            Some(valid),
            ORIGIN
        )
        .await
        .status,
        200
    );
    task.abort();
}

#[tokio::test]
async fn encrypted_login_tickets_bind_browser_reject_tampering_and_replay() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    let a = session(addr).await;
    let b = session(addr).await;
    let options = request(
        addr,
        "POST",
        "/authority/v1/auth/options",
        a.cookie.as_deref(),
        a.body["csrf_token"].as_str(),
        Some(json!({"profile":"alice"})),
        ORIGIN,
    )
    .await;
    let proof = f.key.assertion(&options.body["options"], 0, 0x05, ORIGIN);
    let body = json!({"ceremony_id":options.body["ceremony_id"],"assertion":proof});
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/auth/verify",
            b.cookie.as_deref(),
            b.body["csrf_token"].as_str(),
            Some(body.clone()),
            ORIGIN
        )
        .await
        .status,
        401
    );
    let mut altered = body.clone();
    let mut ticket = altered["ceremony_id"].as_str().unwrap().as_bytes().to_vec();
    ticket[30] = if ticket[30] == b'A' { b'B' } else { b'A' };
    altered["ceremony_id"] = json!(String::from_utf8(ticket).unwrap());
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/auth/verify",
            a.cookie.as_deref(),
            a.body["csrf_token"].as_str(),
            Some(altered),
            ORIGIN
        )
        .await
        .status,
        401
    );
    let auth = request(
        addr,
        "POST",
        "/authority/v1/auth/verify",
        a.cookie.as_deref(),
        a.body["csrf_token"].as_str(),
        Some(body.clone()),
        ORIGIN,
    )
    .await;
    assert_eq!(auth.status, 200, "{}", auth.raw);
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/auth/verify",
            a.cookie.as_deref(),
            a.body["csrf_token"].as_str(),
            Some(body.clone()),
            ORIGIN
        )
        .await
        .status,
        401
    );
    task.abort();
    let (addr, task) = f.start(NOW + 2).await;
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/auth/verify",
            a.cookie.as_deref(),
            a.body["csrf_token"].as_str(),
            Some(body),
            ORIGIN
        )
        .await
        .status,
        401
    );
    task.abort();
}
#[tokio::test]
async fn fresh_proven_logins_replace_old_own_sessions_without_capacity_lockout() {
    let f = Fixture::new();
    let (addr, task) = f.start(NOW + 1).await;
    let first = login(&f, addr, 1).await;
    assert_eq!(first.status, 200);
    let mut last = first.body.clone();
    let mut cookie = first.cookie.clone();
    for counter in 2..=12 {
        let auth = login(&f, addr, counter).await;
        assert_eq!(auth.status, 200, "reload {counter}: {}", auth.raw);
        last = auth.body;
        cookie = auth.cookie;
    }
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            cookie.as_deref(),
            last["csrf_token"].as_str(),
            None,
            ORIGIN
        )
        .await
        .status,
        200
    );
    assert_eq!(
        request(
            addr,
            "GET",
            "/authority/v1/plans",
            first.cookie.as_deref(),
            first.body["csrf_token"].as_str(),
            None,
            ORIGIN
        )
        .await
        .status,
        401
    );
    task.abort();
}

#[tokio::test]
async fn oversized_trusted_review_is_not_truncated_or_approved() {
    let mut f = Fixture::configured(true);
    let (mut plan, requirements, mut evidence) = plans::complete_plan(NOW);
    let new_id = "77777777-7777-4777-8777-777777777777";
    let template = evidence.before.policies[0].clone();
    let association = evidence.before.associations[0].clone();
    for index in 0..30u32 {
        let mut policy = template.clone();
        policy.policy_id = format!("88888888-8888-4888-8888-{index:012}");
        policy.reason = "界".repeat(1900);
        let mut link = association.clone();
        link.policy_hash = fw_contracts::canonical_hash(&policy).unwrap();
        evidence.before.policies.push(policy);
        evidence.before.associations.push(link);
    }
    evidence.before = evidence.before.normalized().unwrap();
    let operations: Vec<fw_planner::PolicyMutation> =
        serde_json::from_value(plan["operations"].clone()).unwrap();
    let candidate = fw_planner::compose_policy_change(
        &evidence.before,
        &operations,
        &[],
        &std::collections::BTreeSet::new(),
    )
    .unwrap();
    assert!(candidate.semantic_complete);
    plan["plan_id"] = json!(new_id);
    plan["baseline_hash"] = json!(candidate.baseline_hash);
    plan["desired_state_hash"] = json!(candidate.desired_state_hash);
    plan["candidate_state_ref"]["object_hash"] = json!(candidate.desired_state_hash);
    plan["candidate_state_ref"]["size_bytes"] = json!(
        fw_contracts::canonical_bytes(&candidate.state)
            .unwrap()
            .len()
    );
    plan["rollback_authority"]["baseline_hash"] = plan["baseline_hash"].clone();
    plan["effect_summary"]["relation"] = serde_json::to_value(candidate.relation).unwrap();
    plan["effect_summary"]["newly_allowed_region_hash"] =
        json!(candidate.semantic_diff.newly_allowed_region_hash);
    plan["effect_summary"]["removed_region_hash"] =
        json!(candidate.semantic_diff.removed_region_hash);
    evidence.after = candidate.state;
    let bytes = serde_json::to_vec(&evidence).unwrap();
    assert!(bytes.len() > 256 * 1024);
    let path = f._directory.path().join("large-review.json");
    write_new_private_fixture(&path, &bytes);
    f.config.review_evidence.insert(new_id.into(), path);
    let mut store = AuthorityStore::open(&f.db).unwrap();
    store
        .register_plan(
            &AuthorityTenant::new(ORG, PROJECT).unwrap(),
            &plan,
            &requirements,
            NOW,
        )
        .unwrap();
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{new_id}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(detail.status, 200);
    assert_eq!(detail.body["review"]["available"], false);
    assert!(detail.raw.len() < 256 * 1024);
    let request_body = json!({"plan_id":new_id,"plan_hash":detail.body["plan_hash"],"requirements_hash":detail.body["requirements_hash"],"role":"owner","decision":"approve"});
    assert_eq!(
        request(
            addr,
            "POST",
            "/authority/v1/approvals/challenges",
            auth.cookie.as_deref(),
            auth.body["csrf_token"].as_str(),
            Some(request_body),
            ORIGIN
        )
        .await
        .status,
        409
    );
    task.abort();
}

#[tokio::test]
async fn unconfigured_authority_is_explicit_before_and_after_recording_a_decision() {
    let f = Fixture::configured(true);
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(detail.status, 200);
    assert_eq!(
        detail.body["aggregation"],
        json!({"state":"authority_unavailable"})
    );
    assert_eq!(detail.body["current_approval_set"], Value::Null);
    let ceremony = challenge(addr, &auth, &detail.body, "approve").await;
    let body = json!({"challenge_id":ceremony.body["challenge"]["challenge_id"],"idempotency_key":IDEMPOTENCY,"assertion":f.key.assertion(&ceremony.body["options"],2,0x05,ORIGIN)});
    let decision = request(
        addr,
        "POST",
        "/authority/v1/approvals/assertions",
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        Some(body),
        ORIGIN,
    )
    .await;
    assert_eq!(decision.status, 200);
    assert_eq!(decision.body["approval"]["decision"], "approve");
    assert_eq!(
        decision.body["aggregation"],
        json!({"state":"authority_unavailable"})
    );
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(
        detail.body["aggregation"],
        json!({"state":"authority_unavailable"})
    );
    assert_eq!(detail.body["current_approval_set"], Value::Null);
    task.abort();
}

fn provision_test_quorum(f: &Fixture, epoch: u64, valid_until: i64, now: i64) {
    let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
    let mut store = AuthorityStore::open(&f.db).unwrap();
    // Trusted fixture configuration, deliberately independent of submitted plans.
    store
        .provision_authority_basis(
            &tenant,
            &fw_authority::AuthorityBasis {
                epoch,
                role_policy_hash: fw_contracts::hash_bytes(b"independently configured role policy"),
                not_before: NOW,
                not_after: valid_until,
            },
            now,
        )
        .unwrap();
    store
        .bind_human_identity(
            &tenant,
            PRINCIPAL,
            "aaaaaaaa-0000-4000-8000-000000000001",
            now,
        )
        .unwrap();
}
async fn submit_http_decision(
    f: &Fixture,
    addr: std::net::SocketAddr,
    auth: &Reply,
    detail: &Value,
    decision: &str,
    counter: u32,
    key: &str,
) -> (Reply, Value) {
    let ceremony = challenge(addr, auth, detail, decision).await;
    assert_eq!(ceremony.status, 200, "{}", ceremony.raw);
    let body = json!({"challenge_id":ceremony.body["challenge"]["challenge_id"],"idempotency_key":key,"assertion":f.key.assertion(&ceremony.body["options"],counter,0x05,ORIGIN)});
    let response = request(
        addr,
        "POST",
        "/authority/v1/approvals/assertions",
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        Some(body.clone()),
        ORIGIN,
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.raw);
    (response, body)
}
#[tokio::test]
async fn verified_current_set_and_historical_replay_are_separate_after_basis_rotation() {
    let f = Fixture::configured(true);
    provision_test_quorum(&f, 1, NOW + 7200, NOW);
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(detail.body["aggregation"], json!({"state":"pending"}));
    assert_eq!(detail.body["current_approval_set"], Value::Null);
    let (decision, body) =
        submit_http_decision(&f, addr, &auth, &detail.body, "approve", 2, IDEMPOTENCY).await;
    assert_eq!(decision.body["aggregation"]["state"], "approved");
    let approved = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(approved.body["aggregation"], decision.body["aggregation"]);
    let current = &approved.body["current_approval_set"];
    assert_eq!(
        current["hash"],
        decision.body["aggregation"]["approval_set_hash"]
    );
    assert_eq!(current["content"]["schema_version"], "f.approval-set/v1");
    assert_eq!(current["content"]["plan_ref"]["plan_id"], PLAN);
    assert_eq!(
        current["content"]["approvals"],
        json!([decision.body["approval"].clone()])
    );
    assert_eq!(current["valid_until"], current["content"]["valid_until"]);
    let reauthenticated = login(&f, addr, 3).await;
    assert_eq!(reauthenticated.status, 200);
    let after_login = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        reauthenticated.cookie.as_deref(),
        reauthenticated.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(
        after_login.body["current_approval_set"], *current,
        "a legitimate later passkey counter must preserve the original verified set"
    );
    task.abort();
    provision_test_quorum(&f, 2, NOW + 7200, NOW + 2);
    let (addr, task) = f.start(NOW + 3).await;
    let auth = login(&f, addr, 4).await;
    let replay = request(
        addr,
        "POST",
        "/authority/v1/approvals/assertions",
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        Some(body),
        ORIGIN,
    )
    .await;
    assert_eq!(replay.status, 200);
    assert_eq!(replay.body["replayed"], true);
    assert_eq!(replay.body["aggregation"], decision.body["aggregation"]);
    let stale = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(stale.body["aggregation"], json!({"state":"stale"}));
    assert_eq!(stale.body["current_approval_set"], Value::Null);
    task.abort();
}
#[tokio::test]
async fn terminal_dissent_remains_blocked_after_a_later_signed_approval() {
    let f = Fixture::configured(true);
    provision_test_quorum(&f, 1, NOW + 7200, NOW);
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    let (rejected, _) =
        submit_http_decision(&f, addr, &auth, &detail.body, "reject", 2, IDEMPOTENCY).await;
    assert_eq!(
        rejected.body["aggregation"],
        json!({"state":"blocked_by_dissent"})
    );
    let (approved, _) =
        submit_http_decision(&f, addr, &auth, &detail.body, "approve", 3, IDEMPOTENCY_2).await;
    assert_eq!(approved.body["approval"]["decision"], "approve");
    assert_eq!(
        approved.body["aggregation"],
        json!({"state":"blocked_by_dissent"})
    );
    let blocked = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(
        blocked.body["aggregation"],
        json!({"state":"blocked_by_dissent"})
    );
    assert_eq!(blocked.body["current_approval_set"], Value::Null);
    task.abort();
}
#[tokio::test]
async fn current_set_disappears_when_independent_authority_basis_expires() {
    let f = Fixture::configured(true);
    provision_test_quorum(&f, 1, NOW + 10, NOW);
    let (addr, task) = f.start(NOW + 1).await;
    let auth = login(&f, addr, 1).await;
    let detail = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    submit_http_decision(&f, addr, &auth, &detail.body, "approve", 2, IDEMPOTENCY).await;
    let current = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(
        current.body["current_approval_set"]["valid_until"],
        time(NOW + 10)
    );
    task.abort();
    let (addr, task) = f.start(NOW + 11).await;
    let auth = login(&f, addr, 3).await;
    let expired = request(
        addr,
        "GET",
        &format!("/authority/v1/plans/{PLAN}"),
        auth.cookie.as_deref(),
        auth.body["csrf_token"].as_str(),
        None,
        ORIGIN,
    )
    .await;
    assert_eq!(expired.body["aggregation"], json!({"state":"stale"}));
    assert_eq!(expired.body["current_approval_set"], Value::Null);
    task.abort();
}

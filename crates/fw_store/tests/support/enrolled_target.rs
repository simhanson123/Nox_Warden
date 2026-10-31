//! Synthetic certificate output for repository-boundary tests only; no signing key.
use chrono::{DateTime, SecondsFormat, Utc};
use fw_contracts::hash_bytes;
use fw_store::enrollment::EnrollmentAttempt;
use fw_store::{Store, Tenant};
use serde_json::Value;
use uuid::Uuid;
fn id() -> String {
    Uuid::new_v4().to_string()
}
fn time(t: i64) -> String {
    DateTime::<Utc>::from_timestamp(t, 0)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}
fn hash() -> String {
    hash_bytes(id().as_bytes())
}
pub fn enrolled(store: &Store, t: &Tenant, p: &str, at: i64) -> (String, String) {
    let key = hash();
    let token = hash();
    let body = serde_json::json!({"name":format!("Host {}",id()),"platform":"linux","expected_key_fingerprint":key,"token_hash":token});
    store
        .create_enrollment_token(t, p, &body, &id(), at)
        .unwrap();
    let attempt = EnrollmentAttempt {
        token_hash: token,
        csr_hash: hash(),
        key_fingerprint: key,
        platform: "linux".into(),
        request_id: id(),
        nonce: hash()[7..].into(),
        agent_version: "0.1.0".into(),
    };
    let job = store.reserve_enrollment(&attempt, at).unwrap();
    let response = serde_json::json!({"schema_version":"f.enrollment-response/v1","request_id":job.request_id,"target_id":job.target_id,"certificate_chain_pem":format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n","A".repeat(192)),"trust_bundle_hash":hash_bytes(b"test root"),"authority_epoch":"0","issued_at":time(at),"expires_at":time(at+86400),"renew_after":time(at+28800),"mode":"observe"});
    let fp = hash();
    store
        .complete_enrollment(&job.job_id, &fp, &response, at)
        .unwrap();
    let identity = store.authenticate_enrollment(&fp, at).unwrap();
    store
        .save_target_capability(&identity, &capability(&job.target_id, at), at)
        .unwrap();
    (job.target_id, fp)
}
pub fn capability(target: &str, checked: i64) -> Value {
    let features = [
        "timed_allow",
        "persistent_deny",
        "strict_current_union",
        "atomic_apply",
        "semantic_readback",
        "writer_fencing",
        "independent_watchdog",
        "new_management_probe",
        "interface_scope",
        "process_binding",
        "independent_expiry",
        "boot_guard",
        "crash_fail_closed",
        "absolute_deadline_guard",
    ];
    let features=features.iter().map(|name|(name.to_string(),serde_json::json!({"state":"unverified","reason_code":"QUALIFICATION_REQUIRED","evidence_hash":null}))).collect::<serde_json::Map<_,_>>();
    serde_json::json!({"schema_version":"f.target-capability/v1","target_id":target,"platform":"linux","enforcement_backend":"nftables","capability_version":"f.target-capability/v1","os_version":"test Linux","backend_version":"unverified","executor_build_hash":hash_bytes(b"fixture executable"),"checked_at":time(checked),"valid_until":time(checked+300),"profiles":[],"families":["ipv4","ipv6"],"directions":["input","output"],"protocols":["tcp","udp"],"binding_kinds":["host"],"features":features,"max_policies":1,"max_rules":1,"max_artifact_bytes":1,"qualification_profiles":[],"interfaces":[]})
}

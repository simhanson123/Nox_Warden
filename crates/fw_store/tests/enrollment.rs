//! Repository-boundary tests. PEM strings below are synthetic CA results; real CSR/TLS
//! verification is tested in the enrollment crypto and live transport suites.
use chrono::{DateTime, SecondsFormat, Utc};
use fw_contracts::{canonical_bytes, hash_bytes};
use fw_store::enrollment::{EnrollmentAttempt, EnrollmentReservation};
use fw_store::{Store, StoreError, Tenant};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::sync::{Arc, Barrier};
use uuid::Uuid;
const NOW: i64 = 1_800_000_000;
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
fn prepare(store: &Store) -> (Tenant, String) {
    let t = store
        .ensure_tenant(&id(), &id(), "Enrollment tests", NOW)
        .unwrap();
    let p = id();
    store.ensure_principal(&t, &p, "human", NOW).unwrap();
    (t, p)
}
fn token(store: &Store, t: &Tenant, p: &str) -> (Value, EnrollmentAttempt) {
    token_at(store, t, p, NOW)
}
fn token_at(store: &Store, t: &Tenant, p: &str, at: i64) -> (Value, EnrollmentAttempt) {
    let key = hash();
    let token_hash = hash();
    let body = json!({"name":"Test host","platform":"linux","expected_key_fingerprint":key,"token_hash":token_hash});
    let value = store
        .create_enrollment_token(t, p, &body, &id(), at)
        .unwrap()
        .value;
    (
        value,
        EnrollmentAttempt {
            token_hash,
            csr_hash: hash(),
            key_fingerprint: key,
            platform: "linux".into(),
            request_id: id(),
            nonce: hash()[7..].to_owned(),
            agent_version: "0.1.0".into(),
        },
    )
}
fn response(job: &EnrollmentReservation) -> Value {
    json!({"schema_version":"f.enrollment-response/v1","request_id":job.request_id,"target_id":job.target_id,"certificate_chain_pem":format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n","A".repeat(192)),"trust_bundle_hash":hash_bytes(b"test root"),"authority_epoch":"0","issued_at":time(job.issued_at),"expires_at":time(job.issued_at+86400),"renew_after":time(job.issued_at+28800),"mode":"observe"})
}
fn enrolled(store: &Store, t: &Tenant, p: &str) -> (String, String, EnrollmentAttempt, Value) {
    enrolled_at(store, t, p, NOW)
}
fn enrolled_at(
    store: &Store,
    t: &Tenant,
    p: &str,
    at: i64,
) -> (String, String, EnrollmentAttempt, Value) {
    let (_, attempt) = token_at(store, t, p, at);
    let job = store.reserve_enrollment(&attempt, at + 1).unwrap();
    let value = response(&job);
    let fp = hash();
    store
        .complete_enrollment(&job.job_id, &fp, &value, at + 2)
        .unwrap();
    (job.target_id, fp, attempt, value)
}
fn capability(target: &str, checked: i64) -> Value {
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
    let features=features.iter().map(|name|(name.to_string(),json!({"state":"unverified","reason_code":"QUALIFICATION_REQUIRED","evidence_hash":null}))).collect::<serde_json::Map<_,_>>();
    json!({"schema_version":"f.target-capability/v1","target_id":target,"platform":"linux","enforcement_backend":"nftables","capability_version":"f.target-capability/v1","os_version":"test Linux","backend_version":"unverified","executor_build_hash":hash_bytes(b"fixture executable"),"checked_at":time(checked),"valid_until":time(checked+300),"profiles":[],"families":["ipv4","ipv6"],"directions":["input","output"],"protocols":["tcp","udp"],"binding_kinds":["host"],"features":features,"max_policies":1,"max_rules":1,"max_artifact_bytes":1,"qualification_profiles":[],"interfaces":[]})
}

#[test]
fn token_registration_is_private_tenant_bound_and_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    let raw_token = "synthetic-secret-do-not-store";
    let body = json!({"name":"Test host","platform":"linux","expected_key_fingerprint":hash(),"token_hash":hash_bytes(raw_token.as_bytes())});
    let key = id();
    let first = store
        .create_enrollment_token(&t, &p, &body, &key, NOW)
        .unwrap();
    let retry = store
        .create_enrollment_token(&t, &p, &body, &key, NOW + 500)
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(first.value, retry.value);
    assert_eq!(first.value["expires_at"], time(NOW + 600));
    assert_eq!(first.value["status"], "unused");
    assert!(first.value.get("token").is_none());
    let mut changed = body.clone();
    changed["name"] = "Other".into();
    assert!(matches!(
        store.create_enrollment_token(&t, &p, &changed, &key, NOW + 1),
        Err(StoreError::IdempotencyConflict)
    ));
    let (another, other_p) = prepare(&store);
    assert!(matches!(
        store.create_enrollment_token(&another, &other_p, &body, &id(), NOW),
        Err(StoreError::Conflict(_))
    ));
    let raw = Connection::open(path).unwrap();
    let saved: String = raw
        .query_row("SELECT token_hash FROM enrollment_tokens", [], |r| r.get(0))
        .unwrap();
    assert_eq!(saved, body["token_hash"]);
    let bytes: Vec<u8> = raw
        .query_row("SELECT response_bytes FROM enrollment_tokens", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains(raw_token));
    assert_eq!(store.count_enrollments(&t).unwrap(), 0);
    assert_eq!(store.count_targets(&t).unwrap(), 0);
}
#[test]
fn reservations_bind_csr_request_nonce_platform_key_and_deadline() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let (_, attempt) = token(&store, &t, &p);
    let job = store.reserve_enrollment(&attempt, NOW + 10).unwrap();
    assert_eq!(
        store.reserve_enrollment(&attempt, NOW + 11).unwrap().job_id,
        job.job_id
    );
    for field in 0..6 {
        let mut bad = attempt.clone();
        match field {
            0 => bad.csr_hash = hash(),
            1 => bad.request_id = id(),
            2 => bad.nonce = hash()[7..].into(),
            3 => bad.agent_version = "0.2.0".into(),
            4 => bad.platform = "windows".into(),
            _ => bad.key_fingerprint = hash(),
        };
        assert!(store.reserve_enrollment(&bad, NOW + 11).is_err());
    }
    assert!(store.reserve_enrollment(&attempt, NOW - 1).is_err());
    assert!(matches!(
        store.reserve_enrollment(&attempt, NOW + 2),
        Err(StoreError::Conflict("ENROLLMENT_CLOCK_REGRESSED"))
    ));
    assert!(store.reserve_enrollment(&attempt, NOW + 600).is_err());
    assert!(store
        .complete_enrollment(&job.job_id, &hash(), &response(&job), NOW + 600)
        .is_err());
}
#[test]
fn expired_reservation_stays_bound_without_blocking_a_new_invitation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let store = Store::open(&path).unwrap();
    let (tenant, principal) = prepare(&store);
    let (_, abandoned) = token(&store, &tenant, &principal);
    let reservation = store.reserve_enrollment(&abandoned, NOW + 1).unwrap();
    drop(store);

    let store = Store::open(&path).unwrap();
    let deadline = NOW + 600;
    assert!(matches!(
        store.reserve_enrollment(&abandoned, deadline),
        Err(StoreError::Conflict("ENROLLMENT_EXPIRED"))
    ));
    assert!(matches!(
        store.complete_enrollment(
            &reservation.job_id,
            &hash(),
            &response(&reservation),
            deadline
        ),
        Err(StoreError::Conflict("ENROLLMENT_EXPIRED"))
    ));
    let (_, fresh) = token_at(&store, &tenant, &principal, deadline);
    let new_job = store.reserve_enrollment(&fresh, deadline + 1).unwrap();
    let fingerprint = hash();
    store
        .complete_enrollment(
            &new_job.job_id,
            &fingerprint,
            &response(&new_job),
            deadline + 2,
        )
        .unwrap();
    let identity = store
        .authenticate_enrollment(&fingerprint, deadline + 2)
        .unwrap();
    assert_eq!(identity.target_id, new_job.target_id);
    assert_ne!(identity.target_id, reservation.target_id);
    assert_eq!(store.count_enrollments(&tenant).unwrap(), 1);
    // The target catalogue requires a current capability report as well.
    assert_eq!(store.count_targets(&tenant).unwrap(), 0);
    let raw = Connection::open(&path).unwrap();
    let retained: (String, String, Option<Vec<u8>>) = raw
        .query_row(
            "SELECT request_id,nonce,response_bytes FROM enrollment_jobs WHERE job_id=?1",
            [&reservation.job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(retained, (abandoned.request_id, abandoned.nonce, None));
}
#[test]
fn concurrent_csr_reservations_have_one_winner_and_recover_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    let (_, attempt) = token(&store, &t, &p);
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|index| {
            let path = path.clone();
            let barrier = barrier.clone();
            let mut candidate = attempt.clone();
            if index % 2 == 1 {
                candidate.csr_hash = hash_bytes(b"competing CSR");
            }
            std::thread::spawn(move || {
                let store = Store::open(path).unwrap();
                barrier.wait();
                store
                    .reserve_enrollment(&candidate, NOW + 1)
                    .map(|job| (job.job_id, job.csr_hash))
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|x| x.join().unwrap()).collect();
    let successes: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(successes.len(), 4);
    assert!(successes.windows(2).all(|w| w[0] == w[1]));
    let winner = successes[0].clone();
    drop(store);
    let recovered = Store::open(&path).unwrap();
    let mut retry = attempt;
    retry.csr_hash = winner.1.clone();
    assert_eq!(
        recovered
            .reserve_enrollment(&retry, NOW + 2)
            .unwrap()
            .job_id,
        winner.0
    );
    let raw = Connection::open(path).unwrap();
    assert_eq!(
        raw.query_row("SELECT count(*) FROM enrollment_jobs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn completion_retries_same_certificate_without_promoting_enforcement() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let (_, attempt) = token(&store, &t, &p);
    let job = store.reserve_enrollment(&attempt, NOW + 1).unwrap();
    let cert = response(&job);
    let fp = hash();
    let first = store
        .complete_enrollment(&job.job_id, &fp, &cert, NOW + 2)
        .unwrap();
    let count = store.count_audit(&t, 0).unwrap();
    assert_eq!(
        store
            .complete_enrollment(&job.job_id, &fp, &cert, NOW + 3)
            .unwrap(),
        first
    );
    assert_eq!(store.count_audit(&t, 0).unwrap(), count);
    assert_eq!(
        store
            .reserve_enrollment(&attempt, NOW + 3)
            .unwrap()
            .response,
        Some(first)
    );
    assert!(store
        .complete_enrollment(&job.job_id, &hash(), &cert, NOW + 3)
        .is_err());
    let mut altered = cert;
    altered["certificate_chain_pem"] = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        "B".repeat(192)
    )
    .into();
    assert!(store
        .complete_enrollment(&job.job_id, &fp, &altered, NOW + 3)
        .is_err());
    let records = store.list_enrollments(&t, 10, NOW + 3).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["state"], "observe_only");
    assert!(records[0]["capability_hash"].is_null());
    assert!(store.list_targets(&t, 10, NOW + 3).unwrap().is_empty());
    assert_eq!(
        store
            .authenticate_enrollment(&fp, NOW + 3)
            .unwrap()
            .target_id,
        job.target_id
    );
}
#[test]
fn completion_rejects_target_epoch_mode_and_time_substitution() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let (_, attempt) = token(&store, &t, &p);
    let job = store.reserve_enrollment(&attempt, NOW + 1).unwrap();
    let cert = response(&job);
    for (key, value) in [
        ("request_id", json!(id())),
        ("target_id", json!(id())),
        ("authority_epoch", json!("1")),
        ("mode", json!("enforce")),
        ("issued_at", json!(time(NOW + 2))),
        ("expires_at", json!(time(NOW + 86402))),
        ("renew_after", json!(time(NOW + 1))),
    ] {
        let mut bad = cert.clone();
        bad[key] = value;
        assert!(
            store
                .complete_enrollment(&job.job_id, &hash(), &bad, NOW + 2)
                .is_err(),
            "{key}"
        );
    }
    assert_eq!(store.count_enrollments(&t).unwrap(), 0);
}
#[test]
fn audit_failure_rolls_back_certificate_token_target_and_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    let (_, attempt) = token(&store, &t, &p);
    let job = store.reserve_enrollment(&attempt, NOW + 1).unwrap();
    let cert = response(&job);
    let raw = Connection::open(path).unwrap();
    let before: i64 = raw
        .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
        .unwrap();
    raw.execute_batch("CREATE TRIGGER reject_completion BEFORE INSERT ON audit_events WHEN NEW.event_type='registry' AND NEW.resource_kind='target' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(store
        .complete_enrollment(&job.job_id, &hash(), &cert, NOW + 2)
        .is_err());
    assert_eq!(store.count_enrollments(&t).unwrap(), 0);
    assert_eq!(
        raw.query_row("SELECT state FROM enrollment_tokens", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "reserved"
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM targets", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before
    );
    raw.execute_batch("DROP TRIGGER reject_completion").unwrap();
    let audit_before = store.count_audit(&t, 0).unwrap();
    raw.execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON outbox WHEN NEW.event_kind='target.enrolled' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(store
        .complete_enrollment(&job.job_id, &hash(), &cert, NOW + 3)
        .is_err());
    assert_eq!(store.count_audit(&t, 0).unwrap(), audit_before);
    assert_eq!(store.count_enrollments(&t).unwrap(), 0);
    assert!(store
        .reserve_enrollment(&attempt, NOW + 3)
        .unwrap()
        .response
        .is_none());
    raw.execute_batch("DROP TRIGGER reject_outbox").unwrap();
    store
        .complete_enrollment(&job.job_id, &hash(), &cert, NOW + 3)
        .unwrap();
}
#[test]
fn revoked_and_expired_credentials_cannot_report_or_reenroll() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let (target, fp, attempt, _) = enrolled(&store, &t, &p);
    let identity = store.authenticate_enrollment(&fp, NOW + 3).unwrap();
    let cap = capability(&target, NOW + 3);
    store
        .save_target_capability(&identity, &cap, NOW + 3)
        .unwrap();
    let revoked = store.revoke_enrollment(&t, &p, &target, NOW + 4).unwrap();
    assert_eq!(revoked["revoked"], true);
    assert_eq!(revoked["state"], "quarantined");
    let count = store.count_audit(&t, 0).unwrap();
    store.revoke_enrollment(&t, &p, &target, NOW + 5).unwrap();
    assert_eq!(store.count_audit(&t, 0).unwrap(), count);
    assert!(store.authenticate_enrollment(&fp, NOW + 5).is_err());
    assert!(store
        .save_target_capability(&identity, &cap, NOW + 5)
        .is_err());
    assert!(store.reserve_enrollment(&attempt, NOW + 5).is_err());
    assert_eq!(
        store.get_target(&t, &target, NOW + 5).unwrap()["state"],
        "quarantined"
    );
    let (second, fp, _, _) = enrolled_at(&store, &t, &p, NOW + 6);
    assert!(store.authenticate_enrollment(&fp, NOW + 86407).is_err());
    let records = store.list_enrollments(&t, 10, NOW + 86407).unwrap();
    assert_eq!(
        records.iter().find(|v| v["target_id"] == second).unwrap()["state"],
        "quarantined"
    );
}
#[test]
fn capability_has_real_hash_strict_shape_and_never_claims_supported() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let (target, fp, _, _) = enrolled(&store, &t, &p);
    let identity = store.authenticate_enrollment(&fp, NOW + 3).unwrap();
    let cap = capability(&target, NOW + 3);
    let result = store
        .save_target_capability(&identity, &cap, NOW + 3)
        .unwrap();
    assert_eq!(
        result["capability_hash"],
        hash_bytes(&canonical_bytes(&cap).unwrap())
    );
    assert_eq!(result["state"], "observe_only");
    assert_eq!(result["authority_epoch"], "0");
    assert_eq!(result["generation"], "0");
    assert!(result["observed_at"].is_null());
    assert_eq!(
        store
            .save_target_capability(&identity, &cap, NOW + 4)
            .unwrap(),
        result
    );
    for kind in 0..6 {
        let mut bad = capability(&target, NOW + 5);
        match kind {
            0 => bad["features"]["timed_allow"]["state"] = "supported".into(),
            1 => bad["qualification_profiles"] = json!(["common-host-v1"]),
            2 => bad["target_id"] = id().into(),
            3 => bad["forged"] = true.into(),
            4 => bad["features"]["timed_allow"]["extra"] = true.into(),
            _ => bad["valid_until"] = time(NOW + 86402).into(),
        };
        assert!(store
            .save_target_capability(&identity, &bad, NOW + 5)
            .is_err());
    }
    let mut same_second = cap.clone();
    same_second["os_version"] = "different".into();
    assert!(store
        .save_target_capability(&identity, &same_second, NOW + 4)
        .is_err());
    assert_eq!(
        store.get_target(&t, &target, NOW + 303).unwrap()["state"],
        "quarantined"
    );
}
#[test]
fn target_views_revoke_and_identity_cannot_cross_tenants() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let (other, other_p) = prepare(&store);
    let (target, fp, _, _) = enrolled(&store, &t, &p);
    let identity = store.authenticate_enrollment(&fp, NOW + 3).unwrap();
    let cap = capability(&target, NOW + 3);
    store
        .save_target_capability(&identity, &cap, NOW + 3)
        .unwrap();
    assert!(matches!(
        store.get_target(&other, &target, NOW + 3),
        Err(StoreError::NotFound)
    ));
    assert!(store.list_targets(&other, 10, NOW + 3).unwrap().is_empty());
    assert!(store
        .list_enrollments(&other, 10, NOW + 3)
        .unwrap()
        .is_empty());
    assert!(store
        .revoke_enrollment(&other, &other_p, &target, NOW + 4)
        .is_err());
    let mut forged = identity;
    forged.tenant = other;
    assert!(store
        .save_target_capability(&forged, &cap, NOW + 4)
        .is_err());
}
#[test]
fn lists_fail_explicitly_instead_of_hiding_registered_targets() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    for index in 0..2 {
        let at = NOW + index * 10;
        let (target, fp, _, _) = enrolled_at(&store, &t, &p, at);
        let identity = store.authenticate_enrollment(&fp, at + 3).unwrap();
        store
            .save_target_capability(&identity, &capability(&target, at + 3), at + 3)
            .unwrap();
    }
    assert_eq!(store.count_enrollments(&t).unwrap(), 2);
    assert_eq!(store.count_targets(&t).unwrap(), 2);
    assert!(store.list_enrollments(&t, 1, NOW + 20).is_err());
    assert!(store.list_targets(&t, 1, NOW + 20).is_err());
}
#[test]
fn capability_tampering_is_detected_on_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    let (target, fp, _, _) = enrolled(&store, &t, &p);
    let identity = store.authenticate_enrollment(&fp, NOW + 3).unwrap();
    store
        .save_target_capability(&identity, &capability(&target, NOW + 3), NOW + 3)
        .unwrap();
    let raw = Connection::open(path).unwrap();
    assert!(raw
        .execute(
            "UPDATE enrolled_capabilities SET valid_until=valid_until+1",
            []
        )
        .is_err());
    raw.execute_batch("DROP TRIGGER enrolled_capability_no_update")
        .unwrap();
    raw.execute(
        "UPDATE enrolled_capabilities SET valid_until=valid_until+1",
        [],
    )
    .unwrap();
    assert!(matches!(
        store.get_target(&t, &target, NOW + 4),
        Err(StoreError::Integrity(_))
    ));
}
#[test]
fn real_enrollment_revocation_blocks_new_service_references() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let (target, fingerprint, _, _) = enrolled(&store, &t, &p);
    let asset=store.create_asset(&t,&p,&json!({"definition":{"name":"Server","asset_kind":"host","owner_id":p,"addresses":[{"family":"ipv4","cidr":"192.0.2.1/32","interface":null}],"criticality":"normal","isolation":"host","provenance":"manual","source_evidence":null},"state":"active"}),&id(),NOW+3).unwrap().value;
    let service = |service_id: &str| json!({"service_id":service_id,"definition":{"name":service_id,"owner_id":p,"destination_asset_ids":[asset["asset_id"]],"target_ids":[target],"transport":{"protocol":"tcp","destination_ports":[{"start":443,"end":443}]},"description":"Test","criticality":"normal"}});
    assert!(matches!(
        store.create_service(&t, &p, &service("no-report"), &id(), NOW + 3),
        Err(StoreError::NotFound)
    ));
    let identity = store
        .authenticate_enrollment(&fingerprint, NOW + 3)
        .unwrap();
    store
        .save_target_capability(&identity, &capability(&target, NOW + 3), NOW + 3)
        .unwrap();
    store
        .create_service(&t, &p, &service("before-revoke"), &id(), NOW + 3)
        .unwrap();
    store.revoke_enrollment(&t, &p, &target, NOW + 4).unwrap();
    assert!(store
        .create_service(&t, &p, &service("after-revoke"), &id(), NOW + 5)
        .is_err());
}

#[test]
fn enrollment_audit_events_follow_original_public_schema_categories() {
    let store = Store::in_memory().unwrap();
    let (tenant, principal) = prepare(&store);
    let (target, fingerprint, _, _) = enrolled(&store, &tenant, &principal);
    let identity = store
        .authenticate_enrollment(&fingerprint, NOW + 3)
        .unwrap();
    store
        .save_target_capability(&identity, &capability(&target, NOW + 3), NOW + 3)
        .unwrap();
    store
        .revoke_enrollment(&tenant, &principal, &target, NOW + 4)
        .unwrap();
    let events = store.list_audit(&tenant, 0, 100).unwrap();
    assert_eq!(events.len(), 5);
    let api: Value =
        serde_json::from_str(include_str!("../../../docs/specs/F_OpenAPI.json")).unwrap();
    let schema = &api["components"]["schemas"]["AuditEvent"];
    let properties = schema["properties"].as_object().unwrap();
    let required = schema["required"].as_array().unwrap();
    for event in &events {
        let object = event.as_object().unwrap();
        assert_eq!(object.len(), properties.len());
        for key in required {
            assert!(object.contains_key(key.as_str().unwrap()));
        }
        for (key, rule) in properties {
            if let Some(allowed) = rule["enum"].as_array() {
                assert!(
                    allowed.contains(&event[key]),
                    "invalid {key}: {}",
                    event[key]
                );
            }
            if let Some(constant) = rule.get("const") {
                assert_eq!(&event[key], constant);
            }
        }
        assert_eq!(event["resource_kind"], "target");
        assert_eq!(event["resource_id"], target);
        assert_eq!(event["outcome"], "success");
    }
    let categories: Vec<_> = events
        .iter()
        .map(|e| {
            (
                e["event_type"].as_str().unwrap(),
                e["reason_code"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        categories,
        vec![
            ("administration", "ENROLLMENT_TOKEN_REGISTERED"),
            ("authentication", "ENROLLMENT_RESERVED"),
            ("registry", "TARGET_ENROLLED"),
            ("registry", "CAPABILITY_UNVERIFIED"),
            ("revocation", "NETWORK_REVOCATION_UNCONFIRMED"),
        ]
    );
    assert!(events[3]["actor_id"].is_null());
    assert_eq!(store.verify_audit_chain(&tenant).unwrap(), 5);
}

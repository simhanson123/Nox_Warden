//! Persistence/state-machine tests only. The verifier closures below are explicit
//! test doubles; WebAuthn cryptography is covered by the adapter/browser suites.
use fw_contracts::hash_bytes;
use fw_store::{passkeys::*, Store, StoreError, Tenant};
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Barrier,
};
use uuid::Uuid;

const NOW: i64 = 1_793_318_400;
fn id() -> String {
    Uuid::new_v4().to_string()
}
fn binding() -> String {
    hash_bytes(b"test server session")
}
fn setup(store: &Store) -> (Tenant, String) {
    let tenant = store
        .ensure_tenant(&id(), &id(), "Passkey test", NOW)
        .unwrap();
    let principal = id();
    store
        .ensure_principal(&tenant, &principal, "human", NOW)
        .unwrap();
    (tenant, principal)
}
fn input(kind: &str, authority: Option<PasskeyAuthority>) -> PasskeyChallengeInput {
    PasskeyChallengeInput {
        kind: kind.into(),
        session_binding: binding(),
        authority,
        name: (kind == "registration").then(|| "Security key".into()),
        request: json!({"fixture":"original client body"}),
        options: json!({"test_only":"options"}),
        state: json!({"test_only":"state"}),
    }
}
fn begin(
    store: &Store,
    t: &Tenant,
    p: &str,
    kind: &str,
    authority: Option<PasskeyAuthority>,
    now: i64,
) -> PasskeyChallenge {
    store
        .begin_passkey_challenge(t, p, &input(kind, authority), &id(), now)
        .unwrap()
}
fn verified(id: &str, counter: u64) -> VerifiedPasskey {
    VerifiedPasskey {
        credential_id: id.into(),
        credential: json!({"test_only":"credential","counter":counter}),
    }
}
fn finish(
    store: &Store,
    t: &Tenant,
    p: &str,
    ch: &PasskeyChallenge,
    credential: &str,
    now: i64,
) -> PasskeyCompletion {
    store
        .finish_passkey_challenge(
            t,
            p,
            &ch.challenge_id,
            &ch.kind,
            &binding(),
            &json!({"test_only":"proof"}),
            &id(),
            now,
            |_, _| Ok(verified(credential, 1)),
        )
        .unwrap()
}
fn enroll(store: &Store, t: &Tenant, p: &str, credential: &str, now: i64) {
    let ch = begin(
        store,
        t,
        p,
        "registration",
        Some(PasskeyAuthority::Bootstrap),
        now,
    );
    finish(store, t, p, &ch, credential, now);
}
fn authenticate(store: &Store, t: &Tenant, p: &str, credential: &str, now: i64) {
    let ch = begin(store, t, p, "authentication", None, now);
    finish(store, t, p, &ch, credential, now);
}
fn authority(credential: &str, now: i64) -> PasskeyAuthority {
    PasskeyAuthority::Passkey {
        credential_id: credential.into(),
        authenticated_at: now,
    }
}
fn add(store: &Store, t: &Tenant, p: &str, old: &str, new: &str, now: i64) {
    let ch = begin(store, t, p, "registration", Some(authority(old, now)), now);
    finish(store, t, p, &ch, new, now);
}
fn conflict<T>(result: Result<T, StoreError>, code: &str) {
    assert!(matches!(result,Err(StoreError::Conflict(found)) if found==code));
}

#[test]
fn durable_owner_enrollment_never_reopens_bootstrap_and_pending_requires_signed_login() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    assert!(!store.passkey_owner_enrolled(&t, &p).unwrap());
    enroll(&store, &t, &p, "key-one", NOW);
    assert!(store.passkey_owner_enrolled(&t, &p).unwrap());
    conflict(
        store.active_passkey(&t, &p, "key-one"),
        "PASSKEY_NOT_ACTIVATED",
    );
    conflict(
        store.begin_passkey_challenge(
            &t,
            &p,
            &input("registration", Some(authority("key-one", NOW))),
            &id(),
            NOW,
        ),
        "PASSKEY_NOT_ACTIVATED",
    );
    drop(store);
    let store = Store::open(&path).unwrap();
    assert!(store.passkey_owner_enrolled(&t, &p).unwrap());
    conflict(
        store.begin_passkey_challenge(
            &t,
            &p,
            &input("registration", Some(PasskeyAuthority::Bootstrap)),
            &id(),
            NOW + 1,
        ),
        "PASSKEY_OWNER_ALREADY_ENROLLED",
    );
    authenticate(&store, &t, &p, "key-one", NOW + 1);
    let key = store.active_passkey(&t, &p, "key-one").unwrap();
    assert_eq!(key.verified_at, Some(NOW + 1));
    assert_eq!(key.revision, 2);
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 4);
}

#[test]
fn failed_proof_records_denial_without_enrollment_or_successful_consumption() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let ch = begin(
        &store,
        &t,
        &p,
        "registration",
        Some(PasskeyAuthority::Bootstrap),
        NOW,
    );
    conflict(
        store.finish_passkey_challenge(
            &t,
            &p,
            &ch.challenge_id,
            "registration",
            &binding(),
            &json!({"bad":true}),
            &id(),
            NOW,
            |_, _| Err(StoreError::InvalidInput("synthetic rejected proof")),
        ),
        "PASSKEY_PROOF_REJECTED",
    );
    assert!(!store.passkey_owner_enrolled(&t, &p).unwrap());
    assert!(store.list_passkeys(&t, &p).unwrap().is_empty());
    finish(&store, &t, &p, &ch, "key-one", NOW + 1);
    assert!(store.passkey_owner_enrolled(&t, &p).unwrap());
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 3);
    let events = store.list_audit(&t, 0, 100).unwrap();
    assert_eq!(events[1]["reason_code"], "PASSKEY_PROOF_REJECTED");
    assert!(!serde_json::to_string(&events)
        .unwrap()
        .contains("synthetic rejected proof"));
}

#[test]
fn successful_replay_is_explicit_read_only_and_never_calls_verifier_twice() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    enroll(&store, &t, &p, "key-one", NOW);
    let ch = begin(&store, &t, &p, "authentication", None, NOW);
    let key = id();
    let proof = json!({"test_only":"signed assertion"});
    let first = store
        .finish_passkey_challenge(
            &t,
            &p,
            &ch.challenge_id,
            &ch.kind,
            &binding(),
            &proof,
            &key,
            NOW,
            |_, creds| {
                assert_eq!(creds.len(), 1);
                assert_eq!(creds[0].verified_at, None);
                Ok(verified("key-one", 3))
            },
        )
        .unwrap();
    assert!(!first.replayed);
    let replay = store
        .finish_passkey_challenge(
            &t,
            &p,
            &ch.challenge_id,
            &ch.kind,
            &binding(),
            &proof,
            &key,
            NOW + 1000,
            |_, _| panic!("replay must not verify or authorize a new session"),
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(store.active_passkey(&t, &p, "key-one").unwrap().revision, 2);
    assert!(matches!(
        store.finish_passkey_challenge(
            &t,
            &p,
            &ch.challenge_id,
            &ch.kind,
            &binding(),
            &proof,
            &id(),
            NOW,
            |_, _| panic!()
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        store.finish_passkey_challenge(
            &t,
            &p,
            &ch.challenge_id,
            &ch.kind,
            &binding(),
            &json!({"changed":true}),
            &key,
            NOW,
            |_, _| panic!()
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 4);
}

#[test]
fn challenge_is_bound_to_tenant_principal_purpose_browser_and_time() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let (t2, p2) = setup(&store);
    let ch = begin(
        &store,
        &t,
        &p,
        "registration",
        Some(PasskeyAuthority::Bootstrap),
        NOW,
    );
    for (tenant, principal, kind, browser) in [
        (&t2, p2.as_str(), "registration", binding()),
        (&t, p.as_str(), "authentication", binding()),
        (
            &t,
            p.as_str(),
            "registration",
            hash_bytes(b"different browser"),
        ),
    ] {
        assert!(matches!(
            store.finish_passkey_challenge(
                tenant,
                principal,
                &ch.challenge_id,
                kind,
                &browser,
                &json!({}),
                &id(),
                NOW,
                |_, _| panic!("wrong binding cannot reach crypto")
            ),
            Err(StoreError::NotFound)
        ));
    }
    for now in [NOW - 1, NOW + 300] {
        conflict(
            store.finish_passkey_challenge(
                &t,
                &p,
                &ch.challenge_id,
                "registration",
                &binding(),
                &json!({}),
                &id(),
                now,
                |_, _| panic!(),
            ),
            "PASSKEY_CHALLENGE_EXPIRED",
        );
    }
    finish(&store, &t, &p, &ch, "key-one", NOW);
    assert!(!store.passkey_owner_enrolled(&t2, &p2).unwrap());
}

#[test]
fn challenge_creation_replays_original_random_options_and_rejects_changed_input() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let key = id();
    let mut body = input("registration", Some(PasskeyAuthority::Bootstrap));
    let first = store
        .begin_passkey_challenge(&t, &p, &body, &key, NOW)
        .unwrap();
    body.options = json!({"test_only":"new random options"});
    body.state = json!({"test_only":"new random state"});
    let again = store
        .begin_passkey_challenge(&t, &p, &body, &key, NOW + 1)
        .unwrap();
    assert_eq!(first.challenge_id, again.challenge_id);
    assert_eq!(first.options, again.options);
    assert_eq!(first.state, again.state);
    body.name = Some("Different key".into());
    assert!(matches!(
        store.begin_passkey_challenge(&t, &p, &body, &key, NOW + 1),
        Err(StoreError::IdempotencyConflict)
    ));
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 1);
}

#[test]
fn credential_changes_require_fresh_verified_authority_and_recheck_revocation_at_finish() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    enroll(&store, &t, &p, "key-one", NOW);
    authenticate(&store, &t, &p, "key-one", NOW);
    add(&store, &t, &p, "key-one", "key-two", NOW);
    authenticate(&store, &t, &p, "key-two", NOW);
    for at in [NOW + 1, NOW - 300] {
        conflict(
            store.begin_passkey_challenge(
                &t,
                &p,
                &input("registration", Some(authority("key-one", at))),
                &id(),
                NOW,
            ),
            "PASSKEY_FRESH_AUTHENTICATION_REQUIRED",
        );
    }
    // A server context cannot claim a newer authentication timestamp than any
    // signed authentication actually committed for this credential.
    conflict(
        store.begin_passkey_challenge(
            &t,
            &p,
            &input("registration", Some(authority("key-one", NOW + 1))),
            &id(),
            NOW + 1,
        ),
        "PASSKEY_FRESH_AUTHENTICATION_REQUIRED",
    );
    let pending = begin(
        &store,
        &t,
        &p,
        "registration",
        Some(authority("key-one", NOW)),
        NOW,
    );
    let login = begin(&store, &t, &p, "authentication", None, NOW);
    store
        .revoke_passkey(&t, &p, "key-one", &authority("key-two", NOW), &id(), NOW)
        .unwrap();
    assert!(matches!(
        store.finish_passkey_challenge(
            &t,
            &p,
            &pending.challenge_id,
            "registration",
            &binding(),
            &json!({}),
            &id(),
            NOW,
            |_, _| panic!("revoked authorizer")
        ),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.finish_passkey_challenge(
            &t,
            &p,
            &login.challenge_id,
            "authentication",
            &binding(),
            &json!({}),
            &id(),
            NOW,
            |_, creds| {
                assert!(creds.iter().all(|key| key.credential_id != "key-one"));
                Ok(verified("key-one", 2))
            }
        ),
        Err(StoreError::NotFound)
    ));
    assert!(store.active_passkey(&t, &p, "key-one").is_err());
    assert!(store.active_passkey(&t, &p, "key-two").is_ok());
}

#[test]
fn pending_backup_cannot_authorize_deletion_of_last_working_key_and_revocation_is_durable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    enroll(&store, &t, &p, "key-one", NOW);
    authenticate(&store, &t, &p, "key-one", NOW);
    add(&store, &t, &p, "key-one", "key-two", NOW);
    conflict(
        store.revoke_passkey(&t, &p, "key-one", &authority("key-one", NOW), &id(), NOW),
        "PASSKEY_LAST_CREDENTIAL",
    );
    authenticate(&store, &t, &p, "key-two", NOW);
    let key = id();
    let auth = authority("key-two", NOW);
    let first = store
        .revoke_passkey(&t, &p, "key-one", &auth, &key, NOW)
        .unwrap();
    assert!(!first.replayed);
    assert!(
        store
            .revoke_passkey(&t, &p, "key-one", &auth, &key, NOW + 1)
            .unwrap()
            .replayed
    );
    drop(store);
    let store = Store::open(path).unwrap();
    assert!(store.passkey_owner_enrolled(&t, &p).unwrap());
    assert!(store.active_passkey(&t, &p, "key-one").is_err());
    assert_eq!(store.list_passkeys(&t, &p).unwrap().len(), 2);
    conflict(
        store.revoke_passkey(
            &t,
            &p,
            "key-two",
            &authority("key-two", NOW),
            &id(),
            NOW + 1,
        ),
        "PASSKEY_LAST_CREDENTIAL",
    );
    let ch = begin(
        &store,
        &t,
        &p,
        "registration",
        Some(authority("key-two", NOW)),
        NOW + 1,
    );
    conflict(
        store.finish_passkey_challenge(
            &t,
            &p,
            &ch.challenge_id,
            "registration",
            &binding(),
            &json!({}),
            &id(),
            NOW + 1,
            |_, _| Ok(verified("key-one", 0)),
        ),
        "PASSKEY_CREDENTIAL_ALREADY_REGISTERED",
    );
}

#[test]
fn failure_budget_is_durable_and_never_creates_a_credential() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    let ch = begin(
        &store,
        &t,
        &p,
        "registration",
        Some(PasskeyAuthority::Bootstrap),
        NOW,
    );
    for _ in 0..10 {
        conflict(
            store.finish_passkey_challenge(
                &t,
                &p,
                &ch.challenge_id,
                &ch.kind,
                &binding(),
                &json!({"invalid":true}),
                &id(),
                NOW,
                |_, _| Err(StoreError::InvalidInput("bad test proof")),
            ),
            "PASSKEY_PROOF_REJECTED",
        );
    }
    drop(store);
    let store = Store::open(path).unwrap();
    conflict(
        store.finish_passkey_challenge(
            &t,
            &p,
            &ch.challenge_id,
            &ch.kind,
            &binding(),
            &json!({}),
            &id(),
            NOW,
            |_, _| panic!("locked challenge"),
        ),
        "PASSKEY_CHALLENGE_LOCKED",
    );
    assert!(!store.passkey_owner_enrolled(&t, &p).unwrap());
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 11);
}

#[test]
fn simultaneous_first_registrations_have_one_owner_and_no_second_bootstrap_credential() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    let a = begin(
        &store,
        &t,
        &p,
        "registration",
        Some(PasskeyAuthority::Bootstrap),
        NOW,
    );
    let b = begin(
        &store,
        &t,
        &p,
        "registration",
        Some(PasskeyAuthority::Bootstrap),
        NOW,
    );
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = [a, b]
        .into_iter()
        .enumerate()
        .map(|(index, ch)| {
            let path = path.clone();
            let t = t.clone();
            let p = p.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = Store::open(path).unwrap();
                barrier.wait();
                store.finish_passkey_challenge(
                    &t,
                    &p,
                    &ch.challenge_id,
                    &ch.kind,
                    &binding(),
                    &json!({}),
                    &id(),
                    NOW,
                    |_, _| Ok(verified(&format!("key-{index}"), 0)),
                )
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(store.list_passkeys(&t, &p).unwrap().len(), 1);
}

#[test]
fn concurrent_same_assertion_consumes_once_and_second_result_is_only_a_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    enroll(&store, &t, &p, "key-one", NOW);
    let ch = begin(&store, &t, &p, "authentication", None, NOW);
    let key = id();
    let barrier = Arc::new(Barrier::new(2));
    let calls = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let t = t.clone();
            let p = p.clone();
            let ch = ch.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            let calls = calls.clone();
            std::thread::spawn(move || {
                let store = Store::open(path).unwrap();
                barrier.wait();
                store
                    .finish_passkey_challenge(
                        &t,
                        &p,
                        &ch.challenge_id,
                        &ch.kind,
                        &binding(),
                        &json!({}),
                        &key,
                        NOW,
                        |_, _| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(verified("key-one", 1))
                        },
                    )
                    .unwrap()
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| !r.replayed).count(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.active_passkey(&t, &p, "key-one").unwrap().revision, 2);
}

#[test]
fn current_counter_snapshot_is_used_for_each_verifier_and_other_sessions_remain_valid() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    enroll(&store, &t, &p, "key-one", NOW);
    authenticate(&store, &t, &p, "key-one", NOW);
    let a = begin(&store, &t, &p, "authentication", None, NOW);
    let b = begin(&store, &t, &p, "authentication", None, NOW);
    for (ch, counter) in [(&a, 2), (&b, 3)] {
        store
            .finish_passkey_challenge(
                &t,
                &p,
                &ch.challenge_id,
                &ch.kind,
                &binding(),
                &json!({"test_counter":counter}),
                &id(),
                NOW,
                |_, creds| {
                    assert_eq!(creds[0].credential["counter"], counter - 1);
                    Ok(verified("key-one", counter))
                },
            )
            .unwrap();
        assert!(store.active_passkey(&t, &p, "key-one").is_ok());
    }
    assert_eq!(store.active_passkey(&t, &p, "key-one").unwrap().revision, 4);
}

#[test]
fn active_principal_is_rechecked_and_failed_atomic_commit_never_enrolls() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    let ch = begin(
        &store,
        &t,
        &p,
        "registration",
        Some(PasskeyAuthority::Bootstrap),
        NOW,
    );
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute(
        "UPDATE principals SET state='suspended' WHERE principal_id=?1",
        [&p],
    )
    .unwrap();
    assert!(matches!(
        store.finish_passkey_challenge(
            &t,
            &p,
            &ch.challenge_id,
            &ch.kind,
            &binding(),
            &json!({}),
            &id(),
            NOW,
            |_, _| panic!()
        ),
        Err(StoreError::NotFound)
    ));
    raw.execute(
        "UPDATE principals SET state='active' WHERE principal_id=?1",
        [&p],
    )
    .unwrap();
    raw.execute_batch("CREATE TRIGGER injected_audit_failure BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(store
        .finish_passkey_challenge(
            &t,
            &p,
            &ch.challenge_id,
            &ch.kind,
            &binding(),
            &json!({}),
            &id(),
            NOW,
            |_, _| Ok(verified("key-one", 0))
        )
        .is_err());
    assert!(!store.passkey_owner_enrolled(&t, &p).unwrap());
    assert!(store.list_passkeys(&t, &p).unwrap().is_empty());
    raw.execute_batch("DROP TRIGGER injected_audit_failure;")
        .unwrap();
    finish(&store, &t, &p, &ch, "key-one", NOW);
    assert_eq!(store.list_passkeys(&t, &p).unwrap().len(), 1);
}

#[test]
fn credential_and_owner_records_cannot_be_deleted_or_revived_by_store_migrations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    enroll(&store, &t, &p, "key-one", NOW);
    authenticate(&store, &t, &p, "key-one", NOW);
    add(&store, &t, &p, "key-one", "key-two", NOW);
    authenticate(&store, &t, &p, "key-two", NOW);
    store
        .revoke_passkey(&t, &p, "key-one", &authority("key-two", NOW), &id(), NOW)
        .unwrap();
    let raw = rusqlite::Connection::open(path).unwrap();
    assert!(raw.execute("DELETE FROM passkey_owners", []).is_err());
    assert!(raw.execute("DELETE FROM passkey_credentials", []).is_err());
    assert!(raw
        .execute(
            "UPDATE passkey_credentials SET revoked_at=NULL WHERE credential_id='key-one'",
            []
        )
        .is_err());
    assert!(store.passkey_owner_enrolled(&t, &p).unwrap());
    assert!(store.active_passkey(&t, &p, "key-one").is_err());
}

#[test]
fn ceremony_budget_counts_locked_attempts_and_cannot_be_reset_by_restarting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    let locked = begin(
        &store,
        &t,
        &p,
        "registration",
        Some(PasskeyAuthority::Bootstrap),
        NOW,
    );
    for _ in 0..10 {
        conflict(
            store.finish_passkey_challenge(
                &t,
                &p,
                &locked.challenge_id,
                &locked.kind,
                &binding(),
                &json!({}),
                &id(),
                NOW,
                |_, _| Err(StoreError::InvalidInput("rejected test proof")),
            ),
            "PASSKEY_PROOF_REJECTED",
        );
    }
    for _ in 0..15 {
        begin(
            &store,
            &t,
            &p,
            "registration",
            Some(PasskeyAuthority::Bootstrap),
            NOW,
        );
    }
    drop(store);
    let store = Store::open(path).unwrap();
    conflict(
        store.begin_passkey_challenge(
            &t,
            &p,
            &input("registration", Some(PasskeyAuthority::Bootstrap)),
            &id(),
            NOW + 1,
        ),
        "PASSKEY_CHALLENGE_LIMIT",
    );
    assert!(store
        .begin_passkey_challenge(
            &t,
            &p,
            &input("registration", Some(PasskeyAuthority::Bootstrap)),
            &id(),
            NOW + 300
        )
        .is_ok());
}

#[test]
fn cli_audit_only_accepts_fixed_events_and_public_request_identifiers() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let request = id();
    for event in [
        "cli_login_requested",
        "cli_login_approved",
        "cli_login_exchanged",
    ] {
        store
            .record_passkey_cli_event(&t, &p, &request, event, NOW)
            .unwrap();
    }
    assert!(store
        .record_passkey_cli_event(&t, &p, &request, "secret token", NOW)
        .is_err());
    assert!(store
        .record_passkey_cli_event(&t, &p, "not a uuid", "cli_login_approved", NOW)
        .is_err());
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 3);
    let events = store.list_audit(&t, 0, 100).unwrap();
    assert_eq!(events[0]["resource_id"], request);
    assert!(events[0]["actor_id"].is_null());
    assert_eq!(events[1]["actor_id"], p);
    assert_eq!(events[2]["reason_code"], "CLI_LOGIN_EXCHANGED");
    assert!(!serde_json::to_string(&events)
        .unwrap()
        .contains("secret token"));
}

#[test]
fn anonymous_login_attempts_do_not_claim_an_authenticated_audit_actor() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    enroll(&store, &t, &p, "key-one", NOW);
    let ch = begin(&store, &t, &p, "authentication", None, NOW);
    conflict(
        store.finish_passkey_challenge(
            &t,
            &p,
            &ch.challenge_id,
            &ch.kind,
            &binding(),
            &json!({}),
            &id(),
            NOW,
            |_, _| Err(StoreError::InvalidInput("test rejection")),
        ),
        "PASSKEY_PROOF_REJECTED",
    );
    finish(&store, &t, &p, &ch, "key-one", NOW);
    let events = store.list_audit(&t, 0, 100).unwrap();
    assert_eq!(events[2]["reason_code"], "PASSKEY_CHALLENGE_CREATED");
    assert!(events[2]["actor_id"].is_null());
    assert_eq!(events[3]["reason_code"], "PASSKEY_PROOF_REJECTED");
    assert!(events[3]["actor_id"].is_null());
    assert_eq!(events[4]["reason_code"], "PASSKEY_AUTHENTICATED");
    assert_eq!(events[4]["actor_id"], p);
}

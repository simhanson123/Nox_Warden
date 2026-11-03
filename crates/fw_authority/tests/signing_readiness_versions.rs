#![cfg(feature = "approval-proofs")]

#[path = "support/core_access_fixture.rs"]
mod core_access_fixture;
#[path = "support/private_directory.rs"]
mod private_directory;

use fw_authority::{AuthorityStore, AuthorityTenant, SigningProjectQuotaPin, SigningRootQuotaPin};
use fw_webauthn::WebAuthn;
use serde_json::{Value, json};

#[test]
fn rooted_core_readiness_requires_retained_provenance_on_both_versions() {
    let directory = private_directory::private_directory();
    let path = directory.path().join("authority.sqlite3");
    let mut store = AuthorityStore::open(&path).unwrap();
    let (plan, provenance) = core_access_fixture::fixture();
    let tenant = AuthorityTenant::new(
        plan["org_id"].as_str().unwrap(),
        plan["project_id"].as_str().unwrap(),
    )
    .unwrap();
    let now = core_access_fixture::NOW;
    store
        .provision_target_metadata_project(&tenant, now)
        .unwrap();
    store
        .register_plan(&tenant, &plan, &core_access_fixture::requirements(), now)
        .unwrap();
    let pin = json!({
        "root_id": provenance.delegation.root_id,
        "limits": {"active_leases":1,"new_leases_per_day":1,"unique_destinations_per_day":1,
            "cumulative_seconds_per_day":3600,"concurrent_deployments":1},
        "not_before":now,"not_after":now+120,
    });
    store
        .pin_signing_root_quota(
            &tenant,
            &serde_json::from_value::<SigningRootQuotaPin>(pin.clone()).unwrap(),
            None,
            now,
        )
        .unwrap();
    store
        .pin_signing_project_quota(
            &tenant,
            &serde_json::from_value::<SigningProjectQuotaPin>(pin).unwrap(),
            None,
            now,
        )
        .unwrap();
    let plan_id = plan["plan_id"].as_str().unwrap();
    let verifier = WebAuthn::new("http://localhost:8787").unwrap();
    let legacy = store
        .signing_readiness(&tenant, plan_id, &verifier, now)
        .unwrap();
    let versioned = store
        .signing_readiness_v2(&tenant, plan_id, &verifier, now)
        .unwrap();
    assert!(!legacy.quota_configured);
    assert!(!versioned.snapshot.quota_configured);
    for reason in [
        "CORE_REQUEST_BINDING_UNAVAILABLE",
        "CORE_SIGNING_PROFILE_UNAVAILABLE",
        "QUOTA_CONFIGURATION_MISSING",
    ] {
        assert!(legacy.reasons.iter().any(|item| item == reason));
        assert!(versioned.snapshot.reasons.iter().any(|item| item == reason));
    }
    assert_eq!(versioned.quota_scope.as_deref(), Some("root"));
    assert_eq!(
        versioned.quota_root_id.as_deref(),
        Some(provenance.delegation.root_id.as_str())
    );
    assert_eq!(versioned.latest_dispatch_unknown_seen, None);
    assert!(!legacy.signing_allowed && !legacy.dispatch_allowed);
    assert!(!versioned.snapshot.signing_allowed && !versioned.snapshot.dispatch_allowed);
    let legacy = serde_json::to_value(legacy).unwrap();
    assert_eq!(legacy.as_object().unwrap().len(), 15);
    let mut versioned = serde_json::to_value(versioned).unwrap();
    for field in [
        "quota_scope",
        "quota_root_id",
        "latest_dispatch_unknown_seen",
    ] {
        versioned.as_object_mut().unwrap().remove(field);
    }
    versioned["schema_version"] = json!("fw.signing-readiness/v1");
    assert_eq!(versioned, legacy);
    // Recording valid cost provenance changes diagnostic applicability, while
    // production signing still requires its separately unavailable profile.
    store
        .register_core_access_provenance(&tenant, plan_id, &provenance, now)
        .unwrap();
    let versioned = store
        .signing_readiness_v2(&tenant, plan_id, &verifier, now)
        .unwrap();
    assert!(versioned.snapshot.quota_configured);
    assert!(!versioned.snapshot.signing_allowed && !versioned.snapshot.dispatch_allowed);
    assert!(
        versioned
            .snapshot
            .reasons
            .iter()
            .any(|r| r == "CORE_SIGNING_PROFILE_UNAVAILABLE")
    );
    assert!(versioned.snapshot.latest_intent.is_none());
    assert_eq!(
        serde_json::to_value(versioned).unwrap()["latest_intent"],
        Value::Null
    );
}

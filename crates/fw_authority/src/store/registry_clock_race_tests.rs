//! A second real AuthorityStore advances the durable floor after the first
//! connection's observation commit and before its final snapshot/mutation.
use super::*;
use crate::{
    DsseEnvelope, DsseSignature, RegistryTrustKey, WORKLOAD_BINDING_TYPE, WorkloadBinding,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use signing_test_support::private_directory;
use std::{cell::Cell, rc::Rc};

const NOW: i64 = 1_800_000_000;
const ORG: &str = "11111111-1111-4111-8111-111111111111";
const PROJECT: &str = "22222222-2222-4222-8222-222222222222";
const TARGET: &str = "33333333-3333-4333-8333-333333333333";
const PRINCIPAL: &str = "44444444-4444-4444-8444-444444444444";
const BINDING: &str = "55555555-5555-4555-8555-555555555555";
const NEXT: &str = "66666666-6666-4666-8666-666666666666";
const ASSET: &str = "77777777-7777-4777-8777-777777777777";

fn workload(key: &SigningKey, pin: &RegistryTrustKey) -> WorkloadBinding {
    let payload: crate::WorkloadBindingPayload = serde_json::from_value(json!({
        "schema_version":"f.workload-binding/v1", "binding_id":BINDING,
        "org_id":ORG,"project_id":PROJECT,"principal_id":PRINCIPAL,
        "issuer_key_id":pin.key_id,"workload_id":"registry-race","target_id":TARGET,
        "platform":"linux","asset_ids":[ASSET],"asset_revision_hashes":[hash_bytes(b"asset")],
        "addresses":[{"family":"ipv4","cidr":"192.0.2.1/32","interface":null}],
        "isolation":{"kind":"host","host_asset_id":ASSET},
        "issued_at":at(NOW).unwrap(),"not_before":at(NOW).unwrap(),"expires_at":at(NOW+120).unwrap(),
        "binding_epoch":"1","attestation_evidence":{"store_id":"fixture","object_hash":hash_bytes(b"attestation fixture"),"media_type":"application/json","size_bytes":1},
        "audience":"fw_controller"
    })).unwrap();
    signed(payload, key, pin)
}
fn signed(
    payload: crate::WorkloadBindingPayload,
    key: &SigningKey,
    pin: &RegistryTrustKey,
) -> WorkloadBinding {
    let canonical = bytes(&payload).unwrap();
    WorkloadBinding {
        payload,
        dsse: DsseEnvelope {
            payload_type: WORKLOAD_BINDING_TYPE.into(),
            payload: STANDARD.encode(&canonical),
            signatures: vec![DsseSignature {
                keyid: pin.key_id.clone(),
                sig: STANDARD.encode(
                    key.sign(&crate::pae(WORKLOAD_BINDING_TYPE, &canonical))
                        .to_bytes(),
                ),
            }],
        },
    }
}
fn count(store: &AuthorityStore, table: &str) -> i64 {
    store
        .connection
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn observed_registry_expiry_between_transactions_cannot_revive_admission_retry_or_read() {
    for operation in ["new_admission", "historical_retry", "status_read"] {
        let directory = private_directory::private_directory();
        let path = directory.path().join("authority.sqlite3");
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        let mut store = AuthorityStore::open(&path).unwrap();
        store
            .provision_target_metadata_project(&tenant, NOW)
            .unwrap();
        let key = SigningKey::from_bytes(&[89; 32]);
        let pin = RegistryTrustKey {
            key_id: "registry-race-issuer".into(),
            org_id: ORG.into(),
            project_id: PROJECT.into(),
            target_id: TARGET.into(),
            payload_type: WORKLOAD_BINDING_TYPE.into(),
            public_key: key.verifying_key().to_bytes(),
            not_before: NOW,
            not_after: NOW + 600,
            revoked: false,
        };
        store.pin_registry_trust_key(&tenant, &pin, NOW).unwrap();
        let original = workload(&key, &pin);
        store
            .admit_workload_binding(&tenant, &original, NOW)
            .unwrap();
        let mut payload = original.payload.clone();
        payload.binding_id = NEXT.into();
        payload.binding_epoch = "2".into();
        let next = signed(payload, &key, &pin);
        let before = (
            count(&store, "authority_registry_objects"),
            count(&store, "authority_audit"),
        );
        let reached = Rc::new(Cell::new(false));
        let observed = reached.clone();
        let peer_path = path.clone();
        authority_registry::AFTER_OBSERVATION_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let mut peer = AuthorityStore::open(&peer_path).unwrap();
                let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
                let expired = peer
                    .read_registry_object(&tenant, "workload_binding", BINDING, NOW + 120)
                    .unwrap()
                    .unwrap();
                assert!(!expired.current);
                observed.set(true);
            }))
        });
        let result = match operation {
            "new_admission" => store
                .admit_workload_binding(&tenant, &next, NOW + 1)
                .map(|_| ()),
            "historical_retry" => store
                .admit_workload_binding(&tenant, &original, NOW + 1)
                .map(|_| ()),
            _ => store
                .read_registry_object(&tenant, "workload_binding", BINDING, NOW + 1)
                .map(|_| ()),
        };
        assert!(
            reached.get(),
            "peer expiry observation reached for {operation}"
        );
        assert!(
            matches!(result, Err(AuthorityError::Time)),
            "{operation}: {result:?}"
        );
        assert_eq!(
            (
                count(&store, "authority_registry_objects"),
                count(&store, "authority_audit")
            ),
            before
        );
        let floor: i64 = store
            .connection
            .query_row(
                "SELECT observed_at FROM authority_registry_clocks WHERE org_id=? AND project_id=?",
                params![ORG, PROJECT],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(floor, NOW + 120);
        drop(store);
        let mut reopened = AuthorityStore::open(&path).unwrap();
        assert!(matches!(
            reopened.read_registry_object(&tenant, "workload_binding", BINDING, NOW + 1),
            Err(AuthorityError::Time)
        ));
    }
}

//! Test-only software authenticator. It produces actual P-256 signatures and
//! CBOR registration data; it is not exposed by the library or control API.
use super::*;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_cbor_2::Value as Cbor;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const ORIGIN: &str = "http://localhost:8787";
const PRINCIPAL: &str = "11111111-1111-4111-8111-111111111111";

struct Authenticator {
    key: PKey<Private>,
    public: Vec<u8>,
    id: Vec<u8>,
}
impl Authenticator {
    fn new() -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let public = key
            .public_key()
            .to_bytes(
                &group,
                PointConversionForm::UNCOMPRESSED,
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap();
        Self {
            key: PKey::from_ec_key(key).unwrap(),
            public,
            id: uuid::Uuid::new_v4().as_bytes().to_vec(),
        }
    }
    fn client_data(options: &Value, kind: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"type":kind,"challenge":options["publicKey"]["challenge"],"origin":origin,"crossOrigin":false})).unwrap()
    }
    fn registration(&self, options: &Value, flags: u8) -> RegistrationResponse {
        let cose = Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(2)),
            (Cbor::Integer(3), Cbor::Integer(-7)),
            (Cbor::Integer(-1), Cbor::Integer(1)),
            (Cbor::Integer(-2), Cbor::Bytes(self.public[1..33].to_vec())),
            (Cbor::Integer(-3), Cbor::Bytes(self.public[33..65].to_vec())),
        ]));
        let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&0_u32.to_be_bytes());
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.id);
        auth_data.extend(serde_cbor_2::to_vec(&cose).unwrap());
        let attestation = Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
        ]));
        RegistrationResponse {
            id: URL_SAFE_NO_PAD.encode(&self.id),
            raw_id: URL_SAFE_NO_PAD.encode(&self.id),
            type_: "public-key".into(),
            response: RegistrationAuthenticatorResponse {
                client_data_json: URL_SAFE_NO_PAD.encode(Self::client_data(
                    options,
                    "webauthn.create",
                    ORIGIN,
                )),
                attestation_object: URL_SAFE_NO_PAD
                    .encode(serde_cbor_2::to_vec(&attestation).unwrap()),
                transports: Some(vec!["internal".into()]),
            },
            client_extension_results: ClientExtensions::default(),
        }
    }
    fn assertion(
        &self,
        options: &Value,
        counter: u32,
        flags: u8,
        origin: &str,
    ) -> AuthenticationResponse {
        let client_data = Self::client_data(options, "webauthn.get", origin);
        let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
        signer.update(&signed).unwrap();
        AuthenticationResponse {
            id: URL_SAFE_NO_PAD.encode(&self.id),
            raw_id: URL_SAFE_NO_PAD.encode(&self.id),
            type_: "public-key".into(),
            response: AuthenticationAuthenticatorResponse {
                client_data_json: URL_SAFE_NO_PAD.encode(client_data),
                authenticator_data: URL_SAFE_NO_PAD.encode(auth_data),
                signature: URL_SAFE_NO_PAD.encode(signer.sign_to_vec().unwrap()),
                user_handle: Some(
                    URL_SAFE_NO_PAD.encode(uuid::Uuid::parse_str(PRINCIPAL).unwrap().as_bytes()),
                ),
            },
            client_extension_results: ClientExtensions::default(),
        }
    }
    fn resign(&self, response: &mut AuthenticationResponse) {
        let mut signed = decode(&response.response.authenticator_data, 16_384).unwrap();
        signed.extend_from_slice(&Sha256::digest(
            decode(&response.response.client_data_json, 8192).unwrap(),
        ));
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
        signer.update(&signed).unwrap();
        response.response.signature = URL_SAFE_NO_PAD.encode(signer.sign_to_vec().unwrap());
    }
}

fn registered() -> (WebAuthn, Authenticator, Credential) {
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new();
    let start = verifier
        .begin_registration(PRINCIPAL, "Local owner", &[])
        .unwrap();
    let response = key.registration(&start.options, 0x45);
    let credential = verifier
        .finish_registration(&start.state, &response)
        .unwrap();
    (verifier, key, credential)
}

#[test]
fn real_registration_and_assertion_survive_private_state_serialization() {
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new();
    let registration = verifier
        .begin_registration(PRINCIPAL, "Local owner", &[])
        .unwrap();
    assert_eq!(
        registration.options["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    let state: RegistrationState =
        serde_json::from_value(serde_json::to_value(&registration.state).unwrap()).unwrap();
    let credential = verifier
        .finish_registration(&state, &key.registration(&registration.options, 0x45))
        .unwrap();
    assert_eq!(credential.id(), URL_SAFE_NO_PAD.encode(&key.id));
    let authentication = verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&credential))
        .unwrap();
    assert_eq!(
        authentication.options["publicKey"]["userVerification"],
        "required"
    );
    let state: AuthenticationState =
        serde_json::from_value(serde_json::to_value(&authentication.state).unwrap()).unwrap();
    let updated = verifier
        .finish_authentication(
            &state,
            &key.assertion(&authentication.options, 1, 0x05, ORIGIN),
            &credential,
        )
        .unwrap();
    assert_eq!(updated.principal_id(), PRINCIPAL);
    assert_ne!(
        serde_json::to_value(&updated).unwrap(),
        serde_json::to_value(&credential).unwrap()
    );
}

#[test]
fn registration_requires_presence_verification_and_exact_challenge() {
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new();
    let start = verifier
        .begin_registration(PRINCIPAL, "Local owner", &[])
        .unwrap();
    for flags in [0x40, 0x41, 0x44] {
        assert!(
            verifier
                .finish_registration(&start.state, &key.registration(&start.options, flags))
                .is_err()
        );
    }
    let other = verifier
        .begin_registration(PRINCIPAL, "Local owner", &[])
        .unwrap();
    assert_ne!(
        start.options["publicKey"]["challenge"],
        other.options["publicKey"]["challenge"]
    );
    assert!(
        verifier
            .finish_registration(&start.state, &key.registration(&other.options, 0x45))
            .is_err()
    );
    let mut response = key.registration(&start.options, 0x45);
    response.id = URL_SAFE_NO_PAD.encode([9; 32]);
    response.raw_id = response.id.clone();
    assert!(
        verifier
            .finish_registration(&start.state, &response)
            .is_err()
    );
}

#[test]
fn authentication_rejects_invalid_signature_flags_origin_rp_and_identity() {
    let (verifier, key, credential) = registered();
    let start = verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&credential))
        .unwrap();
    for flags in [0, 1, 4] {
        assert!(
            verifier
                .finish_authentication(
                    &start.state,
                    &key.assertion(&start.options, 1, flags, ORIGIN),
                    &credential
                )
                .is_err()
        );
    }
    for origin in [
        "http://localhost:9999",
        "https://localhost:8787",
        "http://sub.localhost:8787",
        "http://127.0.0.1:8787",
    ] {
        assert!(
            verifier
                .finish_authentication(
                    &start.state,
                    &key.assertion(&start.options, 1, 5, origin),
                    &credential
                )
                .is_err()
        );
    }
    let original = key.assertion(&start.options, 1, 5, ORIGIN);
    let mut bad = original.clone();
    bad.response.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(
        verifier
            .finish_authentication(&start.state, &bad, &credential)
            .is_err()
    );
    bad = original.clone();
    let mut data = decode(&bad.response.authenticator_data, 16_384).unwrap();
    data[0] ^= 1;
    bad.response.authenticator_data = URL_SAFE_NO_PAD.encode(data);
    assert!(
        verifier
            .finish_authentication(&start.state, &bad, &credential)
            .is_err()
    );
    bad = original.clone();
    bad.response.user_handle = Some(URL_SAFE_NO_PAD.encode([8; 16]));
    assert!(
        verifier
            .finish_authentication(&start.state, &bad, &credential)
            .is_err()
    );
    bad = original;
    bad.raw_id = URL_SAFE_NO_PAD.encode([9; 16]);
    assert!(
        verifier
            .finish_authentication(&start.state, &bad, &credential)
            .is_err()
    );
}

#[test]
fn counters_and_current_credential_snapshot_prevent_stale_updates() {
    let (verifier, key, credential) = registered();
    let start = verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&credential))
        .unwrap();
    let response = key.assertion(&start.options, 1, 5, ORIGIN);
    let updated = verifier
        .finish_authentication(&start.state, &response, &credential)
        .unwrap();
    assert!(matches!(
        verifier.finish_authentication(&start.state, &response, &updated),
        Err(Error::Stale)
    ));
    let next = verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&updated))
        .unwrap();
    assert!(
        verifier
            .finish_authentication(
                &next.state,
                &key.assertion(&next.options, 1, 5, ORIGIN),
                &updated
            )
            .is_err()
    );
    assert!(
        verifier
            .finish_authentication(
                &next.state,
                &key.assertion(&next.options, 2, 5, ORIGIN),
                &updated
            )
            .is_ok()
    );
}

#[test]
fn synchronized_zero_counter_credentials_still_require_a_fresh_signed_challenge() {
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new();
    let registration = verifier
        .begin_registration(PRINCIPAL, "Local owner", &[])
        .unwrap();
    let credential = verifier
        .finish_registration(
            &registration.state,
            &key.registration(&registration.options, 0x5d),
        )
        .unwrap();
    let start = verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&credential))
        .unwrap();
    let response = key.assertion(&start.options, 0, 0x1d, ORIGIN);
    let updated = verifier
        .finish_authentication(&start.state, &response, &credential)
        .unwrap();
    let next = verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&updated))
        .unwrap();
    assert!(
        verifier
            .finish_authentication(&next.state, &response, &updated)
            .is_err()
    );
    assert!(
        verifier
            .finish_authentication(
                &next.state,
                &key.assertion(&next.options, 0, 0x1d, ORIGIN),
                &updated
            )
            .is_ok()
    );
}

#[test]
fn strict_browser_input_rejects_ambiguous_or_oversized_proofs() {
    let (verifier, key, credential) = registered();
    let start = verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&credential))
        .unwrap();
    let original = key.assertion(&start.options, 1, 5, ORIGIN);
    let mut value = serde_json::to_value(&original).unwrap();
    value["approved"] = true.into();
    assert!(
        fw_contracts::parse_strict::<AuthenticationResponse>(&serde_json::to_vec(&value).unwrap())
            .is_err()
    );
    let mut bad = original.clone();
    bad.response.client_data_json = URL_SAFE_NO_PAD.encode(format!(
        "{{\"type\":\"webauthn.get\",\"type\":\"webauthn.get\",\"origin\":\"{ORIGIN}\"}}"
    ));
    assert!(
        verifier
            .finish_authentication(&start.state, &bad, &credential)
            .is_err()
    );
    bad = original.clone();
    bad.response.signature = "A".repeat(100_000);
    assert!(
        verifier
            .finish_authentication(&start.state, &bad, &credential)
            .is_err()
    );
    bad = original;
    bad.response.client_data_json.push('=');
    assert!(
        verifier
            .finish_authentication(&start.state, &bad, &credential)
            .is_err()
    );
}

#[test]
fn optional_browser_credential_properties_do_not_reject_valid_registration() {
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new();
    let start = verifier
        .begin_registration(PRINCIPAL, "Local owner", &[])
        .unwrap();
    let mut value = serde_json::to_value(key.registration(&start.options, 0x45)).unwrap();
    // Chromium can return this empty dictionary when it cannot determine
    // whether a discoverable credential was created. This output is unsigned.
    value["clientExtensionResults"] = json!({"credProps": {}});
    let response =
        fw_contracts::parse_strict::<RegistrationResponse>(&serde_json::to_vec(&value).unwrap())
            .unwrap();
    assert!(
        verifier
            .finish_registration(&start.state, &response)
            .is_ok()
    );
    value["clientExtensionResults"]["credProps"]["rk"] = "true".into();
    assert!(
        fw_contracts::parse_strict::<RegistrationResponse>(&serde_json::to_vec(&value).unwrap())
            .is_err()
    );
    value["clientExtensionResults"]["credProps"] = json!({"trusted": true});
    assert!(
        fw_contracts::parse_strict::<RegistrationResponse>(&serde_json::to_vec(&value).unwrap())
            .is_err()
    );
}

#[test]
fn only_exact_localhost_origin_and_bounded_owner_credentials_are_admitted() {
    for origin in [
        "http://127.0.0.1:8787",
        "http://localhost:8787/",
        "http://localhost:8787/path",
        "http://localhost:8787?x=1",
        "http://localhost:8787#x",
        "http://user@localhost:8787",
        "https://example.com",
        "http://sub.localhost:8787",
    ] {
        assert!(WebAuthn::new(origin).is_err(), "{origin}");
    }
    let (verifier, _, credential) = registered();
    assert!(
        verifier
            .begin_authentication(
                "22222222-2222-4222-8222-222222222222",
                std::slice::from_ref(&credential)
            )
            .is_err()
    );
    assert!(verifier.begin_authentication(PRINCIPAL, &[]).is_err());
    assert!(
        verifier
            .begin_authentication(PRINCIPAL, &[credential.clone(), credential])
            .is_err()
    );
    assert!(
        verifier
            .begin_registration("not-a-uuid", "Local owner", &[])
            .is_err()
    );
    assert!(verifier.begin_registration(PRINCIPAL, "\n", &[]).is_err());
}

#[test]
fn bound_proof_uses_exact_supplied_digest_and_keeps_normal_login_random() {
    let (verifier, key, credential) = registered();
    let digest = Sha256::digest(b"test-only domain-separated immutable subject and nonce").into();
    let start = verifier
        .begin_bound_authentication(PRINCIPAL, std::slice::from_ref(&credential), digest)
        .unwrap();
    assert_eq!(
        start.options["publicKey"]["challenge"],
        URL_SAFE_NO_PAD.encode(digest)
    );
    assert_eq!(start.options["publicKey"]["userVerification"], "required");
    assert_eq!(start.options["publicKey"]["rpId"], RP_ID);
    assert_eq!(start.options["publicKey"]["timeout"], 300_000);
    let state: BoundAuthenticationState =
        serde_json::from_value(serde_json::to_value(&start.state).unwrap()).unwrap();
    let updated = verifier
        .finish_bound_authentication(
            &state,
            &key.assertion(&start.options, 1, 5, ORIGIN),
            &credential,
            digest,
        )
        .unwrap();
    assert_ne!(
        serde_json::to_value(&updated).unwrap(),
        serde_json::to_value(&credential).unwrap()
    );
    let first = verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&updated))
        .unwrap();
    let second = verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&updated))
        .unwrap();
    for normal in [&first, &second] {
        assert_ne!(
            normal.options["publicKey"]["challenge"],
            start.options["publicKey"]["challenge"]
        );
        assert_eq!(
            decode(
                normal.options["publicKey"]["challenge"].as_str().unwrap(),
                128
            )
            .unwrap()
            .len(),
            32
        );
    }
    assert_ne!(
        first.options["publicKey"]["challenge"],
        second.options["publicKey"]["challenge"]
    );
}

#[test]
fn bound_proofs_reject_changed_digest_and_cross_purpose_state_or_assertions() {
    let (verifier, key, credential) = registered();
    let digest = [37; 32];
    let start = verifier
        .begin_bound_authentication(PRINCIPAL, std::slice::from_ref(&credential), digest)
        .unwrap();
    let proof = key.assertion(&start.options, 1, 5, ORIGIN);
    assert!(matches!(
        verifier.finish_bound_authentication(&start.state, &proof, &credential, [38; 32]),
        Err(Error::Stale)
    ));
    let other = verifier
        .begin_bound_authentication(PRINCIPAL, std::slice::from_ref(&credential), [38; 32])
        .unwrap();
    assert!(
        verifier
            .finish_bound_authentication(
                &start.state,
                &key.assertion(&other.options, 1, 5, ORIGIN),
                &credential,
                digest,
            )
            .is_err()
    );
    let login = verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&credential))
        .unwrap();
    assert!(
        serde_json::from_value::<AuthenticationState>(serde_json::to_value(&start.state).unwrap())
            .is_err()
    );
    assert!(
        serde_json::from_value::<BoundAuthenticationState>(
            serde_json::to_value(&login.state).unwrap()
        )
        .is_err()
    );
    assert!(
        verifier
            .finish_authentication(&login.state, &proof, &credential)
            .is_err()
    );
    assert!(
        verifier
            .finish_bound_authentication(
                &start.state,
                &key.assertion(&login.options, 1, 5, ORIGIN),
                &credential,
                digest,
            )
            .is_err()
    );
    let mut wrong_purpose = start.state.clone();
    wrong_purpose.schema_version = "fw.passkey-authentication/v1".into();
    assert!(matches!(
        verifier.finish_bound_authentication(&wrong_purpose, &proof, &credential, digest),
        Err(Error::Stale)
    ));
    // Changing wrapper metadata cannot replace the challenge stored by the
    // maintained verifier. This proof is genuinely signed for the other digest.
    let mut replaced_digest = start.state.clone();
    replaced_digest.challenge = [38; 32];
    assert!(
        verifier
            .finish_bound_authentication(
                &replaced_digest,
                &key.assertion(&other.options, 1, 5, ORIGIN),
                &credential,
                [38; 32],
            )
            .is_err()
    );
}

#[test]
fn bound_proof_preserves_signature_presence_uv_origin_rp_and_identity_checks() {
    let (verifier, key, credential) = registered();
    let digest = [73; 32];
    let start = verifier
        .begin_bound_authentication(PRINCIPAL, std::slice::from_ref(&credential), digest)
        .unwrap();
    for flags in [0, 1, 4] {
        assert!(
            verifier
                .finish_bound_authentication(
                    &start.state,
                    &key.assertion(&start.options, 1, flags, ORIGIN),
                    &credential,
                    digest,
                )
                .is_err()
        );
    }
    for origin in ["http://localhost:9999", "http://127.0.0.1:8787"] {
        assert!(
            verifier
                .finish_bound_authentication(
                    &start.state,
                    &key.assertion(&start.options, 1, 5, origin),
                    &credential,
                    digest,
                )
                .is_err()
        );
    }
    let proof = key.assertion(&start.options, 1, 5, ORIGIN);
    let mut wrong_rp = proof.clone();
    let mut auth_data = decode(&wrong_rp.response.authenticator_data, 16_384).unwrap();
    auth_data[..32].copy_from_slice(&Sha256::digest(b"other.localhost"));
    wrong_rp.response.authenticator_data = URL_SAFE_NO_PAD.encode(auth_data);
    key.resign(&mut wrong_rp);
    let mut wrong_key = proof.clone();
    Authenticator::new().resign(&mut wrong_key);
    let mut wrong_user = proof.clone();
    wrong_user.response.user_handle = Some(URL_SAFE_NO_PAD.encode([8; 16]));
    let mut wrong_id = proof.clone();
    wrong_id.id = URL_SAFE_NO_PAD.encode([8; 16]);
    wrong_id.raw_id = wrong_id.id.clone();
    for bad in [wrong_rp, wrong_key, wrong_user, wrong_id] {
        assert!(
            verifier
                .finish_bound_authentication(&start.state, &bad, &credential, digest)
                .is_err()
        );
    }
    assert!(
        verifier
            .finish_bound_authentication(&start.state, &proof, &credential, digest)
            .is_ok()
    );
}

#[test]
fn bound_proof_preserves_current_snapshot_and_increasing_counter_checks() {
    let (verifier, key, credential) = registered();
    let first = verifier
        .begin_bound_authentication(PRINCIPAL, std::slice::from_ref(&credential), [11; 32])
        .unwrap();
    let proof = key.assertion(&first.options, 1, 5, ORIGIN);
    let updated = verifier
        .finish_bound_authentication(&first.state, &proof, &credential, [11; 32])
        .unwrap();
    assert!(matches!(
        verifier.finish_bound_authentication(&first.state, &proof, &updated, [11; 32]),
        Err(Error::Stale)
    ));
    let next = verifier
        .begin_bound_authentication(PRINCIPAL, std::slice::from_ref(&updated), [12; 32])
        .unwrap();
    for counter in [0, 1] {
        assert!(
            verifier
                .finish_bound_authentication(
                    &next.state,
                    &key.assertion(&next.options, counter, 5, ORIGIN),
                    &updated,
                    [12; 32],
                )
                .is_err()
        );
    }
    assert!(
        verifier
            .finish_bound_authentication(
                &next.state,
                &key.assertion(&next.options, 2, 5, ORIGIN),
                &updated,
                [12; 32],
            )
            .is_ok()
    );
}

#[test]
fn bound_synchronized_zero_counter_credentials_need_a_new_signed_digest() {
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new();
    let registration = verifier
        .begin_registration(PRINCIPAL, "Local owner", &[])
        .unwrap();
    let credential = verifier
        .finish_registration(
            &registration.state,
            &key.registration(&registration.options, 0x5d),
        )
        .unwrap();
    let first = verifier
        .begin_bound_authentication(PRINCIPAL, std::slice::from_ref(&credential), [21; 32])
        .unwrap();
    let proof = key.assertion(&first.options, 0, 0x1d, ORIGIN);
    let updated = verifier
        .finish_bound_authentication(&first.state, &proof, &credential, [21; 32])
        .unwrap();
    let next = verifier
        .begin_bound_authentication(PRINCIPAL, std::slice::from_ref(&updated), [22; 32])
        .unwrap();
    assert!(
        verifier
            .finish_bound_authentication(&next.state, &proof, &updated, [22; 32])
            .is_err()
    );
    assert!(
        verifier
            .finish_bound_authentication(
                &next.state,
                &key.assertion(&next.options, 0, 0x1d, ORIGIN),
                &updated,
                [22; 32],
            )
            .is_ok()
    );
    assert!(
        verifier
            .finish_bound_authentication(
                &next.state,
                &key.assertion(&next.options, 0, 5, ORIGIN),
                &updated,
                [22; 32],
            )
            .is_err()
    );
}

#[test]
fn bound_ceremonies_keep_strict_input_and_owner_scope() {
    let (verifier, key, credential) = registered();
    assert!(
        verifier
            .begin_bound_authentication(PRINCIPAL, &[], [1; 32])
            .is_err()
    );
    assert!(
        verifier
            .begin_bound_authentication(
                "22222222-2222-4222-8222-222222222222",
                std::slice::from_ref(&credential),
                [1; 32],
            )
            .is_err()
    );
    let start = verifier
        .begin_bound_authentication(PRINCIPAL, std::slice::from_ref(&credential), [1; 32])
        .unwrap();
    let mut proof = key.assertion(&start.options, 1, 5, ORIGIN);
    proof.response.client_data_json = URL_SAFE_NO_PAD.encode(format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{ORIGIN}\",\"origin\":\"{ORIGIN}\"}}",
        URL_SAFE_NO_PAD.encode([1; 32])
    ));
    key.resign(&mut proof);
    assert!(
        verifier
            .finish_bound_authentication(&start.state, &proof, &credential, [1; 32])
            .is_err()
    );
    let proof = key.assertion(&start.options, 1, 5, ORIGIN);
    assert!(
        WebAuthn::new("http://localhost:9999")
            .unwrap()
            .finish_bound_authentication(&start.state, &proof, &credential, [1; 32])
            .is_err()
    );
}

#![cfg(feature = "approval-proofs")]

//! Cryptographic bridge tests with real P-256 signatures and retained state.
//! These exercise no authority transaction, membership service, or human consent.
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;

use approval_authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fw_authority::{
    ApprovalChallenge, ApprovalChallengeContext, ApprovalChallengeSubject, ApprovalDecision,
    ApprovalPlanKind, ApprovalPlanRef, ApprovalProofCeremony, ApprovalProofState, ApprovalRole,
    AuthorityError, VerifiedBoundAssertion, begin_approval_proof, finish_approval_proof,
};
use fw_webauthn::{AuthenticationResponse, Credential, WebAuthn};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const NOW: i64 = 1_700_000_000;
const OTHER_ID: &str = "99999999-9999-4999-8999-999999999999";

fn context() -> ApprovalChallengeContext {
    ApprovalChallengeContext {
        org_id: "22222222-2222-4222-8222-222222222222".into(),
        project_id: "33333333-3333-4333-8333-333333333333".into(),
        principal_id: PRINCIPAL.into(),
        subject: ApprovalChallengeSubject::Plan {
            plan_ref: ApprovalPlanRef {
                plan_kind: ApprovalPlanKind::PolicyChange,
                plan_id: "44444444-4444-4444-8444-444444444444".into(),
                plan_hash: fw_contracts::hash_bytes(b"immutable policy plan"),
            },
        },
        requirements_hash: fw_contracts::hash_bytes(b"current approval requirements"),
        decision: ApprovalDecision::Approve,
        role: ApprovalRole::Owner,
        subject_valid_until: NOW + 600,
    }
}

struct Fixture {
    verifier: WebAuthn,
    key: Authenticator,
    credential: Credential,
    context: ApprovalChallengeContext,
    challenge: ApprovalChallenge,
    ceremony: ApprovalProofCeremony,
}

impl Fixture {
    fn new() -> Self {
        Self::with_counter(1)
    }

    fn with_counter(counter: u32) -> Self {
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let key = Authenticator::new(PRINCIPAL);
        let registration = verifier
            .begin_registration(PRINCIPAL, "Integration test key", &[])
            .unwrap();
        let registered = verifier
            .finish_registration(
                &registration.state,
                &key.registration(&registration.options),
            )
            .unwrap();
        // A none-attestation registration is not a signed possession proof.
        // First establish the current credential through a genuine signed login.
        let login = verifier
            .begin_authentication(PRINCIPAL, std::slice::from_ref(&registered))
            .unwrap();
        let credential = verifier
            .finish_authentication(
                &login.state,
                &key.assertion(&login.options, counter, 0x05, ORIGIN),
                &registered,
            )
            .unwrap();
        let context = context();
        let challenge = ApprovalChallenge::issue(&context, &verifier, NOW).unwrap();
        let ceremony = begin_approval_proof(
            &verifier,
            &challenge,
            &context,
            std::slice::from_ref(&credential),
            NOW,
        )
        .unwrap();
        Self {
            verifier,
            key,
            credential,
            context,
            challenge,
            ceremony,
        }
    }

    fn assertion(&self) -> AuthenticationResponse {
        self.key.assertion(&self.ceremony.options, 2, 0x05, ORIGIN)
    }

    fn finish(
        &self,
        response: &AuthenticationResponse,
    ) -> Result<VerifiedBoundAssertion, AuthorityError> {
        finish_approval_proof(
            &self.verifier,
            &self.ceremony.state,
            &self.challenge,
            &self.context,
            response,
            &self.credential,
            NOW + 1,
        )
    }
}

#[test]
fn signed_plan_proof_survives_state_roundtrip_and_retains_original_bytes() {
    let f = Fixture::new();
    assert_eq!(
        f.ceremony.options["publicKey"]["challenge"],
        URL_SAFE_NO_PAD.encode(f.challenge.challenge_bytes())
    );
    assert_eq!(
        f.ceremony.options["publicKey"]["userVerification"],
        "required"
    );
    let restored_challenge = ApprovalChallenge::from_json(f.challenge.canonical_payload()).unwrap();
    let restored_state =
        ApprovalProofState::from_json(&serde_json::to_vec(&f.ceremony.state).unwrap()).unwrap();
    let mut response = f.assertion();
    // The signature covers these exact whitespace and member-order choices.
    // Re-canonicalizing clientDataJSON before verification would invalidate it.
    let client_data = format!(
        "{{\n  \"origin\": {origin}, \"crossOrigin\": false,\n  \"challenge\": {challenge}, \"type\": \"webauthn.get\"\n}}",
        origin = json!(ORIGIN),
        challenge = f.ceremony.options["publicKey"]["challenge"],
    );
    response.response.client_data_json = URL_SAFE_NO_PAD.encode(client_data.as_bytes());
    f.key.resign(&mut response);
    let verified = finish_approval_proof(
        &f.verifier,
        &restored_state,
        &restored_challenge,
        &f.context,
        &response,
        &f.credential,
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        verified.challenge().payload_hash(),
        f.challenge.payload_hash()
    );
    assert_eq!(
        verified.challenge().canonical_payload(),
        f.challenge.canonical_payload()
    );
    assert_eq!(verified.challenge().subject(), &f.context.subject);
    assert_eq!(verified.verified_at(), NOW + 1);
    assert_eq!(
        serde_json::to_value(verified.assertion()).unwrap(),
        serde_json::to_value(&response).unwrap()
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(&verified.assertion().response.client_data_json)
            .unwrap(),
        client_data.as_bytes()
    );
    assert_eq!(verified.updated_credential().id(), f.credential.id());
    assert_eq!(verified.updated_credential().principal_id(), PRINCIPAL);
    assert_ne!(
        serde_json::to_value(verified.updated_credential()).unwrap(),
        serde_json::to_value(&f.credential).unwrap()
    );
}

#[test]
fn freshly_resolved_authority_context_must_match_every_bound_input() {
    let f = Fixture::new();
    let response = f.assertion();
    type Change = (&'static str, fn(&mut ApprovalChallengeContext));
    let changes: [Change; 11] = [
        ("organization", |c| c.org_id = OTHER_ID.into()),
        ("project", |c| c.project_id = OTHER_ID.into()),
        ("principal", |c| c.principal_id = OTHER_ID.into()),
        ("plan identifier", |c| {
            let ApprovalChallengeSubject::Plan { plan_ref } = &mut c.subject else {
                unreachable!()
            };
            plan_ref.plan_id = OTHER_ID.into();
        }),
        ("plan hash", |c| {
            let ApprovalChallengeSubject::Plan { plan_ref } = &mut c.subject else {
                unreachable!()
            };
            plan_ref.plan_hash = fw_contracts::hash_bytes(b"changed policy plan");
        }),
        ("plan kind", |c| {
            let ApprovalChallengeSubject::Plan { plan_ref } = &mut c.subject else {
                unreachable!()
            };
            plan_ref.plan_kind = ApprovalPlanKind::AddAccessLease;
        }),
        ("requirements", |c| {
            c.requirements_hash = fw_contracts::hash_bytes(b"changed requirements");
        }),
        ("decision", |c| c.decision = ApprovalDecision::Reject),
        ("role", |c| c.role = ApprovalRole::NetworkReviewer),
        ("shorter subject expiry", |c| c.subject_valid_until -= 1),
        ("extended subject expiry", |c| c.subject_valid_until += 1),
    ];
    for (name, change) in changes {
        let mut current = f.context.clone();
        change(&mut current);
        assert!(
            matches!(
                begin_approval_proof(
                    &f.verifier,
                    &f.challenge,
                    &current,
                    std::slice::from_ref(&f.credential),
                    NOW,
                ),
                Err(AuthorityError::Binding)
            ),
            "begin accepted changed {name}"
        );
        assert!(
            matches!(
                finish_approval_proof(
                    &f.verifier,
                    &f.ceremony.state,
                    &f.challenge,
                    &current,
                    &response,
                    &f.credential,
                    NOW + 1,
                ),
                Err(AuthorityError::Binding)
            ),
            "finish accepted changed {name}"
        );
    }
    assert!(f.finish(&response).is_ok());
}

#[test]
fn expired_or_not_yet_valid_proofs_and_changed_verifier_origin_are_rejected() {
    let f = Fixture::new();
    let response = f.assertion();
    for at in [
        NOW - 1,
        f.challenge.expires_at(),
        f.context.subject_valid_until,
    ] {
        assert!(matches!(
            finish_approval_proof(
                &f.verifier,
                &f.ceremony.state,
                &f.challenge,
                &f.context,
                &response,
                &f.credential,
                at,
            ),
            Err(AuthorityError::Time)
        ));
    }
    assert!(
        finish_approval_proof(
            &f.verifier,
            &f.ceremony.state,
            &f.challenge,
            &f.context,
            &response,
            &f.credential,
            f.challenge.expires_at() - 1,
        )
        .is_ok()
    );
    let other_origin = WebAuthn::new("http://localhost:8788").unwrap();
    assert!(matches!(
        finish_approval_proof(
            &other_origin,
            &f.ceremony.state,
            &f.challenge,
            &f.context,
            &response,
            &f.credential,
            NOW,
        ),
        Err(AuthorityError::Binding)
    ));
}

#[test]
fn identical_context_with_fresh_nonce_cannot_reuse_old_state_or_signature() {
    let f = Fixture::new();
    let next = ApprovalChallenge::issue(&f.context, &f.verifier, NOW).unwrap();
    assert_ne!(next.payload_hash(), f.challenge.payload_hash());
    assert_ne!(next.challenge_bytes(), f.challenge.challenge_bytes());
    let response = f.assertion();
    assert!(matches!(
        finish_approval_proof(
            &f.verifier,
            &f.ceremony.state,
            &next,
            &f.context,
            &response,
            &f.credential,
            NOW,
        ),
        Err(AuthorityError::Binding)
    ));
    let next_ceremony = begin_approval_proof(
        &f.verifier,
        &next,
        &f.context,
        std::slice::from_ref(&f.credential),
        NOW,
    )
    .unwrap();
    assert!(matches!(
        finish_approval_proof(
            &f.verifier,
            &next_ceremony.state,
            &next,
            &f.context,
            &response,
            &f.credential,
            NOW,
        ),
        Err(AuthorityError::Signature)
    ));
    let next_response = f.key.assertion(&next_ceremony.options, 2, 5, ORIGIN);
    assert!(
        finish_approval_proof(
            &f.verifier,
            &next_ceremony.state,
            &next,
            &f.context,
            &next_response,
            &f.credential,
            NOW,
        )
        .is_ok()
    );
}

#[test]
fn signed_policy_and_authority_bootstrap_subjects_are_not_interchangeable() {
    let f = Fixture::new();
    let mut bootstrap_context = f.context.clone();
    bootstrap_context.subject = ApprovalChallengeSubject::AuthorityBootstrap {
        manifest_id: "55555555-5555-4555-8555-555555555555".into(),
        subject_hash: fw_contracts::hash_bytes(b"immutable authority bootstrap manifest"),
    };
    let bootstrap = ApprovalChallenge::issue(&bootstrap_context, &f.verifier, NOW).unwrap();
    let ceremony = begin_approval_proof(
        &f.verifier,
        &bootstrap,
        &bootstrap_context,
        std::slice::from_ref(&f.credential),
        NOW,
    )
    .unwrap();
    let response = f.key.assertion(&ceremony.options, 2, 5, ORIGIN);
    let verified = finish_approval_proof(
        &f.verifier,
        &ceremony.state,
        &bootstrap,
        &bootstrap_context,
        &response,
        &f.credential,
        NOW,
    )
    .unwrap();
    assert_eq!(verified.challenge().subject(), &bootstrap_context.subject);
    assert!(verified.challenge().plan_challenge_response().is_none());
    assert!(f.challenge.plan_challenge_response().is_some());
    assert!(matches!(
        f.finish(&response),
        Err(AuthorityError::Signature)
    ));
    assert!(matches!(
        finish_approval_proof(
            &f.verifier,
            &ceremony.state,
            &bootstrap,
            &bootstrap_context,
            &f.assertion(),
            &f.credential,
            NOW,
        ),
        Err(AuthorityError::Signature)
    ));
    assert!(matches!(
        finish_approval_proof(
            &f.verifier,
            &f.ceremony.state,
            &f.challenge,
            &bootstrap_context,
            &f.assertion(),
            &f.credential,
            NOW,
        ),
        Err(AuthorityError::Binding)
    ));
}

#[test]
fn ordinary_signed_login_is_not_a_plan_bound_proof_or_state() {
    let f = Fixture::new();
    let login = f
        .verifier
        .begin_authentication(PRINCIPAL, std::slice::from_ref(&f.credential))
        .unwrap();
    let login_response = f.key.assertion(&login.options, 2, 5, ORIGIN);
    assert!(
        f.verifier
            .finish_authentication(&login.state, &login_response, &f.credential,)
            .is_ok()
    );
    assert!(matches!(
        f.finish(&login_response),
        Err(AuthorityError::Signature)
    ));
    assert!(
        f.verifier
            .finish_authentication(&login.state, &f.assertion(), &f.credential,)
            .is_err()
    );
    let mut state = serde_json::to_value(&f.ceremony.state).unwrap();
    state["webauthn"] = serde_json::to_value(&login.state).unwrap();
    assert!(ApprovalProofState::from_json(&serde_json::to_vec(&state).unwrap()).is_err());
}

#[test]
fn signature_presence_verification_origin_rp_and_user_handle_are_checked() {
    let f = Fixture::new();
    for flags in [0, 1, 4] {
        let response = f.key.assertion(&f.ceremony.options, 2, flags, ORIGIN);
        assert!(
            matches!(f.finish(&response), Err(AuthorityError::Signature)),
            "flags {flags}"
        );
    }
    for origin in [
        "http://localhost:9999",
        "https://localhost:8787",
        "http://127.0.0.1:8787",
    ] {
        let response = f.key.assertion(&f.ceremony.options, 2, 5, origin);
        assert!(matches!(
            f.finish(&response),
            Err(AuthorityError::Signature)
        ));
    }
    let good = f.assertion();
    let mut wrong_rp = good.clone();
    let mut auth_data = URL_SAFE_NO_PAD
        .decode(&wrong_rp.response.authenticator_data)
        .unwrap();
    auth_data[..32].copy_from_slice(&Sha256::digest(b"other.localhost"));
    wrong_rp.response.authenticator_data = URL_SAFE_NO_PAD.encode(auth_data);
    f.key.resign(&mut wrong_rp); // A valid signature must not hide a wrong RP hash.
    assert!(matches!(
        f.finish(&wrong_rp),
        Err(AuthorityError::Signature)
    ));
    let mut wrong_handle = good.clone();
    wrong_handle.response.user_handle =
        Some(URL_SAFE_NO_PAD.encode(uuid::Uuid::parse_str(OTHER_ID).unwrap().as_bytes()));
    assert!(matches!(
        f.finish(&wrong_handle),
        Err(AuthorityError::Signature)
    ));
    let mut forged = good.clone();
    let mut signature = URL_SAFE_NO_PAD.decode(&forged.response.signature).unwrap();
    *signature.last_mut().unwrap() ^= 1;
    forged.response.signature = URL_SAFE_NO_PAD.encode(signature);
    assert!(matches!(f.finish(&forged), Err(AuthorityError::Signature)));
    assert!(f.finish(&good).is_ok());
}

#[test]
fn current_credential_snapshot_and_monotonic_counter_are_required() {
    let f = Fixture::new();
    let response = f.assertion();
    let verified = f.finish(&response).unwrap();
    let current = verified.updated_credential();
    // Supplying the newer protected-store credential must not make a saved
    // ceremony silently verify against its stale embedded counter snapshot.
    assert!(matches!(
        finish_approval_proof(
            &f.verifier,
            &f.ceremony.state,
            &f.challenge,
            &f.context,
            &response,
            current,
            NOW,
        ),
        Err(AuthorityError::Binding)
    ));
    let next = ApprovalChallenge::issue(&f.context, &f.verifier, NOW + 1).unwrap();
    let ceremony = begin_approval_proof(
        &f.verifier,
        &next,
        &f.context,
        std::slice::from_ref(current),
        NOW + 1,
    )
    .unwrap();
    for counter in [0, 1, 2] {
        let stale = f.key.assertion(&ceremony.options, counter, 5, ORIGIN);
        assert!(
            matches!(
                finish_approval_proof(
                    &f.verifier,
                    &ceremony.state,
                    &next,
                    &f.context,
                    &stale,
                    current,
                    NOW + 1,
                ),
                Err(AuthorityError::Signature)
            ),
            "non-increasing counter {counter}"
        );
    }
    let fresh = f.key.assertion(&ceremony.options, 3, 5, ORIGIN);
    assert!(
        finish_approval_proof(
            &f.verifier,
            &ceremony.state,
            &next,
            &f.context,
            &fresh,
            current,
            NOW + 1,
        )
        .is_ok()
    );
}

#[test]
fn zero_counter_verification_does_not_claim_durable_challenge_consumption() {
    let f = Fixture::with_counter(0);
    let response = f.key.assertion(&f.ceremony.options, 0, 5, ORIGIN);
    let verified = f.finish(&response).unwrap();
    // Authenticators may legitimately keep a zero counter. The pure bridge
    // cannot enforce one use; a separate protected transaction must consume it.
    assert!(
        finish_approval_proof(
            &f.verifier,
            &f.ceremony.state,
            &f.challenge,
            &f.context,
            &response,
            verified.updated_credential(),
            NOW + 1,
        )
        .is_ok()
    );
}

#[test]
fn retained_state_is_bounded_closed_and_rejects_duplicate_json_members() {
    let f = Fixture::new();
    let original = serde_json::to_value(&f.ceremony.state).unwrap();
    for (name, replacement) in [
        ("schema_version", json!("fw.approval-proof-state/v0")),
        ("challenge_payload_hash", json!("not-a-digest")),
        ("approved", json!(true)),
    ] {
        let mut bad = original.clone();
        bad[name] = replacement;
        assert!(ApprovalProofState::from_json(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let mut bad = original.clone();
    bad["webauthn"]["approved"] = json!(true);
    assert!(ApprovalProofState::from_json(&serde_json::to_vec(&bad).unwrap()).is_err());
    let text = serde_json::to_string(&original).unwrap();
    let duplicate_outer = format!(
        "{{\"schema_version\":\"fw.approval-proof-state/v1\",{}",
        &text[1..]
    );
    assert!(ApprovalProofState::from_json(duplicate_outer.as_bytes()).is_err());
    let duplicate_nested = text.replacen(
        "\"webauthn\":{",
        &format!("\"webauthn\":{{\"principal_id\":\"{PRINCIPAL}\","),
        1,
    );
    assert_ne!(duplicate_nested, text);
    assert!(ApprovalProofState::from_json(duplicate_nested.as_bytes()).is_err());
    let mut oversized = text.into_bytes();
    oversized.resize(fw_contracts::MAX_BODY_BYTES + 1, b' ');
    assert!(ApprovalProofState::from_json(&oversized).is_err());
    assert!(ApprovalProofState::from_json(&serde_json::to_vec(&original).unwrap()).is_ok());
}

#[test]
fn well_formed_but_mismatched_retained_state_does_not_authorize_a_proof() {
    let f = Fixture::new();
    let original = serde_json::to_value(&f.ceremony.state).unwrap();
    let changes: [(&str, Value); 4] = [
        (
            "/challenge_payload_hash",
            json!(fw_contracts::hash_bytes(b"different payload")),
        ),
        (
            "/webauthn/schema_version",
            json!("fw.passkey-authentication/v1"),
        ),
        ("/webauthn/origin", json!("http://localhost:9999")),
        ("/webauthn/challenge", json!(vec![0_u8; 32])),
    ];
    for (pointer, replacement) in changes {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = replacement;
        let state = ApprovalProofState::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            finish_approval_proof(
                &f.verifier,
                &state,
                &f.challenge,
                &f.context,
                &f.assertion(),
                &f.credential,
                NOW,
            ),
            Err(AuthorityError::Binding)
        ));
    }
}

#[test]
fn current_credential_must_belong_to_the_bound_principal_and_signing_key() {
    let f = Fixture::new();
    let other_key = Fixture::new();
    assert!(matches!(
        finish_approval_proof(
            &f.verifier,
            &f.ceremony.state,
            &f.challenge,
            &f.context,
            &f.assertion(),
            &other_key.credential,
            NOW,
        ),
        Err(AuthorityError::Signature)
    ));

    let outsider_key = Authenticator::new(OTHER_ID);
    let registration = f
        .verifier
        .begin_registration(OTHER_ID, "Other principal", &[])
        .unwrap();
    let registered = f
        .verifier
        .finish_registration(
            &registration.state,
            &outsider_key.registration(&registration.options),
        )
        .unwrap();
    let login = f
        .verifier
        .begin_authentication(OTHER_ID, std::slice::from_ref(&registered))
        .unwrap();
    let outsider = f
        .verifier
        .finish_authentication(
            &login.state,
            &outsider_key.assertion(&login.options, 1, 5, ORIGIN),
            &registered,
        )
        .unwrap();
    assert!(matches!(
        finish_approval_proof(
            &f.verifier,
            &f.ceremony.state,
            &f.challenge,
            &f.context,
            &f.assertion(),
            &outsider,
            NOW,
        ),
        Err(AuthorityError::Binding)
    ));
}

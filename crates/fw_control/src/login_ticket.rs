//! Process-scoped encrypted login state. Registration uses protected DB state.
//! A ticket alone cannot authenticate: completion verifies a current credential
//! and atomically records successful consumption in the controller database.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::{Compression, Decompress, FlushDecompress, Status, write::DeflateEncoder};
use fw_webauthn::AuthenticationState;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    sign::Signer,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
};
use subtle::ConstantTimeEq;

const PURPOSE: &str = "fw.local-login-ticket/v1";
const PREFIX: &str = "login1.";
const MAX_PLAINTEXT: usize = 65536 + 1024;
const MAX_ENCODED: usize = 26000;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const NONCE_VERSION: &[u8; 4] = b"FWT2";
const MAX_CIPHERTEXT: usize = (MAX_ENCODED - PREFIX.len()) * 3 / 4 - NONCE_BYTES - TAG_BYTES;
const MAX_AAD: usize = 4096;
const EPOCH_BITS: u32 = 16;
const SECONDS: i64 = 300;

// Never Clone: one allocator belongs to each boot-random master. Every derived
// AES key encrypts at most 2^16 tickets and fewer than 2^27 GHASH input blocks
// (ciphertext + AAD + length block). Failed verification attempts are separate.
pub(super) struct LoginTickets {
    master: [u8; 32],
    next: AtomicU64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoginClaims {
    purpose: String,
    pub challenge_id: String,
    org_id: String,
    project_id: String,
    principal_id: String,
    origin: String,
    pub session_binding: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub state: AuthenticationState,
}

impl LoginTickets {
    pub fn new() -> Result<Self, openssl::error::ErrorStack> {
        let mut key = [0; 32];
        openssl::rand::rand_bytes(&mut key)?;
        Ok(Self {
            master: key,
            next: AtomicU64::new(0),
        })
    }
    fn epoch_key(&self, sequence: u64) -> Result<[u8; 32], ()> {
        let master = PKey::hmac(&self.master).map_err(|_| ())?;
        let mut signer = Signer::new(MessageDigest::sha256(), &master).map_err(|_| ())?;
        signer
            .update(b"fw.local-login-ticket/aes-gcm-epoch/v2\0")
            .map_err(|_| ())?;
        signer
            .update(&(sequence >> EPOCH_BITS).to_be_bytes())
            .map_err(|_| ())?;
        signer
            .sign_to_vec()
            .map_err(|_| ())?
            .try_into()
            .map_err(|_| ())
    }
    fn next_nonce(&self) -> Result<[u8; NONCE_BYTES], ()> {
        let sequence = self
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| ())?;
        let mut nonce = [0; NONCE_BYTES];
        nonce[..4].copy_from_slice(NONCE_VERSION);
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        Ok(nonce)
    }
    fn opening_key(&self, nonce: &[u8]) -> Result<[u8; 32], ()> {
        if nonce.len() != NONCE_BYTES || &nonce[..4] != NONCE_VERSION {
            return Err(());
        }
        let sequence = u64::from_be_bytes(nonce[4..].try_into().map_err(|_| ())?);
        if sequence >= self.next.load(Ordering::Relaxed) {
            return Err(());
        }
        self.epoch_key(sequence)
    }
    pub fn issue(
        &self,
        origin: &str,
        binding: String,
        state: AuthenticationState,
        now: i64,
    ) -> Result<(String, i64), ()> {
        if fw_contracts::canonical_bytes(&state).map_err(|_| ())?.len() > 65536 {
            return Err(());
        }
        let claims = LoginClaims {
            purpose: PURPOSE.into(),
            challenge_id: uuid::Uuid::new_v4().to_string(),
            org_id: super::ORG.into(),
            project_id: super::PROJECT.into(),
            principal_id: super::PRINCIPAL.into(),
            origin: origin.into(),
            session_binding: binding,
            issued_at: now,
            expires_at: now.checked_add(SECONDS).ok_or(())?,
            state,
        };
        self.validate(&claims, origin, &claims.session_binding, now)?;
        Ok((self.seal(&claims, origin)?, claims.expires_at))
    }
    fn seal(&self, claims: &LoginClaims, origin: &str) -> Result<String, ()> {
        let plaintext = fw_contracts::canonical_bytes(claims).map_err(|_| ())?;
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(());
        }
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&plaintext).map_err(|_| ())?;
        let compressed = encoder.finish().map_err(|_| ())?;
        let aad = associated_data(origin);
        if compressed.len() > MAX_CIPHERTEXT || aad.len() > MAX_AAD {
            return Err(());
        }
        let nonce = self.next_nonce()?;
        let key = self.opening_key(&nonce)?;
        let mut tag = [0; TAG_BYTES];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &key,
            Some(&nonce),
            &aad,
            &compressed,
            &mut tag,
        )
        .map_err(|_| ())?;
        let mut envelope = Vec::with_capacity(NONCE_BYTES + ciphertext.len() + TAG_BYTES);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        envelope.extend_from_slice(&tag);
        let encoded = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(envelope));
        if encoded.len() > MAX_ENCODED {
            return Err(());
        }
        Ok(encoded)
    }
    pub fn open(
        &self,
        token: &str,
        origin: &str,
        binding: &str,
        now: i64,
    ) -> Result<LoginClaims, ()> {
        if token.len() > MAX_ENCODED {
            return Err(());
        }
        let encoded = token.strip_prefix(PREFIX).ok_or(())?;
        if encoded.is_empty()
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(());
        }
        let envelope = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?;
        if URL_SAFE_NO_PAD.encode(&envelope) != encoded
            || envelope.len() <= NONCE_BYTES + TAG_BYTES
            || envelope.len() > MAX_CIPHERTEXT + NONCE_BYTES + TAG_BYTES
        {
            return Err(());
        }
        let (nonce, rest) = envelope.split_at(NONCE_BYTES);
        let (ciphertext, tag) = rest.split_at(rest.len() - TAG_BYTES);
        let aad = associated_data(origin);
        if aad.len() > MAX_AAD {
            return Err(());
        }
        let key = self.opening_key(nonce)?;
        let compressed = decrypt_aead(
            Cipher::aes_256_gcm(),
            &key,
            Some(nonce),
            &aad,
            ciphertext,
            tag,
        )
        .map_err(|_| ())?;
        let plaintext = decompress(&compressed)?;
        let claims: LoginClaims =
            fw_contracts::parse_strict_with_limit(&plaintext, MAX_PLAINTEXT).map_err(|_| ())?;
        self.validate(&claims, origin, binding, now)?;
        Ok(claims)
    }
    fn validate(
        &self,
        claims: &LoginClaims,
        origin: &str,
        binding: &str,
        now: i64,
    ) -> Result<(), ()> {
        if claims.purpose != PURPOSE
            || !super::uuid(&claims.challenge_id)
            || claims.org_id != super::ORG
            || claims.project_id != super::PROJECT
            || claims.principal_id != super::PRINCIPAL
            || claims.origin != origin
            || !bool::from(claims.session_binding.as_bytes().ct_eq(binding.as_bytes()))
            || !binding.starts_with("sha256:")
            || binding.len() != 71
            || !binding.as_bytes()[7..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            || claims.issued_at < 0
            || claims.expires_at > 253_402_300_799
            || claims.expires_at.checked_sub(claims.issued_at) != Some(SECONDS)
            || now < claims.issued_at
            || now >= claims.expires_at
        {
            return Err(());
        }
        Ok(())
    }
}

// Only AEAD-authenticated bytes reach this parser. A single fixed-capacity
// output buffer and exact stream consumption reject bombs/truncation/trailing
// streams even if a future issuing path supplies malformed compressed state.
fn decompress(compressed: &[u8]) -> Result<Vec<u8>, ()> {
    let mut inflater = Decompress::new(false);
    let mut output = vec![0; MAX_PLAINTEXT + 1];
    let status = inflater
        .decompress(compressed, &mut output, FlushDecompress::Finish)
        .map_err(|_| ())?;
    if status != Status::StreamEnd
        || inflater.total_in() != compressed.len() as u64
        || inflater.total_out() > MAX_PLAINTEXT as u64
    {
        return Err(());
    }
    output.truncate(inflater.total_out() as usize);
    Ok(output)
}

fn associated_data(origin: &str) -> Vec<u8> {
    let mut bytes = b"fw.local-login-ticket/v1\0".to_vec();
    bytes.extend_from_slice(origin.as_bytes());
    bytes
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../fw_authority/tests/support/approval_authenticator.rs"]
mod test_authenticator;

#[cfg(test)]
mod tests {
    use super::*;
    use fw_webauthn::{Credential, WebAuthn};
    use test_authenticator::{Authenticator, ORIGIN};

    const NOW: i64 = 1_700_000_000;
    fn state(large: bool) -> AuthenticationState {
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let key = Authenticator::new(crate::PRINCIPAL);
        let registration = verifier
            .begin_registration(crate::PRINCIPAL, "Owner", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &key.registration(&registration.options),
            )
            .unwrap();
        let credentials = if large {
            (0..8)
                .map(|_| {
                    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
                    let mut id = vec![0; 1024];
                    openssl::rand::rand_bytes(&mut id).unwrap();
                    let mut value = serde_json::to_value(&credential).unwrap();
                    value["passkey"]["cred"]["cred_id"] = URL_SAFE_NO_PAD.encode(id).into();
                    value["passkey"]["cred"]["cred"] = serde_json::json!({"type_":"RS256",
                    "key":{"RSA":{"n":URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),"e":[1,0,1]}}});
                    serde_json::from_value::<Credential>(value).unwrap()
                })
                .collect()
        } else {
            vec![credential]
        };
        verifier
            .begin_authentication(crate::PRINCIPAL, &credentials)
            .unwrap()
            .state
    }
    fn binding() -> String {
        fw_contracts::hash_bytes(b"server browser secret")
    }

    #[test]
    fn ticket_nonces_have_a_checked_unique_sequence() {
        let key = LoginTickets::new().unwrap();
        let state = state(false);
        for sequence in 0u64..2 {
            let (token, _) = key.issue(ORIGIN, binding(), state.clone(), NOW).unwrap();
            let envelope = URL_SAFE_NO_PAD
                .decode(token.strip_prefix(PREFIX).unwrap())
                .unwrap();
            assert_eq!(&envelope[..4], b"FWT2");
            assert_eq!(&envelope[4..12], &sequence.to_be_bytes());
        }
    }

    #[test]
    fn epoch_rollovers_preserve_pending_tickets_and_exhaustion_never_wraps() {
        let key = LoginTickets::new().unwrap();
        let state = state(false);
        let mut tokens = vec![key.issue(ORIGIN, binding(), state.clone(), NOW).unwrap().0];
        assert_eq!(
            key.epoch_key(0).unwrap(),
            key.epoch_key((1 << EPOCH_BITS) - 1).unwrap()
        );
        assert_ne!(
            key.epoch_key(0).unwrap(),
            key.epoch_key(1 << EPOCH_BITS).unwrap()
        );
        for sequence in [
            (1 << EPOCH_BITS) - 1,
            1 << EPOCH_BITS,
            (2 << EPOCH_BITS) - 1,
            2 << EPOCH_BITS,
            u64::MAX - 1,
        ] {
            // Jump to the boundary; no requirement for 2^64 real issuances.
            key.next.store(sequence, Ordering::Relaxed);
            tokens.push(key.issue(ORIGIN, binding(), state.clone(), NOW).unwrap().0);
        }
        assert!(key.issue(ORIGIN, binding(), state, NOW).is_err());
        assert_eq!(key.next.load(Ordering::Relaxed), u64::MAX);
        for token in tokens {
            assert!(
                key.open(&token, ORIGIN, &binding(), NOW + SECONDS - 1)
                    .is_ok()
            );
            assert!(key.open(&token, ORIGIN, &binding(), NOW + SECONDS).is_err());
            assert!(
                LoginTickets::new()
                    .unwrap()
                    .open(&token, ORIGIN, &binding(), NOW)
                    .is_err()
            );
            let envelope = URL_SAFE_NO_PAD
                .decode(token.strip_prefix(PREFIX).unwrap())
                .unwrap();
            assert!(
                decrypt_aead(
                    Cipher::aes_256_gcm(),
                    &key.master,
                    Some(&envelope[..12]),
                    &associated_data(ORIGIN),
                    &envelope[12..envelope.len() - 16],
                    &envelope[envelope.len() - 16..]
                )
                .is_err()
            );
        }
    }

    #[test]
    fn concurrent_ticket_issuance_allocates_each_nonce_once() {
        let key = std::sync::Arc::new(LoginTickets::new().unwrap());
        let state = state(false);
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let key = key.clone();
                let state = state.clone();
                std::thread::spawn(move || {
                    (0..32)
                        .map(|_| {
                            let (token, _) =
                                key.issue(ORIGIN, binding(), state.clone(), NOW).unwrap();
                            assert!(key.open(&token, ORIGIN, &binding(), NOW).is_ok());
                            let envelope = URL_SAFE_NO_PAD
                                .decode(token.strip_prefix(PREFIX).unwrap())
                                .unwrap();
                            u64::from_be_bytes(envelope[4..12].try_into().unwrap())
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut sequences: Vec<_> = workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect();
        sequences.sort_unstable();
        assert_eq!(sequences, (0..256).collect::<Vec<_>>());
    }

    #[test]
    fn future_nonce_epochs_and_oversized_associated_data_are_rejected() {
        let key = LoginTickets::new().unwrap();
        let (token, _) = key.issue(ORIGIN, binding(), state(false), NOW).unwrap();
        let mut envelope = URL_SAFE_NO_PAD
            .decode(token.strip_prefix(PREFIX).unwrap())
            .unwrap();
        for sequence in [1, 1 << EPOCH_BITS, u64::MAX] {
            envelope[4..12].copy_from_slice(&sequence.to_be_bytes());
            assert!(key.opening_key(&envelope[..12]).is_err());
            assert!(
                key.open(
                    &format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&envelope)),
                    ORIGIN,
                    &binding(),
                    NOW
                )
                .is_err()
            );
        }
        let claims = key.open(&token, ORIGIN, &binding(), NOW).unwrap();
        assert!(key.seal(&claims, &"x".repeat(MAX_AAD)).is_err());
        assert!(
            key.open(&token, &"x".repeat(MAX_AAD), &binding(), NOW)
                .is_err()
        );
        assert_eq!(key.next.load(Ordering::Relaxed), 1);
        assert!(
            (MAX_CIPHERTEXT.div_ceil(16) + MAX_AAD.div_ceil(16) + 1) * (1 << EPOCH_BITS)
                < (1 << 27)
        );
    }

    #[test]
    fn encrypted_ticket_rejects_tampering_wrong_context_and_another_server_key() {
        let key = LoginTickets::new().unwrap();
        let (token, _) = key.issue(ORIGIN, binding(), state(false), NOW).unwrap();
        assert!(key.open(&token, ORIGIN, &binding(), NOW).is_ok());
        assert!(
            key.open(&token, "http://localhost:9999", &binding(), NOW)
                .is_err()
        );
        assert!(
            key.open(
                &token,
                ORIGIN,
                &fw_contracts::hash_bytes(b"another browser"),
                NOW
            )
            .is_err()
        );
        let restarted = LoginTickets::new().unwrap();
        restarted
            .issue(ORIGIN, binding(), state(false), NOW)
            .unwrap();
        assert!(restarted.open(&token, ORIGIN, &binding(), NOW).is_err());
        let original = URL_SAFE_NO_PAD
            .decode(token.strip_prefix(PREFIX).unwrap())
            .unwrap();
        for index in [0, NONCE_BYTES, original.len() - 1] {
            let mut changed = original.clone();
            changed[index] ^= 1;
            assert!(
                key.open(
                    &format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(changed)),
                    ORIGIN,
                    &binding(),
                    NOW
                )
                .is_err()
            );
        }
        for invalid in [
            format!("{token}="),
            "registration.invalid".into(),
            format!("{PREFIX}AA"),
            "A".repeat(MAX_ENCODED + 1),
        ] {
            assert!(key.open(&invalid, ORIGIN, &binding(), NOW).is_err());
        }
    }

    #[test]
    fn sealed_claims_cannot_change_login_purpose_tenant_principal_or_time_window() {
        let key = LoginTickets::new().unwrap();
        let (token, expiry) = key.issue(ORIGIN, binding(), state(false), NOW).unwrap();
        assert_eq!(expiry, NOW + 300);
        assert!(key.open(&token, ORIGIN, &binding(), NOW + 299).is_ok());
        for now in [NOW - 1, NOW + 300, NOW + 301] {
            assert!(key.open(&token, ORIGIN, &binding(), now).is_err());
        }
        for field in [
            "purpose",
            "org_id",
            "project_id",
            "principal_id",
            "challenge_id",
            "origin",
        ] {
            let claims = key.open(&token, ORIGIN, &binding(), NOW).unwrap();
            let mut value = serde_json::to_value(claims).unwrap();
            value[field] = "different".into();
            let changed: LoginClaims = serde_json::from_value(value).unwrap();
            let sealed = key.seal(&changed, ORIGIN).unwrap();
            assert!(
                key.open(&sealed, ORIGIN, &binding(), NOW).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn eight_maximum_size_credential_ids_fit_bounded_login_tickets() {
        let key = LoginTickets::new().unwrap();
        let (ticket, _) = key.issue(ORIGIN, binding(), state(true), NOW).unwrap();
        let field = |size| URL_SAFE_NO_PAD.encode(vec![255; size]);
        let mut body = serde_json::json!({"ceremony_id":ticket, "credential":{
            "id":field(1024), "rawId":field(1024), "type":"public-key",
            "response":{"clientDataJSON":field(8192), "authenticatorData":field(16384),
                "signature":field(2048), "userHandle":field(64)},
            "clientExtensionResults":{"credProps":{"rk":true}, "credProtect":3,
                "minPinLength":u32::MAX, "uvm":vec![[u32::MAX;3];16]}}});
        assert!(
            serde_json::to_vec(&body).unwrap().len() < 65536,
            "ticket plus maximum permitted assertion fields must retain the 64 KiB public request bound"
        );
        assert!(key.open(&ticket, ORIGIN, &binding(), NOW).is_ok());
        body["ceremony_id"] = "x".repeat(MAX_ENCODED).into();
        assert!(
            serde_json::to_vec(&body).unwrap().len() < 65536,
            "even the encoded ticket limit must fit alongside every maximum extension field"
        );
    }

    #[test]
    fn authenticated_compression_is_bounded_and_rejects_incomplete_or_extra_streams() {
        let encode = |bytes: &[u8]| {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap()
        };
        let encoded = encode(b"complete");
        assert_eq!(decompress(&encoded).unwrap(), b"complete");
        assert!(decompress(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decompress(&trailing).is_err());
        let mut concatenated = encoded.clone();
        concatenated.extend_from_slice(&encoded);
        assert!(decompress(&concatenated).is_err());
        assert!(decompress(&encode(&vec![0; MAX_PLAINTEXT + 1])).is_err());
        assert_eq!(
            decompress(&encode(&vec![0; MAX_PLAINTEXT])).unwrap().len(),
            MAX_PLAINTEXT
        );
    }
}

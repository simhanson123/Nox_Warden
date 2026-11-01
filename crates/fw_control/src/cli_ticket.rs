//! A public CLI initiation carries its own encrypted, short-lived state. Only
//! verified browser interaction allocates protected request state. A ticket is
//! neither approval nor the polling secret; it must conceal the short code hash
//! to prevent offline guessing by someone who receives the verification URL.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    sign::Signer,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use serde::{Deserialize, Serialize};

const PURPOSE: &str = "fw.cli-request-ticket/v1";
const PREFIX: &str = "cli1.";
const MAX_ENCODED: usize = 2048;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const NONCE_VERSION: &[u8; 4] = b"FWC1";
const EPOCH_BITS: u32 = 16;
const MAX_TIME: i64 = 253_402_300_799;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Claims {
    purpose: String,
    pub request_id: String,
    org_id: String,
    project_id: String,
    principal_id: String,
    origin: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub code_hash: [u8; 32],
    pub poll_hash: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Invalid,
    Expired,
    Internal,
}
type Result<T> = std::result::Result<T, Error>;

// Deliberately not Clone. The parent mutex serializes one checked nonce
// allocator per boot-random master. Each domain-separated AES epoch encrypts
// at most 2^16 small tickets. Older epochs remain derivable until expiry;
// anonymous issuance cannot evict a key needed by an earlier valid request.
pub(super) struct Tickets {
    master: [u8; 32],
    next: u64,
}

impl Tickets {
    pub fn new() -> Result<Self> {
        let mut master = [0; 32];
        openssl::rand::rand_bytes(&mut master).map_err(|_| Error::Internal)?;
        Ok(Self { master, next: 0 })
    }

    fn epoch_key(&self, sequence: u64) -> Result<[u8; 32]> {
        let master = PKey::hmac(&self.master).map_err(|_| Error::Internal)?;
        let mut signer =
            Signer::new(MessageDigest::sha256(), &master).map_err(|_| Error::Internal)?;
        signer
            .update(b"fw.cli-request-ticket/aes-gcm-epoch/v1\0")
            .map_err(|_| Error::Internal)?;
        signer
            .update(&(sequence >> EPOCH_BITS).to_be_bytes())
            .map_err(|_| Error::Internal)?;
        signer
            .sign_to_vec()
            .map_err(|_| Error::Internal)?
            .try_into()
            .map_err(|_| Error::Internal)
    }

    pub fn issue(
        &mut self,
        origin: &str,
        request_id: String,
        code_hash: [u8; 32],
        poll_hash: [u8; 32],
        at: i64,
    ) -> Result<(String, Claims)> {
        let claims = Claims {
            purpose: PURPOSE.into(),
            request_id,
            org_id: crate::ORG.into(),
            project_id: crate::PROJECT.into(),
            principal_id: crate::PRINCIPAL.into(),
            origin: origin.into(),
            issued_at: at,
            expires_at: at.checked_add(super::LIFETIME).ok_or(Error::Invalid)?,
            code_hash,
            poll_hash,
        };
        claims.validate(origin, &claims.request_id, at)?;
        Ok((self.seal(&claims)?, claims))
    }

    fn seal(&mut self, claims: &Claims) -> Result<String> {
        let plaintext = fw_contracts::canonical_bytes(claims).map_err(|_| Error::Internal)?;
        // A pre-encoding bound prevents allocating unexpectedly large ciphertext.
        if plaintext.len() > (MAX_ENCODED - PREFIX.len()) * 3 / 4 - NONCE_BYTES - TAG_BYTES {
            return Err(Error::Invalid);
        }
        let sequence = self.next;
        self.next = sequence.checked_add(1).ok_or(Error::Internal)?;
        let mut nonce = [0; NONCE_BYTES];
        nonce[..4].copy_from_slice(NONCE_VERSION);
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        let mut tag = [0; TAG_BYTES];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &self.epoch_key(sequence)?,
            Some(&nonce),
            PURPOSE.as_bytes(),
            &plaintext,
            &mut tag,
        )
        .map_err(|_| Error::Internal)?;
        let mut envelope = Vec::with_capacity(NONCE_BYTES + ciphertext.len() + TAG_BYTES);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        envelope.extend_from_slice(&tag);
        let encoded = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(envelope));
        if encoded.len() > MAX_ENCODED {
            return Err(Error::Invalid);
        }
        Ok(encoded)
    }

    pub fn open(&self, token: &str, origin: &str, request_id: &str, at: i64) -> Result<Claims> {
        if token.len() > MAX_ENCODED {
            return Err(Error::Invalid);
        }
        let encoded = token.strip_prefix(PREFIX).ok_or(Error::Invalid)?;
        if encoded.is_empty()
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Invalid);
        }
        let envelope = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::Invalid)?;
        if URL_SAFE_NO_PAD.encode(&envelope) != encoded
            || envelope.len() <= NONCE_BYTES + TAG_BYTES
            || &envelope[..4] != NONCE_VERSION
        {
            return Err(Error::Invalid);
        }
        let sequence = u64::from_be_bytes(envelope[4..NONCE_BYTES].try_into().unwrap());
        if sequence >= self.next {
            return Err(Error::Invalid);
        }
        let ciphertext_end = envelope.len() - TAG_BYTES;
        let plaintext = decrypt_aead(
            Cipher::aes_256_gcm(),
            &self.epoch_key(sequence)?,
            Some(&envelope[..NONCE_BYTES]),
            PURPOSE.as_bytes(),
            &envelope[NONCE_BYTES..ciphertext_end],
            &envelope[ciphertext_end..],
        )
        .map_err(|_| Error::Invalid)?;
        let claims: Claims = fw_contracts::parse_strict(&plaintext).map_err(|_| Error::Invalid)?;
        claims.validate(origin, request_id, at)?;
        Ok(claims)
    }
}

impl Claims {
    fn validate(&self, origin: &str, request_id: &str, at: i64) -> Result<()> {
        if self.purpose != PURPOSE
            || self.org_id != crate::ORG
            || self.project_id != crate::PROJECT
            || self.principal_id != crate::PRINCIPAL
            || self.origin != origin
            || self.origin.len() > 512
            || self.request_id != request_id
            || !crate::uuid(request_id)
            || !(0..=MAX_TIME).contains(&self.issued_at)
            || self.expires_at > MAX_TIME
            || self.expires_at.checked_sub(self.issued_at) != Some(super::LIFETIME)
            || at < self.issued_at
        {
            return Err(Error::Invalid);
        }
        if at >= self.expires_at {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORIGIN: &str = "http://localhost:8787";
    fn issued(tickets: &mut Tickets) -> (String, Claims) {
        tickets
            .issue(
                ORIGIN,
                uuid::Uuid::new_v4().to_string(),
                [1; 32],
                [2; 32],
                1000,
            )
            .unwrap()
    }

    #[test]
    fn ticket_binds_scope_origin_request_and_exclusive_time() {
        let mut tickets = Tickets::new().unwrap();
        let (token, claims) = issued(&mut tickets);
        assert!(
            tickets
                .open(&token, ORIGIN, &claims.request_id, 1000)
                .is_ok()
        );
        assert!(
            tickets
                .open(&token, ORIGIN, &claims.request_id, 1299)
                .is_ok()
        );
        assert!(matches!(
            tickets.open(&token, ORIGIN, &claims.request_id, 1300),
            Err(Error::Expired)
        ));
        assert!(matches!(
            tickets.open(&token, ORIGIN, &claims.request_id, 999),
            Err(Error::Invalid)
        ));
        assert!(
            tickets
                .open(&token, "http://localhost:8788", &claims.request_id, 1000)
                .is_err()
        );
        assert!(
            tickets
                .open(&token, ORIGIN, &uuid::Uuid::new_v4().to_string(), 1000)
                .is_err()
        );
        for field in ["purpose", "org", "project", "principal", "lifetime"] {
            let mut changed = claims.clone();
            match field {
                "purpose" => changed.purpose = "fw.local-login-ticket/v1".into(),
                "org" => changed.org_id = uuid::Uuid::new_v4().to_string(),
                "project" => changed.project_id = uuid::Uuid::new_v4().to_string(),
                "principal" => changed.principal_id = uuid::Uuid::new_v4().to_string(),
                "lifetime" => changed.expires_at += 1,
                _ => unreachable!(),
            }
            let wrong = tickets.seal(&changed).unwrap();
            assert!(
                tickets
                    .open(&wrong, ORIGIN, &claims.request_id, 1000)
                    .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn tickets_reject_tampering_restart_and_malformed_bounds() {
        let mut tickets = Tickets::new().unwrap();
        let (token, claims) = issued(&mut tickets);
        let mut restarted = Tickets::new().unwrap();
        issued(&mut restarted);
        assert!(
            restarted
                .open(&token, ORIGIN, &claims.request_id, 1000)
                .is_err()
        );
        let bytes = URL_SAFE_NO_PAD
            .decode(token.strip_prefix(PREFIX).unwrap())
            .unwrap();
        for index in [0, 4, NONCE_BYTES, bytes.len() - 1] {
            let mut modified = bytes.clone();
            modified[index] ^= 1;
            let altered = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(modified));
            assert!(
                tickets
                    .open(&altered, ORIGIN, &claims.request_id, 1000)
                    .is_err()
            );
        }
        for malformed in [
            String::new(),
            "cli1.".into(),
            format!("{token}="),
            format!("cli1.{}", "A".repeat(MAX_ENCODED)),
            "login1.AAAA".into(),
        ] {
            assert!(
                tickets
                    .open(&malformed, ORIGIN, &claims.request_id, 1000)
                    .is_err()
            );
        }
        // Even the short code's hash is absent from the public envelope.
        assert!(!bytes.windows(32).any(|part| part == claims.code_hash));
        assert!(!bytes.windows(32).any(|part| part == claims.poll_hash));
    }

    #[test]
    fn epoch_rollover_preserves_prior_tickets_and_exhaustion_never_wraps() {
        let mut tickets = Tickets::new().unwrap();
        tickets.next = (1 << EPOCH_BITS) - 1;
        let (old, claims) = issued(&mut tickets);
        let (new, new_claims) = issued(&mut tickets);
        assert_ne!(old, new);
        assert_ne!(
            tickets.epoch_key((1 << EPOCH_BITS) - 1).unwrap(),
            tickets.epoch_key(1 << EPOCH_BITS).unwrap()
        );
        assert!(tickets.open(&old, ORIGIN, &claims.request_id, 1000).is_ok());
        assert!(
            tickets
                .open(&new, ORIGIN, &new_claims.request_id, 1000)
                .is_ok()
        );
        tickets.next = u64::MAX;
        assert!(matches!(
            tickets.issue(
                ORIGIN,
                uuid::Uuid::new_v4().to_string(),
                [1; 32],
                [2; 32],
                1000
            ),
            Err(Error::Internal)
        ));
        assert_eq!(tickets.next, u64::MAX);
        assert!(tickets.open(&old, ORIGIN, &claims.request_id, 1000).is_ok());
    }
}

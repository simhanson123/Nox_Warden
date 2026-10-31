//! Stateless anonymous bindings and encrypted, browser-bound login challenges.
//! No anonymous HTTP request reserves durable credential or session capacity.
use super::*;
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
const ANON_DOMAIN: &[u8] = b"fw.authority-review/anonymous/v1";
const LOGIN_DOMAIN: &[u8] = b"fw.authority-review/login/v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anonymous {
    csrf: String,
    issued_at: i64,
    expires_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ceremony {
    binding_hash: String,
    profile: LocalProfile,
    issued_at: i64,
    login: ReviewLogin,
}
pub(super) struct BrowserBinding {
    pub id: Option<String>,
    cookie: String,
    csrf: String,
}
// One non-clonable allocator per boot master. At most 2^16 encryptions and
// fewer than 2^27 GHASH input blocks (ciphertext, AAD and length) per derived
// key. Derive old epochs on demand so issuance never evicts unexpired tickets.
// These bounds do not count attacker-controlled failed verification attempts.
pub(super) struct EnvelopeKeys {
    master: [u8; 32],
    next: std::sync::atomic::AtomicU64,
}
const NONCE_VERSION: &[u8; 4] = b"FWA2";
const MAX_CIPHERTEXT: usize = 24548;
const MAX_AAD: usize = 4096;
const EPOCH_BITS: u32 = 16;
impl EnvelopeKeys {
    pub(super) fn new(master: [u8; 32]) -> Self {
        Self {
            master,
            next: std::sync::atomic::AtomicU64::new(0),
        }
    }
    fn key(&self, domain: &[u8], sequence: u64) -> Result<[u8; 32]> {
        if domain != ANON_DOMAIN && domain != LOGIN_DOMAIN {
            return Err(Failure::Unauthorized);
        }
        let master = PKey::hmac(&self.master).map_err(|_| Failure::Unavailable)?;
        let mut signer =
            Signer::new(MessageDigest::sha256(), &master).map_err(|_| Failure::Unavailable)?;
        signer
            .update(b"fw.authority-review/aes-gcm-epoch/v2\0")
            .map_err(|_| Failure::Unavailable)?;
        signer
            .update(&(domain.len() as u64).to_be_bytes())
            .map_err(|_| Failure::Unavailable)?;
        signer.update(domain).map_err(|_| Failure::Unavailable)?;
        signer
            .update(&(sequence >> EPOCH_BITS).to_be_bytes())
            .map_err(|_| Failure::Unavailable)?;
        signer
            .sign_to_vec()
            .map_err(|_| Failure::Unavailable)?
            .try_into()
            .map_err(|_| Failure::Unavailable)
    }
    fn nonce(&self) -> Result<[u8; 12]> {
        use std::sync::atomic::Ordering;
        let sequence = self
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| Failure::Unavailable)?;
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(NONCE_VERSION);
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        Ok(nonce)
    }
    fn opening_key(&self, domain: &[u8], nonce: &[u8]) -> Result<[u8; 32]> {
        use std::sync::atomic::Ordering;
        if nonce.len() != 12 || &nonce[..4] != NONCE_VERSION {
            return Err(Failure::Unauthorized);
        }
        let sequence =
            u64::from_be_bytes(nonce[4..].try_into().map_err(|_| Failure::Unauthorized)?);
        if sequence >= self.next.load(Ordering::Relaxed) {
            return Err(Failure::Unauthorized);
        }
        self.key(domain, sequence)
    }
    fn seal(&self, domain: &[u8], origin: &str, bytes: &[u8]) -> Result<String> {
        let aad = [domain, b"\0", origin.as_bytes()].concat();
        if bytes.len() > MAX_CIPHERTEXT || aad.len() > MAX_AAD {
            return Err(Failure::Unavailable);
        }
        let nonce = self.nonce()?;
        let key = self.opening_key(domain, &nonce)?;
        let mut tag = [0; 16];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &key,
            Some(&nonce),
            &aad,
            bytes,
            &mut tag,
        )
        .map_err(|_| Failure::Unavailable)?;
        let mut sealed = nonce.to_vec();
        sealed.extend(ciphertext);
        sealed.extend(tag);
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }
    fn unseal(&self, domain: &[u8], origin: &str, sealed: &str) -> Result<Vec<u8>> {
        if sealed.len() > 32768 {
            return Err(Failure::Unauthorized);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(sealed)
            .map_err(|_| Failure::Unauthorized)?;
        if bytes.len() < 28 || bytes.len() > MAX_CIPHERTEXT + 28 {
            return Err(Failure::Unauthorized);
        }
        let aad = [domain, b"\0", origin.as_bytes()].concat();
        if aad.len() > MAX_AAD {
            return Err(Failure::Unauthorized);
        }
        let key = self.opening_key(domain, &bytes[..12])?;
        decrypt_aead(
            Cipher::aes_256_gcm(),
            &key,
            Some(&bytes[..12]),
            &aad,
            &bytes[12..bytes.len() - 16],
            &bytes[bytes.len() - 16..],
        )
        .map_err(|_| Failure::Unauthorized)
    }
}
impl Runtime {
    fn seal<T: Serialize>(&self, domain: &[u8], value: &T) -> Result<String> {
        let bytes = serde_json::to_vec(value).map_err(|_| Failure::Unavailable)?;
        self.envelope_key.seal(domain, &self.config.origin, &bytes)
    }
    fn unseal<T: DeserializeOwned>(&self, domain: &[u8], sealed: &str) -> Result<T> {
        let plaintext = self
            .envelope_key
            .unseal(domain, &self.config.origin, sealed)?;
        parse_strict_with_limit(&plaintext, 24576).map_err(|_| Failure::Unauthorized)
    }
    fn token_hash(&self, token: &str) -> Result<String> {
        if token.is_empty() || token.len() > 4096 {
            return Err(Failure::Unauthorized);
        }
        let key = PKey::hmac(&self.key).map_err(|_| Failure::Unavailable)?;
        let mut signer =
            Signer::new(MessageDigest::sha256(), &key).map_err(|_| Failure::Unavailable)?;
        signer
            .update(token.as_bytes())
            .map_err(|_| Failure::Unavailable)?;
        Ok(URL_SAFE_NO_PAD.encode(signer.sign_to_vec().map_err(|_| Failure::Unavailable)?))
    }
    fn cookie(&self, headers: &HeaderMap) -> Result<String> {
        let cookie = one(headers, "cookie")?.ok_or(Failure::Unauthorized)?;
        if cookie.len() > 4096 {
            return Err(Failure::Invalid);
        }
        let mut found = None;
        for part in cookie.split(';') {
            let (name, value) = part.trim().split_once('=').ok_or(Failure::Invalid)?;
            if name == COOKIE {
                if found.is_some() {
                    return Err(Failure::Invalid);
                }
                found = Some(value);
            }
        }
        Ok(found.ok_or(Failure::Unauthorized)?.into())
    }
    pub(super) fn session(&self, headers: &HeaderMap, now: i64) -> Result<BrowserBinding> {
        let cookie = self.cookie(headers)?;
        let (id, csrf, issued_at, expires_at) = if let Some(value) = cookie.strip_prefix("a.") {
            let anonymous: Anonymous = self.unseal(ANON_DOMAIN, value)?;
            (
                None,
                anonymous.csrf,
                anonymous.issued_at,
                anonymous.expires_at,
            )
        } else {
            let id = self.token_hash(&cookie)?;
            let session = self.sessions.get(&id).ok_or(Failure::Unauthorized)?;
            (
                Some(id),
                session.csrf.clone(),
                session.issued_at,
                session.expires_at,
            )
        };
        if now < issued_at || now >= expires_at {
            return Err(Failure::Unauthorized);
        }
        if !one(headers, "x-authority-csrf")?.is_some_and(|value| same(value, &csrf)) {
            return Err(Failure::Forbidden);
        }
        Ok(BrowserBinding { id, cookie, csrf })
    }
    pub(super) fn authenticated(
        &mut self,
        id: &str,
        now: i64,
    ) -> Result<(LocalProfile, ReviewProfile)> {
        let (identity, revision) = self
            .sessions
            .get(id)
            .and_then(|s| s.identity.clone())
            .ok_or(Failure::Unauthorized)?;
        let profile = self
            .store
            .review_profile(
                &identity.tenant()?,
                &identity.principal_id,
                &identity.credential_id,
                now,
            )
            .map_err(|_| Failure::Unauthorized)?;
        if profile.state != "active" || profile.security_revision != revision {
            return Err(Failure::Unauthorized);
        }
        Ok((identity, profile))
    }
    fn anonymous_response(&self, now: i64) -> Result<Response> {
        let csrf = random()?;
        let token = format!(
            "a.{}",
            self.seal(
                ANON_DOMAIN,
                &Anonymous {
                    csrf: csrf.clone(),
                    issued_at: now,
                    expires_at: now + SESSION_SECONDS
                }
            )?
        );
        Ok(json_response(
            json!({"authenticated":false,"csrf_token":csrf}),
            Some(cookie_header(&token)),
        ))
    }
    fn new_authenticated(
        &mut self,
        identity: LocalProfile,
        revision: i64,
        now: i64,
    ) -> Result<Response> {
        self.sessions
            .retain(|_, s| now >= s.issued_at && now < s.expires_at);
        // Capacity is available only to proven key holders. Four sessions per
        // configured credential bound memory without sacrificing other owners.
        let mut own = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.identity.as_ref().is_some_and(|(p, _)| {
                    p.org_id == identity.org_id
                        && p.project_id == identity.project_id
                        && p.credential_id == identity.credential_id
                })
            })
            .map(|(id, s)| (id.clone(), s.serial))
            .collect::<Vec<_>>();
        own.sort_by_key(|(_, issued)| *issued);
        while own.len() >= 4 {
            let (old, _) = own.remove(0);
            self.sessions.remove(&old);
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Failure::Limited);
        }
        self.next_session_serial = self
            .next_session_serial
            .checked_add(1)
            .ok_or(Failure::Unavailable)?;
        let token = random()?;
        let id = self.token_hash(&token)?;
        self.sessions.insert(
            id.clone(),
            Session {
                serial: self.next_session_serial,
                csrf: random()?,
                issued_at: now,
                expires_at: now + SESSION_SECONDS,
                identity: Some((identity, revision)),
                rate_start: now,
                rate_count: 0,
            },
        );
        Ok(json_response(
            self.session_json(&id, now)?,
            Some(cookie_header(&token)),
        ))
    }
    fn session_json(&mut self, id: &str, now: i64) -> Result<Value> {
        let (identity, profile) = self.authenticated(id, now)?;
        Ok(
            json!({"authenticated":true,"csrf_token":self.sessions[id].csrf,"principal_id":identity.principal_id,"org_id":identity.org_id,"project_id":identity.project_id,"roles":profile.roles,"expires_at":chrono::DateTime::from_timestamp(self.sessions[id].expires_at,0).ok_or(Failure::Unavailable)?.format("%Y-%m-%dT%H:%M:%SZ").to_string()}),
        )
    }
    pub(super) fn rate_authenticated(&mut self, id: &str, now: i64) -> Result<()> {
        let session = self.sessions.get_mut(id).ok_or(Failure::Unauthorized)?;
        if now < session.rate_start || now - session.rate_start >= 60 {
            session.rate_start = now;
            session.rate_count = 0;
        }
        session.rate_count = session.rate_count.saturating_add(1);
        if session.rate_count > 120 {
            return Err(Failure::Limited);
        }
        Ok(())
    }
    pub(super) fn auth_route(
        &mut self,
        method: &str,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
        now: i64,
    ) -> Result<Option<Response>> {
        if path == "/authority/v1/session" && method == "GET" {
            if one(headers, "x-authority-csrf")?.is_some() {
                let binding = self.session(headers, now)?;
                let value = if let Some(id) = binding.id {
                    self.session_json(&id, now)?
                } else {
                    json!({"authenticated":false,"csrf_token":binding.csrf})
                };
                return Ok(Some(json_response(value, None)));
            }
            // Validate cookie syntax, but a cookie-only caller cannot delete or
            // rotate another browser's authenticated server-side session.
            match self.cookie(headers) {
                Ok(_) | Err(Failure::Unauthorized) => {}
                Err(error) => return Err(error),
            }
            return self.anonymous_response(now).map(Some);
        }
        if method != "POST"
            || ![
                "/authority/v1/logout",
                "/authority/v1/auth/options",
                "/authority/v1/auth/verify",
            ]
            .contains(&path)
        {
            return Ok(None);
        }
        let binding = self.session(headers, now)?;
        if path == "/authority/v1/logout" {
            let _: Empty = parse(body)?;
            if let Some(id) = binding.id {
                self.sessions.remove(&id);
            }
            return self.anonymous_response(now).map(Some);
        }
        if path == "/authority/v1/auth/options" {
            let request: AuthOptions = parse(body)?;
            let profile = self
                .config
                .profiles
                .get(&request.profile)
                .cloned()
                .ok_or(Failure::Unauthorized)?;
            let tenant = profile.tenant()?;
            let status = self
                .store
                .review_profile(&tenant, &profile.principal_id, &profile.credential_id, now)
                .map_err(|_| Failure::Unauthorized)?;
            let login = self.store.begin_review_login(
                &tenant,
                &profile.principal_id,
                &profile.credential_id,
                &self.verifier,
                now,
            )?;
            let options = login.options.clone();
            let kind = if status.state == "pending" {
                "activation"
            } else {
                "login"
            };
            let ceremony = Ceremony {
                binding_hash: self.token_hash(&binding.cookie)?,
                profile,
                issued_at: now,
                login,
            };
            let ceremony_id = self.seal(LOGIN_DOMAIN, &ceremony)?;
            return Ok(Some(json_response(
                json!({"ceremony_id":ceremony_id,"options":options,"kind":kind}),
                None,
            )));
        }
        let request: AuthVerify = parse(body)?;
        let ceremony: Ceremony = self.unseal(LOGIN_DOMAIN, &request.ceremony_id)?;
        if now < ceremony.issued_at
            || now >= ceremony.issued_at + 300
            || !same(&ceremony.binding_hash, &self.token_hash(&binding.cookie)?)
        {
            return Err(Failure::Unauthorized);
        }
        let tenant = ceremony.profile.tenant()?;
        let sample_key = format!(
            "{}:{}:{}",
            ceremony.profile.org_id, ceremony.profile.project_id, ceremony.profile.credential_id
        );
        let record_failure = self
            .failure_samples
            .get(&sample_key)
            .is_none_or(|last| now >= last.saturating_add(60));
        let outcome = self.store.finish_review_login_sampled(
            &tenant,
            &ceremony.login,
            &request.assertion,
            &self.verifier,
            now,
            record_failure,
        );
        if matches!(outcome, Err(fw_authority::AuthorityError::Signature)) && record_failure {
            // At most one retained failure per configured key per minute. This
            // is observation sampling, never a key/account admission lockout.
            self.failure_samples.insert(sample_key, now);
        }
        outcome.map_err(|_| Failure::Unauthorized)?;
        let profile = self
            .store
            .review_profile(
                &tenant,
                &ceremony.profile.principal_id,
                &ceremony.profile.credential_id,
                now,
            )
            .map_err(|_| Failure::Unauthorized)?;
        if let Some(id) = binding.id {
            self.sessions.remove(&id);
        }
        self.new_authenticated(ceremony.profile, profile.security_revision, now)
            .map(Some)
    }
}
fn cookie_header(token: &str) -> String {
    format!(
        "{COOKIE}={token}; Path=/; Max-Age={SESSION_SECONDS}; HttpOnly; Secure; SameSite=Strict"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::Ordering};
    const ORIGIN: &str = "https://authority.example.test";
    fn keys() -> EnvelopeKeys {
        let mut master = [0; 32];
        openssl::rand::rand_bytes(&mut master).unwrap();
        EnvelopeKeys::new(master)
    }
    #[test]
    fn old_tickets_survive_multiple_epoch_rollovers_and_sequence_exhaustion() {
        let keys = keys();
        let mut tickets = vec![keys.seal(LOGIN_DOMAIN, ORIGIN, b"pending login").unwrap()];
        assert_eq!(
            keys.key(LOGIN_DOMAIN, 0).unwrap(),
            keys.key(LOGIN_DOMAIN, (1 << EPOCH_BITS) - 1).unwrap()
        );
        assert_ne!(
            keys.key(LOGIN_DOMAIN, 0).unwrap(),
            keys.key(LOGIN_DOMAIN, 1 << EPOCH_BITS).unwrap()
        );
        assert_ne!(
            keys.key(LOGIN_DOMAIN, 0).unwrap(),
            keys.key(ANON_DOMAIN, 0).unwrap()
        );
        for sequence in [
            (1 << EPOCH_BITS) - 1,
            1 << EPOCH_BITS,
            (2 << EPOCH_BITS) - 1,
            2 << EPOCH_BITS,
            u64::MAX - 1,
        ] {
            keys.next.store(sequence, Ordering::Relaxed);
            tickets.push(keys.seal(LOGIN_DOMAIN, ORIGIN, b"pending login").unwrap());
        }
        assert!(keys.seal(ANON_DOMAIN, ORIGIN, b"new binding").is_err());
        assert_eq!(keys.next.load(Ordering::Relaxed), u64::MAX);
        for ticket in tickets {
            assert_eq!(
                keys.unseal(LOGIN_DOMAIN, ORIGIN, &ticket).unwrap(),
                b"pending login"
            );
            // Even retaining the master without its allocator is not a restart:
            // a real runtime restart also derives a fresh boot master.
            assert!(
                EnvelopeKeys::new(keys.master)
                    .unseal(LOGIN_DOMAIN, ORIGIN, &ticket)
                    .is_err()
            );
            let bytes = URL_SAFE_NO_PAD.decode(&ticket).unwrap();
            assert!(
                decrypt_aead(
                    Cipher::aes_256_gcm(),
                    &keys.master,
                    Some(&bytes[..12]),
                    &[LOGIN_DOMAIN, b"\0", ORIGIN.as_bytes()].concat(),
                    &bytes[12..bytes.len() - 16],
                    &bytes[bytes.len() - 16..]
                )
                .is_err()
            );
        }
    }
    #[test]
    fn tampered_nonce_epoch_purpose_origin_and_restarted_runtime_cannot_open_ticket() {
        let keys = keys();
        let ticket = keys.seal(LOGIN_DOMAIN, ORIGIN, b"pending login").unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(&ticket).unwrap();
        assert_eq!(&bytes[..4], NONCE_VERSION);
        assert_eq!(&bytes[4..12], &0u64.to_be_bytes());
        assert!(keys.unseal(ANON_DOMAIN, ORIGIN, &ticket).is_err());
        assert!(
            keys.unseal(LOGIN_DOMAIN, "https://other.example.test", &ticket)
                .is_err()
        );
        let restarted = super::tests::keys();
        restarted.seal(LOGIN_DOMAIN, ORIGIN, b"new login").unwrap();
        assert!(restarted.unseal(LOGIN_DOMAIN, ORIGIN, &ticket).is_err());
        for index in [0, 4, 11, 12, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(
                keys.unseal(LOGIN_DOMAIN, ORIGIN, &URL_SAFE_NO_PAD.encode(changed))
                    .is_err()
            );
        }
        for sequence in [1u64, 1 << EPOCH_BITS, u64::MAX] {
            let mut changed = bytes.clone();
            changed[4..12].copy_from_slice(&sequence.to_be_bytes());
            assert!(keys.opening_key(LOGIN_DOMAIN, &changed[..12]).is_err());
            assert!(
                keys.unseal(LOGIN_DOMAIN, ORIGIN, &URL_SAFE_NO_PAD.encode(changed))
                    .is_err()
            );
        }
    }
    #[test]
    fn concurrent_domains_share_one_unique_allocator_and_remain_isolated() {
        let keys = Arc::new(keys());
        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let keys = keys.clone();
                std::thread::spawn(move || {
                    let domain = if worker % 2 == 0 {
                        ANON_DOMAIN
                    } else {
                        LOGIN_DOMAIN
                    };
                    (0..64)
                        .map(|_| {
                            let ticket = keys.seal(domain, ORIGIN, b"state").unwrap();
                            assert_eq!(keys.unseal(domain, ORIGIN, &ticket).unwrap(), b"state");
                            let bytes = URL_SAFE_NO_PAD.decode(ticket).unwrap();
                            u64::from_be_bytes(bytes[4..12].try_into().unwrap())
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
        assert_eq!(sequences, (0..512).collect::<Vec<_>>());
    }
    #[test]
    fn ciphertext_and_aad_bounds_limit_blocks_without_spending_issuance_capacity() {
        let keys = keys();
        let aad_origin = "x".repeat(MAX_AAD - LOGIN_DOMAIN.len() - 1);
        let body = vec![42; MAX_CIPHERTEXT];
        let ticket = keys.seal(LOGIN_DOMAIN, &aad_origin, &body).unwrap();
        assert_eq!(ticket.len(), 32768);
        assert_eq!(
            keys.unseal(LOGIN_DOMAIN, &aad_origin, &ticket).unwrap(),
            body
        );
        assert!(
            keys.seal(LOGIN_DOMAIN, ORIGIN, &vec![0; MAX_CIPHERTEXT + 1])
                .is_err()
        );
        assert!(
            keys.seal(LOGIN_DOMAIN, &(aad_origin.clone() + "x"), b"state")
                .is_err()
        );
        assert!(
            keys.unseal(LOGIN_DOMAIN, &(aad_origin + "x"), &ticket)
                .is_err()
        );
        assert!(keys.unseal(LOGIN_DOMAIN, ORIGIN, &(ticket + "A")).is_err());
        assert_eq!(keys.next.load(Ordering::Relaxed), 1);
        assert!(
            (MAX_CIPHERTEXT.div_ceil(16) + MAX_AAD.div_ceil(16) + 1) * (1 << EPOCH_BITS)
                < (1 << 27)
        );
    }
}

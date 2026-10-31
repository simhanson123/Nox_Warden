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
impl Runtime {
    fn seal<T: Serialize>(&self, domain: &[u8], value: &T) -> Result<String> {
        let bytes = serde_json::to_vec(value).map_err(|_| Failure::Unavailable)?;
        if bytes.len() > 24548 {
            return Err(Failure::Unavailable);
        }
        let aad = [domain, b"\0", self.config.origin.as_bytes()].concat();
        let mut nonce = [0; 12];
        let mut tag = [0; 16];
        openssl::rand::rand_bytes(&mut nonce).map_err(|_| Failure::Unavailable)?;
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &self.envelope_key,
            Some(&nonce),
            &aad,
            &bytes,
            &mut tag,
        )
        .map_err(|_| Failure::Unavailable)?;
        let mut sealed = nonce.to_vec();
        sealed.extend(ciphertext);
        sealed.extend(tag);
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }
    fn unseal<T: DeserializeOwned>(&self, domain: &[u8], sealed: &str) -> Result<T> {
        if sealed.len() > 32768 {
            return Err(Failure::Unauthorized);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(sealed)
            .map_err(|_| Failure::Unauthorized)?;
        if bytes.len() < 28 {
            return Err(Failure::Unauthorized);
        }
        let aad = [domain, b"\0", self.config.origin.as_bytes()].concat();
        let plaintext = decrypt_aead(
            Cipher::aes_256_gcm(),
            &self.envelope_key,
            Some(&bytes[..12]),
            &aad,
            &bytes[12..bytes.len() - 16],
            &bytes[bytes.len() - 16..],
        )
        .map_err(|_| Failure::Unauthorized)?;
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

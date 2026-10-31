//! Resource admission only. The runtime rechecks all policy authorization.
use super::*;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
struct Candidate {
    serial: u64,
    csrf: String,
    issued_at: i64,
    expires_at: i64,
    profile: LocalProfile,
    revision: i64,
}

pub(super) struct Admission {
    key: [u8; 32],
    sessions: Mutex<BTreeMap<String, Candidate>>,
    store: Mutex<AuthorityStore>,
    public: Arc<Semaphore>,
    authenticated: Arc<Semaphore>,
    checks: Arc<Semaphore>,
}

impl Admission {
    pub(super) fn new(path: &std::path::Path, key: [u8; 32]) -> Result<Self> {
        Ok(Self {
            key,
            sessions: Mutex::new(BTreeMap::new()),
            store: Mutex::new(AuthorityStore::open(path)?),
            public: Arc::new(Semaphore::new(8)),
            authenticated: Arc::new(Semaphore::new(8)),
            checks: Arc::new(Semaphore::new(8)),
        })
    }

    /// A bounded routing snapshot, published before dispatch returns on success
    /// or error. It cannot grant authority and is never serialized to a client.
    pub(super) fn synchronize(&self, sessions: &BTreeMap<String, Session>) -> Result<()> {
        let snapshot = sessions
            .iter()
            .filter_map(|(id, session)| {
                session.identity.as_ref().map(|(profile, revision)| {
                    (
                        id.clone(),
                        Candidate {
                            serial: session.serial,
                            csrf: session.csrf.clone(),
                            issued_at: session.issued_at,
                            expires_at: session.expires_at,
                            profile: profile.clone(),
                            revision: *revision,
                        },
                    )
                })
            })
            .collect();
        *self.sessions.lock().map_err(|_| Failure::Unavailable)? = snapshot;
        Ok(())
    }

    fn candidate(&self, headers: &HeaderMap, now: i64) -> Result<Option<(String, Candidate)>> {
        let Some(cookie) = one(headers, "cookie")? else {
            return Ok(None);
        };
        if cookie.len() > 4096 {
            return Err(Failure::Invalid);
        }
        let mut token = None;
        for part in cookie.split(';') {
            let (name, value) = part.trim().split_once('=').ok_or(Failure::Invalid)?;
            if name == COOKIE {
                if token.is_some() {
                    return Err(Failure::Invalid);
                }
                token = Some(value);
            }
        }
        let Some(token) = token.filter(|token| !token.is_empty() && !token.starts_with("a."))
        else {
            return Ok(None);
        };
        let Some(csrf) = one(headers, "x-authority-csrf")? else {
            return Ok(None);
        };
        let key = PKey::hmac(&self.key).map_err(|_| Failure::Unavailable)?;
        let mut signer =
            Signer::new(MessageDigest::sha256(), &key).map_err(|_| Failure::Unavailable)?;
        signer
            .update(token.as_bytes())
            .map_err(|_| Failure::Unavailable)?;
        let id = URL_SAFE_NO_PAD.encode(signer.sign_to_vec().map_err(|_| Failure::Unavailable)?);
        let sessions = self.sessions.lock().map_err(|_| Failure::Unavailable)?;
        Ok(sessions
            .get(&id)
            .filter(|entry| {
                now >= entry.issued_at && now < entry.expires_at && same(csrf, &entry.csrf)
            })
            .map(|entry| (id, entry.clone())))
    }

    pub(super) async fn reserve(
        self: &Arc<Self>,
        headers: &HeaderMap,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
        phase: Option<&listener::Phase>,
    ) -> Result<OwnedSemaphorePermit> {
        let candidate = self.candidate(headers, clock())?;
        let verified = if let Some((id, candidate)) = candidate {
            // Only an exact live memory proof reaches this bounded checking
            // lane. A stale mirror alone never reserves authenticated work.
            let check = self
                .checks
                .clone()
                .try_acquire_owned()
                .map_err(|_| Failure::Limited)?;
            let this = self.clone();
            tokio::task::spawn_blocking(move || {
                let _check = check; // Keep until actual completion after disconnect.
                let mut store = this.store.lock().map_err(|_| Failure::Unavailable)?;
                let now = clock();
                let current = match store.review_profile(
                    &candidate.profile.tenant()?,
                    &candidate.profile.principal_id,
                    &candidate.profile.credential_id,
                    now,
                ) {
                    Ok(current) => current,
                    Err(fw_authority::AuthorityError::Storage(_)) => {
                        return Err(Failure::Unavailable);
                    }
                    Err(_) => return Ok(false),
                };
                if current.state != "active" || current.security_revision != candidate.revision {
                    return Ok(false);
                }
                // Logout/eviction may have removed the session during the read.
                let checked_at = clock();
                if checked_at < now {
                    return Ok(false);
                }
                let sessions = this.sessions.lock().map_err(|_| Failure::Unavailable)?;
                Ok(sessions.get(&id).is_some_and(|entry| {
                    entry.serial == candidate.serial
                        && checked_at >= entry.issued_at
                        && checked_at < entry.expires_at
                        && same(&entry.csrf, &candidate.csrf)
                }))
            })
            .await
            .map_err(|_| Failure::Unavailable)??
        } else {
            false
        };
        if verified {
            if let Some(phase) = phase {
                phase.protect()?;
            }
            self.authenticated
                .clone()
                .try_acquire_owned()
                .map_err(|_| Failure::Limited)
        } else {
            self.public
                .clone()
                .try_acquire_owned()
                .map_err(|_| Failure::Limited)
        }
    }
}

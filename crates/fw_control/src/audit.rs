//! Bounded authentication-denial aggregation and authenticated audit snapshots.
use super::*;
use crate::audit_cursor::{self, CursorClaims, CursorError};
use std::time::{Duration, Instant};

const DENIAL_WINDOW: Duration = Duration::from_secs(60);
const MAX_DENIAL_REASONS: usize = 16;
struct DenialBucket {
    sample_persisted: bool,
    last_attempt: Instant,
    count: u64,
    first_at: i64,
    last_at: i64,
}
#[derive(Default)]
pub(super) struct DenialState {
    buckets: HashMap<&'static str, DenialBucket>,
}
impl AppState {
    pub(super) fn record_authentication_denial(&self, reason: &'static str) {
        let reason = match reason {
            "AUTHENTICATION_REQUIRED"
            | "SESSION_EXPIRED"
            | "SESSION_PROOF_REQUIRED"
            | "PASSKEY_SESSION_REVOKED"
            | "PASSKEY_AUTHENTICATION_REQUIRED"
            | "ORIGIN_REJECTED"
            | "CSRF_REJECTED"
            | "IDEMPOTENCY_KEY_INVALID"
            | "HEADER_REQUIRED"
            | "STORAGE_UNAVAILABLE"
            | "BOOTSTRAP_INVALID"
            | "BOOTSTRAP_RATE_LIMITED"
            | "BOOTSTRAP_TOKEN_CLEANUP_FAILED"
            | "PASSKEY_REAUTHENTICATION_REQUIRED" => reason,
            _ => "OTHER_AUTHENTICATION_DENIAL",
        };
        let at = now();
        let Ok(mut state) = self.denial_audit.lock() else {
            return;
        };
        let reason =
            if state.buckets.contains_key(reason) || state.buckets.len() < MAX_DENIAL_REASONS - 1 {
                reason
            } else {
                "OTHER_AUTHENTICATION_DENIAL"
            };
        let bucket = state.buckets.entry(reason).or_insert_with(|| DenialBucket {
            sample_persisted: false,
            last_attempt: Instant::now(),
            count: 0,
            first_at: at,
            last_at: at,
        });
        if !bucket.sample_persisted && bucket.count == 0 {
            bucket.sample_persisted = self
                .store
                .record_denied_action(&self.tenant, None, reason, at)
                .is_ok();
            // Never retry a failed first write for each incoming packet.
            bucket.count = 1;
            bucket.first_at = at;
            bucket.last_at = at;
            return;
        }
        bucket.count = bucket.count.saturating_add(1);
        if bucket.count == 2 {
            bucket.first_at = at;
        }
        bucket.last_at = bucket.last_at.max(at);
        flush_bucket(self, reason, bucket);
    }
    /// Flush at most once per minute for each bounded reason bucket. Counts are
    /// process-local until persisted; a crash can lose a pending summary.
    pub fn flush_authentication_denials(&self) {
        let Ok(mut state) = self.denial_audit.lock() else {
            return;
        };
        for (reason, bucket) in &mut state.buckets {
            flush_bucket(self, reason, bucket);
        }
    }
}
fn flush_bucket(s: &AppState, reason: &str, bucket: &mut DenialBucket) {
    if bucket.last_attempt.elapsed() < DENIAL_WINDOW {
        return;
    }
    bucket.last_attempt = Instant::now();
    if !bucket.sample_persisted {
        if s.store
            .record_denied_action(&s.tenant, None, reason, now())
            .is_err()
        {
            return;
        }
        bucket.sample_persisted = true;
    }
    // count includes the first separately recorded sample. Keep that sentinel
    // after each summary so later windows contain only suppressed followups.
    if bucket.count <= 1 {
        return;
    }
    if s.store
        .record_denied_summary(
            &s.tenant,
            None,
            reason,
            bucket.count - 1,
            bucket.first_at,
            bucket.last_at,
            now(),
        )
        .is_ok()
    {
        bucket.count = 1;
        bucket.first_at = now();
        bucket.last_at = bucket.first_at;
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuditQuery {
    pub limit: Option<usize>,
    #[serde(default, deserialize_with = "canonical_sequence")]
    pub after_sequence: Option<u64>,
    pub cursor: Option<String>,
}
fn canonical_sequence<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    let input = String::deserialize(deserializer)?;
    let value = input.parse::<u64>().map_err(serde::de::Error::custom)?;
    if value.to_string() != input {
        return Err(serde::de::Error::custom(
            "canonical decimal sequence required",
        ));
    }
    Ok(Some(value))
}
fn cursor_error(error: CursorError) -> Problem {
    match error {
        CursorError::Expired => Problem(StatusCode::GONE, "CURSOR_EXPIRED"),
        CursorError::Invalid => bad("CURSOR_INVALID"),
        CursorError::Internal => unavailable(),
    }
}
pub(super) fn page(
    s: &AppState,
    session: &Session,
    q: AuditQuery,
    route: &str,
) -> Result<Value, Problem> {
    let at = now();
    let (after, through, limit, mut claims) = if let Some(cursor) = q.cursor.as_deref() {
        let claims = audit_cursor::decode(cursor, &s.audit_cursor_key, at).map_err(cursor_error)?;
        if claims.org_id != s.tenant.org_id
            || claims.project_id != s.tenant.project_id
            || claims.principal_id != PRINCIPAL
            || claims.session_id != session.id
            || claims.route != route
            || q.limit.is_some_and(|limit| limit != claims.limit)
            || q.after_sequence
                .is_some_and(|after| after != claims.filter_after_sequence)
        {
            return Err(bad("CURSOR_SCOPE_MISMATCH"));
        }
        (
            claims.last_sequence,
            Some(claims.snapshot_sequence),
            claims.limit,
            claims,
        )
    } else {
        let limit = q.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(bad("PAGE_LIMIT_INVALID"));
        }
        let after = q.after_sequence.unwrap_or(0);
        (
            after,
            None,
            limit,
            CursorClaims {
                schema_version: audit_cursor::SCHEMA.into(),
                org_id: s.tenant.org_id.clone(),
                project_id: s.tenant.project_id.clone(),
                principal_id: PRINCIPAL.into(),
                session_id: session.id.clone(),
                route: route.into(),
                filter_after_sequence: after,
                limit,
                snapshot_sequence: 0,
                last_sequence: after,
                issued_at: at,
                expires_at: at + 900,
            },
        )
    };
    let page = s
        .store
        .list_audit_page(&s.tenant, after, through, limit)
        .map_err(map_store)?;
    let mut response = envelope(json!(page.events));
    if let Some(next) = page.next_after_sequence {
        claims.snapshot_sequence = page.snapshot_sequence;
        claims.last_sequence = next;
        response["next_cursor"] =
            json!(audit_cursor::encode(&claims, &s.audit_cursor_key).map_err(cursor_error)?);
    }
    Ok(response)
}
pub(super) async fn denial_summary(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    s.auth(&h, false)?;
    Ok(axum::Json(envelope(
        s.store
            .get_denial_summary(&s.tenant, &id)
            .map_err(map_store)?,
    ))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    const ORIGIN: &str = "http://localhost:8787";
    fn setup() -> (Arc<AppState>, Router) {
        let state = Arc::new(
            AppState::new(
                Store::in_memory().unwrap(),
                ORIGIN.into(),
                "unit-console-token",
            )
            .unwrap(),
        );
        let app = router(state.clone(), "/tmp/fw-audit-test-absent".into());
        (state, app)
    }
    async fn value(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 262144).await.unwrap()).unwrap()
    }
    async fn login(app: &Router) -> (String, String) {
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v1/session/bootstrap")
                    .header("origin", ORIGIN)
                    .header("idempotency-key", Uuid::new_v4().to_string())
                    .body(Body::from(
                        json!({"token":"unit-console-token"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body = value(response).await;
        (cookie, body["data"]["csrf_token"].as_str().unwrap().into())
    }
    #[tokio::test]
    async fn anonymous_flood_and_sampled_denials_leave_http_and_mcp_audit_readable() {
        let (s, app) = setup();
        for _ in 0..100 {
            assert_eq!(
                app.clone()
                    .oneshot(Request::get("/api/v1/status").body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(s.store.count_audit(&s.tenant, 0).unwrap(), 0);
        for _ in 0..100 {
            assert_eq!(
                app.clone()
                    .oneshot(
                        Request::get("/api/v1/status")
                            .header("cookie", "fw_session=invalid")
                            .body(Body::empty())
                            .unwrap()
                    )
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(s.store.count_audit(&s.tenant, 0).unwrap(), 1);
        let (cookie, csrf) = login(&app).await;
        let response = app
            .clone()
            .oneshot(
                Request::get("/api/v1/audit/events?limit=25")
                    .header("cookie", &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(value(response).await["data"].as_array().unwrap().len(), 1);
        let response=app.clone().oneshot(Request::post("/mcp").header("cookie",&cookie).header("origin",ORIGIN)
            .header("x-csrf-token",&csrf).header("idempotency-key",Uuid::new_v4().to_string()).body(Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_audit_events","arguments":{}}}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(value(response).await["result"]["isError"], false);
        s.denial_audit
            .lock()
            .unwrap()
            .buckets
            .get_mut("SESSION_EXPIRED")
            .unwrap()
            .last_attempt = Instant::now() - Duration::from_secs(61);
        s.flush_authentication_denials();
        let events = s.store.list_audit(&s.tenant, 0, 10).unwrap();
        assert_eq!(events.len(), 2);
        let hash = events[1]["evidence_hashes"][0].as_str().unwrap();
        let summary = s.store.get_denial_summary(&s.tenant, hash).unwrap();
        assert_eq!(summary["count"], "99");
        let response = app
            .oneshot(
                Request::get(format!("/api/v1/audit/denial-summaries/{hash}"))
                    .header("cookie", cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(value(response).await["data"]["count"], "99");
    }
    #[tokio::test]
    async fn snapshot_pages_are_complete_and_bound_to_filter_session_and_route() {
        let (s, app) = setup();
        for _ in 0..110 {
            s.store
                .record_denied_action(&s.tenant, None, "UNIT_FIXTURE", now())
                .unwrap();
        }
        let (cookie, csrf) = login(&app).await;
        let first = app
            .clone()
            .oneshot(
                Request::get("/api/v1/audit/events?limit=25&after_sequence=0")
                    .header("cookie", &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first = value(first).await;
        assert_eq!(first["data"].as_array().unwrap().len(), 25);
        let mut collected = first["data"].as_array().unwrap().clone();
        let cursor = first["next_cursor"].as_str().unwrap();
        let changed = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/audit/events?limit=26&cursor={cursor}"))
                    .header("cookie", &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(changed.status(), StatusCode::BAD_REQUEST);
        for query in ["after_sequence=01", "after_sequence=%2B1"] {
            assert_eq!(
                app.clone()
                    .oneshot(
                        Request::get(format!("/api/v1/audit/events?{query}"))
                            .header("cookie", &cookie)
                            .header("x-csrf-token", &csrf)
                            .body(Body::empty())
                            .unwrap()
                    )
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let crossed=app.clone().oneshot(Request::post("/mcp").header("cookie",&cookie).header("origin",ORIGIN).header("x-csrf-token",&csrf)
            .header("idempotency-key",Uuid::new_v4().to_string()).body(Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_audit_events","arguments":{"cursor":cursor}}}).to_string())).unwrap()).await.unwrap();
        assert_eq!(value(crossed).await["result"]["isError"], true);
        s.store
            .record_denied_action(&s.tenant, None, "APPENDED_AFTER_SNAPSHOT", now())
            .unwrap();
        let mut next = Some(cursor.to_owned());
        while let Some(cursor) = next {
            let response = app
                .clone()
                .oneshot(
                    Request::get(format!("/api/v1/audit/events?cursor={cursor}"))
                        .header("cookie", &cookie)
                        .header("x-csrf-token", &csrf)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let page = value(response).await;
            collected.extend(page["data"].as_array().unwrap().clone());
            next = page["next_cursor"].as_str().map(str::to_owned);
        }
        assert_eq!(collected.len(), 110);
        let ids: HashSet<_> = collected
            .iter()
            .map(|event| event["event_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 110);
        assert!(
            !collected
                .iter()
                .any(|event| event["reason_code"] == "APPENDED_AFTER_SNAPSHOT")
        );
    }
    #[test]
    fn bootstrap_backoff_cannot_extend_expiry_or_permanently_block_valid_token() {
        let (s, _) = setup();
        let mut login = s.login.lock().unwrap();
        let at = now();
        let expires = login.expires;
        for _ in 0..10 {
            assert!(matches!(
                login.consume_bootstrap("wrong", at),
                Err(Problem(StatusCode::UNAUTHORIZED, _))
            ));
        }
        assert!(matches!(
            login.consume_bootstrap("wrong", at),
            Err(Problem(StatusCode::TOO_MANY_REQUESTS, _))
        ));
        login.failure_window = Instant::now() - Duration::from_secs(61);
        assert!(matches!(
            login.consume_bootstrap("wrong", at),
            Err(Problem(StatusCode::UNAUTHORIZED, _))
        ));
        assert_eq!(login.failures, 1);
        assert_eq!(login.expires, expires);
        login.failures = 10;
        assert!(login.consume_bootstrap("unit-console-token", at).is_ok());
        assert!(login.consume_bootstrap("unit-console-token", at).is_err());
        assert_eq!(login.token_hash, [0; 32]);
        assert_eq!(login.expires, expires);
        let (expired, _) = setup();
        let mut expired = expired.login.lock().unwrap();
        let expiry = expired.expires;
        assert!(matches!(
            expired.consume_bootstrap("unit-console-token", expiry),
            Err(Problem(StatusCode::UNAUTHORIZED, _))
        ));
    }

    #[tokio::test]
    async fn bootstrap_guess_cooldown_is_audited_and_does_not_lock_out_the_console() {
        let (s, app) = setup();
        for attempt in 0..12 {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/api/v1/session/bootstrap")
                        .header("origin", ORIGIN)
                        .header("idempotency-key", Uuid::new_v4().to_string())
                        .body(Body::from(json!({"token":"incorrect"}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            if attempt < 10 {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            } else {
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(response.headers()["retry-after"], "60");
            }
        }
        assert_eq!(s.store.count_audit(&s.tenant, 0).unwrap(), 2);
        let (cookie, csrf) = login(&app).await;
        let response = app
            .oneshot(
                Request::get("/api/v1/audit/events?limit=25")
                    .header("cookie", cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(s.login.lock().unwrap().consumed);
    }

    #[test]
    fn failed_sample_retry_preserves_followups_after_an_intervening_audit_event() {
        let (s, _) = setup();
        let at = now();
        s.store
            .record_denied_action(&s.tenant, None, "INTERVENING_EVENT", at)
            .unwrap();
        // Model the bounded accumulator after its first DB write failed. The
        // retry must use the current append time, not its older observation.
        s.denial_audit.lock().unwrap().buckets.insert(
            "SESSION_EXPIRED",
            DenialBucket {
                sample_persisted: false,
                last_attempt: Instant::now() - Duration::from_secs(61),
                count: 3,
                first_at: at - 60,
                last_at: at - 30,
            },
        );
        s.flush_authentication_denials();
        let events = s.store.list_audit(&s.tenant, 0, 10).unwrap();
        assert_eq!(events.len(), 3);
        let evidence = events[2]["evidence_hashes"][0].as_str().unwrap();
        assert_eq!(
            s.store.get_denial_summary(&s.tenant, evidence).unwrap()["count"],
            "2"
        );
        assert_eq!(
            s.denial_audit.lock().unwrap().buckets["SESSION_EXPIRED"].count,
            1
        );
    }
}

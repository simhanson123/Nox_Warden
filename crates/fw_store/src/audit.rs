//! Bounded snapshot pages and immutable evidence for coalesced login denials.
use super::*;

// MCP includes both structured data and a JSON text representation. Reserve
// room for that duplication, escaping and the protocol/response envelope.
const PAGE_BYTES: usize = 96 * 1024;

#[derive(Clone, Debug)]
pub struct AuditPage {
    pub events: Vec<Value>,
    pub next_after_sequence: Option<u64>,
    pub snapshot_sequence: u64,
}

impl Store {
    /// Return an append-only snapshot page. The HTTP/MCP boundary must bind the
    /// snapshot, after sequence, tenant, current principal authorization, route,
    /// filters and expiry into its authenticated cursor; these numbers alone
    /// are not a portable authorization token.
    pub fn list_audit_page(
        &self,
        t: &Tenant,
        after_sequence: u64,
        through_sequence: Option<u64>,
        limit: usize,
    ) -> Result<AuditPage> {
        valid_limit(limit)?;
        let c = self.connection()?;
        let head: Vec<u8> = c
            .query_row(
                "SELECT sequence FROM audit_heads WHERE org_id=?1 AND project_id=?2",
                params![t.org_id, t.project_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let head = decode_u64(&head)?;
        let snapshot = through_sequence.unwrap_or(head);
        if snapshot > head {
            return Err(StoreError::InvalidInput(
                "audit snapshot beyond current head",
            ));
        }
        if after_sequence >= snapshot {
            return Ok(AuditPage {
                events: vec![],
                next_after_sequence: None,
                snapshot_sequence: snapshot,
            });
        }
        let mut previous: Option<Vec<u8>> = if after_sequence == 0 {
            None
        } else {
            Some(c.query_row(
                "SELECT event_hash FROM audit_events WHERE org_id=?1 AND project_id=?2 AND sequence=?3",
                params![t.org_id,t.project_id,encode_u64(after_sequence).as_slice()],
                |row| row.get(0),
            ).optional()?.ok_or(StoreError::Integrity("audit page predecessor missing"))?)
        };
        let mut statement = c.prepare(
            "SELECT sequence,canonical_bytes,event_hash,previous_hash FROM audit_events WHERE org_id=?1 AND project_id=?2 AND sequence>?3 AND sequence<=?4 ORDER BY sequence LIMIT ?5",
        )?;
        let rows = statement
            .query_map(
                params![
                    t.org_id,
                    t.project_id,
                    encode_u64(after_sequence).as_slice(),
                    encode_u64(snapshot).as_slice(),
                    limit + 1
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut events = Vec::new();
        let mut bytes_used = 2usize;
        let mut last = after_sequence;
        let mut more = false;
        for (sequence, bytes, hash, prev) in rows {
            if events.len() == limit {
                more = true;
                break;
            }
            let sequence = decode_u64(&sequence)?;
            if last.checked_add(1) != Some(sequence)
                || prev != previous
                || sha256(&bytes).as_slice() != hash
            {
                return Err(StoreError::Integrity("audit page chain mismatch"));
            }
            let mut event: Value = serde_json::from_slice(&bytes)?;
            if event["org_id"] != t.org_id
                || event["project_id"] != t.project_id
                || event["sequence"].as_str() != Some(sequence.to_string().as_str())
                || event["previous_event_hash"]
                    != previous
                        .as_ref()
                        .map(|value| Value::String(hex_hash(value)))
                        .unwrap_or(Value::Null)
            {
                return Err(StoreError::Integrity("audit page projection mismatch"));
            }
            event["event_hash"] = Value::String(hex_hash(&hash));
            let event_size = canonical_bytes(&event)?.len() + 1;
            if bytes_used + event_size > PAGE_BYTES {
                if events.is_empty() {
                    return Err(StoreError::InvalidInput("audit event exceeds page budget"));
                }
                more = true;
                break;
            }
            bytes_used += event_size;
            events.push(event);
            last = sequence;
            previous = Some(hash);
        }
        if !more && last < snapshot {
            return Err(StoreError::Integrity("audit snapshot has missing events"));
        }
        Ok(AuditPage {
            events,
            next_after_sequence: more.then_some(last),
            snapshot_sequence: snapshot,
        })
    }

    /// Store counts for suppressed follow-up denials, excluding an initial
    /// separately recorded sample. The caller aggregates only fixed server
    /// reasons; it must not claim that unflushed in-memory counts survive a crash.
    #[allow(clippy::too_many_arguments)]
    pub fn record_denied_summary(
        &self,
        t: &Tenant,
        actor: Option<&str>,
        reason: &str,
        count: u64,
        window_start: i64,
        window_end: i64,
        now: i64,
    ) -> Result<()> {
        valid_time(window_start)?;
        valid_time(window_end)?;
        valid_time(now)?;
        if count == 0 || window_start > window_end || window_end > now {
            return Err(StoreError::InvalidInput("denial summary window or count"));
        }
        if !matches!(
            reason,
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
                | "OTHER_AUTHENTICATION_DENIAL"
                | "PASSKEY_REAUTHENTICATION_REQUIRED"
        ) {
            return Err(StoreError::InvalidInput("denial summary reason"));
        }
        let value = json!({
            "schema_version":"fw.authentication-denial-summary/v1",
            "org_id":t.org_id,"project_id":t.project_id,"actor_id":actor,
            "reason_code":reason,"count":count.to_string(),
            "window_start":timestamp(window_start)?,"window_end":timestamp(window_end)?,
            "scope":"suppressed_followup_denials"
        });
        let bytes = canonical_bytes(&value)?;
        let hash = hash_bytes(&bytes);
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(actor) = actor {
            valid_uuid(actor)?;
            active_principal(&tx, t, actor)?;
        }
        let old: Option<Vec<u8>> = tx.query_row(
            "SELECT canonical_bytes FROM audit_denial_summaries WHERE org_id=?1 AND project_id=?2 AND content_hash=?3",
            params![t.org_id,t.project_id,hash], |row| row.get(0),
        ).optional()?;
        if let Some(old) = old {
            if old != bytes {
                return Err(StoreError::Integrity("denial summary content mismatch"));
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO audit_denial_summaries VALUES(?1,?2,?3,?4,?5)",
            params![t.org_id, t.project_id, hash, bytes, now],
        )?;
        append_audit_with_evidence(
            &tx,
            t,
            actor,
            "denied_action",
            "system",
            None,
            None,
            "denied",
            Some(reason),
            &[hash],
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Resolve only this tenant's immutable summary. Callers authenticate and
    /// authorize the read exactly as they do for the corresponding audit page.
    pub fn get_denial_summary(&self, t: &Tenant, hash: &str) -> Result<Value> {
        if hash.len() != 71
            || !hash.starts_with("sha256:")
            || !hash[7..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(StoreError::InvalidInput("denial summary hash"));
        }
        let bytes: Vec<u8> = self.connection()?.query_row(
            "SELECT canonical_bytes FROM audit_denial_summaries WHERE org_id=?1 AND project_id=?2 AND content_hash=?3",
            params![t.org_id,t.project_id,hash], |row|row.get(0),
        ).optional()?.ok_or(StoreError::NotFound)?;
        if bytes.len() > 4096 || hash_bytes(&bytes) != hash {
            return Err(StoreError::Integrity("denial summary content mismatch"));
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        if value["org_id"] != t.org_id || value["project_id"] != t.project_id {
            return Err(StoreError::Integrity("denial summary tenant mismatch"));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_byte_budget_has_an_explicit_continuation_and_preserves_every_event() {
        let store = Store::in_memory().unwrap();
        let tenant = store
            .ensure_tenant(
                &Uuid::new_v4().to_string(),
                &Uuid::new_v4().to_string(),
                "Audit",
                100,
            )
            .unwrap();
        let hashes: Vec<_> = (0..16)
            .map(|index| hash_bytes(format!("evidence-{index}").as_bytes()))
            .collect();
        let mut c = store.connection().unwrap();
        let tx = c.transaction().unwrap();
        for _ in 0..100 {
            append_audit_with_evidence(
                &tx,
                &tenant,
                None,
                "denied_action",
                "system",
                None,
                None,
                "denied",
                Some("SESSION_EXPIRED"),
                &hashes,
                100,
            )
            .unwrap();
        }
        tx.commit().unwrap();
        drop(c);
        let first = store.list_audit_page(&tenant, 0, None, 100).unwrap();
        assert!(first.events.len() < 100);
        assert!(first.next_after_sequence.is_some());
        let mut count = first.events.len();
        let mut next = first.next_after_sequence;
        while let Some(after) = next {
            let page = store
                .list_audit_page(&tenant, after, Some(first.snapshot_sequence), 100)
                .unwrap();
            count += page.events.len();
            next = page.next_after_sequence;
        }
        assert_eq!(count, 100);
        assert_eq!(store.verify_audit_chain(&tenant).unwrap(), 100);
    }
}

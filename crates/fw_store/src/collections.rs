//! Bounded immutable list snapshots, independent of the append-only evidence log.
//! Callers authenticate scope and MAC cursor fields. Expiry is also checked here:
//! discarded cache history must never yield a silently incomplete old snapshot.
use super::*;

pub const SNAPSHOT_SECONDS: i64 = 900;
pub const PAGE_BYTES: usize = 192 * 1024;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionKind {
    Assets,
    Services,
    Requests,
    Operations,
    Targets,
    Enrollments,
}
impl CollectionKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Assets => "assets",
            Self::Services => "services",
            Self::Requests => "requests",
            Self::Operations => "operations",
            Self::Targets => "targets",
            Self::Enrollments => "enrollments",
        }
    }
    pub fn supports_eligibility(self) -> bool {
        matches!(self, Self::Assets | Self::Services | Self::Targets)
    }
    fn source(self) -> (&'static str, &'static str, &'static str, &'static str) {
        match self {
            Self::Assets => ("assets", "asset_id", "(SELECT min(created_at) FROM asset_revisions r WHERE r.org_id=s.org_id AND r.project_id=s.project_id AND r.asset_id=s.asset_id)", "(SELECT max(created_at) FROM asset_revisions r WHERE r.org_id=s.org_id AND r.project_id=s.project_id AND r.asset_id=s.asset_id)"),
            Self::Services => ("services", "service_id", "(SELECT min(created_at) FROM service_revisions r WHERE r.org_id=s.org_id AND r.project_id=s.project_id AND r.service_id=s.service_id)", "(SELECT max(created_at) FROM service_revisions r WHERE r.org_id=s.org_id AND r.project_id=s.project_id AND r.service_id=s.service_id)"),
            Self::Requests => ("requests", "request_id", "created_at", "(SELECT updated_at FROM operations o WHERE o.org_id=s.org_id AND o.project_id=s.project_id AND o.request_id=s.request_id)"),
            Self::Operations => ("operations", "operation_id", "created_at", "updated_at"),
            Self::Targets|Self::Enrollments => ("target_enrollments", "target_id", "enrolled_at", "max(enrolled_at,coalesce(revoked_at,0),coalesce((SELECT max(checked_at) FROM enrolled_capabilities c WHERE c.org_id=s.org_id AND c.project_id=s.project_id AND c.target_id=s.target_id),0))")
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollectionSnapshot {
    pub version: i64,
    pub issued_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollectionKey {
    pub created_at: i64,
    pub id: String,
}
pub struct CollectionPage {
    pub items: Vec<Value>,
    pub next_after: Option<CollectionKey>,
    pub snapshot: CollectionSnapshot,
}
fn view(c: &Connection, t: &Tenant, kind: CollectionKind, id: &str, now: i64) -> Result<Value> {
    match kind {
        CollectionKind::Assets | CollectionKind::Services => {
            registry::collection_view(c, t, kind, id)
        }
        CollectionKind::Requests => Ok(serde_json::to_value(read_request(c, t, id)?)?),
        CollectionKind::Operations => Ok(read_operation(c, t, id)?.view()),
        CollectionKind::Targets => enrollment::target_view(c, t, id, now),
        CollectionKind::Enrollments => enrollment::enrollment_view(c, t, id, now),
    }
}
fn original_creation(c: &Connection, t: &Tenant, kind: CollectionKind, id: &str) -> Result<i64> {
    let (table, key, created, _) = kind.source();
    let created: i64 = c
        .query_row(
            &format!(
                "SELECT {created} FROM {table} s WHERE org_id=?1 AND project_id=?2 AND {key}=?3"
            ),
            params![t.org_id, t.project_id, id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(StoreError::Integrity("collection source missing"))?;
    valid_time(created).map_err(|_| StoreError::Integrity("collection creation time"))?;
    Ok(created)
}
fn verify_projection(
    c: &Connection,
    t: &Tenant,
    kind: CollectionKind,
    key: &CollectionKey,
    value: &Value,
) -> Result<()> {
    let (_, id, _, _) = kind.source();
    if value[id] != key.id
        || value.get("org_id").is_some_and(|v| v != &t.org_id)
        || value.get("project_id").is_some_and(|v| v != &t.project_id)
        || original_creation(c, t, kind, &key.id)? != key.created_at
    {
        return Err(StoreError::Integrity("collection projection mismatch"));
    }
    Ok(())
}
/// Must run inside the same transaction as the source mutation.
pub(crate) fn capture(
    c: &Connection,
    t: &Tenant,
    kind: CollectionKind,
    id: &str,
    now: i64,
) -> Result<()> {
    capture_inner(c, t, kind, id, now, false)
}
fn capture_inner(
    c: &Connection,
    t: &Tenant,
    kind: CollectionKind,
    id: &str,
    now: i64,
    backfill: bool,
) -> Result<()> {
    if !backfill {
        check_clock(c, t, now)?;
    }
    let value = match view(c, t, kind, id, now) {
        Err(StoreError::NotFound) if kind == CollectionKind::Targets => return Ok(()),
        other => other?,
    };
    let bytes = canonical_bytes(&value)?;
    let hash = hash_bytes(&bytes);
    let previous:Option<String>=c.query_row("SELECT content_hash FROM collection_versions WHERE org_id=?1 AND project_id=?2 AND kind=?3 AND resource_id=?4 ORDER BY version DESC LIMIT 1",params![t.org_id,t.project_id,kind.name(),id],|r|r.get(0)).optional()?;
    if previous.as_deref() == Some(&hash) {
        return Ok(());
    }
    let created = original_creation(c, t, kind, id)?;
    c.execute("INSERT INTO collection_versions(org_id,project_id,kind,resource_id,sort_created_at,recorded_at,canonical_bytes,content_hash,version) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,(SELECT coalesce(max(version),0)+1 FROM collection_versions WHERE org_id=?1 AND project_id=?2))",params![t.org_id,t.project_id,kind.name(),id,created,now,bytes,hash])?;
    if !backfill {
        prune(c, t, now)?;
    }
    Ok(())
}
pub(crate) fn capture_enrollment(c: &Connection, t: &Tenant, id: &str, now: i64) -> Result<()> {
    capture(c, t, CollectionKind::Enrollments, id, now)?;
    capture(c, t, CollectionKind::Targets, id, now)
}
fn check_clock(c: &Connection, t: &Tenant, now: i64) -> Result<()> {
    let previous: Option<i64> = c
        .query_row(
            "SELECT checked_at FROM collection_clocks WHERE org_id=?1 AND project_id=?2",
            params![t.org_id, t.project_id],
            |r| r.get(0),
        )
        .optional()?;
    if previous.is_some_and(|p| p > now) {
        return Err(StoreError::InvalidInput("collection clock regressed"));
    }
    c.execute("INSERT INTO collection_clocks VALUES(?1,?2,?3) ON CONFLICT(org_id,project_id) DO UPDATE SET checked_at=excluded.checked_at",params![t.org_id,t.project_id,now])?;
    Ok(())
}
fn prune(c: &Connection, t: &Tenant, now: i64) -> Result<()> {
    // Keep all versions in the live cursor window and the last older version per
    // resource. That predecessor is needed by a snapshot started before a change.
    c.execute("DELETE FROM collection_versions WHERE org_id=?1 AND project_id=?2 AND recorded_at<?3 AND version NOT IN (SELECT max(version) FROM collection_versions WHERE org_id=?1 AND project_id=?2 AND recorded_at<?3 GROUP BY kind,resource_id)",params![t.org_id,t.project_id,now.saturating_sub(SNAPSHOT_SECONDS)])?;
    Ok(())
}
/// Migration runs atomically; memory is bounded to 128 IDs, never all objects.
pub(crate) fn backfill(c: &Connection) -> Result<()> {
    for kind in [
        CollectionKind::Assets,
        CollectionKind::Services,
        CollectionKind::Requests,
        CollectionKind::Operations,
        CollectionKind::Enrollments,
        CollectionKind::Targets,
    ] {
        let (table, key, _, recorded) = kind.source();
        let mut after = 0_i64;
        loop {
            let rows = {
                let mut q=c.prepare(&format!("SELECT rowid,org_id,project_id,{key},{recorded} FROM {table} s WHERE rowid>?1 ORDER BY rowid LIMIT 128"))?;
                let rows = q
                    .query_map([after], |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            Tenant {
                                org_id: r.get(1)?,
                                project_id: r.get(2)?,
                            },
                            r.get::<_, String>(3)?,
                            r.get::<_, i64>(4)?,
                        ))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                rows
            };
            if rows.is_empty() {
                break;
            }
            for (rowid, t, id, at) in rows {
                capture_inner(c, &t, kind, &id, at, true)?;
                after = rowid;
            }
        }
    }
    Ok(())
}
impl Store {
    #[allow(clippy::too_many_arguments)]
    pub fn list_collection_page(
        &self,
        t: &Tenant,
        kind: CollectionKind,
        snapshot: Option<CollectionSnapshot>,
        after: Option<CollectionKey>,
        limit: usize,
        eligible: bool,
        now: i64,
    ) -> Result<CollectionPage> {
        valid_limit(limit)?;
        valid_time(now)?;
        if eligible && !kind.supports_eligibility() {
            return Err(StoreError::InvalidInput("eligibility filter"));
        }
        if let Some(key) = &after {
            valid_time(key.created_at)?;
            if key.id.is_empty() || key.id.len() > 128 {
                return Err(StoreError::InvalidInput("page key"));
            }
        }
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_clock(&tx, t, now)?;
        let snapshot=match snapshot {
            Some(s) if s.version<0||s.issued_at>now||s.issued_at<0=>return Err(StoreError::InvalidInput("snapshot")),
            Some(s) if now-s.issued_at>=SNAPSHOT_SECONDS=>return Err(StoreError::Conflict("SNAPSHOT_EXPIRED")),
            Some(s)=>s,
            None=>CollectionSnapshot{version:tx.query_row("SELECT coalesce(max(version),0) FROM collection_versions WHERE org_id=?1 AND project_id=?2",params![t.org_id,t.project_id],|r|r.get(0))?,issued_at:now}
        };
        prune(&tx, t, now)?;
        let start = after.unwrap_or(CollectionKey {
            created_at: 0,
            id: String::new(),
        });
        let rows = {
            let mut q=tx.prepare("SELECT resource_id,sort_created_at,canonical_bytes,content_hash FROM collection_versions v WHERE org_id=?1 AND project_id=?2 AND kind=?3 AND version<=?4 AND (sort_created_at,resource_id)>(?5,?6) AND version=(SELECT max(version) FROM collection_versions x WHERE x.org_id=v.org_id AND x.project_id=v.project_id AND x.kind=v.kind AND x.resource_id=v.resource_id AND x.version<=?4) ORDER BY sort_created_at,resource_id LIMIT ?7")?;
            let rows = q
                .query_map(
                    params![
                        t.org_id,
                        t.project_id,
                        kind.name(),
                        snapshot.version,
                        start.created_at,
                        start.id,
                        limit + 1
                    ],
                    |r| {
                        Ok((
                            CollectionKey {
                                id: r.get(0)?,
                                created_at: r.get(1)?,
                            },
                            r.get::<_, Vec<u8>>(2)?,
                            r.get::<_, String>(3)?,
                        ))
                    },
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let mut items = Vec::new();
        let mut bytes = 2;
        let mut last = start;
        let mut more = false;
        for (scanned, (key, raw, hash)) in rows.into_iter().enumerate() {
            if scanned == limit {
                more = true;
                break;
            }
            if hash_bytes(&raw) != hash {
                return Err(StoreError::Integrity("collection cache digest"));
            }
            let mut value: Value = serde_json::from_slice(&raw)?;
            verify_projection(&tx, t, kind, &key, &value)?;
            // Snapshot identity/content is stable, but safety can only decrease as
            // credentials and reports expire. A newer report cannot revive an old one.
            let valid = if kind == CollectionKind::Targets {
                enrollment::snapshot_target_eligible(&tx, t, &value, now)?
            } else if kind == CollectionKind::Enrollments {
                enrollment::enrollment_view(&tx, t, &key.id, now)?["state"] == "observe_only"
            } else {
                true
            };
            if !valid && matches!(kind, CollectionKind::Targets | CollectionKind::Enrollments) {
                value["state"] = json!("quarantined");
            }
            if eligible {
                let current = match kind {
                    CollectionKind::Targets => {
                        valid && enrollment::target_eligible(&tx, t, &key.id, now)?
                    }
                    _ => {
                        view(&tx, t, kind, &key.id, now)?["state"] == "active"
                            && value["state"] == "active"
                    }
                };
                if !current {
                    last = key;
                    continue;
                }
            }
            let size = serde_json::to_vec(&value)?.len() + 1;
            if size + 2 > PAGE_BYTES {
                return Err(StoreError::Conflict("ITEM_TOO_LARGE"));
            }
            if bytes + size > PAGE_BYTES {
                more = true;
                break;
            }
            bytes += size;
            items.push(value);
            last = key;
        }
        tx.commit()?;
        Ok(CollectionPage {
            items,
            next_after: more.then_some(last),
            snapshot,
        })
    }
}

//! Durable atomic root AND project admission. UNKNOWN keeps both reservations.
//! This is a local SQLite authority ledger, not a distributed signer service.
use crate::{AuthorityError, Result};
use fw_contracts::canonical_hash;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path, time::Duration};

#[derive(Debug, Clone, Copy)]
pub struct QuotaLimits {
    pub active_leases: i64,
    pub new_leases_per_day: i64,
    pub unique_destinations_per_day: i64,
    pub cumulative_seconds_per_day: i64,
    pub concurrent_deployments: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    pub reservation_id: String,
    pub org_id: String,
    pub root_id: String,
    pub project_id: String,
    pub lease_not_before: i64,
    pub lease_expires_at: i64,
    pub issued_at: i64,
    pub destination_ids: Vec<String>,
    pub plan_hash: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub reservation_id: String,
    pub replay: bool,
}
pub struct QuotaLedger {
    connection: Connection,
}
impl QuotaLedger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_connection(Connection::open(path)?)
    }
    pub fn in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }
    fn from_connection(connection: Connection) -> Result<Self> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS authority_clock (org_id TEXT PRIMARY KEY, as_of INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS authority_reservations (
          reservation_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, root_id TEXT NOT NULL,
          project_id TEXT NOT NULL, request_hash TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','active','unknown','released')));
        CREATE TABLE IF NOT EXISTS authority_usage (
          reservation_id TEXT NOT NULL REFERENCES authority_reservations(reservation_id),
          org_id TEXT NOT NULL, scope TEXT NOT NULL, issued_at INTEGER NOT NULL,
          new_leases INTEGER NOT NULL, seconds INTEGER NOT NULL,
          PRIMARY KEY(reservation_id,scope,issued_at));
        CREATE INDEX IF NOT EXISTS authority_usage_day ON authority_usage(org_id,scope,issued_at);
        CREATE TABLE IF NOT EXISTS authority_destinations (
          reservation_id TEXT NOT NULL REFERENCES authority_reservations(reservation_id),
          org_id TEXT NOT NULL, scope TEXT NOT NULL, issued_at INTEGER NOT NULL,
          destination_id TEXT NOT NULL, PRIMARY KEY(reservation_id,scope,issued_at,destination_id));")?;
        Ok(Self { connection })
    }
    pub fn reserve(
        &mut self,
        request: &ReservationRequest,
        root: QuotaLimits,
        project: QuotaLimits,
    ) -> Result<Reservation> {
        if request.lease_not_before < 0
            || request.lease_expires_at < 0
            || request.lease_expires_at <= request.lease_not_before
            || request.lease_expires_at - request.lease_not_before > 86400
            || request.lease_expires_at - request.lease_not_before < 60
            || request.issued_at > request.lease_not_before
            || request.issued_at < 0
        {
            return Err(AuthorityError::Invalid("lease interval"));
        }
        for id in [
            &request.reservation_id,
            &request.org_id,
            &request.root_id,
            &request.project_id,
        ] {
            if !crate::uuid_ok(id) {
                return Err(AuthorityError::Invalid("reservation identity"));
            }
        }
        if !crate::hash_ok(&request.plan_hash)
            || request.destination_ids.is_empty()
            || request.destination_ids.len() > 4096
            || request.destination_ids.iter().any(|d| !crate::uuid_ok(d))
        {
            return Err(AuthorityError::Invalid("reservation destinations or plan"));
        }
        if request
            .destination_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != request.destination_ids.len()
        {
            return Err(AuthorityError::Invalid("duplicate destination"));
        }
        let mut normalized = request.clone();
        normalized.destination_ids.sort();
        let digest = canonical_hash(&normalized)
            .map_err(|_| AuthorityError::Invalid("reservation canonicalization"))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = tx
            .query_row(
                "SELECT request_hash,state FROM authority_reservations WHERE reservation_id=?",
                [&request.reservation_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if existing.0 != digest || existing.1 != "reserved" {
                return Err(AuthorityError::Conflict);
            }
            return Ok(Reservation {
                reservation_id: request.reservation_id.clone(),
                replay: true,
            });
        }
        if tx
            .query_row(
                "SELECT as_of FROM authority_clock WHERE org_id=?",
                [&request.org_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_some_and(|last| last > request.issued_at)
        {
            return Err(AuthorityError::Time);
        }
        let scopes = [
            (format!("root:{}", request.root_id), root),
            (format!("project:{}", request.project_id), project),
        ];
        let issued_day = request.issued_at;
        let days = BTreeSet::from([issued_day]);
        for (scope, limits) in &scopes {
            if [
                limits.active_leases,
                limits.new_leases_per_day,
                limits.unique_destinations_per_day,
                limits.cumulative_seconds_per_day,
                limits.concurrent_deployments,
            ]
            .iter()
            .any(|v| *v < 1)
            {
                return Err(AuthorityError::Quota);
            }
            let key = if scope.starts_with("root:") {
                "root_id"
            } else {
                "project_id"
            };
            let id = if key == "root_id" {
                &request.root_id
            } else {
                &request.project_id
            };
            let (active,dispatch):(i64,i64)=tx.query_row(&format!("SELECT COUNT(*),COALESCE(SUM(CASE WHEN state IN ('reserved','dispatched','unknown') THEN 1 ELSE 0 END),0) FROM authority_reservations WHERE org_id=? AND {key}=? AND state!='released'"),params![request.org_id,id],|r|Ok((r.get(0)?,r.get(1)?)))?;
            if active >= limits.active_leases || dispatch >= limits.concurrent_deployments {
                return Err(AuthorityError::Quota);
            }
            for day in &days {
                let seconds = request.lease_expires_at - request.lease_not_before;
                let new_count = i64::from(*day == issued_day);
                let (used_new,used_secs):(i64,i64)=tx.query_row("SELECT COALESCE(SUM(new_leases),0),COALESCE(SUM(seconds),0) FROM authority_usage WHERE org_id=? AND scope=? AND issued_at>? AND issued_at<=?",params![request.org_id,scope,day-86400,day],|r|Ok((r.get(0)?,r.get(1)?)))?;
                let mut stmt=tx.prepare("SELECT DISTINCT destination_id FROM authority_destinations WHERE org_id=? AND scope=? AND issued_at>? AND issued_at<=?")?;
                let mut destinations = stmt
                    .query_map(params![request.org_id, scope, day - 86400, day], |r| {
                        r.get::<_, String>(0)
                    })?
                    .collect::<std::result::Result<BTreeSet<_>, _>>()?;
                destinations.extend(request.destination_ids.iter().cloned());
                if used_new
                    .checked_add(new_count)
                    .is_none_or(|n| n > limits.new_leases_per_day)
                    || used_secs
                        .checked_add(seconds)
                        .is_none_or(|n| n > limits.cumulative_seconds_per_day)
                    || destinations.len() as i64 > limits.unique_destinations_per_day
                {
                    return Err(AuthorityError::Quota);
                }
            }
        }
        tx.execute(
            "INSERT INTO authority_reservations VALUES(?,?,?,?,?,'reserved')",
            params![
                request.reservation_id,
                request.org_id,
                request.root_id,
                request.project_id,
                digest
            ],
        )?;
        for (scope, _) in &scopes {
            for day in &days {
                let seconds = request.lease_expires_at - request.lease_not_before;
                tx.execute(
                    "INSERT INTO authority_usage VALUES(?,?,?,?,?,?)",
                    params![
                        request.reservation_id,
                        request.org_id,
                        scope,
                        day,
                        i64::from(*day == issued_day),
                        seconds
                    ],
                )?;
                for destination in &request.destination_ids {
                    tx.execute(
                        "INSERT INTO authority_destinations VALUES(?,?,?,?,?)",
                        params![
                            request.reservation_id,
                            request.org_id,
                            scope,
                            day,
                            destination
                        ],
                    )?;
                }
            }
        }
        tx.execute("INSERT INTO authority_clock VALUES(?,?) ON CONFLICT(org_id) DO UPDATE SET as_of=excluded.as_of",params![request.org_id,request.issued_at])?;
        tx.commit()?;
        Ok(Reservation {
            reservation_id: request.reservation_id.clone(),
            replay: false,
        })
    }
    /// CAS state transition. `released` requires externally verified non-dispatch,
    /// expiry/readback, or revocation proof; UNKNOWN is deliberately not releasable.
    pub fn transition(&mut self, org: &str, id: &str, from: &str, to: &str) -> Result<()> {
        if !matches!(
            (from, to),
            ("reserved", "dispatched" | "released")
                | ("dispatched", "active" | "unknown")
                | ("active", "released" | "unknown")
                | ("unknown", "active")
        ) {
            return Err(AuthorityError::Invalid("unsafe quota state transition"));
        }
        if self.connection.execute("UPDATE authority_reservations SET state=? WHERE org_id=? AND reservation_id=? AND state=?",params![to,org,id,from])?!=1 {return Err(AuthorityError::Conflict);}
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u128) -> String {
        uuid::Uuid::from_u128(n).to_string()
    }
    fn request(n: u128) -> ReservationRequest {
        ReservationRequest {
            reservation_id: id(n),
            org_id: id(2),
            root_id: id(3),
            project_id: id(4),
            lease_not_before: 86370,
            lease_expires_at: 86430,
            issued_at: 86370,
            destination_ids: vec![id(5)],
            plan_hash: format!("sha256:{}", "a".repeat(64)),
        }
    }
    fn limits() -> QuotaLimits {
        QuotaLimits {
            active_leases: 1,
            new_leases_per_day: 10,
            unique_destinations_per_day: 10,
            cumulative_seconds_per_day: 100,
            concurrent_deployments: 1,
        }
    }
    #[test]
    fn root_and_project_are_atomic_and_unknown_is_held() {
        let mut l = QuotaLedger::in_memory().unwrap();
        let r = request(1);
        l.reserve(&r, limits(), limits()).unwrap();
        assert!(l.reserve(&r, limits(), limits()).unwrap().replay);
        let mut other = request(6);
        other.project_id = id(7);
        assert!(matches!(
            l.reserve(&other, limits(), limits()),
            Err(AuthorityError::Quota)
        ));
        l.transition(&r.org_id, &r.reservation_id, "reserved", "dispatched")
            .unwrap();
        l.transition(&r.org_id, &r.reservation_id, "dispatched", "unknown")
            .unwrap();
        assert!(
            l.transition(&r.org_id, &r.reservation_id, "unknown", "released")
                .is_err()
        );
        assert!(l.reserve(&other, limits(), limits()).is_err());
    }
    #[test]
    fn idempotency_conflict_and_no_refund() {
        let mut l = QuotaLedger::in_memory().unwrap();
        let r = request(1);
        let mut q = limits();
        q.cumulative_seconds_per_day = 60;
        l.reserve(&r, q, q).unwrap();
        let mut changed = r.clone();
        changed.plan_hash = format!("sha256:{}", "b".repeat(64));
        assert!(matches!(
            l.reserve(&changed, q, q),
            Err(AuthorityError::Conflict)
        ));
        l.transition(&r.org_id, &r.reservation_id, "reserved", "released")
            .unwrap();
        let other = request(6);
        assert!(matches!(
            l.reserve(&other, q, q),
            Err(AuthorityError::Quota)
        ));
    }
    #[test]
    fn project_quota_failure_does_not_consume_root() {
        let mut l = QuotaLedger::in_memory().unwrap();
        let r = request(1);
        let mut bad = limits();
        bad.active_leases = 0;
        assert!(l.reserve(&r, limits(), bad).is_err());
        l.reserve(&r, limits(), limits()).unwrap();
    }
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use std::{
        sync::{Arc, Barrier},
        thread,
    };
    fn id(n: u128) -> String {
        uuid::Uuid::from_u128(n).to_string()
    }
    fn req(n: u128, at: i64) -> ReservationRequest {
        ReservationRequest {
            reservation_id: id(n),
            org_id: id(2),
            root_id: id(3),
            project_id: id(4),
            lease_not_before: at,
            lease_expires_at: at + 60,
            issued_at: at,
            destination_ids: vec![id(5)],
            plan_hash: format!("sha256:{}", "a".repeat(64)),
        }
    }
    fn limits() -> QuotaLimits {
        QuotaLimits {
            active_leases: 1,
            new_leases_per_day: 1,
            unique_destinations_per_day: 1,
            cumulative_seconds_per_day: 60,
            concurrent_deployments: 1,
        }
    }
    #[test]
    fn rolling_window_excludes_exact_old_boundary() {
        let mut ledger = QuotaLedger::in_memory().unwrap();
        let r = req(10, 100000);
        ledger.reserve(&r, limits(), limits()).unwrap();
        ledger
            .transition(&r.org_id, &r.reservation_id, "reserved", "released")
            .unwrap();
        assert!(
            ledger
                .reserve(&req(11, 186399), limits(), limits())
                .is_err()
        );
        ledger
            .reserve(&req(11, 186400), limits(), limits())
            .unwrap();
    }
    #[test]
    fn backwards_clock_does_not_create_new_credit() {
        let mut ledger = QuotaLedger::in_memory().unwrap();
        let r = req(10, 100000);
        ledger.reserve(&r, limits(), limits()).unwrap();
        ledger
            .transition(&r.org_id, &r.reservation_id, "reserved", "released")
            .unwrap();
        assert!(matches!(
            ledger.reserve(&req(11, 100), limits(), limits()),
            Err(AuthorityError::Time)
        ));
    }
    #[test]
    fn separate_connections_cannot_oversubscribe_and_survive_reopen() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fw-authority-{}-{unique}.sqlite",
            std::process::id()
        ));
        drop(QuotaLedger::open(&path).unwrap());
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let mut l = QuotaLedger::open(path).unwrap();
                    barrier.wait();
                    l.reserve(&req(100 + i, 100000), limits(), limits()).is_ok()
                })
            })
            .collect();
        let count = handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>();
        assert_eq!(count, 1);
        let mut restored = QuotaLedger::open(&path).unwrap();
        assert!(matches!(
            restored.reserve(&req(999, 100000), limits(), limits()),
            Err(AuthorityError::Quota)
        ));
        drop(restored);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn consumed_or_released_reservation_cannot_authorize_new_signature() {
        for terminal in ["released", "dispatched", "active", "unknown"] {
            let mut ledger = QuotaLedger::in_memory().unwrap();
            let r = req(10, 100000);
            ledger.reserve(&r, limits(), limits()).unwrap();
            if terminal == "released" {
                ledger
                    .transition(&r.org_id, &r.reservation_id, "reserved", "released")
                    .unwrap();
            } else {
                ledger
                    .transition(&r.org_id, &r.reservation_id, "reserved", "dispatched")
                    .unwrap();
                if terminal != "dispatched" {
                    ledger
                        .transition(&r.org_id, &r.reservation_id, "dispatched", terminal)
                        .unwrap();
                }
            }
            assert!(matches!(
                ledger.reserve(&r, limits(), limits()),
                Err(AuthorityError::Conflict)
            ));
        }
    }
}

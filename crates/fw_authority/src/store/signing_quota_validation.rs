// A reservation has at most four distinct quota states. Imported genesis may
// begin at an advanced state, but never excuses a gap or an absent revision 0.
const MAX_RETAINED_QUOTA_TRANSITIONS: usize = 4;

struct RetainedTransition {
    revision: i64,
    state: String,
    issued: Option<i64>,
    active: i64,
    dispatch: i64,
    recorded: i64,
    kind: String,
    job: Option<String>,
    phase: Option<String>,
    work_revision: Option<Vec<u8>>,
}

fn validate_transition_history(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    stored: &Stored,
) -> Result<()> {
    let mut statement = tx.prepare("SELECT revision,state,issued_at,active_slots,dispatch_slots,recorded_at,kind,job_id,work_phase,work_revision FROM authority_signing_quota_transitions WHERE org_id=? AND project_id=? AND reservation_id=? ORDER BY revision LIMIT 5")?;
    let transitions = statement
        .query_map(params![tenant.org_id, tenant.project_id, id], |r| {
            Ok(RetainedTransition {
                revision: r.get(0)?,
                state: r.get(1)?,
                issued: r.get(2)?,
                active: r.get(3)?,
                dispatch: r.get(4)?,
                recorded: r.get(5)?,
                kind: r.get(6)?,
                job: r.get(7)?,
                phase: r.get(8)?,
                work_revision: r.get(9)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if transitions.is_empty() || transitions.len() > MAX_RETAINED_QUOTA_TRANSITIONS {
        return Err(invalid("signing quota retained history"));
    }
    let mut previous: Option<&RetainedTransition> = None;
    for (index, event) in transitions.iter().enumerate() {
        let legal = match event.state.as_str() {
            "reserved" => event.issued.is_none() && event.dispatch == 1,
            "issued" => event.issued.is_some() && event.dispatch == 1,
            "unknown" => event.issued.is_some() && event.dispatch == 1,
            "active" => event.issued.is_some() && event.dispatch == 0,
            "released" => event.issued.is_none() && event.active == 0 && event.dispatch == 0,
            _ => false,
        };
        if !legal
            || event.revision != index as i64
            || event.active
                != if event.state == "released" {
                    0
                } else {
                    i64::from(stored.lease.is_some())
                }
            || event.recorded < stored.reserved_at
            || event.recorded > MAX_TIME
            || event.issued.is_some_and(|at| {
                at < stored.reserved_at || at >= stored.reserved_until || at > event.recorded
            })
        {
            return Err(invalid("signing quota retained history"));
        }
        if let Some(previous) = previous {
            let next = matches!(
                (previous.state.as_str(), event.state.as_str()),
                ("reserved", "issued" | "unknown" | "released")
                    | ("issued", "unknown" | "active")
                    | ("unknown", "active")
            );
            if !next
                || event.kind != event.state
                || event.recorded < previous.recorded
                || if event.state == "issued" {
                    previous.issued.is_some() || event.issued != Some(event.recorded)
                } else {
                    event.issued != previous.issued
                }
            {
                return Err(invalid("signing quota retained sequence"));
            }
        } else if event.kind == "reserved" {
            if event.state != "reserved"
                || event.recorded != stored.reserved_at
                || event.job.is_some()
                || event.phase.is_some()
                || event.work_revision.is_some()
            {
                return Err(invalid("signing quota genesis"));
            }
        } else if event.kind != "imported" {
            return Err(invalid("signing quota genesis"));
        }
        // Original reservation genesis precedes the job in the same transaction.
        // Every later transition, including a supported imported genesis, binds
        // its actual retained work event rather than an arbitrary latest event.
        #[cfg(test)]
        let primitive_fixture = tests::PRIMITIVE_QUOTA_FIXTURE.get();
        #[cfg(not(test))]
        let primitive_fixture = false;
        if !(primitive_fixture || index == 0 && event.kind == "reserved") {
            let witness: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_signing_intents i JOIN authority_signing_jobs j ON j.org_id=i.org_id AND j.project_id=i.project_id AND j.job_id=i.job_id AND j.intent_id=i.intent_id JOIN authority_signing_work_events e ON e.org_id=j.org_id AND e.project_id=j.project_id AND e.job_id=j.job_id WHERE i.org_id=?1 AND i.project_id=?2 AND i.reservation_id=?3 AND e.job_id=?4 AND e.phase=?5 AND e.revision=?6 AND e.updated_at=?7 AND ((?8='reserved' AND e.phase='signer' AND e.state IN ('prepared','claimed')) OR (?8='released' AND e.phase='signer' AND e.state='cancelled' AND e.kind='cancelled') OR (?8='issued' AND e.phase='signer' AND e.state='ready' AND e.kind='finalized') OR (?8='unknown' AND e.phase='dispatch' AND e.state='unknown' AND e.kind='unknown') OR (?8='active' AND e.phase='dispatch' AND e.state='delivered' AND e.kind='delivered')) AND ((?9 IS NULL AND (?8='reserved' OR NOT EXISTS(SELECT 1 FROM authority_signing_results s WHERE s.org_id=i.org_id AND s.project_id=i.project_id AND s.intent_id=i.intent_id))) OR (?9 IS NOT NULL AND EXISTS(SELECT 1 FROM authority_signing_results s JOIN authority_signing_outbox o ON o.org_id=s.org_id AND o.project_id=s.project_id AND o.intent_id=s.intent_id AND o.job_id=i.job_id AND o.grant_hash=s.grant_hash AND o.grant_bytes=s.grant_bytes JOIN authority_signing_quota_usage u ON u.org_id=i.org_id AND u.project_id=i.project_id AND u.reservation_id=i.reservation_id WHERE s.org_id=i.org_id AND s.project_id=i.project_id AND s.intent_id=i.intent_id AND s.finalized_at=?9 AND u.charged_at=?9 AND u.cost_hash=?10 AND (?8!='active' OR EXISTS(SELECT 1 FROM authority_signing_deliveries d WHERE d.org_id=i.org_id AND d.project_id=i.project_id AND d.job_id=i.job_id AND d.grant_hash=s.grant_hash AND d.recorded_at=?7))))))",
                params![tenant.org_id,tenant.project_id,id,event.job,event.phase,event.work_revision,event.recorded,event.state,event.issued,stored.cost_hash],|r|r.get(0))?;
            if !witness {
                return Err(invalid("signing quota retained witness"));
            }
        }
        previous = Some(event);
    }
    let last = previous.ok_or_else(|| invalid("signing quota retained history"))?;
    if last.state != stored.state
        || last.issued != stored.issued_at
        || last.active != stored.active
        || last.dispatch != stored.dispatch
    {
        return Err(invalid("signing quota retained projection"));
    }
    Ok(())
}

pub(super) fn validate_retained_transitions(tx: &Transaction<'_>) -> Result<()> {
    let dangling: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM authority_signing_quota_transition_heads h NOT INDEXED WHERE NOT EXISTS(SELECT 1 FROM authority_signing_quota_reservations r WHERE r.org_id=h.org_id AND r.project_id=h.project_id AND r.reservation_id=h.reservation_id) UNION ALL SELECT 1 FROM authority_signing_quota_transitions t NOT INDEXED WHERE NOT EXISTS(SELECT 1 FROM authority_signing_quota_reservations r WHERE r.org_id=t.org_id AND r.project_id=t.project_id AND r.reservation_id=t.reservation_id))",
        [],
        |r| r.get(0),
    )?;
    if dangling {
        return Err(invalid("signing quota retained reservation graph"));
    }
    let mut statement = tx.prepare(
        "SELECT org_id,project_id,reservation_id FROM authority_signing_quota_reservations NOT INDEXED",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        read_record(
            tx,
            &tenant,
            &row.get::<_, String>(2)?,
            true,
            false,
            ReservationRead::Committed,
        )?;
    }
    Ok(())
}

// Validate only edges reachable from the current indexed obligation. Global
// orphan checks run at open/maintenance; sensitive admission never scans a
// project's entire cancelled history or imposes a lifetime job ceiling.
fn validate_reservation_graph(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    initializing: ReservationRead,
) -> Result<()> {
    let intents:i64=tx.query_row("SELECT COUNT(*) FROM (SELECT 1 FROM authority_signing_intents WHERE org_id=? AND project_id=? AND reservation_id=? LIMIT 2)",params![tenant.org_id,tenant.project_id,id],|r|r.get(0))?;
    #[cfg(test)]
    let primitive_fixture = tests::PRIMITIVE_QUOTA_FIXTURE.get();
    #[cfg(not(test))]
    let primitive_fixture = false;
    let expected_intents = i64::from(!matches!(initializing, ReservationRead::BeforeJob));
    if intents > 1 || (!primitive_fixture && intents != expected_intents) {
        return Err(invalid("signing reservation intent identity"));
    }
    let events:i64=tx.query_row("SELECT COUNT(*) FROM (SELECT 1 FROM authority_signing_work_events e JOIN authority_signing_intents i ON i.org_id=e.org_id AND i.project_id=e.project_id AND i.job_id=e.job_id WHERE i.org_id=? AND i.project_id=? AND i.reservation_id=? LIMIT ?4)",params![tenant.org_id,tenant.project_id,id,(signing_jobs::MAX_WORK_EVENTS * 2 + 1) as i64],|r|r.get(0))?;
    if events > (signing_jobs::MAX_WORK_EVENTS * 2) as i64 {
        return Err(AuthorityError::Quota);
    }
    let bound_audits:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='authority_signing_work_audits')",[],|r|r.get(0))?;
    if bound_audits {
        // The preceding event bound makes this an indexed, per-obligation
        // check. Retained cancelled history is never scanned on admission.
        let missing:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_intents i JOIN authority_signing_work_events e ON e.org_id=i.org_id AND e.project_id=i.project_id AND e.job_id=i.job_id WHERE i.org_id=?1 AND i.project_id=?2 AND i.reservation_id=?3 AND NOT EXISTS(SELECT 1 FROM authority_signing_work_audits b JOIN authority_audit a ON a.org_id=b.org_id AND a.project_id=b.project_id AND a.sequence=b.audit_sequence AND a.event_hash=b.audit_hash WHERE b.org_id=e.org_id AND b.project_id=e.project_id AND b.job_id=e.job_id AND b.phase=e.phase AND b.revision=e.revision AND b.kind=e.kind AND b.updated_at=e.updated_at AND a.resource_id=e.job_id AND a.kind='signing_'||e.phase||'_'||e.kind AND a.recorded_at=e.updated_at))",params![tenant.org_id,tenant.project_id,id],|r|r.get(0))?;
        if missing {
            return Err(invalid("signing retained work audit graph"));
        }
    } else if tx.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? >= 11 {
        return Err(invalid("missing signing work audit bindings"));
    }
    let broken:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_intents i WHERE i.org_id=?1 AND i.project_id=?2 AND i.reservation_id=?3 AND (NOT EXISTS(SELECT 1 FROM authority_signing_jobs j WHERE j.org_id=i.org_id AND j.project_id=i.project_id AND j.job_id=i.job_id AND j.intent_id=i.intent_id) OR EXISTS(SELECT 1 FROM authority_signing_jobs j WHERE j.org_id=i.org_id AND j.project_id=i.project_id AND j.intent_id=i.intent_id AND j.job_id!=i.job_id) OR (?4=0 AND NOT EXISTS(SELECT 1 FROM authority_signing_work_heads h WHERE h.org_id=i.org_id AND h.project_id=i.project_id AND h.job_id=i.job_id AND h.phase='signer')) OR EXISTS(SELECT 1 FROM authority_signing_work_heads h WHERE h.org_id=i.org_id AND h.project_id=i.project_id AND h.job_id=i.job_id AND NOT EXISTS(SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=h.org_id AND e.project_id=h.project_id AND e.job_id=h.job_id AND e.phase=h.phase AND e.revision=h.revision AND e.revision=(SELECT MAX(w.revision) FROM authority_signing_work_events w WHERE w.org_id=h.org_id AND w.project_id=h.project_id AND w.job_id=h.job_id AND w.phase=h.phase) AND e.state=h.state AND e.claim_generation=h.claim_generation AND e.claim_hash IS h.claim_hash AND e.worker_id IS h.worker_id AND e.claim_until IS h.claim_until AND e.attempts=h.attempts AND e.available_at=h.available_at AND e.updated_at=h.updated_at)) OR EXISTS(SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=i.org_id AND e.project_id=i.project_id AND e.job_id=i.job_id AND NOT EXISTS(SELECT 1 FROM authority_signing_work_heads h WHERE h.org_id=e.org_id AND h.project_id=e.project_id AND h.job_id=e.job_id AND h.phase=e.phase)) OR EXISTS(SELECT 1 FROM authority_signing_outbox o WHERE o.org_id=i.org_id AND o.project_id=i.project_id AND (o.job_id=i.job_id OR o.intent_id=i.intent_id) AND (o.job_id!=i.job_id OR o.intent_id!=i.intent_id OR NOT EXISTS(SELECT 1 FROM authority_signing_results s WHERE s.org_id=o.org_id AND s.project_id=o.project_id AND s.intent_id=o.intent_id AND s.grant_hash=o.grant_hash AND s.grant_bytes=o.grant_bytes)))))",params![tenant.org_id,tenant.project_id,id,matches!(initializing, ReservationRead::InitializingJob)],|r|r.get(0))?;
    if broken {
        return Err(invalid("signing retained reference graph"));
    }
    Ok(())
}

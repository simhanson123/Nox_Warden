-- State and slot projections advance only with retained transition evidence.
CREATE TABLE authority_signing_quota_transitions (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, reservation_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 2147483647),
 state TEXT NOT NULL CHECK(state IN ('reserved','issued','unknown','active','released')),
 issued_at INTEGER, active_slots INTEGER NOT NULL CHECK(active_slots BETWEEN 0 AND 1),
 dispatch_slots INTEGER NOT NULL CHECK(dispatch_slots BETWEEN 0 AND 1),
 recorded_at INTEGER NOT NULL CHECK(recorded_at>=0),
 kind TEXT NOT NULL CHECK(kind IN ('reserved','issued','unknown','active','released','imported')),
 job_id TEXT, work_phase TEXT, work_revision BLOB,
 PRIMARY KEY(org_id,project_id,reservation_id,revision),
 FOREIGN KEY(org_id,project_id,reservation_id) REFERENCES authority_signing_quota_reservations,
 FOREIGN KEY(org_id,project_id,job_id,work_phase,work_revision) REFERENCES authority_signing_work_events,
 CHECK((job_id IS NULL AND work_phase IS NULL AND work_revision IS NULL)
    OR (job_id IS NOT NULL AND work_phase IN ('signer','dispatch') AND length(work_revision)=8)),
 CHECK((state='reserved' AND issued_at IS NULL AND dispatch_slots=1)
    OR (state='issued' AND issued_at IS NOT NULL AND dispatch_slots=1)
    OR (state='unknown' AND dispatch_slots=1)
    OR (state='active' AND issued_at IS NOT NULL AND dispatch_slots=0)
    OR (state='released' AND issued_at IS NULL AND active_slots=0 AND dispatch_slots=0))
) STRICT;
CREATE TRIGGER authority_signing_quota_transitions_no_update BEFORE UPDATE ON authority_signing_quota_transitions BEGIN SELECT RAISE(ABORT,'immutable quota transition'); END;
CREATE TRIGGER authority_signing_quota_transitions_no_delete BEFORE DELETE ON authority_signing_quota_transitions BEGIN SELECT RAISE(ABORT,'retained quota transition'); END;
CREATE TRIGGER authority_signing_quota_reservations_initial
 BEFORE INSERT ON authority_signing_quota_reservations
 WHEN NEW.state!='reserved' OR NEW.issued_at IS NOT NULL OR NEW.dispatch_slots!=1 OR NEW.active_slots!=(NEW.lease_id IS NOT NULL)
 BEGIN SELECT RAISE(ABORT,'invalid initial quota state'); END;
CREATE TRIGGER authority_signing_quota_transitions_order BEFORE INSERT ON authority_signing_quota_transitions
 WHEN NOT EXISTS(
  SELECT 1 FROM authority_signing_quota_reservations r
  WHERE r.org_id=NEW.org_id AND r.project_id=NEW.project_id AND r.reservation_id=NEW.reservation_id
   AND NEW.active_slots=CASE WHEN NEW.state='released' THEN 0 ELSE r.lease_id IS NOT NULL END
   AND NEW.recorded_at>=r.reserved_at
   AND ((NEW.revision=0 AND NEW.kind IN ('reserved','imported')
       AND NOT EXISTS(SELECT 1 FROM authority_signing_quota_transitions p WHERE p.org_id=NEW.org_id AND p.project_id=NEW.project_id AND p.reservation_id=NEW.reservation_id)
       AND NEW.state=r.state AND NEW.issued_at IS r.issued_at AND NEW.active_slots=r.active_slots AND NEW.dispatch_slots=r.dispatch_slots)
    OR (NEW.kind=NEW.state AND EXISTS(
      SELECT 1 FROM authority_signing_quota_transitions p
      WHERE p.org_id=NEW.org_id AND p.project_id=NEW.project_id AND p.reservation_id=NEW.reservation_id
       AND p.revision=(SELECT MAX(q.revision) FROM authority_signing_quota_transitions q WHERE q.org_id=NEW.org_id AND q.project_id=NEW.project_id AND q.reservation_id=NEW.reservation_id)
       AND NEW.revision=p.revision+1 AND NEW.recorded_at>=p.recorded_at
       AND p.state=r.state AND p.issued_at IS r.issued_at AND p.active_slots=r.active_slots AND p.dispatch_slots=r.dispatch_slots
       AND ((p.state='reserved' AND NEW.state IN ('issued','unknown','released'))
        OR (p.state='issued' AND NEW.state IN ('unknown','active'))
        OR (p.state='unknown' AND NEW.state='active'))
       AND ((NEW.state='issued' AND p.issued_at IS NULL AND NEW.issued_at=NEW.recorded_at)
        OR (NEW.state!='issued' AND NEW.issued_at IS p.issued_at))
    )))
 ) BEGIN SELECT RAISE(ABORT,'invalid quota transition sequence'); END;
CREATE TRIGGER authority_signing_quota_transitions_evidence BEFORE INSERT ON authority_signing_quota_transitions
 WHEN NOT (NEW.revision=0 AND NEW.kind='reserved' AND NEW.state='reserved' AND NEW.job_id IS NULL)
 AND NOT EXISTS(
  SELECT 1 FROM authority_signing_intents i
  JOIN authority_signing_jobs j ON j.org_id=i.org_id AND j.project_id=i.project_id AND j.job_id=i.job_id AND j.intent_id=i.intent_id
  JOIN authority_signing_work_events e ON e.org_id=j.org_id AND e.project_id=j.project_id AND e.job_id=j.job_id
  WHERE i.org_id=NEW.org_id AND i.project_id=NEW.project_id AND i.reservation_id=NEW.reservation_id
   AND e.job_id=NEW.job_id AND e.phase=NEW.work_phase AND e.revision=NEW.work_revision
   AND e.updated_at=NEW.recorded_at
   AND EXISTS(SELECT 1 FROM authority_signing_work_heads h
    JOIN authority_signing_work_events w ON w.org_id=h.org_id AND w.project_id=h.project_id AND w.job_id=h.job_id AND w.phase=h.phase AND w.revision=h.revision
    WHERE h.org_id=e.org_id AND h.project_id=e.project_id AND h.job_id=e.job_id AND h.phase=e.phase
     AND (NEW.kind='imported' OR h.revision=e.revision)
     AND h.revision=(SELECT MAX(v.revision) FROM authority_signing_work_events v WHERE v.org_id=h.org_id AND v.project_id=h.project_id AND v.job_id=h.job_id AND v.phase=h.phase)
     AND h.state=w.state AND h.claim_generation=w.claim_generation AND h.claim_hash IS w.claim_hash AND h.worker_id IS w.worker_id AND h.claim_until IS w.claim_until AND h.attempts=w.attempts AND h.available_at=w.available_at AND h.updated_at=w.updated_at)
   AND (NEW.kind='imported' OR e.revision=(SELECT MAX(w.revision) FROM authority_signing_work_events w WHERE w.org_id=e.org_id AND w.project_id=e.project_id AND w.job_id=e.job_id AND w.phase=e.phase))
   AND (
    (NEW.state IN ('reserved','released') AND e.phase='signer'
     AND ((NEW.state='reserved' AND e.state IN ('prepared','claimed')) OR (NEW.state='released' AND e.state='cancelled' AND e.kind='cancelled'))
     AND NOT EXISTS(SELECT 1 FROM authority_signing_results s WHERE s.org_id=i.org_id AND s.project_id=i.project_id AND s.intent_id=i.intent_id)
     AND NOT EXISTS(SELECT 1 FROM authority_signing_outbox o WHERE o.org_id=i.org_id AND o.project_id=i.project_id AND o.intent_id=i.intent_id)
     AND NOT EXISTS(SELECT 1 FROM authority_signing_quota_usage u WHERE u.org_id=i.org_id AND u.project_id=i.project_id AND u.reservation_id=i.reservation_id)
     AND NOT EXISTS(SELECT 1 FROM authority_signing_work_events d WHERE d.org_id=i.org_id AND d.project_id=i.project_id AND d.job_id=i.job_id AND d.phase='dispatch'))
    OR (NEW.state IN ('issued','unknown','active')
     AND ((NEW.state='issued' AND e.phase='signer' AND e.state='ready' AND e.kind='finalized')
       OR (NEW.state='unknown' AND e.phase='dispatch' AND e.state='unknown' AND e.kind='unknown')
       OR (NEW.state='active' AND e.phase='dispatch' AND e.state='delivered' AND e.kind='delivered'))
     AND EXISTS(SELECT 1 FROM authority_signing_results s
       JOIN authority_signing_outbox o ON o.org_id=s.org_id AND o.project_id=s.project_id AND o.intent_id=s.intent_id AND o.grant_hash=s.grant_hash AND o.grant_bytes=s.grant_bytes
       JOIN authority_signing_quota_usage u ON u.org_id=i.org_id AND u.project_id=i.project_id AND u.reservation_id=i.reservation_id
       JOIN authority_signing_quota_reservations r ON r.org_id=u.org_id AND r.project_id=u.project_id AND r.reservation_id=u.reservation_id AND r.cost_hash=u.cost_hash
       WHERE s.org_id=i.org_id AND s.project_id=i.project_id AND s.intent_id=i.intent_id AND o.job_id=i.job_id
        AND s.finalized_at=NEW.issued_at AND u.charged_at=NEW.issued_at
        AND (NEW.state!='active' OR EXISTS(SELECT 1 FROM authority_signing_deliveries d WHERE d.org_id=i.org_id AND d.project_id=i.project_id AND d.job_id=i.job_id AND d.grant_hash=s.grant_hash AND d.recorded_at=NEW.recorded_at)))
    )
   )
 ) BEGIN SELECT RAISE(ABORT,'quota transition evidence missing'); END;
CREATE TRIGGER authority_signing_quota_reservations_seed AFTER INSERT ON authority_signing_quota_reservations
 BEGIN INSERT INTO authority_signing_quota_transitions VALUES(NEW.org_id,NEW.project_id,NEW.reservation_id,0,'reserved',NULL,NEW.active_slots,1,NEW.reserved_at,'reserved',NULL,NULL,NULL); END;
CREATE TRIGGER authority_signing_quota_reservations_projection
 BEFORE UPDATE OF state,issued_at,active_slots,dispatch_slots ON authority_signing_quota_reservations
 WHEN NOT EXISTS(SELECT 1 FROM authority_signing_quota_transitions t
  WHERE t.org_id=NEW.org_id AND t.project_id=NEW.project_id AND t.reservation_id=NEW.reservation_id
   AND t.revision=(SELECT MAX(q.revision) FROM authority_signing_quota_transitions q WHERE q.org_id=NEW.org_id AND q.project_id=NEW.project_id AND q.reservation_id=NEW.reservation_id)
   AND t.state=NEW.state AND t.issued_at IS NEW.issued_at AND t.active_slots=NEW.active_slots AND t.dispatch_slots=NEW.dispatch_slots)
 BEGIN SELECT RAISE(ABORT,'quota state lacks latest transition'); END;
-- Accounting membership follows the transition, not the separately mutable
-- reservation projection. A damaged projection cannot hide a held obligation.
CREATE TABLE authority_signing_quota_transition_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, reservation_id TEXT NOT NULL,
 root_id TEXT NOT NULL, lease_id TEXT, revision INTEGER NOT NULL,
 state TEXT NOT NULL, issued_at INTEGER,
 PRIMARY KEY(org_id,project_id,reservation_id),
 FOREIGN KEY(org_id,project_id,reservation_id,revision) REFERENCES authority_signing_quota_transitions
) STRICT;
CREATE INDEX authority_signing_quota_transition_root_held ON authority_signing_quota_transition_heads(org_id,root_id)
 WHERE state IN ('reserved','issued','unknown') OR (state='active' AND lease_id IS NOT NULL);
CREATE INDEX authority_signing_quota_transition_project_held ON authority_signing_quota_transition_heads(org_id,project_id)
 WHERE state IN ('reserved','issued','unknown') OR (state='active' AND lease_id IS NOT NULL);
CREATE INDEX authority_signing_quota_transition_root_accounting ON authority_signing_quota_transition_heads(org_id,root_id,issued_at)
 WHERE state='released' AND lease_id IS NOT NULL;
CREATE INDEX authority_signing_quota_transition_project_accounting ON authority_signing_quota_transition_heads(org_id,project_id,issued_at)
 WHERE state='released' AND lease_id IS NOT NULL;
CREATE TRIGGER authority_signing_quota_transition_heads_no_delete BEFORE DELETE ON authority_signing_quota_transition_heads BEGIN SELECT RAISE(ABORT,'retained quota accounting membership'); END;
CREATE TRIGGER authority_signing_quota_transition_heads_insert BEFORE INSERT ON authority_signing_quota_transition_heads
 WHEN NOT EXISTS(SELECT 1 FROM authority_signing_quota_transitions t JOIN authority_signing_quota_reservations r ON r.org_id=t.org_id AND r.project_id=t.project_id AND r.reservation_id=t.reservation_id
  WHERE t.org_id=NEW.org_id AND t.project_id=NEW.project_id AND t.reservation_id=NEW.reservation_id
   AND t.revision=NEW.revision AND t.revision=(SELECT MAX(q.revision) FROM authority_signing_quota_transitions q WHERE q.org_id=t.org_id AND q.project_id=t.project_id AND q.reservation_id=t.reservation_id)
   AND t.state=NEW.state AND t.issued_at IS NEW.issued_at AND r.root_id=NEW.root_id AND r.lease_id IS NEW.lease_id)
 BEGIN SELECT RAISE(ABORT,'invalid quota accounting membership'); END;
CREATE TRIGGER authority_signing_quota_transition_heads_update BEFORE UPDATE ON authority_signing_quota_transition_heads
 WHEN NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.reservation_id!=OLD.reservation_id OR NEW.root_id!=OLD.root_id OR NEW.lease_id IS NOT OLD.lease_id
 OR NOT EXISTS(SELECT 1 FROM authority_signing_quota_transitions t
  WHERE t.org_id=NEW.org_id AND t.project_id=NEW.project_id AND t.reservation_id=NEW.reservation_id
   AND t.revision=NEW.revision AND t.revision=(SELECT MAX(q.revision) FROM authority_signing_quota_transitions q WHERE q.org_id=t.org_id AND q.project_id=t.project_id AND q.reservation_id=t.reservation_id)
   AND t.state=NEW.state AND t.issued_at IS NEW.issued_at)
 BEGIN SELECT RAISE(ABORT,'invalid quota accounting membership'); END;
CREATE TRIGGER authority_signing_quota_transitions_membership AFTER INSERT ON authority_signing_quota_transitions
 BEGIN
 INSERT INTO authority_signing_quota_transition_heads SELECT NEW.org_id,NEW.project_id,NEW.reservation_id,r.root_id,r.lease_id,NEW.revision,NEW.state,NEW.issued_at FROM authority_signing_quota_reservations r WHERE r.org_id=NEW.org_id AND r.project_id=NEW.project_id AND r.reservation_id=NEW.reservation_id
 ON CONFLICT(org_id,project_id,reservation_id) DO UPDATE SET revision=excluded.revision,state=excluded.state,issued_at=excluded.issued_at;
 END;

-- Unsigned delivery records are retained diagnostics, not capacity-release
-- authority. Include every active record in bounded held-obligation accounting;
-- the runtime conservatively charges issued capacity until authenticated proof.
DROP INDEX authority_signing_quota_transition_root_held;
DROP INDEX authority_signing_quota_transition_project_held;
CREATE INDEX authority_signing_quota_transition_root_held ON authority_signing_quota_transition_heads(org_id,root_id)
 WHERE state IN ('reserved','issued','unknown','active');
CREATE INDEX authority_signing_quota_transition_project_held ON authority_signing_quota_transition_heads(org_id,project_id)
 WHERE state IN ('reserved','issued','unknown','active');

-- REPLACE must not bypass append-only guards through either visible identities
-- or hidden rowid collisions, regardless of recursive_triggers configuration.
CREATE TRIGGER authority_signing_work_events_no_replace BEFORE INSERT ON authority_signing_work_events
 WHEN EXISTS(SELECT 1 FROM authority_signing_work_events e WHERE e.rowid=NEW.rowid OR (e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase AND e.revision=NEW.revision))
 BEGIN SELECT RAISE(ABORT,'immutable signing work identity'); END;
CREATE TRIGGER authority_signing_work_events_sequence BEFORE INSERT ON authority_signing_work_events
 WHEN (
  (SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase LIMIT 193))<192 AND hex(NEW.revision)=printf('%016X',(SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase LIMIT 193))+1)
  AND hex(NEW.claim_generation)=printf('%016X',NEW.attempts)
  AND NEW.attempts BETWEEN 0 AND CASE WHEN NEW.phase='signer' THEN 3 ELSE 5 END
  AND NEW.updated_at BETWEEN 0 AND 253402300799 AND NEW.available_at BETWEEN 0 AND 253402300799
  AND ((NEW.state='claimed' AND length(NEW.claim_hash)=32 AND length(NEW.worker_id)=36
    AND NEW.claim_until>NEW.updated_at AND NEW.claim_until-NEW.updated_at<=900)
   OR (NEW.state!='claimed' AND NEW.claim_hash IS NULL AND NEW.worker_id IS NULL AND NEW.claim_until IS NULL))
  AND EXISTS(SELECT 1 FROM authority_signing_jobs j
   WHERE j.org_id=NEW.org_id AND j.project_id=NEW.project_id AND j.job_id=NEW.job_id
    AND NEW.updated_at>=j.created_at AND (NEW.claim_until IS NULL OR NEW.claim_until<=j.deadline)
    AND (
     (NEW.kind='created' AND (SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase LIMIT 193))=0 AND NEW.attempts=0
      AND NEW.available_at=NEW.updated_at AND NEW.updated_at<j.deadline
      AND NOT EXISTS(SELECT 1 FROM authority_signing_work_heads h WHERE h.org_id=NEW.org_id AND h.project_id=NEW.project_id AND h.job_id=NEW.job_id AND h.phase=NEW.phase)
      AND ((NEW.phase='signer' AND NEW.state='prepared' AND NEW.updated_at=j.created_at)
       OR (NEW.phase='dispatch' AND NEW.state='queued'
        AND EXISTS(SELECT 1 FROM authority_signing_work_heads h JOIN authority_signing_outbox o ON o.org_id=h.org_id AND o.project_id=h.project_id AND o.job_id=h.job_id
          WHERE h.org_id=j.org_id AND h.project_id=j.project_id AND h.job_id=j.job_id AND h.phase='signer' AND h.state='ready' AND o.created_at=NEW.updated_at))))
     OR EXISTS(SELECT 1 FROM authority_signing_work_heads h JOIN authority_signing_work_events p ON p.org_id=h.org_id AND p.project_id=h.project_id AND p.job_id=h.job_id AND p.phase=h.phase AND p.revision=h.revision
      WHERE h.org_id=NEW.org_id AND h.project_id=NEW.project_id AND h.job_id=NEW.job_id AND h.phase=NEW.phase AND h.state IS p.state AND h.revision IS p.revision AND h.claim_generation IS p.claim_generation AND h.claim_hash IS p.claim_hash AND h.worker_id IS p.worker_id AND h.claim_until IS p.claim_until AND h.attempts IS p.attempts AND h.available_at IS p.available_at AND h.updated_at IS p.updated_at
       AND hex(h.revision)=printf('%016X',(SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase LIMIT 193))) AND NEW.updated_at>=h.updated_at
       AND (
        (NEW.kind='claimed' AND NEW.state='claimed'
       AND NEW.attempts=h.attempts+1 AND NEW.available_at=h.available_at
       AND NEW.updated_at>=h.available_at AND NEW.updated_at<j.deadline
       AND ((NEW.phase='signer' AND h.state='prepared')
        OR (NEW.phase='dispatch' AND h.state IN ('queued','unknown'))
        OR (NEW.phase='signer' AND h.state='claimed' AND NEW.updated_at>=h.claim_until+min((1 << min(h.attempts,5))+(((instr('0123456789ABCDEF',substr(hex(h.claim_hash),1,1))-1)*16+instr('0123456789ABCDEF',substr(hex(h.claim_hash),2,1))-1)%(1 << min(h.attempts,5))),60))))
        OR (NEW.kind='renewed' AND h.state='claimed' AND NEW.state='claimed'
       AND NEW.claim_generation=h.claim_generation AND NEW.attempts=h.attempts AND NEW.available_at=h.available_at AND NEW.claim_hash=h.claim_hash AND NEW.worker_id=h.worker_id
       AND NEW.claim_until>h.claim_until AND NEW.updated_at<h.claim_until
       AND (SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_events r WHERE r.org_id=NEW.org_id AND r.project_id=NEW.project_id AND r.job_id=NEW.job_id AND r.phase=NEW.phase AND r.claim_generation=NEW.claim_generation AND r.kind='renewed' LIMIT 32))<32)
        OR (NEW.kind='retried' AND NEW.phase='signer' AND h.state='claimed' AND NEW.state='prepared'
       AND NEW.claim_generation=h.claim_generation AND NEW.attempts=h.attempts AND NEW.updated_at<h.claim_until
       AND NEW.available_at=NEW.updated_at+min((1 << min(h.attempts,5))+(((instr('0123456789ABCDEF',substr(hex(h.claim_hash),1,1))-1)*16+instr('0123456789ABCDEF',substr(hex(h.claim_hash),2,1))-1)%(1 << min(h.attempts,5))),60) AND NEW.available_at<j.deadline)
        OR (NEW.kind='unknown' AND NEW.phase='dispatch' AND h.state='claimed' AND NEW.state='unknown'
       AND NEW.claim_generation=h.claim_generation AND NEW.attempts=h.attempts AND (NEW.available_at=min(253402300799,NEW.updated_at+min((1 << min(h.attempts,5))+(((instr('0123456789ABCDEF',substr(hex(h.claim_hash),1,1))-1)*16+instr('0123456789ABCDEF',substr(hex(h.claim_hash),2,1))-1)%(1 << min(h.attempts,5))),60))
        OR (NEW.available_at=h.available_at AND NEW.updated_at>=h.claim_until+min((1 << min(h.attempts,5))+(((instr('0123456789ABCDEF',substr(hex(h.claim_hash),1,1))-1)*16+instr('0123456789ABCDEF',substr(hex(h.claim_hash),2,1))-1)%(1 << min(h.attempts,5))),60))))
        OR (NEW.kind='cancelled' AND NEW.phase='signer' AND h.state IN ('prepared','claimed') AND NEW.state='cancelled'
       AND NEW.claim_generation=h.claim_generation AND NEW.attempts=h.attempts AND NEW.available_at=h.available_at
       AND NOT EXISTS(SELECT 1 FROM authority_signing_results r WHERE r.org_id=j.org_id AND r.project_id=j.project_id AND r.intent_id=j.intent_id)
       AND NOT EXISTS(SELECT 1 FROM authority_signing_outbox o WHERE o.org_id=j.org_id AND o.project_id=j.project_id AND o.job_id=j.job_id)
       AND NOT EXISTS(SELECT 1 FROM authority_signing_work_heads d WHERE d.org_id=j.org_id AND d.project_id=j.project_id AND d.job_id=j.job_id AND d.phase='dispatch'))
        OR (NEW.kind='finalized' AND NEW.phase='signer' AND h.state='claimed' AND NEW.state='ready'
       AND NEW.claim_generation=h.claim_generation AND NEW.attempts=h.attempts AND NEW.available_at=h.available_at AND NEW.updated_at<h.claim_until
       AND EXISTS(SELECT 1 FROM authority_signing_results r JOIN authority_signing_outbox o ON o.org_id=r.org_id AND o.project_id=r.project_id AND o.intent_id=r.intent_id AND o.grant_hash=r.grant_hash AND o.grant_bytes=r.grant_bytes
        WHERE r.org_id=j.org_id AND r.project_id=j.project_id AND r.intent_id=j.intent_id AND o.job_id=j.job_id AND r.finalized_at=NEW.updated_at AND o.created_at=NEW.updated_at))
        OR (NEW.kind='delivered' AND NEW.phase='dispatch' AND h.state='claimed' AND NEW.state='delivered'
       AND NEW.claim_generation=h.claim_generation AND NEW.attempts=h.attempts AND NEW.available_at=h.available_at AND NEW.updated_at<h.claim_until
       AND EXISTS(SELECT 1 FROM authority_signing_deliveries d JOIN authority_signing_outbox o ON o.org_id=d.org_id AND o.project_id=d.project_id AND o.job_id=d.job_id AND o.grant_hash=d.grant_hash
        WHERE d.org_id=j.org_id AND d.project_id=j.project_id AND d.job_id=j.job_id AND d.recorded_at=NEW.updated_at))
       )
     )
    )
  )
 ) IS NOT 1 BEGIN SELECT RAISE(ABORT,'invalid signing work sequence'); END;
CREATE TRIGGER authority_signing_work_heads_no_replace BEFORE INSERT ON authority_signing_work_heads
 WHEN EXISTS(SELECT 1 FROM authority_signing_work_heads h WHERE h.rowid=NEW.rowid OR (h.org_id=NEW.org_id AND h.project_id=NEW.project_id AND h.job_id=NEW.job_id AND h.phase=NEW.phase))
 BEGIN SELECT RAISE(ABORT,'retained signing work head identity'); END;
CREATE TRIGGER authority_signing_work_heads_insert BEFORE INSERT ON authority_signing_work_heads
 WHEN NOT EXISTS(SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase
  AND e.state IS NEW.state AND e.revision IS NEW.revision AND e.claim_generation IS NEW.claim_generation AND e.claim_hash IS NEW.claim_hash AND e.worker_id IS NEW.worker_id AND e.claim_until IS NEW.claim_until AND e.attempts IS NEW.attempts AND e.available_at IS NEW.available_at AND e.updated_at IS NEW.updated_at AND hex(e.revision)='0000000000000001'
  AND e.revision=(SELECT max(v.revision) FROM authority_signing_work_events v WHERE v.org_id=NEW.org_id AND v.project_id=NEW.project_id AND v.job_id=NEW.job_id AND v.phase=NEW.phase))
 BEGIN SELECT RAISE(ABORT,'invalid initial signing work head'); END;
CREATE TRIGGER authority_signing_work_heads_update BEFORE UPDATE ON authority_signing_work_heads
 WHEN NEW.rowid!=OLD.rowid OR NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.job_id!=OLD.job_id OR NEW.phase!=OLD.phase
  OR hex(OLD.revision)!=printf('%016X',(SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase LIMIT 193))-1)
  OR NOT EXISTS(SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase
   AND e.state IS NEW.state AND e.revision IS NEW.revision AND e.claim_generation IS NEW.claim_generation AND e.claim_hash IS NEW.claim_hash AND e.worker_id IS NEW.worker_id AND e.claim_until IS NEW.claim_until AND e.attempts IS NEW.attempts AND e.available_at IS NEW.available_at AND e.updated_at IS NEW.updated_at AND hex(e.revision)=printf('%016X',(SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase LIMIT 193)))
   AND e.revision=(SELECT max(v.revision) FROM authority_signing_work_events v WHERE v.org_id=NEW.org_id AND v.project_id=NEW.project_id AND v.job_id=NEW.job_id AND v.phase=NEW.phase))
 BEGIN SELECT RAISE(ABORT,'signing work head lacks latest event'); END;
CREATE TRIGGER authority_signing_work_heads_no_delete BEFORE DELETE ON authority_signing_work_heads
 BEGIN SELECT RAISE(ABORT,'retained signing work head'); END;
CREATE TRIGGER authority_signing_deliveries_no_replace BEFORE INSERT ON authority_signing_deliveries
 WHEN EXISTS(SELECT 1 FROM authority_signing_deliveries d WHERE d.rowid=NEW.rowid OR (d.org_id=NEW.org_id AND d.project_id=NEW.project_id AND d.job_id=NEW.job_id))
 BEGIN SELECT RAISE(ABORT,'immutable signing delivery identity'); END;
CREATE TRIGGER authority_signing_deliveries_claim BEFORE INSERT ON authority_signing_deliveries
 WHEN NOT EXISTS(SELECT 1 FROM authority_signing_work_heads h
  JOIN authority_signing_work_events e ON e.org_id=h.org_id AND e.project_id=h.project_id AND e.job_id=h.job_id AND e.phase=h.phase AND e.revision=h.revision
  JOIN authority_signing_outbox o ON o.org_id=h.org_id AND o.project_id=h.project_id AND o.job_id=h.job_id
  WHERE h.org_id=NEW.org_id AND h.project_id=NEW.project_id AND h.job_id=NEW.job_id AND h.phase='dispatch'
   AND h.state='claimed' AND h.state IS e.state AND h.revision IS e.revision AND h.claim_generation IS e.claim_generation AND h.claim_hash IS e.claim_hash AND h.worker_id IS e.worker_id AND h.claim_until IS e.claim_until AND h.attempts IS e.attempts AND h.available_at IS e.available_at AND h.updated_at IS e.updated_at
   AND h.revision=(SELECT max(v.revision) FROM authority_signing_work_events v WHERE v.org_id=h.org_id AND v.project_id=h.project_id AND v.job_id=h.job_id AND v.phase=h.phase)
   AND o.grant_hash=NEW.grant_hash AND NEW.recorded_at>=o.created_at
   AND NEW.recorded_at>=h.updated_at AND NEW.recorded_at<h.claim_until)
 BEGIN SELECT RAISE(ABORT,'signing delivery lacks current dispatch claim'); END;

-- A partial accounting index cannot see a head removed by REPLACE. Protect
-- both its logical key and hidden rowid even when recursive triggers are off.
-- Membership advances update an existing row first; fresh heads alone insert.
DROP TRIGGER authority_signing_quota_transitions_membership;
CREATE TRIGGER authority_signing_quota_transitions_membership AFTER INSERT ON authority_signing_quota_transitions
 BEGIN
 UPDATE authority_signing_quota_transition_heads
  SET revision=NEW.revision,state=NEW.state,issued_at=NEW.issued_at
  WHERE org_id=NEW.org_id AND project_id=NEW.project_id AND reservation_id=NEW.reservation_id;
 INSERT INTO authority_signing_quota_transition_heads
  SELECT NEW.org_id,NEW.project_id,NEW.reservation_id,r.root_id,r.lease_id,NEW.revision,NEW.state,NEW.issued_at
  FROM authority_signing_quota_reservations r
  WHERE r.org_id=NEW.org_id AND r.project_id=NEW.project_id AND r.reservation_id=NEW.reservation_id
   AND NOT EXISTS(SELECT 1 FROM authority_signing_quota_transition_heads h
    WHERE h.org_id=NEW.org_id AND h.project_id=NEW.project_id AND h.reservation_id=NEW.reservation_id);
 END;
CREATE TRIGGER authority_signing_quota_transition_heads_no_replace BEFORE INSERT ON authority_signing_quota_transition_heads
 WHEN EXISTS(SELECT 1 FROM authority_signing_quota_transition_heads h
  WHERE h.rowid=NEW.rowid OR (h.org_id=NEW.org_id AND h.project_id=NEW.project_id AND h.reservation_id=NEW.reservation_id))
 BEGIN SELECT RAISE(ABORT,'retained quota accounting identity'); END;
DROP TRIGGER authority_signing_quota_transition_heads_update;
CREATE TRIGGER authority_signing_quota_transition_heads_update BEFORE UPDATE ON authority_signing_quota_transition_heads
 WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.reservation_id!=OLD.reservation_id OR NEW.root_id!=OLD.root_id OR NEW.lease_id IS NOT OLD.lease_id
 OR NOT EXISTS(SELECT 1 FROM authority_signing_quota_transitions t
  WHERE t.org_id=NEW.org_id AND t.project_id=NEW.project_id AND t.reservation_id=NEW.reservation_id
   AND t.revision=NEW.revision AND t.revision=(SELECT MAX(q.revision) FROM authority_signing_quota_transitions q WHERE q.org_id=t.org_id AND q.project_id=t.project_id AND q.reservation_id=t.reservation_id)
   AND t.state=NEW.state AND t.issued_at IS NEW.issued_at)
 BEGIN SELECT RAISE(ABORT,'invalid quota accounting membership'); END;

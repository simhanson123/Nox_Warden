CREATE TRIGGER authority_signing_work_audits_no_replace BEFORE INSERT ON authority_signing_work_audits
 WHEN EXISTS(SELECT 1 FROM authority_signing_work_audits a WHERE a.rowid=NEW.rowid
  OR (a.org_id=NEW.org_id AND a.project_id=NEW.project_id AND
   ((a.job_id=NEW.job_id AND a.phase=NEW.phase AND a.revision=NEW.revision)
    OR a.audit_sequence=NEW.audit_sequence OR a.audit_hash=NEW.audit_hash)))
 BEGIN SELECT RAISE(ABORT,'retained signing work audit identity'); END;
CREATE TRIGGER authority_signing_work_audits_immutable_update BEFORE UPDATE ON authority_signing_work_audits
 BEGIN SELECT RAISE(ABORT,'immutable signing work audit'); END;
CREATE TRIGGER authority_signing_work_audits_immutable_delete BEFORE DELETE ON authority_signing_work_audits
 BEGIN SELECT RAISE(ABORT,'immutable signing work audit'); END;
CREATE TRIGGER authority_signing_work_audits_exact BEFORE INSERT ON authority_signing_work_audits
 WHEN NOT EXISTS(SELECT 1 FROM authority_audit a JOIN authority_audit_heads h
  ON h.org_id=a.org_id AND h.project_id=a.project_id AND h.sequence=a.sequence AND h.event_hash=a.event_hash
  WHERE a.org_id=NEW.org_id AND a.project_id=NEW.project_id AND a.sequence=NEW.audit_sequence AND a.event_hash=NEW.audit_hash
   AND a.kind='signing_'||NEW.phase||'_'||NEW.kind AND a.resource_id=NEW.job_id AND a.recorded_at=NEW.updated_at
   AND hex(NEW.revision)=printf('%016X',(SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase LIMIT 193))+1)
   AND (SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=NEW.org_id AND e.project_id=NEW.project_id AND e.job_id=NEW.job_id AND e.phase=NEW.phase LIMIT 193))<192
   AND NOT EXISTS(SELECT 1 FROM authority_signing_work_audits p WHERE p.org_id=NEW.org_id AND p.project_id=NEW.project_id AND p.job_id=NEW.job_id AND p.phase=NEW.phase AND p.audit_sequence>=NEW.audit_sequence))
 BEGIN SELECT RAISE(ABORT,'signing work audit lacks exact current evidence'); END;
CREATE TRIGGER authority_signing_work_events_audit BEFORE INSERT ON authority_signing_work_events
 WHEN NOT EXISTS(SELECT 1 FROM authority_signing_work_audits a
  WHERE a.org_id=NEW.org_id AND a.project_id=NEW.project_id AND a.job_id=NEW.job_id AND a.phase=NEW.phase
   AND a.revision=NEW.revision AND a.kind=NEW.kind AND a.updated_at=NEW.updated_at)
 BEGIN SELECT RAISE(ABORT,'signing work event lacks exact audit binding'); END;

-- Rust accepts every lowercase canonical UUID, without version/variant limits.
-- BLOB byte length also excludes multibyte and embedded-NUL lookalikes.
CREATE TRIGGER authority_signing_work_events_worker_uuid BEFORE INSERT ON authority_signing_work_events
 WHEN NEW.state='claimed' AND
  (length(CAST(NEW.worker_id AS BLOB))=36 AND length(NEW.worker_id)=36
   AND substr(NEW.worker_id,9,1)='-' AND substr(NEW.worker_id,14,1)='-'
   AND substr(NEW.worker_id,19,1)='-' AND substr(NEW.worker_id,24,1)='-'
   AND length(replace(NEW.worker_id,'-',''))=32
   AND replace(NEW.worker_id,'-','') NOT GLOB '*[^0-9a-f]*') IS NOT 1
 BEGIN SELECT RAISE(ABORT,'noncanonical signing worker UUID'); END;

-- Event insertion is the only head-advancing statement. A failure in either
-- projection rolls the complete event statement back, even with recursive OFF.
CREATE TRIGGER authority_signing_work_events_project_head AFTER INSERT ON authority_signing_work_events
 BEGIN
 UPDATE authority_signing_work_heads
  SET state=NEW.state,revision=NEW.revision,claim_generation=NEW.claim_generation,
   claim_hash=NEW.claim_hash,worker_id=NEW.worker_id,claim_until=NEW.claim_until,
   attempts=NEW.attempts,available_at=NEW.available_at,updated_at=NEW.updated_at
  WHERE org_id=NEW.org_id AND project_id=NEW.project_id AND job_id=NEW.job_id AND phase=NEW.phase;
 INSERT INTO authority_signing_work_heads
  SELECT NEW.org_id,NEW.project_id,NEW.job_id,NEW.phase,NEW.state,NEW.revision,NEW.claim_generation,
   NEW.claim_hash,NEW.worker_id,NEW.claim_until,NEW.attempts,NEW.available_at,NEW.updated_at
  WHERE NOT EXISTS(SELECT 1 FROM authority_signing_work_heads h
   WHERE h.org_id=NEW.org_id AND h.project_id=NEW.project_id AND h.job_id=NEW.job_id AND h.phase=NEW.phase);
 END;

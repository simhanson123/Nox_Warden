-- Preserve the original audit bytes. Each work revision consumes one exact
-- tenant audit identity; a pending binding cannot commit without its event.
CREATE TABLE authority_signing_work_audits (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, job_id TEXT NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('signer','dispatch')),
 revision BLOB NOT NULL CHECK(length(revision)=8),
 kind TEXT NOT NULL CHECK(kind IN ('created','claimed','renewed','retried','cancelled','finalized','unknown','delivered')),
 updated_at INTEGER NOT NULL CHECK(updated_at BETWEEN 0 AND 253402300799),
 audit_sequence BLOB NOT NULL CHECK(length(audit_sequence)=8),
 audit_hash BLOB NOT NULL CHECK(length(audit_hash)=32),
 PRIMARY KEY(org_id,project_id,job_id,phase,revision),
 UNIQUE(org_id,project_id,audit_sequence),
 UNIQUE(org_id,project_id,audit_hash),
 FOREIGN KEY(org_id,project_id,job_id,phase,revision) REFERENCES authority_signing_work_events DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(org_id,project_id,audit_sequence) REFERENCES authority_audit(org_id,project_id,sequence)
) STRICT;
CREATE INDEX authority_signing_work_audit_candidates ON authority_audit(org_id,project_id,resource_id,kind,recorded_at,sequence);

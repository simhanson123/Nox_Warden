-- Coalesced denial evidence remains separate from the closed AuditEvent shape.
-- Every evidence object and its audit reference are committed atomically.
CREATE TABLE audit_denial_summaries (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL,
    content_hash TEXT NOT NULL CHECK(length(content_hash)=71),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=4096),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(org_id,project_id,content_hash),
    FOREIGN KEY(org_id,project_id) REFERENCES projects(org_id,project_id)
) STRICT;
CREATE TRIGGER audit_denial_summary_no_update BEFORE UPDATE ON audit_denial_summaries BEGIN SELECT RAISE(ABORT,'denial summary is immutable'); END;
CREATE TRIGGER audit_denial_summary_no_delete BEFORE DELETE ON audit_denial_summaries BEGIN SELECT RAISE(ABORT,'denial summary is immutable'); END;

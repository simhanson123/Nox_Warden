-- Explicit absolute windows for reviewed core plans. Legacy cost provenance is
-- unchanged and receives no inferred activation/expiry or review authority.
CREATE TABLE authority_core_access_lease_windows (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, request_id TEXT NOT NULL,
 lease_id TEXT NOT NULL,
 provenance_hash BLOB NOT NULL CHECK(length(provenance_hash)=32),
 window_hash BLOB NOT NULL CHECK(length(window_hash)=32),
 not_before INTEGER NOT NULL CHECK(not_before>=0),
 expires_at INTEGER NOT NULL CHECK(expires_at>not_before AND expires_at-not_before BETWEEN 60 AND 86400),
 admitted_at INTEGER NOT NULL CHECK(admitted_at>=0),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 4096),
 PRIMARY KEY(org_id,project_id,request_id),
 UNIQUE(org_id,lease_id),
 FOREIGN KEY(org_id,project_id,request_id) REFERENCES authority_core_access_requests(org_id,project_id,request_id)
) STRICT;
CREATE TRIGGER authority_core_access_lease_windows_no_update BEFORE UPDATE ON authority_core_access_lease_windows BEGIN SELECT RAISE(ABORT,'immutable core access lease window'); END;
CREATE TRIGGER authority_core_access_lease_windows_no_delete BEFORE DELETE ON authority_core_access_lease_windows BEGIN SELECT RAISE(ABORT,'retained core access lease window'); END;
CREATE TRIGGER authority_core_access_lease_windows_no_replace BEFORE INSERT ON authority_core_access_lease_windows
 WHEN EXISTS(SELECT 1 FROM authority_core_access_lease_windows w
  WHERE w.rowid=NEW.rowid
   OR (w.org_id=NEW.org_id AND w.project_id=NEW.project_id AND w.request_id=NEW.request_id)
   OR (w.org_id=NEW.org_id AND w.lease_id=NEW.lease_id))
 BEGIN SELECT RAISE(ABORT,'immutable core access lease window identity'); END;

-- Trusted-local original core request provenance. Importing these immutable
-- inputs supplies quota cost provenance, never approval or signing authority.
-- Legacy plans receive no invented original request or lease binding.
CREATE TABLE authority_core_access_requests (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, request_id TEXT NOT NULL,
 request_revision INTEGER NOT NULL CHECK(request_revision=1),
 lease_id TEXT NOT NULL, root_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
 provenance_hash BLOB NOT NULL CHECK(length(provenance_hash)=32),
 admitted_at INTEGER NOT NULL CHECK(admitted_at>=0),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 131072),
 PRIMARY KEY(org_id,project_id,request_id),
 UNIQUE(org_id,lease_id),
 UNIQUE(org_id,project_id,idempotency_key),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects(org_id,project_id)
) STRICT;
CREATE TABLE authority_core_access_plan_bindings (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, plan_id TEXT NOT NULL,
 plan_hash BLOB NOT NULL CHECK(length(plan_hash)=32),
 request_id TEXT NOT NULL,
 provenance_hash BLOB NOT NULL CHECK(length(provenance_hash)=32),
 admitted_at INTEGER NOT NULL CHECK(admitted_at>=0),
 PRIMARY KEY(org_id,project_id,plan_id),
 FOREIGN KEY(org_id,project_id,plan_id) REFERENCES authority_plans(org_id,project_id,plan_id),
 FOREIGN KEY(org_id,project_id,request_id) REFERENCES authority_core_access_requests(org_id,project_id,request_id)
) STRICT;
CREATE TRIGGER authority_core_access_requests_no_update BEFORE UPDATE ON authority_core_access_requests BEGIN SELECT RAISE(ABORT,'immutable original access request'); END;
CREATE TRIGGER authority_core_access_requests_no_delete BEFORE DELETE ON authority_core_access_requests BEGIN SELECT RAISE(ABORT,'retained original access request'); END;
-- REPLACE can delete a conflicting row without firing DELETE triggers when
-- recursive_triggers is off. Refuse every original identity collision before
-- SQLite applies conflict handling, independently of connection settings.
CREATE TRIGGER authority_core_access_requests_no_replace BEFORE INSERT ON authority_core_access_requests
 WHEN EXISTS(SELECT 1 FROM authority_core_access_requests r
  WHERE r.rowid=NEW.rowid
   OR (r.org_id=NEW.org_id AND r.project_id=NEW.project_id AND r.request_id=NEW.request_id)
   OR (r.org_id=NEW.org_id AND r.lease_id=NEW.lease_id)
   OR (r.org_id=NEW.org_id AND r.project_id=NEW.project_id AND r.idempotency_key=NEW.idempotency_key))
 BEGIN SELECT RAISE(ABORT,'immutable original access request identity'); END;
CREATE TRIGGER authority_core_access_plan_bindings_no_update BEFORE UPDATE ON authority_core_access_plan_bindings BEGIN SELECT RAISE(ABORT,'immutable access plan binding'); END;
CREATE TRIGGER authority_core_access_plan_bindings_no_delete BEFORE DELETE ON authority_core_access_plan_bindings BEGIN SELECT RAISE(ABORT,'retained access plan binding'); END;
CREATE TRIGGER authority_core_access_plan_bindings_no_replace BEFORE INSERT ON authority_core_access_plan_bindings
 WHEN EXISTS(SELECT 1 FROM authority_core_access_plan_bindings b
  WHERE b.rowid=NEW.rowid
   OR (b.org_id=NEW.org_id AND b.project_id=NEW.project_id AND b.plan_id=NEW.plan_id))
 BEGIN SELECT RAISE(ABORT,'immutable access plan binding identity'); END;

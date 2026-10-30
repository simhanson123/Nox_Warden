-- Transport enrollment is an identity record, never a firewall authorization.
CREATE TABLE enrollment_tokens (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, token_id TEXT NOT NULL,
 target_id TEXT NOT NULL, principal_id TEXT NOT NULL, name TEXT NOT NULL,
 platform TEXT NOT NULL CHECK(platform IN ('linux','windows','macos')),
 key_fingerprint TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at=created_at+600),
 state TEXT NOT NULL CHECK(state IN ('unused','reserved','consumed','revoked')),
 idempotency_key TEXT NOT NULL, body_hash TEXT NOT NULL, response_bytes BLOB NOT NULL,
 PRIMARY KEY(org_id,project_id,token_id), UNIQUE(org_id,project_id,target_id),
 UNIQUE(org_id,project_id,principal_id,idempotency_key),
 FOREIGN KEY(org_id,project_id,principal_id) REFERENCES principals(org_id,project_id,principal_id)
) STRICT;
CREATE TABLE enrollment_jobs (
 job_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, project_id TEXT NOT NULL, token_id TEXT NOT NULL,
 csr_hash TEXT NOT NULL, request_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE,
 agent_version TEXT NOT NULL, issued_at INTEGER NOT NULL,
 certificate_fingerprint TEXT UNIQUE, response_bytes BLOB,
 UNIQUE(org_id,project_id,token_id),
 CHECK((certificate_fingerprint IS NULL)=(response_bytes IS NULL)),
 FOREIGN KEY(org_id,project_id,token_id) REFERENCES enrollment_tokens(org_id,project_id,token_id)
) STRICT;
CREATE TABLE target_enrollments (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 job_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, key_fingerprint TEXT NOT NULL,
 certificate_fingerprint TEXT NOT NULL UNIQUE, certificate_chain_pem TEXT NOT NULL,
 enrolled_at INTEGER NOT NULL, certificate_expires_at INTEGER NOT NULL,
 revoked_at INTEGER, capability_hash TEXT,
 CHECK(certificate_expires_at>enrolled_at),
 PRIMARY KEY(org_id,project_id,target_id),
 FOREIGN KEY(org_id,project_id,target_id) REFERENCES targets(org_id,project_id,target_id),
 FOREIGN KEY(job_id) REFERENCES enrollment_jobs(job_id)
) STRICT;
CREATE TABLE enrolled_capabilities (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 capability_hash TEXT NOT NULL, checked_at INTEGER NOT NULL, valid_until INTEGER NOT NULL,
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=65536),
 CHECK(valid_until>checked_at),
 PRIMARY KEY(org_id,project_id,target_id,capability_hash),
 FOREIGN KEY(org_id,project_id,target_id) REFERENCES target_enrollments(org_id,project_id,target_id)
) STRICT;
CREATE TRIGGER enrolled_capability_no_update BEFORE UPDATE ON enrolled_capabilities BEGIN SELECT RAISE(ABORT,'capability immutable'); END;
CREATE TRIGGER enrolled_capability_no_delete BEFORE DELETE ON enrolled_capabilities BEGIN SELECT RAISE(ABORT,'capability immutable'); END;

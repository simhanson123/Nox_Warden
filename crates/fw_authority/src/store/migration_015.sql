-- Authority-owned trust pins, exact signed workload identities, and staged
-- bootstrap objects. Existing evidence never acquires authority during upgrade.
CREATE TABLE authority_registry_keys (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, key_id TEXT NOT NULL,
 target_id TEXT NOT NULL, payload_type TEXT NOT NULL,
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 key_fingerprint BLOB NOT NULL CHECK(length(key_fingerprint)=32),
 not_before INTEGER NOT NULL CHECK(not_before>=0),
 not_after INTEGER NOT NULL CHECK(not_after>not_before),
 pinned_at INTEGER NOT NULL CHECK(pinned_at>=not_before AND pinned_at<not_after),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 8192),
 PRIMARY KEY(org_id,project_id,key_id),
 UNIQUE(org_id,key_fingerprint),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects(org_id,project_id)
) STRICT;
CREATE TABLE authority_registry_key_revocations (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, key_id TEXT NOT NULL,
 revoked_at INTEGER NOT NULL CHECK(revoked_at>=0),
 PRIMARY KEY(org_id,project_id,key_id),
 FOREIGN KEY(org_id,project_id,key_id) REFERENCES authority_registry_keys(org_id,project_id,key_id)
) STRICT;
CREATE TABLE authority_registry_objects (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL,
 object_kind TEXT NOT NULL CHECK(object_kind IN ('workload_binding','envelope','delegation','bootstrap_manifest','bootstrap_authorization')),
 object_id TEXT NOT NULL, content_hash BLOB NOT NULL CHECK(length(content_hash)=32),
 target_id TEXT NOT NULL, admitted_at INTEGER NOT NULL CHECK(admitted_at>=0),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 262144),
 PRIMARY KEY(org_id,project_id,object_kind,object_id),
 UNIQUE(org_id,project_id,content_hash),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects(org_id,project_id)
) STRICT;
CREATE TABLE authority_registry_object_revocations (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL,
 content_hash BLOB NOT NULL CHECK(length(content_hash)=32),
 revoked_at INTEGER NOT NULL CHECK(revoked_at>=0),
 PRIMARY KEY(org_id,project_id,content_hash),
 FOREIGN KEY(org_id,project_id,content_hash) REFERENCES authority_registry_objects(org_id,project_id,content_hash)
) STRICT;
CREATE TABLE authority_registry_clocks (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL,
 observed_at INTEGER NOT NULL CHECK(observed_at>=0),
 PRIMARY KEY(org_id,project_id),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects(org_id,project_id)
) STRICT;
CREATE TABLE authority_workload_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL,
 principal_id TEXT NOT NULL, target_id TEXT NOT NULL, workload_id TEXT NOT NULL,
 binding_id TEXT NOT NULL, binding_epoch BLOB NOT NULL CHECK(length(binding_epoch)=8),
 content_hash BLOB NOT NULL CHECK(length(content_hash)=32),
 PRIMARY KEY(org_id,project_id,principal_id,target_id,workload_id),
 FOREIGN KEY(org_id,project_id,content_hash) REFERENCES authority_registry_objects(org_id,project_id,content_hash)
) STRICT;
CREATE TABLE authority_bootstrap_challenges (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, challenge_id TEXT NOT NULL,
 manifest_id TEXT NOT NULL, principal_id TEXT NOT NULL, credential_id TEXT NOT NULL,
 membership_id TEXT NOT NULL, credential_revision INTEGER NOT NULL CHECK(credential_revision>0),
 role_revision INTEGER NOT NULL CHECK(role_revision>0), security_revision INTEGER NOT NULL CHECK(security_revision>0),
 issued_at INTEGER NOT NULL CHECK(issued_at>=0), expires_at INTEGER NOT NULL CHECK(expires_at>issued_at),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 10),
 consumed_at INTEGER CHECK(consumed_at>=issued_at AND consumed_at<expires_at),
 challenge_bytes BLOB NOT NULL CHECK(length(challenge_bytes) BETWEEN 1 AND 8192),
 state_bytes BLOB NOT NULL CHECK(length(state_bytes) BETWEEN 1 AND 65536),
 credential_bytes BLOB NOT NULL CHECK(length(credential_bytes) BETWEEN 1 AND 65536),
 PRIMARY KEY(org_id,project_id,challenge_id),
 FOREIGN KEY(org_id,project_id,credential_id) REFERENCES authority_credentials(org_id,project_id,credential_id),
 FOREIGN KEY(org_id,project_id,membership_id) REFERENCES authority_roles(org_id,project_id,membership_id)
) STRICT;
CREATE TABLE authority_bootstrap_proofs (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, proof_id TEXT NOT NULL,
 challenge_id TEXT NOT NULL, manifest_id TEXT NOT NULL, principal_id TEXT NOT NULL,
 proof_hash BLOB NOT NULL CHECK(length(proof_hash)=32),
 request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
 admitted_at INTEGER NOT NULL CHECK(admitted_at>=0), expires_at INTEGER NOT NULL CHECK(expires_at>admitted_at),
 proof_bytes BLOB NOT NULL CHECK(length(proof_bytes) BETWEEN 1 AND 8192),
 assertion_bytes BLOB NOT NULL CHECK(length(assertion_bytes) BETWEEN 1 AND 65536),
 role_bytes BLOB NOT NULL CHECK(length(role_bytes) BETWEEN 1 AND 8192),
 PRIMARY KEY(org_id,project_id,proof_id),
 UNIQUE(org_id,project_id,challenge_id), UNIQUE(org_id,project_id,proof_hash),
 FOREIGN KEY(org_id,project_id,challenge_id) REFERENCES authority_bootstrap_challenges(org_id,project_id,challenge_id)
) STRICT;
-- This is the latest locally authorized transition, still pending target
-- durable epoch/baseline/probe confirmation. It is not a dispatch authority head.
CREATE TABLE authority_bootstrap_pending_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 authority_epoch BLOB NOT NULL CHECK(length(authority_epoch)=8),
 manifest_hash BLOB NOT NULL CHECK(length(manifest_hash)=32),
 authorization_hash BLOB NOT NULL CHECK(length(authorization_hash)=32),
 PRIMARY KEY(org_id,project_id,target_id),
 FOREIGN KEY(org_id,project_id,manifest_hash) REFERENCES authority_registry_objects(org_id,project_id,content_hash),
 FOREIGN KEY(org_id,project_id,authorization_hash) REFERENCES authority_registry_objects(org_id,project_id,content_hash)
) STRICT;

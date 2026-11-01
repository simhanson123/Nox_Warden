-- Explicit development native evidence. No legacy/controller record acquires
-- observer trust, baseline qualification or permission to sign/dispatch.
CREATE TABLE authority_native_pins (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('references','observer')),
 revision BLOB NOT NULL CHECK(length(revision)=8),
 content_hash BLOB NOT NULL CHECK(length(content_hash)=32),
 pinned_at INTEGER NOT NULL, not_before INTEGER NOT NULL, not_after INTEGER NOT NULL,
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 262144),
 PRIMARY KEY(org_id,project_id,target_id,kind,revision),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects
) STRICT;
CREATE TABLE authority_native_pin_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('references','observer')),
 revision BLOB NOT NULL CHECK(length(revision)=8),
 PRIMARY KEY(org_id,project_id,target_id,kind),
 FOREIGN KEY(org_id,project_id,target_id,kind,revision) REFERENCES authority_native_pins
) STRICT;
CREATE TABLE authority_native_pin_revocations (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL, kind TEXT NOT NULL,
 revision BLOB NOT NULL CHECK(length(revision)=8), revoked_at INTEGER NOT NULL,
 PRIMARY KEY(org_id,project_id,target_id,kind,revision),
 FOREIGN KEY(org_id,project_id,target_id,kind,revision) REFERENCES authority_native_pins
) STRICT;
CREATE TABLE authority_native_observer_keys (
 org_id TEXT NOT NULL, key_fingerprint BLOB NOT NULL CHECK(length(key_fingerprint)=32),
 project_id TEXT NOT NULL,target_id TEXT NOT NULL,
 public_key BLOB NOT NULL CHECK(length(public_key)=32),registered_at INTEGER NOT NULL,
 PRIMARY KEY(org_id,key_fingerprint),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects
) STRICT;
CREATE TABLE authority_native_observer_revocations (
 org_id TEXT NOT NULL,key_fingerprint BLOB NOT NULL CHECK(length(key_fingerprint)=32),
 revoked_at INTEGER NOT NULL,
 PRIMARY KEY(org_id,key_fingerprint),
 FOREIGN KEY(org_id,key_fingerprint) REFERENCES authority_native_observer_keys
) STRICT;
CREATE TABLE authority_native_compilations (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL, plan_id TEXT NOT NULL,
 compilation_id TEXT NOT NULL, sequence BLOB NOT NULL CHECK(length(sequence)=8),
 reference_revision BLOB NOT NULL CHECK(length(reference_revision)=8),
 metadata_receipt_id TEXT NOT NULL,
 evidence_hash BLOB NOT NULL CHECK(length(evidence_hash)=32),
 admitted_at INTEGER NOT NULL,valid_until INTEGER NOT NULL,
 evidence_bytes BLOB NOT NULL CHECK(length(evidence_bytes) BETWEEN 1 AND 1048576),
 receipt_bytes BLOB NOT NULL CHECK(length(receipt_bytes) BETWEEN 1 AND 16384),
 PRIMARY KEY(org_id,project_id,compilation_id),
 UNIQUE(org_id,project_id,plan_id,sequence),
 UNIQUE(org_id,project_id,plan_id,reference_revision,metadata_receipt_id),
 FOREIGN KEY(org_id,project_id,plan_id) REFERENCES authority_plans,
 FOREIGN KEY(org_id,project_id,metadata_receipt_id) REFERENCES authority_target_metadata
) STRICT;
CREATE TABLE authority_native_compilation_heads (
 org_id TEXT NOT NULL,project_id TEXT NOT NULL,plan_id TEXT NOT NULL,compilation_id TEXT NOT NULL,
 PRIMARY KEY(org_id,project_id,plan_id),
 FOREIGN KEY(org_id,project_id,compilation_id) REFERENCES authority_native_compilations
) STRICT;
CREATE TABLE authority_native_challenges (
 org_id TEXT NOT NULL,project_id TEXT NOT NULL,target_id TEXT NOT NULL,plan_id TEXT NOT NULL,
 challenge_id TEXT NOT NULL,compilation_id TEXT NOT NULL,
 observer_revision BLOB NOT NULL CHECK(length(observer_revision)=8),
 challenge_hash BLOB NOT NULL CHECK(length(challenge_hash)=32),
 issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 4096),
 PRIMARY KEY(org_id,project_id,challenge_id),
 FOREIGN KEY(org_id,project_id,compilation_id) REFERENCES authority_native_compilations
) STRICT;
CREATE INDEX authority_native_challenge_lookup ON authority_native_challenges(org_id,project_id,target_id,observer_revision,expires_at);
CREATE TABLE authority_native_observations (
 org_id TEXT NOT NULL,project_id TEXT NOT NULL,target_id TEXT NOT NULL,plan_id TEXT NOT NULL,
 receipt_id TEXT NOT NULL,challenge_id TEXT NOT NULL,compilation_id TEXT NOT NULL,
 sequence BLOB NOT NULL CHECK(length(sequence)=8),
 proof_hash BLOB NOT NULL CHECK(length(proof_hash)=32),
 receipt_hash BLOB NOT NULL CHECK(length(receipt_hash)=32),
 admitted_at INTEGER NOT NULL,valid_until INTEGER NOT NULL,
 proof_bytes BLOB NOT NULL CHECK(length(proof_bytes) BETWEEN 1 AND 3145728),
 receipt_bytes BLOB NOT NULL CHECK(length(receipt_bytes) BETWEEN 1 AND 16384),
 PRIMARY KEY(org_id,project_id,receipt_id),
 UNIQUE(org_id,project_id,challenge_id),
 UNIQUE(org_id,project_id,target_id,sequence),
 FOREIGN KEY(org_id,project_id,challenge_id) REFERENCES authority_native_challenges,
 FOREIGN KEY(org_id,project_id,compilation_id) REFERENCES authority_native_compilations
) STRICT;
CREATE TABLE authority_native_observation_heads (
 org_id TEXT NOT NULL,project_id TEXT NOT NULL,target_id TEXT NOT NULL,receipt_id TEXT NOT NULL,
 PRIMARY KEY(org_id,project_id,target_id),
 FOREIGN KEY(org_id,project_id,receipt_id) REFERENCES authority_native_observations
) STRICT;
CREATE INDEX authority_native_observation_plan_lookup
 ON authority_native_observations(org_id,project_id,plan_id,sequence DESC);

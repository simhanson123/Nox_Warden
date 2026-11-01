-- Independent target transport trust and portable metadata. No existing
-- controller registration, plan or report becomes trusted by this migration.
CREATE TABLE authority_target_keys (
 org_id TEXT NOT NULL, key_fingerprint BLOB NOT NULL CHECK(length(key_fingerprint)=32),
 project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 public_key BLOB NOT NULL CHECK(length(public_key)=32), registered_at INTEGER NOT NULL,
 PRIMARY KEY(org_id,key_fingerprint),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects
) STRICT;
CREATE TABLE authority_target_key_revocations (
 org_id TEXT NOT NULL, key_fingerprint BLOB NOT NULL CHECK(length(key_fingerprint)=32),
 revoked_at INTEGER NOT NULL, reason TEXT NOT NULL CHECK(reason IN ('rotated','revoked')),
 PRIMARY KEY(org_id,key_fingerprint),
 FOREIGN KEY(org_id,key_fingerprint) REFERENCES authority_target_keys
) STRICT;
CREATE TABLE authority_target_pins (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 revision BLOB NOT NULL CHECK(length(revision)=8),
 key_fingerprint BLOB NOT NULL CHECK(length(key_fingerprint)=32),
 certificate_fingerprint BLOB NOT NULL CHECK(length(certificate_fingerprint)=32),
 pin_hash BLOB NOT NULL CHECK(length(pin_hash)=32), pinned_at INTEGER NOT NULL,
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 8192),
 PRIMARY KEY(org_id,project_id,target_id,revision),
 UNIQUE(org_id,certificate_fingerprint),
 FOREIGN KEY(org_id,key_fingerprint) REFERENCES authority_target_keys
) STRICT;
CREATE TABLE authority_target_pin_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 revision BLOB NOT NULL CHECK(length(revision)=8),
 PRIMARY KEY(org_id,project_id,target_id),
 FOREIGN KEY(org_id,project_id,target_id,revision) REFERENCES authority_target_pins
) STRICT;
CREATE TABLE authority_target_clocks (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 observed_at INTEGER NOT NULL CHECK(observed_at BETWEEN 0 AND 253402300799),
 PRIMARY KEY(org_id,project_id,target_id),
 FOREIGN KEY(org_id,project_id,target_id) REFERENCES authority_target_pin_heads
) STRICT;
CREATE TABLE authority_target_challenges (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 challenge_id TEXT NOT NULL, pin_revision BLOB NOT NULL CHECK(length(pin_revision)=8),
 challenge_hash BLOB NOT NULL CHECK(length(challenge_hash)=32),
 issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 4096),
 PRIMARY KEY(org_id,project_id,challenge_id),
 FOREIGN KEY(org_id,project_id,target_id,pin_revision) REFERENCES authority_target_pins
) STRICT;
CREATE INDEX authority_target_challenge_lookup ON authority_target_challenges(org_id,project_id,target_id,pin_revision,expires_at);
CREATE TABLE authority_target_metadata (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 receipt_id TEXT NOT NULL, challenge_id TEXT NOT NULL,
 pin_revision BLOB NOT NULL CHECK(length(pin_revision)=8),
 sequence BLOB NOT NULL CHECK(length(sequence)=8),
 report_hash BLOB NOT NULL CHECK(length(report_hash)=32),
 proof_hash BLOB NOT NULL CHECK(length(proof_hash)=32),
 admitted_at INTEGER NOT NULL, checked_at INTEGER NOT NULL, valid_until INTEGER NOT NULL,
 proof_bytes BLOB NOT NULL CHECK(length(proof_bytes) BETWEEN 1 AND 131072),
 receipt_bytes BLOB NOT NULL CHECK(length(receipt_bytes) BETWEEN 1 AND 8192),
 PRIMARY KEY(org_id,project_id,receipt_id),
 UNIQUE(org_id,project_id,challenge_id),
 UNIQUE(org_id,project_id,target_id,sequence),
 FOREIGN KEY(org_id,project_id,challenge_id) REFERENCES authority_target_challenges,
 FOREIGN KEY(org_id,project_id,target_id,pin_revision) REFERENCES authority_target_pins
) STRICT;
CREATE TABLE authority_target_metadata_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 receipt_id TEXT NOT NULL,
 PRIMARY KEY(org_id,project_id,target_id),
 FOREIGN KEY(org_id,project_id,receipt_id) REFERENCES authority_target_metadata
) STRICT;

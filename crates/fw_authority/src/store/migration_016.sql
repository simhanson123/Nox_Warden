-- Explicit project WebAuthn origin trust. No origin/pin is inferred from any
-- existing challenge, proof, caller configuration or signed authorization.
CREATE TABLE authority_bootstrap_approval_origin_pins (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL,
 revision BLOB NOT NULL CHECK(length(revision)=8 AND revision>x'0000000000000000'),
 origin TEXT NOT NULL CHECK(length(CAST(origin AS BLOB)) BETWEEN 1 AND 2048),
 rp_id TEXT NOT NULL CHECK(length(CAST(rp_id AS BLOB)) BETWEEN 1 AND 253),
 not_before INTEGER NOT NULL CHECK(not_before>=0),
 not_after INTEGER NOT NULL CHECK(not_after>not_before),
 pinned_at INTEGER NOT NULL CHECK(pinned_at>=not_before AND pinned_at<not_after),
 pin_hash BLOB NOT NULL CHECK(length(pin_hash)=32),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 8192),
 PRIMARY KEY(org_id,project_id,revision), UNIQUE(org_id,project_id,pin_hash),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects(org_id,project_id)
) STRICT;
CREATE TRIGGER authority_bootstrap_approval_origin_pins_no_update BEFORE UPDATE ON authority_bootstrap_approval_origin_pins BEGIN SELECT RAISE(ABORT,'immutable bootstrap approval origin pin'); END;
CREATE TRIGGER authority_bootstrap_approval_origin_pins_no_delete BEFORE DELETE ON authority_bootstrap_approval_origin_pins BEGIN SELECT RAISE(ABORT,'retained bootstrap approval origin pin'); END;
CREATE TRIGGER authority_bootstrap_approval_origin_pins_no_replace BEFORE INSERT ON authority_bootstrap_approval_origin_pins
 WHEN EXISTS(SELECT 1 FROM authority_bootstrap_approval_origin_pins p WHERE p.rowid=NEW.rowid OR (p.org_id=NEW.org_id AND p.project_id=NEW.project_id AND (p.revision=NEW.revision OR p.pin_hash=NEW.pin_hash)))
 BEGIN SELECT RAISE(ABORT,'retained bootstrap approval origin pin identity'); END;
CREATE TABLE authority_bootstrap_approval_origin_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL,
 revision BLOB NOT NULL CHECK(length(revision)=8 AND revision>x'0000000000000000'),
 PRIMARY KEY(org_id,project_id),
 FOREIGN KEY(org_id,project_id,revision) REFERENCES authority_bootstrap_approval_origin_pins(org_id,project_id,revision)
) STRICT;
CREATE TRIGGER authority_bootstrap_approval_origin_heads_no_delete BEFORE DELETE ON authority_bootstrap_approval_origin_heads BEGIN SELECT RAISE(ABORT,'retained bootstrap approval origin head'); END;
CREATE TRIGGER authority_bootstrap_approval_origin_heads_no_replace BEFORE INSERT ON authority_bootstrap_approval_origin_heads
 WHEN EXISTS(SELECT 1 FROM authority_bootstrap_approval_origin_heads h WHERE h.rowid=NEW.rowid OR (h.org_id=NEW.org_id AND h.project_id=NEW.project_id))
 BEGIN SELECT RAISE(ABORT,'retained bootstrap approval origin head identity'); END;
CREATE TRIGGER authority_bootstrap_approval_origin_heads_forward BEFORE UPDATE ON authority_bootstrap_approval_origin_heads
 WHEN NEW.rowid!=OLD.rowid OR NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.revision<=OLD.revision
 BEGIN SELECT RAISE(ABORT,'bootstrap approval origin revision regression'); END;
CREATE TABLE authority_bootstrap_challenge_origin_bindings (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, challenge_id TEXT NOT NULL,
 -- NULL is an explicit legacy-unpinned classification, never a current grant.
 origin_revision BLOB CHECK(origin_revision IS NULL OR (length(origin_revision)=8 AND origin_revision>x'0000000000000000')),
 PRIMARY KEY(org_id,project_id,challenge_id),
 FOREIGN KEY(org_id,project_id,challenge_id) REFERENCES authority_bootstrap_challenges(org_id,project_id,challenge_id),
 FOREIGN KEY(org_id,project_id,origin_revision) REFERENCES authority_bootstrap_approval_origin_pins(org_id,project_id,revision)
) STRICT;
CREATE TRIGGER authority_bootstrap_challenge_origin_bindings_no_update BEFORE UPDATE ON authority_bootstrap_challenge_origin_bindings BEGIN SELECT RAISE(ABORT,'immutable bootstrap challenge origin binding'); END;
CREATE TRIGGER authority_bootstrap_challenge_origin_bindings_no_delete BEFORE DELETE ON authority_bootstrap_challenge_origin_bindings BEGIN SELECT RAISE(ABORT,'retained bootstrap challenge origin binding'); END;
CREATE TRIGGER authority_bootstrap_challenge_origin_bindings_no_replace BEFORE INSERT ON authority_bootstrap_challenge_origin_bindings
 WHEN EXISTS(SELECT 1 FROM authority_bootstrap_challenge_origin_bindings b WHERE b.rowid=NEW.rowid OR (b.org_id=NEW.org_id AND b.project_id=NEW.project_id AND b.challenge_id=NEW.challenge_id))
 BEGIN SELECT RAISE(ABORT,'retained bootstrap challenge origin binding identity'); END;
INSERT INTO authority_bootstrap_challenge_origin_bindings(org_id,project_id,challenge_id,origin_revision)
 SELECT org_id,project_id,challenge_id,NULL FROM authority_bootstrap_challenges;

-- A purpose-isolated key authenticates only the bounded disposable-target
-- bootstrap receipt. These records never initialize policy signing counters.
CREATE TABLE authority_target_bootstrap_key_pins (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 revision BLOB NOT NULL CHECK(length(revision)=8 AND revision>x'0000000000000000'),
 key_id TEXT NOT NULL CHECK(length(CAST(key_id AS BLOB)) BETWEEN 1 AND 256),
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 key_fingerprint BLOB NOT NULL CHECK(length(key_fingerprint)=32),
 not_before INTEGER NOT NULL CHECK(not_before>=0),
 not_after INTEGER NOT NULL CHECK(not_after>not_before),
 pinned_at INTEGER NOT NULL CHECK(pinned_at>=not_before AND pinned_at<not_after),
 pin_hash BLOB NOT NULL CHECK(length(pin_hash)=32),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 8192),
 PRIMARY KEY(org_id,project_id,target_id,revision),
 UNIQUE(org_id,key_fingerprint), UNIQUE(org_id,project_id,target_id,pin_hash),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects(org_id,project_id)
) STRICT;
-- Cross-purpose checks compare actual keys, independent of historical
-- fingerprint encodings. Keep current admissions and full history scans indexed.
CREATE INDEX authority_registry_keys_public_key ON authority_registry_keys(org_id,public_key);
CREATE INDEX authority_target_keys_public_key ON authority_target_keys(org_id,public_key);
CREATE INDEX authority_native_observer_keys_public_key ON authority_native_observer_keys(org_id,public_key);
CREATE INDEX authority_target_bootstrap_keys_public_key ON authority_target_bootstrap_key_pins(org_id,public_key);
CREATE TABLE authority_target_bootstrap_key_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 revision BLOB NOT NULL CHECK(length(revision)=8 AND revision>x'0000000000000000'),
 PRIMARY KEY(org_id,project_id,target_id),
 FOREIGN KEY(org_id,project_id,target_id,revision) REFERENCES authority_target_bootstrap_key_pins(org_id,project_id,target_id,revision)
) STRICT;
CREATE TABLE authority_target_bootstrap_key_revocations (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 revision BLOB NOT NULL CHECK(length(revision)=8 AND revision>x'0000000000000000'),
 revoked_at INTEGER NOT NULL CHECK(revoked_at>=0),
 PRIMARY KEY(org_id,project_id,target_id,revision),
 FOREIGN KEY(org_id,project_id,target_id,revision) REFERENCES authority_target_bootstrap_key_pins(org_id,project_id,target_id,revision)
) STRICT;
CREATE TABLE authority_target_bootstrap_challenges (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, challenge_id TEXT NOT NULL,
 target_id TEXT NOT NULL, manifest_id TEXT NOT NULL,
 manifest_hash BLOB NOT NULL CHECK(length(manifest_hash)=32),
 authorization_hash BLOB NOT NULL CHECK(length(authorization_hash)=32),
 challenge_hash BLOB NOT NULL CHECK(length(challenge_hash)=32),
 key_revision BLOB NOT NULL CHECK(length(key_revision)=8),
 origin_revision BLOB NOT NULL CHECK(length(origin_revision)=8),
 expected_target_revision BLOB CHECK(expected_target_revision IS NULL OR length(expected_target_revision)=8),
 previous_confirmation_hash BLOB CHECK(previous_confirmation_hash IS NULL OR length(previous_confirmation_hash)=32),
 new_epoch BLOB NOT NULL CHECK(length(new_epoch)=8),
 highest_generation BLOB NOT NULL CHECK(length(highest_generation)=8),
 issued_at INTEGER NOT NULL CHECK(issued_at>=0),
 expires_at INTEGER NOT NULL CHECK(expires_at>issued_at AND expires_at-issued_at<=300),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 8192),
 baseline_bytes BLOB NOT NULL CHECK(length(baseline_bytes) BETWEEN 1 AND 65536),
 capability_bytes BLOB NOT NULL CHECK(length(capability_bytes) BETWEEN 1 AND 8192),
 PRIMARY KEY(org_id,project_id,challenge_id), UNIQUE(org_id,project_id,manifest_hash), UNIQUE(org_id,project_id,manifest_id),
 UNIQUE(org_id,project_id,challenge_hash),
 FOREIGN KEY(org_id,project_id,manifest_hash) REFERENCES authority_registry_objects(org_id,project_id,content_hash),
 FOREIGN KEY(org_id,project_id,authorization_hash) REFERENCES authority_registry_objects(org_id,project_id,content_hash),
 FOREIGN KEY(org_id,project_id,target_id,key_revision) REFERENCES authority_target_bootstrap_key_pins(org_id,project_id,target_id,revision),
 FOREIGN KEY(org_id,project_id,origin_revision) REFERENCES authority_bootstrap_approval_origin_pins(org_id,project_id,revision)
) STRICT;
-- A unique retained signed receipt consumes its one immutable challenge. There
-- is no mutable boolean that can turn an unobserved challenge into confirmation.
CREATE TABLE authority_target_bootstrap_confirmations (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL,
 confirmation_hash BLOB NOT NULL CHECK(length(confirmation_hash)=32),
 challenge_id TEXT NOT NULL, challenge_hash BLOB NOT NULL CHECK(length(challenge_hash)=32),
 target_id TEXT NOT NULL, revision BLOB NOT NULL CHECK(length(revision)=8 AND revision>x'0000000000000000'),
 accepted_epoch BLOB NOT NULL CHECK(length(accepted_epoch)=8),
 highest_generation BLOB NOT NULL CHECK(length(highest_generation)=8),
 journal_id TEXT NOT NULL, observed_at INTEGER NOT NULL CHECK(observed_at>=0),
 admitted_at INTEGER NOT NULL CHECK(admitted_at>=observed_at),
 valid_until INTEGER NOT NULL CHECK(valid_until>admitted_at),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 262144),
 PRIMARY KEY(org_id,project_id,confirmation_hash), UNIQUE(org_id,project_id,challenge_id),
 FOREIGN KEY(org_id,project_id,challenge_id) REFERENCES authority_target_bootstrap_challenges(org_id,project_id,challenge_id)
) STRICT;
CREATE TABLE authority_target_bootstrap_confirmation_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
 revision BLOB NOT NULL CHECK(length(revision)=8 AND revision>x'0000000000000000'),
 accepted_epoch BLOB NOT NULL CHECK(length(accepted_epoch)=8 AND accepted_epoch>x'0000000000000000'),
 highest_generation BLOB NOT NULL CHECK(length(highest_generation)=8),
 confirmation_hash BLOB NOT NULL CHECK(length(confirmation_hash)=32),
 observed_at INTEGER NOT NULL CHECK(observed_at>=0),
 PRIMARY KEY(org_id,project_id,target_id),
 FOREIGN KEY(org_id,project_id,confirmation_hash) REFERENCES authority_target_bootstrap_confirmations(org_id,project_id,confirmation_hash)
) STRICT;
CREATE TRIGGER authority_target_bootstrap_key_pins_no_update BEFORE UPDATE ON authority_target_bootstrap_key_pins BEGIN SELECT RAISE(ABORT,'immutable target bootstrap key pin'); END;
CREATE TRIGGER authority_target_bootstrap_key_pins_purpose BEFORE INSERT ON authority_target_bootstrap_key_pins
 WHEN EXISTS(SELECT 1 FROM authority_registry_keys k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 OR EXISTS(SELECT 1 FROM authority_target_keys k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 OR EXISTS(SELECT 1 FROM authority_native_observer_keys k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 BEGIN SELECT RAISE(ABORT,'target bootstrap key purpose alias'); END;
CREATE TRIGGER authority_registry_keys_target_bootstrap_purpose BEFORE INSERT ON authority_registry_keys
 WHEN EXISTS(SELECT 1 FROM authority_target_bootstrap_key_pins k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 BEGIN SELECT RAISE(ABORT,'target bootstrap key purpose alias'); END;
CREATE TRIGGER authority_target_keys_target_bootstrap_purpose BEFORE INSERT ON authority_target_keys
 WHEN EXISTS(SELECT 1 FROM authority_target_bootstrap_key_pins k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 BEGIN SELECT RAISE(ABORT,'target bootstrap key purpose alias'); END;
CREATE TRIGGER authority_native_observer_keys_target_bootstrap_purpose BEFORE INSERT ON authority_native_observer_keys
 WHEN EXISTS(SELECT 1 FROM authority_target_bootstrap_key_pins k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 BEGIN SELECT RAISE(ABORT,'target bootstrap key purpose alias'); END;
-- Registry fingerprints hash raw Ed25519 bytes; transport and observer pins
-- retain SPKI fingerprints. Cross-purpose ownership follows public key bytes.
CREATE TRIGGER authority_registry_keys_legacy_purpose BEFORE INSERT ON authority_registry_keys
 WHEN EXISTS(SELECT 1 FROM authority_target_keys k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 OR EXISTS(SELECT 1 FROM authority_native_observer_keys k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 BEGIN SELECT RAISE(ABORT,'authority key purpose alias'); END;
CREATE TRIGGER authority_target_keys_legacy_purpose BEFORE INSERT ON authority_target_keys
 WHEN EXISTS(SELECT 1 FROM authority_registry_keys k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 OR EXISTS(SELECT 1 FROM authority_native_observer_keys k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 BEGIN SELECT RAISE(ABORT,'authority key purpose alias'); END;
CREATE TRIGGER authority_native_observer_keys_legacy_purpose BEFORE INSERT ON authority_native_observer_keys
 WHEN EXISTS(SELECT 1 FROM authority_registry_keys k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 OR EXISTS(SELECT 1 FROM authority_target_keys k WHERE k.org_id=NEW.org_id AND k.public_key=NEW.public_key)
 BEGIN SELECT RAISE(ABORT,'authority key purpose alias'); END;
CREATE TRIGGER authority_target_bootstrap_key_pins_no_delete BEFORE DELETE ON authority_target_bootstrap_key_pins BEGIN SELECT RAISE(ABORT,'retained target bootstrap key pin'); END;
CREATE TRIGGER authority_target_bootstrap_key_pins_no_replace BEFORE INSERT ON authority_target_bootstrap_key_pins
 WHEN EXISTS(SELECT 1 FROM authority_target_bootstrap_key_pins p WHERE p.rowid=NEW.rowid OR (p.org_id=NEW.org_id AND p.key_fingerprint=NEW.key_fingerprint) OR (p.org_id=NEW.org_id AND p.project_id=NEW.project_id AND p.target_id=NEW.target_id AND (p.revision=NEW.revision OR p.pin_hash=NEW.pin_hash)))
 BEGIN SELECT RAISE(ABORT,'retained target bootstrap key pin identity'); END;
CREATE TRIGGER authority_target_bootstrap_key_heads_no_delete BEFORE DELETE ON authority_target_bootstrap_key_heads BEGIN SELECT RAISE(ABORT,'retained target bootstrap key head'); END;
CREATE TRIGGER authority_target_bootstrap_key_heads_no_replace BEFORE INSERT ON authority_target_bootstrap_key_heads
 WHEN EXISTS(SELECT 1 FROM authority_target_bootstrap_key_heads h WHERE h.rowid=NEW.rowid OR (h.org_id=NEW.org_id AND h.project_id=NEW.project_id AND h.target_id=NEW.target_id))
 BEGIN SELECT RAISE(ABORT,'retained target bootstrap key head identity'); END;
CREATE TRIGGER authority_target_bootstrap_key_heads_forward BEFORE UPDATE ON authority_target_bootstrap_key_heads
 WHEN NEW.rowid!=OLD.rowid OR NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.target_id!=OLD.target_id OR NEW.revision<=OLD.revision
 BEGIN SELECT RAISE(ABORT,'target bootstrap key revision regression'); END;
CREATE TRIGGER authority_target_bootstrap_key_revocations_no_update BEFORE UPDATE ON authority_target_bootstrap_key_revocations BEGIN SELECT RAISE(ABORT,'immutable target bootstrap key revocation'); END;
CREATE TRIGGER authority_target_bootstrap_key_revocations_no_delete BEFORE DELETE ON authority_target_bootstrap_key_revocations BEGIN SELECT RAISE(ABORT,'retained target bootstrap key revocation'); END;
CREATE TRIGGER authority_target_bootstrap_key_revocations_no_replace BEFORE INSERT ON authority_target_bootstrap_key_revocations
 WHEN EXISTS(SELECT 1 FROM authority_target_bootstrap_key_revocations r WHERE r.rowid=NEW.rowid OR (r.org_id=NEW.org_id AND r.project_id=NEW.project_id AND r.target_id=NEW.target_id AND r.revision=NEW.revision))
 BEGIN SELECT RAISE(ABORT,'retained target bootstrap key revocation identity'); END;
CREATE TRIGGER authority_target_bootstrap_challenges_no_update BEFORE UPDATE ON authority_target_bootstrap_challenges BEGIN SELECT RAISE(ABORT,'immutable target bootstrap challenge'); END;
CREATE TRIGGER authority_target_bootstrap_challenges_no_delete BEFORE DELETE ON authority_target_bootstrap_challenges BEGIN SELECT RAISE(ABORT,'retained target bootstrap challenge'); END;
CREATE TRIGGER authority_target_bootstrap_challenges_no_replace BEFORE INSERT ON authority_target_bootstrap_challenges
 WHEN EXISTS(SELECT 1 FROM authority_target_bootstrap_challenges c WHERE c.rowid=NEW.rowid OR (c.org_id=NEW.org_id AND c.project_id=NEW.project_id AND (c.challenge_id=NEW.challenge_id OR c.manifest_hash=NEW.manifest_hash OR c.manifest_id=NEW.manifest_id OR c.challenge_hash=NEW.challenge_hash)))
 BEGIN SELECT RAISE(ABORT,'retained target bootstrap challenge identity'); END;
CREATE TRIGGER authority_target_bootstrap_confirmations_no_update BEFORE UPDATE ON authority_target_bootstrap_confirmations BEGIN SELECT RAISE(ABORT,'immutable target bootstrap confirmation'); END;
CREATE TRIGGER authority_target_bootstrap_confirmations_no_delete BEFORE DELETE ON authority_target_bootstrap_confirmations BEGIN SELECT RAISE(ABORT,'retained target bootstrap confirmation'); END;
CREATE TRIGGER authority_target_bootstrap_confirmations_no_replace BEFORE INSERT ON authority_target_bootstrap_confirmations
 WHEN EXISTS(SELECT 1 FROM authority_target_bootstrap_confirmations r WHERE r.rowid=NEW.rowid OR (r.org_id=NEW.org_id AND r.project_id=NEW.project_id AND (r.confirmation_hash=NEW.confirmation_hash OR r.challenge_id=NEW.challenge_id)))
 BEGIN SELECT RAISE(ABORT,'retained target bootstrap confirmation identity'); END;
CREATE TRIGGER authority_target_bootstrap_confirmation_heads_no_delete BEFORE DELETE ON authority_target_bootstrap_confirmation_heads BEGIN SELECT RAISE(ABORT,'retained target bootstrap confirmation head'); END;
CREATE TRIGGER authority_target_bootstrap_confirmation_heads_no_replace BEFORE INSERT ON authority_target_bootstrap_confirmation_heads
 WHEN EXISTS(SELECT 1 FROM authority_target_bootstrap_confirmation_heads h WHERE h.rowid=NEW.rowid OR (h.org_id=NEW.org_id AND h.project_id=NEW.project_id AND h.target_id=NEW.target_id))
 BEGIN SELECT RAISE(ABORT,'retained target bootstrap confirmation head identity'); END;
CREATE TRIGGER authority_target_bootstrap_confirmation_heads_forward BEFORE UPDATE ON authority_target_bootstrap_confirmation_heads
 WHEN NEW.rowid!=OLD.rowid OR NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.target_id!=OLD.target_id OR NEW.revision<=OLD.revision OR NEW.accepted_epoch<=OLD.accepted_epoch OR NEW.highest_generation<OLD.highest_generation OR NEW.observed_at<OLD.observed_at
 BEGIN SELECT RAISE(ABORT,'target bootstrap confirmed authority regression'); END;

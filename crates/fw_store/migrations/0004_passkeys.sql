-- Local human authentication only. These records are not policy approvals or
-- an independent signer's trusted authority registry.
CREATE TABLE passkey_owners (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, principal_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role='owner'), enrolled_at INTEGER NOT NULL,
    PRIMARY KEY(org_id,project_id),
    FOREIGN KEY(org_id,project_id,principal_id) REFERENCES principals(org_id,project_id,principal_id)
) STRICT;
CREATE TRIGGER passkey_owner_no_update BEFORE UPDATE ON passkey_owners BEGIN SELECT RAISE(ABORT,'local owner enrollment is permanent'); END;
CREATE TRIGGER passkey_owner_no_delete BEFORE DELETE ON passkey_owners BEGIN SELECT RAISE(ABORT,'local owner enrollment is permanent'); END;

CREATE TABLE passkey_credentials (
    credential_id TEXT PRIMARY KEY NOT NULL,
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, principal_id TEXT NOT NULL,
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
    credential_bytes BLOB NOT NULL CHECK(length(credential_bytes)<=65536),
    credential_hash BLOB NOT NULL CHECK(length(credential_hash)=32),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
    created_at INTEGER NOT NULL, verified_at INTEGER, last_used_at INTEGER, revoked_at INTEGER,
    FOREIGN KEY(org_id,project_id,principal_id) REFERENCES principals(org_id,project_id,principal_id)
) STRICT;
CREATE INDEX passkey_credential_owner ON passkey_credentials(org_id,project_id,principal_id,revoked_at);
CREATE TRIGGER passkey_credential_no_delete BEFORE DELETE ON passkey_credentials BEGIN SELECT RAISE(ABORT,'credential tombstones are retained'); END;
CREATE TRIGGER passkey_credential_no_revival BEFORE UPDATE ON passkey_credentials WHEN OLD.revoked_at IS NOT NULL BEGIN SELECT RAISE(ABORT,'revoked credentials are immutable'); END;

CREATE TABLE passkey_challenges (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, principal_id TEXT NOT NULL,
    challenge_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('registration','authentication')),
    idempotency_key TEXT NOT NULL, request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
    challenge_bytes BLOB NOT NULL CHECK(length(challenge_bytes)<=196608),
    challenge_hash BLOB NOT NULL CHECK(length(challenge_hash)=32),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=300),
    failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 10),
    completed_at INTEGER, completion_key TEXT, proof_bytes BLOB CHECK(proof_bytes IS NULL OR length(proof_bytes)<=65536),
    proof_hash BLOB CHECK(proof_hash IS NULL OR length(proof_hash)=32), credential_id TEXT,
    CHECK((completed_at IS NULL)=(completion_key IS NULL)),
    CHECK((completed_at IS NULL)=(proof_bytes IS NULL)),
    CHECK((completed_at IS NULL)=(proof_hash IS NULL)),
    CHECK((completed_at IS NULL)=(credential_id IS NULL)),
    PRIMARY KEY(org_id,project_id,principal_id,challenge_id),
    UNIQUE(org_id,project_id,principal_id,kind,idempotency_key),
    FOREIGN KEY(org_id,project_id,principal_id) REFERENCES principals(org_id,project_id,principal_id),
    FOREIGN KEY(credential_id) REFERENCES passkey_credentials(credential_id)
) STRICT;
CREATE INDEX passkey_challenge_pending ON passkey_challenges(org_id,project_id,principal_id,expires_at,completed_at);
CREATE TRIGGER passkey_challenge_immutable BEFORE UPDATE ON passkey_challenges
WHEN NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.principal_id!=OLD.principal_id
 OR NEW.challenge_id!=OLD.challenge_id OR NEW.kind!=OLD.kind OR NEW.idempotency_key!=OLD.idempotency_key
 OR NEW.request_hash!=OLD.request_hash OR NEW.challenge_bytes!=OLD.challenge_bytes OR NEW.challenge_hash!=OLD.challenge_hash
 OR NEW.created_at!=OLD.created_at OR NEW.expires_at!=OLD.expires_at OR OLD.completed_at IS NOT NULL
BEGIN SELECT RAISE(ABORT,'ceremony binding is immutable'); END;

CREATE TABLE passkey_revocations (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, principal_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL, request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
    credential_id TEXT NOT NULL, created_at INTEGER NOT NULL,
    response_bytes BLOB NOT NULL CHECK(length(response_bytes)<=65536),
    PRIMARY KEY(org_id,project_id,principal_id,idempotency_key),
    FOREIGN KEY(credential_id) REFERENCES passkey_credentials(credential_id),
    FOREIGN KEY(org_id,project_id,principal_id) REFERENCES principals(org_id,project_id,principal_id)
) STRICT;

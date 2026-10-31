CREATE TABLE authority_public_key_registry (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL,
    public_key_hash BLOB NOT NULL CHECK(length(public_key_hash)=32),
    credential_id TEXT NOT NULL,
    PRIMARY KEY(org_id,project_id,public_key_hash),
    UNIQUE(org_id,project_id,credential_id),
    FOREIGN KEY(org_id,project_id,credential_id) REFERENCES authority_credentials
) STRICT;
CREATE TRIGGER authority_public_key_registry_no_update BEFORE UPDATE ON authority_public_key_registry
BEGIN SELECT RAISE(ABORT,'immutable public key registration'); END;
CREATE TRIGGER authority_public_key_registry_no_delete BEFORE DELETE ON authority_public_key_registry
BEGIN SELECT RAISE(ABORT,'public key tombstones must be retained'); END;
CREATE TABLE authority_schema_migrations (
    version INTEGER PRIMARY KEY CHECK(version>=1),
    checksum BLOB NOT NULL CHECK(length(checksum)=32),
    minimum_app_schema INTEGER NOT NULL CHECK(minimum_app_schema>=1),
    maximum_app_schema INTEGER NOT NULL CHECK(maximum_app_schema>=minimum_app_schema),
    completed_at INTEGER NOT NULL CHECK(completed_at BETWEEN 0 AND 253402300799)
) STRICT;
CREATE TRIGGER authority_schema_migrations_no_update BEFORE UPDATE ON authority_schema_migrations
BEGIN SELECT RAISE(ABORT,'immutable migration record'); END;
CREATE TRIGGER authority_schema_migrations_no_delete BEFORE DELETE ON authority_schema_migrations
BEGIN SELECT RAISE(ABORT,'migration history must be retained'); END;

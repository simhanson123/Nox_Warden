-- Discardable read projections. Original audit and registry evidence stays immutable.
CREATE TABLE collection_versions (
 version INTEGER NOT NULL CHECK(version>0),
 org_id TEXT NOT NULL, project_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('assets','services','requests','operations','targets','enrollments')),
 resource_id TEXT NOT NULL, sort_created_at INTEGER NOT NULL CHECK(sort_created_at BETWEEN 0 AND 253402300799),
 recorded_at INTEGER NOT NULL CHECK(recorded_at BETWEEN sort_created_at AND 253402300799),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=262144),
 content_hash TEXT NOT NULL CHECK(length(content_hash)=71),
 PRIMARY KEY(org_id,project_id,version),
 FOREIGN KEY(org_id,project_id) REFERENCES projects(org_id,project_id)
) STRICT;
CREATE INDEX collection_resource_version ON collection_versions(org_id,project_id,kind,resource_id,version);
CREATE INDEX collection_order ON collection_versions(org_id,project_id,kind,sort_created_at,resource_id,version);
CREATE INDEX collection_retention ON collection_versions(org_id,project_id,recorded_at);
CREATE TRIGGER collection_version_no_update BEFORE UPDATE ON collection_versions BEGIN SELECT RAISE(ABORT,'collection version is immutable'); END;
CREATE TABLE collection_clocks (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, checked_at INTEGER NOT NULL CHECK(checked_at BETWEEN 0 AND 253402300799),
 PRIMARY KEY(org_id,project_id),
 FOREIGN KEY(org_id,project_id) REFERENCES projects(org_id,project_id)
) STRICT;

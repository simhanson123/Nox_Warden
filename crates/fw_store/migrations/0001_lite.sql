-- Lite persistence slice. SQLite only; not a substitute for PostgreSQL RLS.
CREATE TABLE organizations (
    org_id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','suspended')),
    created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE projects (
    org_id TEXT NOT NULL REFERENCES organizations(org_id),
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','suspended')),
    security_revision INTEGER NOT NULL DEFAULT 1 CHECK(security_revision BETWEEN 1 AND 2147483647),
    PRIMARY KEY(org_id,project_id), UNIQUE(org_id,name)
) STRICT;
CREATE TABLE principals (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, principal_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('human','workload','worker','issuer','agent')),
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','suspended','revoked')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(org_id,project_id,principal_id),
    FOREIGN KEY(org_id,project_id) REFERENCES projects(org_id,project_id)
) STRICT;
CREATE TABLE requests (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, request_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('add_access_lease','policy_change')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 2147483647),
    state TEXT NOT NULL CHECK(state IN ('submitted','validating','ready','needs_info','rejected','cancelled')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(org_id,project_id,request_id),
    FOREIGN KEY(org_id,project_id,principal_id) REFERENCES principals(org_id,project_id,principal_id)
) STRICT;
CREATE TABLE request_revisions (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, request_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision=1),
    content_hash BLOB NOT NULL CHECK(length(content_hash)=32), canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=65536),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(org_id,project_id,request_id,revision),
    FOREIGN KEY(org_id,project_id,request_id) REFERENCES requests(org_id,project_id,request_id)
) STRICT;
CREATE TABLE operations (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, operation_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind='validate'),
    state TEXT NOT NULL CHECK(state IN ('queued','running','failed','cancelled')),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, completed_at INTEGER,
    reason_code TEXT,
    CHECK((state IN ('failed','cancelled'))=(completed_at IS NOT NULL)),
    PRIMARY KEY(org_id,project_id,operation_id), UNIQUE(org_id,project_id,request_id),
    FOREIGN KEY(org_id,project_id,request_id) REFERENCES requests(org_id,project_id,request_id)
) STRICT;
CREATE TABLE idempotency (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, principal_id TEXT NOT NULL,
    method TEXT NOT NULL CHECK(method='POST'), route TEXT NOT NULL, key TEXT NOT NULL,
    body_hash BLOB NOT NULL CHECK(length(body_hash)=32), resource_id TEXT NOT NULL,
    response_status INTEGER NOT NULL CHECK(response_status=202), response_bytes BLOB NOT NULL CHECK(length(response_bytes)<=262144),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at>created_at),
    PRIMARY KEY(org_id,project_id,principal_id,method,route,key),
    FOREIGN KEY(org_id,project_id,principal_id) REFERENCES principals(org_id,project_id,principal_id),
    FOREIGN KEY(org_id,project_id,resource_id) REFERENCES requests(org_id,project_id,request_id)
) STRICT;
CREATE TABLE outbox (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, event_id TEXT NOT NULL,
    aggregate_kind TEXT NOT NULL, aggregate_id TEXT NOT NULL,
    aggregate_revision INTEGER NOT NULL CHECK(aggregate_revision BETWEEN 1 AND 2147483647),
    event_kind TEXT NOT NULL, payload_hash BLOB NOT NULL CHECK(length(payload_hash)=32), payload_bytes BLOB NOT NULL,
    available_at INTEGER NOT NULL,
    claim_generation BLOB NOT NULL CHECK(length(claim_generation)=8),
    claim_until INTEGER, attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt>=0),
    state TEXT NOT NULL CHECK(state IN ('pending','claimed','delivered')),
    CHECK((state='claimed')=(claim_until IS NOT NULL)),
    PRIMARY KEY(org_id,project_id,event_id),
    UNIQUE(org_id,project_id,aggregate_kind,aggregate_id,aggregate_revision,event_kind),
    FOREIGN KEY(org_id,project_id) REFERENCES projects(org_id,project_id)
) STRICT;
CREATE INDEX outbox_due ON outbox(org_id,project_id,state,available_at);
CREATE TABLE audit_heads (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL,
    sequence BLOB NOT NULL CHECK(length(sequence)=8), last_event_hash BLOB CHECK(last_event_hash IS NULL OR length(last_event_hash)=32),
    PRIMARY KEY(org_id,project_id), FOREIGN KEY(org_id,project_id) REFERENCES projects(org_id,project_id)
) STRICT;
CREATE TABLE audit_events (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL,
    sequence BLOB NOT NULL CHECK(length(sequence)=8), event_id TEXT NOT NULL,
    event_type TEXT NOT NULL, actor_id TEXT, resource_kind TEXT NOT NULL, resource_id TEXT,
    operation_id TEXT, outcome TEXT NOT NULL CHECK(outcome IN ('accepted','denied','pending','success','failed','unknown')),
    previous_hash BLOB CHECK(previous_hash IS NULL OR length(previous_hash)=32), event_hash BLOB NOT NULL CHECK(length(event_hash)=32),
    recorded_at INTEGER NOT NULL, canonical_bytes BLOB NOT NULL,
    PRIMARY KEY(org_id,project_id,sequence), UNIQUE(org_id,project_id,event_id),
    FOREIGN KEY(org_id,project_id) REFERENCES projects(org_id,project_id),
    FOREIGN KEY(org_id,project_id,actor_id) REFERENCES principals(org_id,project_id,principal_id),
    FOREIGN KEY(org_id,project_id,operation_id) REFERENCES operations(org_id,project_id,operation_id)
) STRICT;
CREATE INDEX audit_timeline ON audit_events(org_id,project_id,operation_id,sequence);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER request_revision_no_update BEFORE UPDATE ON request_revisions BEGIN SELECT RAISE(ABORT,'request revision is immutable'); END;
CREATE TRIGGER request_revision_no_delete BEFORE DELETE ON request_revisions BEGIN SELECT RAISE(ABORT,'request revision is immutable'); END;
CREATE TABLE targets (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, target_id TEXT NOT NULL,
    platform TEXT NOT NULL CHECK(platform IN ('linux','windows','macos')),
    backend TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'observe_only' CHECK(state='observe_only'),
    CHECK((platform='linux' AND backend='nftables') OR (platform='windows' AND backend='windows_wfp') OR (platform='macos' AND backend='macos_network_extension')),
    PRIMARY KEY(org_id,project_id,target_id), FOREIGN KEY(org_id,project_id) REFERENCES projects(org_id,project_id)
) STRICT;
CREATE TABLE policies (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, policy_id TEXT NOT NULL, target_id TEXT NOT NULL,
    current_revision INTEGER NOT NULL CHECK(current_revision BETWEEN 1 AND 2147483647),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('draft','tombstoned')),
    PRIMARY KEY(org_id,project_id,policy_id),
    FOREIGN KEY(org_id,project_id,target_id) REFERENCES targets(org_id,project_id,target_id),
    FOREIGN KEY(org_id,project_id,policy_id,current_revision) REFERENCES policy_revisions(org_id,project_id,policy_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE policy_revisions (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, policy_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
    policy_hash BLOB NOT NULL CHECK(length(policy_hash)=32),
    action TEXT NOT NULL CHECK(action IN ('allow','deny')),
    not_before INTEGER NOT NULL, expires_at INTEGER, review_at INTEGER,
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=65536),
    CHECK((action='allow' AND expires_at IS NOT NULL AND review_at IS NULL AND expires_at>not_before AND expires_at-not_before<=86400) OR (action='deny' AND expires_at IS NULL AND review_at IS NOT NULL AND review_at>not_before AND review_at-not_before<=7776000)),
    PRIMARY KEY(org_id,project_id,policy_id,revision),
    FOREIGN KEY(org_id,project_id,policy_id) REFERENCES policies(org_id,project_id,policy_id)
) STRICT;
CREATE TRIGGER policy_revision_no_update BEFORE UPDATE ON policy_revisions BEGIN SELECT RAISE(ABORT,'policy revision is immutable'); END;
CREATE TRIGGER policy_revision_no_delete BEFORE DELETE ON policy_revisions BEGIN SELECT RAISE(ABORT,'policy revision is immutable'); END;

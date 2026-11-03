-- Nullable project-only roots share the existing retained accounting graph.
-- A dedicated maintenance connection disables FKs before BEGIN IMMEDIATE;
-- all expected guards are recreated by the versioned migration orchestrator.

CREATE TABLE authority_signing_quota_pins_retained_v12 AS SELECT rowid,org_id,bucket_kind,bucket_id,revision,root_id,pinned_at,pin_hash,canonical_bytes FROM authority_signing_quota_pins;

DROP TABLE authority_signing_quota_pins;

CREATE TABLE authority_signing_quota_pins (
 org_id TEXT NOT NULL, bucket_kind TEXT NOT NULL CHECK(bucket_kind IN ('root','project')),
 bucket_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
 root_id TEXT, pinned_at INTEGER NOT NULL CHECK(pinned_at>=0),
 pin_hash BLOB NOT NULL CHECK(length(pin_hash)=32),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 32768),
 PRIMARY KEY(org_id,bucket_kind,bucket_id,revision),
 CHECK(bucket_kind='project' OR root_id IS NOT NULL)
) STRICT;

INSERT INTO authority_signing_quota_pins(rowid,org_id,bucket_kind,bucket_id,revision,root_id,pinned_at,pin_hash,canonical_bytes) SELECT rowid,org_id,bucket_kind,bucket_id,revision,root_id,pinned_at,pin_hash,canonical_bytes FROM authority_signing_quota_pins_retained_v12;

DROP TABLE authority_signing_quota_pins_retained_v12;

CREATE TABLE authority_signing_quota_reservations_retained_v12 AS SELECT rowid,org_id,project_id,reservation_id,root_id,plan_id,plan_hash,lease_id,lease_seconds,cost_hash,cost_bytes,snapshot_bytes,reserved_at,reserved_until,state,issued_at,active_slots,dispatch_slots FROM authority_signing_quota_reservations;

DROP TABLE authority_signing_quota_reservations;

CREATE TABLE authority_signing_quota_reservations (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, reservation_id TEXT NOT NULL,
 root_id TEXT, plan_id TEXT NOT NULL,
 plan_hash BLOB NOT NULL CHECK(length(plan_hash)=32),
 lease_id TEXT, lease_seconds INTEGER NOT NULL CHECK(lease_seconds BETWEEN 0 AND 86400),
 cost_hash BLOB NOT NULL CHECK(length(cost_hash)=32),
 cost_bytes BLOB NOT NULL CHECK(length(cost_bytes) BETWEEN 1 AND 262144),
 snapshot_bytes BLOB NOT NULL CHECK(length(snapshot_bytes) BETWEEN 1 AND 32768),
 reserved_at INTEGER NOT NULL CHECK(reserved_at>=0),
 reserved_until INTEGER NOT NULL CHECK(reserved_until>reserved_at),
 state TEXT NOT NULL CHECK(state IN ('reserved','issued','unknown','active','released')),
 issued_at INTEGER,
 active_slots INTEGER NOT NULL CHECK(active_slots BETWEEN 0 AND 1),
 dispatch_slots INTEGER NOT NULL CHECK(dispatch_slots BETWEEN 0 AND 1),
 PRIMARY KEY(org_id,project_id,reservation_id),
 UNIQUE(org_id,reservation_id),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects,
 CHECK((lease_id IS NULL AND lease_seconds=0) OR (lease_id IS NOT NULL AND lease_seconds BETWEEN 60 AND 86400)),
 CHECK(issued_at IS NULL OR issued_at>=reserved_at),
 CHECK(state!='reserved' OR issued_at IS NULL),
 CHECK(state NOT IN ('issued','active') OR issued_at IS NOT NULL),
 CHECK(state!='released' OR (active_slots=0 AND dispatch_slots=0)),
 CHECK(root_id IS NOT NULL OR (lease_id IS NULL AND lease_seconds=0 AND active_slots=0))
) STRICT;

INSERT INTO authority_signing_quota_reservations(rowid,org_id,project_id,reservation_id,root_id,plan_id,plan_hash,lease_id,lease_seconds,cost_hash,cost_bytes,snapshot_bytes,reserved_at,reserved_until,state,issued_at,active_slots,dispatch_slots) SELECT rowid,org_id,project_id,reservation_id,root_id,plan_id,plan_hash,lease_id,lease_seconds,cost_hash,cost_bytes,snapshot_bytes,reserved_at,reserved_until,state,issued_at,active_slots,dispatch_slots FROM authority_signing_quota_reservations_retained_v12;

DROP TABLE authority_signing_quota_reservations_retained_v12;

CREATE UNIQUE INDEX authority_signing_quota_lease_identity
 ON authority_signing_quota_reservations(org_id,lease_id) WHERE lease_id IS NOT NULL;

CREATE INDEX authority_signing_quota_project_accounting
 ON authority_signing_quota_reservations(org_id,project_id,issued_at)
 WHERE state='released' AND lease_id IS NOT NULL;

CREATE INDEX authority_signing_quota_project_held
 ON authority_signing_quota_reservations(org_id,project_id)
 WHERE state IN ('reserved','issued','unknown') OR (state='active' AND lease_id IS NOT NULL);

CREATE INDEX authority_signing_quota_root_accounting
 ON authority_signing_quota_reservations(org_id,root_id,issued_at)
 WHERE state='released' AND lease_id IS NOT NULL;

CREATE INDEX authority_signing_quota_root_held
 ON authority_signing_quota_reservations(org_id,root_id)
 WHERE state IN ('reserved','issued','unknown') OR (state='active' AND lease_id IS NOT NULL);

CREATE TABLE authority_signing_quota_transition_heads_retained_v12 AS SELECT rowid,org_id,project_id,reservation_id,root_id,lease_id,revision,state,issued_at FROM authority_signing_quota_transition_heads;

DROP TABLE authority_signing_quota_transition_heads;

CREATE TABLE authority_signing_quota_transition_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, reservation_id TEXT NOT NULL,
 root_id TEXT, lease_id TEXT, revision INTEGER NOT NULL,
 state TEXT NOT NULL, issued_at INTEGER,
 PRIMARY KEY(org_id,project_id,reservation_id),
 FOREIGN KEY(org_id,project_id,reservation_id,revision) REFERENCES authority_signing_quota_transitions,
 CHECK(root_id IS NOT NULL OR lease_id IS NULL)
) STRICT;

INSERT INTO authority_signing_quota_transition_heads(rowid,org_id,project_id,reservation_id,root_id,lease_id,revision,state,issued_at) SELECT rowid,org_id,project_id,reservation_id,root_id,lease_id,revision,state,issued_at FROM authority_signing_quota_transition_heads_retained_v12;

DROP TABLE authority_signing_quota_transition_heads_retained_v12;

CREATE INDEX authority_signing_quota_transition_project_accounting ON authority_signing_quota_transition_heads(org_id,project_id,issued_at)
 WHERE state='released' AND lease_id IS NOT NULL;

CREATE INDEX authority_signing_quota_transition_project_held ON authority_signing_quota_transition_heads(org_id,project_id)
 WHERE state IN ('reserved','issued','unknown','active');

CREATE INDEX authority_signing_quota_transition_root_accounting ON authority_signing_quota_transition_heads(org_id,root_id,issued_at)
 WHERE state='released' AND lease_id IS NOT NULL;

CREATE INDEX authority_signing_quota_transition_root_held ON authority_signing_quota_transition_heads(org_id,root_id)
 WHERE state IN ('reserved','issued','unknown','active');

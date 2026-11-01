-- Semantic review evidence is immutable and bound to an existing exact plan.
-- No legacy plan is assigned evidence or dispatch authority by this migration.
CREATE TABLE authority_plan_review_evidence (
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_hash BLOB NOT NULL CHECK(length(plan_hash) = 32),
    evidence_hash BLOB NOT NULL CHECK(length(evidence_hash) = 32),
    admitted_at INTEGER NOT NULL CHECK(admitted_at >= 0),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 131072),
    PRIMARY KEY(org_id, project_id, plan_id),
    FOREIGN KEY(org_id, project_id, plan_id) REFERENCES authority_plans(org_id, project_id, plan_id)
) STRICT;
CREATE TRIGGER authority_plan_review_evidence_no_update BEFORE UPDATE ON authority_plan_review_evidence BEGIN SELECT RAISE(ABORT,'immutable plan review evidence'); END;
CREATE TRIGGER authority_plan_review_evidence_no_delete BEFORE DELETE ON authority_plan_review_evidence BEGIN SELECT RAISE(ABORT,'immutable plan review evidence'); END;

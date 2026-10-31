CREATE TABLE authority_basis_pins (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, basis_id TEXT NOT NULL,
    epoch BLOB NOT NULL CHECK(length(epoch)=8), role_policy_hash BLOB NOT NULL CHECK(length(role_policy_hash)=32),
    not_before INTEGER NOT NULL CHECK(not_before>=0), not_after INTEGER NOT NULL CHECK(not_after>not_before),
    pinned_at INTEGER NOT NULL CHECK(pinned_at>=0), content_hash BLOB NOT NULL CHECK(length(content_hash)=32),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 8192),
    PRIMARY KEY(org_id,project_id,basis_id), UNIQUE(org_id,project_id,epoch),
    UNIQUE(org_id,project_id,basis_id,epoch,role_policy_hash),
    FOREIGN KEY(org_id,project_id) REFERENCES authority_projects
) STRICT;
CREATE TABLE authority_basis_heads (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, basis_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
    PRIMARY KEY(org_id,project_id),
    FOREIGN KEY(org_id,project_id,basis_id) REFERENCES authority_basis_pins
) STRICT;
CREATE TABLE authority_human_bindings (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, principal_id TEXT NOT NULL,
    human_id TEXT NOT NULL, bound_at INTEGER NOT NULL CHECK(bound_at>=0),
    PRIMARY KEY(org_id,project_id,principal_id), UNIQUE(org_id,project_id,principal_id,human_id),
    FOREIGN KEY(org_id,project_id,principal_id) REFERENCES authority_principals
) STRICT;
CREATE UNIQUE INDEX authority_plan_set_identity ON authority_plans(org_id,project_id,plan_id,plan_hash,requirements_hash);
CREATE UNIQUE INDEX authority_decision_set_identity ON authority_decisions(org_id,project_id,approval_id,principal_id,plan_id,credential_id,membership_id,decision);
CREATE UNIQUE INDEX authority_role_set_identity ON authority_roles(org_id,project_id,membership_id,principal_id,role);
CREATE INDEX authority_plan_decision_lookup ON authority_decisions(org_id,project_id,plan_id,decision,expires_at,created_at,approval_id);
CREATE TABLE authority_approval_sets (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, approval_set_id TEXT NOT NULL,
    plan_id TEXT NOT NULL, plan_hash BLOB NOT NULL CHECK(length(plan_hash)=32),
    requirements_hash BLOB NOT NULL CHECK(length(requirements_hash)=32),
    basis_id TEXT NOT NULL, epoch BLOB NOT NULL CHECK(length(epoch)=8), role_policy_hash BLOB NOT NULL CHECK(length(role_policy_hash)=32),
    selection_hash BLOB NOT NULL CHECK(length(selection_hash)=32), content_hash BLOB NOT NULL CHECK(length(content_hash)=32),
    created_at INTEGER NOT NULL CHECK(created_at>=0), valid_until INTEGER NOT NULL CHECK(valid_until>created_at),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 65536),
    PRIMARY KEY(org_id,project_id,approval_set_id), UNIQUE(org_id,project_id,content_hash),
    UNIQUE(org_id,project_id,selection_hash), UNIQUE(org_id,project_id,approval_set_id,plan_id),
    FOREIGN KEY(org_id,project_id,plan_id,plan_hash,requirements_hash) REFERENCES authority_plans(org_id,project_id,plan_id,plan_hash,requirements_hash),
    FOREIGN KEY(org_id,project_id,basis_id,epoch,role_policy_hash) REFERENCES authority_basis_pins(org_id,project_id,basis_id,epoch,role_policy_hash)
) STRICT;
CREATE TABLE authority_approval_set_members (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, approval_set_id TEXT NOT NULL, approval_id TEXT NOT NULL,
    plan_id TEXT NOT NULL, principal_id TEXT NOT NULL, human_id TEXT NOT NULL,
    credential_id TEXT NOT NULL, membership_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner','network_reviewer','service_reviewer','security_reviewer')),
    decision TEXT NOT NULL CHECK(decision='approve'), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 2),
    PRIMARY KEY(org_id,project_id,approval_set_id,approval_id),
    UNIQUE(org_id,project_id,approval_set_id,human_id), UNIQUE(org_id,project_id,approval_set_id,role),
    UNIQUE(org_id,project_id,approval_set_id,position),
    FOREIGN KEY(org_id,project_id,approval_set_id,plan_id) REFERENCES authority_approval_sets(org_id,project_id,approval_set_id,plan_id),
    FOREIGN KEY(org_id,project_id,approval_id,principal_id,plan_id,credential_id,membership_id,decision) REFERENCES authority_decisions(org_id,project_id,approval_id,principal_id,plan_id,credential_id,membership_id,decision),
    FOREIGN KEY(org_id,project_id,membership_id,principal_id,role) REFERENCES authority_roles(org_id,project_id,membership_id,principal_id,role),
    FOREIGN KEY(org_id,project_id,principal_id,human_id) REFERENCES authority_human_bindings(org_id,project_id,principal_id,human_id)
) STRICT;
CREATE TABLE authority_set_heads (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, plan_id TEXT NOT NULL, approval_set_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
    PRIMARY KEY(org_id,project_id,plan_id),
    FOREIGN KEY(org_id,project_id,approval_set_id,plan_id) REFERENCES authority_approval_sets(org_id,project_id,approval_set_id,plan_id)
) STRICT;
CREATE TABLE authority_decision_revocations (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, approval_id TEXT NOT NULL,
    actor_id TEXT NOT NULL, reason_code TEXT NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 64), revoked_at INTEGER NOT NULL CHECK(revoked_at>=0),
    PRIMARY KEY(org_id,project_id,approval_id),
    FOREIGN KEY(org_id,project_id,approval_id) REFERENCES authority_decisions,
    FOREIGN KEY(org_id,project_id,actor_id) REFERENCES authority_principals
) STRICT;
CREATE TABLE authority_set_revocations (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, approval_set_id TEXT NOT NULL,
    actor_id TEXT NOT NULL, reason_code TEXT NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 64), revoked_at INTEGER NOT NULL CHECK(revoked_at>=0),
    PRIMARY KEY(org_id,project_id,approval_set_id),
    FOREIGN KEY(org_id,project_id,approval_set_id) REFERENCES authority_approval_sets,
    FOREIGN KEY(org_id,project_id,actor_id) REFERENCES authority_principals
) STRICT;
CREATE TABLE authority_admission_results (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, approval_id TEXT NOT NULL,
    content_hash BLOB NOT NULL CHECK(length(content_hash)=32),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 8192),
    PRIMARY KEY(org_id,project_id,approval_id),
    FOREIGN KEY(org_id,project_id,approval_id) REFERENCES authority_decisions
) STRICT;
CREATE TRIGGER authority_basis_pins_no_update BEFORE UPDATE ON authority_basis_pins BEGIN SELECT RAISE(ABORT,'immutable approval authority'); END;
CREATE TRIGGER authority_basis_pins_no_delete BEFORE DELETE ON authority_basis_pins BEGIN SELECT RAISE(ABORT,'retained approval authority'); END;
CREATE TRIGGER authority_human_bindings_no_update BEFORE UPDATE ON authority_human_bindings BEGIN SELECT RAISE(ABORT,'immutable approval authority'); END;
CREATE TRIGGER authority_human_bindings_no_delete BEFORE DELETE ON authority_human_bindings BEGIN SELECT RAISE(ABORT,'retained approval authority'); END;
CREATE TRIGGER authority_approval_sets_no_update BEFORE UPDATE ON authority_approval_sets BEGIN SELECT RAISE(ABORT,'immutable approval authority'); END;
CREATE TRIGGER authority_approval_sets_no_delete BEFORE DELETE ON authority_approval_sets BEGIN SELECT RAISE(ABORT,'retained approval authority'); END;
CREATE TRIGGER authority_approval_set_members_no_update BEFORE UPDATE ON authority_approval_set_members BEGIN SELECT RAISE(ABORT,'immutable approval authority'); END;
CREATE TRIGGER authority_approval_set_members_no_delete BEFORE DELETE ON authority_approval_set_members BEGIN SELECT RAISE(ABORT,'retained approval authority'); END;
CREATE TRIGGER authority_decision_revocations_no_update BEFORE UPDATE ON authority_decision_revocations BEGIN SELECT RAISE(ABORT,'immutable approval authority'); END;
CREATE TRIGGER authority_decision_revocations_no_delete BEFORE DELETE ON authority_decision_revocations BEGIN SELECT RAISE(ABORT,'retained approval authority'); END;
CREATE TRIGGER authority_set_revocations_no_update BEFORE UPDATE ON authority_set_revocations BEGIN SELECT RAISE(ABORT,'immutable approval authority'); END;
CREATE TRIGGER authority_set_revocations_no_delete BEFORE DELETE ON authority_set_revocations BEGIN SELECT RAISE(ABORT,'retained approval authority'); END;
CREATE TRIGGER authority_admission_results_no_update BEFORE UPDATE ON authority_admission_results BEGIN SELECT RAISE(ABORT,'immutable approval authority'); END;
CREATE TRIGGER authority_admission_results_no_delete BEFORE DELETE ON authority_admission_results BEGIN SELECT RAISE(ABORT,'retained approval authority'); END;
CREATE TRIGGER authority_basis_heads_forward BEFORE UPDATE ON authority_basis_heads
WHEN NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.revision!=OLD.revision+1
 OR (SELECT epoch FROM authority_basis_pins WHERE org_id=NEW.org_id AND project_id=NEW.project_id AND basis_id=NEW.basis_id)
 <=(SELECT epoch FROM authority_basis_pins WHERE org_id=OLD.org_id AND project_id=OLD.project_id AND basis_id=OLD.basis_id)
BEGIN SELECT RAISE(ABORT,'authority epoch must advance'); END;
CREATE TRIGGER authority_basis_heads_no_delete BEFORE DELETE ON authority_basis_heads
BEGIN SELECT RAISE(ABORT,'authority basis head must be retained'); END;
CREATE TRIGGER authority_set_heads_forward BEFORE UPDATE ON authority_set_heads
WHEN NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.plan_id IS NOT OLD.plan_id
 OR NEW.approval_set_id=OLD.approval_set_id OR NEW.revision!=OLD.revision+1
 OR (SELECT created_at FROM authority_approval_sets WHERE org_id=NEW.org_id AND project_id=NEW.project_id AND approval_set_id=NEW.approval_set_id)
 <(SELECT created_at FROM authority_approval_sets WHERE org_id=OLD.org_id AND project_id=OLD.project_id AND approval_set_id=OLD.approval_set_id)
BEGIN SELECT RAISE(ABORT,'approval set head must advance'); END;
CREATE TRIGGER authority_set_heads_no_delete BEFORE DELETE ON authority_set_heads
BEGIN SELECT RAISE(ABORT,'approval set head must be retained'); END;

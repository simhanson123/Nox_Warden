-- Retained identity guards apply before SQLite conflict handling, including
-- explicit hidden rowid, logical PK and every alternate unique key.

CREATE TRIGGER authority_activations_no_replace BEFORE INSERT ON authority_activations
WHEN EXISTS(SELECT 1 FROM authority_activations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND activation_id=NEW.activation_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_activations_row_identity BEFORE UPDATE ON authority_activations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.activation_id IS NOT OLD.activation_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_admission_results_no_replace BEFORE INSERT ON authority_admission_results
WHEN EXISTS(SELECT 1 FROM authority_admission_results WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_id=NEW.approval_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_admission_results_row_identity BEFORE UPDATE ON authority_admission_results
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.approval_id IS NOT OLD.approval_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_approval_set_members_no_replace BEFORE INSERT ON authority_approval_set_members
WHEN EXISTS(SELECT 1 FROM authority_approval_set_members WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_set_id=NEW.approval_set_id AND position=NEW.position) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_set_id=NEW.approval_set_id AND role=NEW.role) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_set_id=NEW.approval_set_id AND human_id=NEW.human_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_set_id=NEW.approval_set_id AND approval_id=NEW.approval_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_approval_set_members_row_identity BEFORE UPDATE ON authority_approval_set_members
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.approval_set_id IS NOT OLD.approval_set_id OR NEW.approval_id IS NOT OLD.approval_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_approval_sets_no_replace BEFORE INSERT ON authority_approval_sets
WHEN EXISTS(SELECT 1 FROM authority_approval_sets WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_set_id=NEW.approval_set_id AND plan_id=NEW.plan_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND selection_hash=NEW.selection_hash) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND content_hash=NEW.content_hash) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_set_id=NEW.approval_set_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_approval_sets_row_identity BEFORE UPDATE ON authority_approval_sets
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.approval_set_id IS NOT OLD.approval_set_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_audit_no_replace BEFORE INSERT ON authority_audit
WHEN EXISTS(SELECT 1 FROM authority_audit WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND event_hash=NEW.event_hash) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND sequence=NEW.sequence))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_audit_row_identity BEFORE UPDATE ON authority_audit
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.sequence IS NOT OLD.sequence
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_audit_heads_no_replace BEFORE INSERT ON authority_audit_heads
WHEN EXISTS(SELECT 1 FROM authority_audit_heads WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_audit_heads_row_identity BEFORE UPDATE ON authority_audit_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_audit_heads_no_delete BEFORE DELETE ON authority_audit_heads
BEGIN SELECT RAISE(ABORT,'retained authority record'); END;

CREATE TRIGGER authority_basis_heads_no_replace BEFORE INSERT ON authority_basis_heads
WHEN EXISTS(SELECT 1 FROM authority_basis_heads WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_basis_heads_row_identity BEFORE UPDATE ON authority_basis_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_basis_pins_no_replace BEFORE INSERT ON authority_basis_pins
WHEN EXISTS(SELECT 1 FROM authority_basis_pins WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND basis_id=NEW.basis_id AND epoch=NEW.epoch AND role_policy_hash=NEW.role_policy_hash) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND epoch=NEW.epoch) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND basis_id=NEW.basis_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_basis_pins_row_identity BEFORE UPDATE ON authority_basis_pins
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.basis_id IS NOT OLD.basis_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_challenges_no_replace BEFORE INSERT ON authority_challenges
WHEN EXISTS(SELECT 1 FROM authority_challenges WHERE (rowid=NEW.rowid) OR (nonce_hash=NEW.nonce_hash) OR (challenge_hash=NEW.challenge_hash) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND challenge_id=NEW.challenge_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_challenges_row_identity BEFORE UPDATE ON authority_challenges
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.challenge_id IS NOT OLD.challenge_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_core_access_plan_bindings_row_identity BEFORE UPDATE ON authority_core_access_plan_bindings
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.plan_id IS NOT OLD.plan_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_core_access_requests_row_identity BEFORE UPDATE ON authority_core_access_requests
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.request_id IS NOT OLD.request_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_credentials_no_replace BEFORE INSERT ON authority_credentials
WHEN EXISTS(SELECT 1 FROM authority_credentials WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND credential_id=NEW.credential_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_credentials_row_identity BEFORE UPDATE ON authority_credentials
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.credential_id IS NOT OLD.credential_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_decision_revocations_no_replace BEFORE INSERT ON authority_decision_revocations
WHEN EXISTS(SELECT 1 FROM authority_decision_revocations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_id=NEW.approval_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_decision_revocations_row_identity BEFORE UPDATE ON authority_decision_revocations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.approval_id IS NOT OLD.approval_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_decisions_no_replace BEFORE INSERT ON authority_decisions
WHEN EXISTS(SELECT 1 FROM authority_decisions WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_id=NEW.approval_id AND principal_id=NEW.principal_id AND plan_id=NEW.plan_id AND credential_id=NEW.credential_id AND membership_id=NEW.membership_id AND decision=NEW.decision) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND principal_id=NEW.principal_id AND idempotency_key=NEW.idempotency_key) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND challenge_id=NEW.challenge_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_id=NEW.approval_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_decisions_row_identity BEFORE UPDATE ON authority_decisions
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.approval_id IS NOT OLD.approval_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_evidence_no_replace BEFORE INSERT ON authority_evidence
WHEN EXISTS(SELECT 1 FROM authority_evidence WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND challenge_id=NEW.challenge_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND evidence_hash=NEW.evidence_hash))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_evidence_row_identity BEFORE UPDATE ON authority_evidence
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.evidence_hash IS NOT OLD.evidence_hash
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_human_bindings_no_replace BEFORE INSERT ON authority_human_bindings
WHEN EXISTS(SELECT 1 FROM authority_human_bindings WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND principal_id=NEW.principal_id AND human_id=NEW.human_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND principal_id=NEW.principal_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_human_bindings_row_identity BEFORE UPDATE ON authority_human_bindings
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.principal_id IS NOT OLD.principal_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_metadata_no_replace BEFORE INSERT ON authority_metadata
WHEN EXISTS(SELECT 1 FROM authority_metadata WHERE (rowid=NEW.rowid) OR (singleton=NEW.singleton))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_metadata_row_identity BEFORE UPDATE ON authority_metadata
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.singleton IS NOT OLD.singleton
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_native_challenges_no_replace BEFORE INSERT ON authority_native_challenges
WHEN EXISTS(SELECT 1 FROM authority_native_challenges WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND challenge_id=NEW.challenge_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_native_challenges_row_identity BEFORE UPDATE ON authority_native_challenges
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.challenge_id IS NOT OLD.challenge_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_native_compilation_heads_no_replace BEFORE INSERT ON authority_native_compilation_heads
WHEN EXISTS(SELECT 1 FROM authority_native_compilation_heads WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND plan_id=NEW.plan_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_native_compilation_heads_row_identity BEFORE UPDATE ON authority_native_compilation_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.plan_id IS NOT OLD.plan_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_native_compilation_heads_no_delete BEFORE DELETE ON authority_native_compilation_heads
BEGIN SELECT RAISE(ABORT,'retained authority record'); END;

CREATE TRIGGER authority_native_compilations_no_replace BEFORE INSERT ON authority_native_compilations
WHEN EXISTS(SELECT 1 FROM authority_native_compilations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND plan_id=NEW.plan_id AND reference_revision=NEW.reference_revision AND metadata_receipt_id=NEW.metadata_receipt_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND plan_id=NEW.plan_id AND sequence=NEW.sequence) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND compilation_id=NEW.compilation_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_native_compilations_row_identity BEFORE UPDATE ON authority_native_compilations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.compilation_id IS NOT OLD.compilation_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_native_observation_heads_no_replace BEFORE INSERT ON authority_native_observation_heads
WHEN EXISTS(SELECT 1 FROM authority_native_observation_heads WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_native_observation_heads_row_identity BEFORE UPDATE ON authority_native_observation_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.target_id IS NOT OLD.target_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_native_observation_heads_no_delete BEFORE DELETE ON authority_native_observation_heads
BEGIN SELECT RAISE(ABORT,'retained authority record'); END;

CREATE TRIGGER authority_native_observations_no_replace BEFORE INSERT ON authority_native_observations
WHEN EXISTS(SELECT 1 FROM authority_native_observations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id AND sequence=NEW.sequence) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND challenge_id=NEW.challenge_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND receipt_id=NEW.receipt_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_native_observations_row_identity BEFORE UPDATE ON authority_native_observations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.receipt_id IS NOT OLD.receipt_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_native_observer_keys_no_replace BEFORE INSERT ON authority_native_observer_keys
WHEN EXISTS(SELECT 1 FROM authority_native_observer_keys WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND key_fingerprint=NEW.key_fingerprint))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_native_observer_keys_row_identity BEFORE UPDATE ON authority_native_observer_keys
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.key_fingerprint IS NOT OLD.key_fingerprint
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_native_observer_revocations_no_replace BEFORE INSERT ON authority_native_observer_revocations
WHEN EXISTS(SELECT 1 FROM authority_native_observer_revocations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND key_fingerprint=NEW.key_fingerprint))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_native_observer_revocations_row_identity BEFORE UPDATE ON authority_native_observer_revocations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.key_fingerprint IS NOT OLD.key_fingerprint
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_native_pin_heads_no_replace BEFORE INSERT ON authority_native_pin_heads
WHEN EXISTS(SELECT 1 FROM authority_native_pin_heads WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id AND kind=NEW.kind))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_native_pin_heads_row_identity BEFORE UPDATE ON authority_native_pin_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.target_id IS NOT OLD.target_id OR NEW.kind IS NOT OLD.kind
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_native_pin_heads_no_delete BEFORE DELETE ON authority_native_pin_heads
BEGIN SELECT RAISE(ABORT,'retained authority record'); END;

CREATE TRIGGER authority_native_pin_revocations_no_replace BEFORE INSERT ON authority_native_pin_revocations
WHEN EXISTS(SELECT 1 FROM authority_native_pin_revocations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id AND kind=NEW.kind AND revision=NEW.revision))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_native_pin_revocations_row_identity BEFORE UPDATE ON authority_native_pin_revocations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.target_id IS NOT OLD.target_id OR NEW.kind IS NOT OLD.kind OR NEW.revision IS NOT OLD.revision
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_native_pins_no_replace BEFORE INSERT ON authority_native_pins
WHEN EXISTS(SELECT 1 FROM authority_native_pins WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id AND kind=NEW.kind AND revision=NEW.revision))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_native_pins_row_identity BEFORE UPDATE ON authority_native_pins
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.target_id IS NOT OLD.target_id OR NEW.kind IS NOT OLD.kind OR NEW.revision IS NOT OLD.revision
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_plan_retirements_no_replace BEFORE INSERT ON authority_plan_retirements
WHEN EXISTS(SELECT 1 FROM authority_plan_retirements WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND plan_id=NEW.plan_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_plan_retirements_row_identity BEFORE UPDATE ON authority_plan_retirements
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.plan_id IS NOT OLD.plan_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_plan_review_evidence_no_replace BEFORE INSERT ON authority_plan_review_evidence
WHEN EXISTS(SELECT 1 FROM authority_plan_review_evidence WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND plan_id=NEW.plan_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_plan_review_evidence_row_identity BEFORE UPDATE ON authority_plan_review_evidence
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.plan_id IS NOT OLD.plan_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_plans_no_replace BEFORE INSERT ON authority_plans
WHEN EXISTS(SELECT 1 FROM authority_plans WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND plan_id=NEW.plan_id AND plan_hash=NEW.plan_hash AND requirements_hash=NEW.requirements_hash) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND plan_hash=NEW.plan_hash) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND plan_id=NEW.plan_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_plans_row_identity BEFORE UPDATE ON authority_plans
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.plan_id IS NOT OLD.plan_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_principals_no_replace BEFORE INSERT ON authority_principals
WHEN EXISTS(SELECT 1 FROM authority_principals WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND issuer=NEW.issuer AND subject=NEW.subject) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND principal_id=NEW.principal_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_principals_row_identity BEFORE UPDATE ON authority_principals
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.principal_id IS NOT OLD.principal_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_projects_no_replace BEFORE INSERT ON authority_projects
WHEN EXISTS(SELECT 1 FROM authority_projects WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_projects_row_identity BEFORE UPDATE ON authority_projects
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_projects_no_delete BEFORE DELETE ON authority_projects
BEGIN SELECT RAISE(ABORT,'retained authority record'); END;

CREATE TRIGGER authority_public_key_registry_no_replace BEFORE INSERT ON authority_public_key_registry
WHEN EXISTS(SELECT 1 FROM authority_public_key_registry WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND credential_id=NEW.credential_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND public_key_hash=NEW.public_key_hash))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_public_key_registry_row_identity BEFORE UPDATE ON authority_public_key_registry
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.public_key_hash IS NOT OLD.public_key_hash
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_requirement_roles_no_replace BEFORE INSERT ON authority_requirement_roles
WHEN EXISTS(SELECT 1 FROM authority_requirement_roles WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND requirements_hash=NEW.requirements_hash AND role=NEW.role))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_requirement_roles_row_identity BEFORE UPDATE ON authority_requirement_roles
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.requirements_hash IS NOT OLD.requirements_hash OR NEW.role IS NOT OLD.role
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_requirements_no_replace BEFORE INSERT ON authority_requirements
WHEN EXISTS(SELECT 1 FROM authority_requirements WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND requirements_hash=NEW.requirements_hash))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_requirements_row_identity BEFORE UPDATE ON authority_requirements
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.requirements_hash IS NOT OLD.requirements_hash
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_roles_no_replace BEFORE INSERT ON authority_roles
WHEN EXISTS(SELECT 1 FROM authority_roles WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND membership_id=NEW.membership_id AND principal_id=NEW.principal_id AND role=NEW.role) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND principal_id=NEW.principal_id AND role=NEW.role AND (revoked_at IS NULL) AND (NEW.revoked_at IS NULL)) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND membership_id=NEW.membership_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_roles_row_identity BEFORE UPDATE ON authority_roles
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.membership_id IS NOT OLD.membership_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_schema_migrations_no_replace BEFORE INSERT ON authority_schema_migrations
WHEN EXISTS(SELECT 1 FROM authority_schema_migrations WHERE (rowid=NEW.rowid) OR (version=NEW.version))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_schema_migrations_row_identity BEFORE UPDATE ON authority_schema_migrations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.version IS NOT OLD.version
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_set_heads_no_replace BEFORE INSERT ON authority_set_heads
WHEN EXISTS(SELECT 1 FROM authority_set_heads WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND plan_id=NEW.plan_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_set_heads_row_identity BEFORE UPDATE ON authority_set_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.plan_id IS NOT OLD.plan_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_set_revocations_no_replace BEFORE INSERT ON authority_set_revocations
WHEN EXISTS(SELECT 1 FROM authority_set_revocations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND approval_set_id=NEW.approval_set_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_set_revocations_row_identity BEFORE UPDATE ON authority_set_revocations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.approval_set_id IS NOT OLD.approval_set_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_deliveries_row_identity BEFORE UPDATE ON authority_signing_deliveries
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.job_id IS NOT OLD.job_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_intents_no_replace BEFORE INSERT ON authority_signing_intents
WHEN EXISTS(SELECT 1 FROM authority_signing_intents WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id AND epoch=NEW.epoch AND generation=NEW.generation) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND request_id=NEW.request_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND intent_id=NEW.intent_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_intents_row_identity BEFORE UPDATE ON authority_signing_intents
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.intent_id IS NOT OLD.intent_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_jobs_no_replace BEFORE INSERT ON authority_signing_jobs
WHEN EXISTS(SELECT 1 FROM authority_signing_jobs WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND intent_id=NEW.intent_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND job_id=NEW.job_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_jobs_row_identity BEFORE UPDATE ON authority_signing_jobs
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.job_id IS NOT OLD.job_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_outbox_no_replace BEFORE INSERT ON authority_signing_outbox
WHEN EXISTS(SELECT 1 FROM authority_signing_outbox WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND intent_id=NEW.intent_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND job_id=NEW.job_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_outbox_row_identity BEFORE UPDATE ON authority_signing_outbox
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.job_id IS NOT OLD.job_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_quota_clocks_no_replace BEFORE INSERT ON authority_signing_quota_clocks
WHEN EXISTS(SELECT 1 FROM authority_signing_quota_clocks WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND bucket_kind=NEW.bucket_kind AND bucket_id=NEW.bucket_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_quota_clocks_row_identity BEFORE UPDATE ON authority_signing_quota_clocks
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.bucket_kind IS NOT OLD.bucket_kind OR NEW.bucket_id IS NOT OLD.bucket_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_quota_destinations_no_replace BEFORE INSERT ON authority_signing_quota_destinations
WHEN EXISTS(SELECT 1 FROM authority_signing_quota_destinations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND reservation_id=NEW.reservation_id AND asset_id=NEW.asset_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_quota_destinations_row_identity BEFORE UPDATE ON authority_signing_quota_destinations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.reservation_id IS NOT OLD.reservation_id OR NEW.asset_id IS NOT OLD.asset_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_quota_heads_no_replace BEFORE INSERT ON authority_signing_quota_heads
WHEN EXISTS(SELECT 1 FROM authority_signing_quota_heads WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND bucket_kind=NEW.bucket_kind AND bucket_id=NEW.bucket_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_quota_heads_row_identity BEFORE UPDATE ON authority_signing_quota_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.bucket_kind IS NOT OLD.bucket_kind OR NEW.bucket_id IS NOT OLD.bucket_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_quota_heads_no_delete BEFORE DELETE ON authority_signing_quota_heads
BEGIN SELECT RAISE(ABORT,'retained authority record'); END;

CREATE TRIGGER authority_signing_quota_pins_no_replace BEFORE INSERT ON authority_signing_quota_pins
WHEN EXISTS(SELECT 1 FROM authority_signing_quota_pins WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND bucket_kind=NEW.bucket_kind AND bucket_id=NEW.bucket_id AND revision=NEW.revision))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_quota_pins_row_identity BEFORE UPDATE ON authority_signing_quota_pins
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.bucket_kind IS NOT OLD.bucket_kind OR NEW.bucket_id IS NOT OLD.bucket_id OR NEW.revision IS NOT OLD.revision
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_quota_reservations_no_replace BEFORE INSERT ON authority_signing_quota_reservations
WHEN EXISTS(SELECT 1 FROM authority_signing_quota_reservations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND lease_id=NEW.lease_id AND (lease_id IS NOT NULL) AND (NEW.lease_id IS NOT NULL)) OR (org_id=NEW.org_id AND reservation_id=NEW.reservation_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND reservation_id=NEW.reservation_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_quota_reservations_row_identity BEFORE UPDATE ON authority_signing_quota_reservations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.reservation_id IS NOT OLD.reservation_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_quota_revocations_no_replace BEFORE INSERT ON authority_signing_quota_revocations
WHEN EXISTS(SELECT 1 FROM authority_signing_quota_revocations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND bucket_kind=NEW.bucket_kind AND bucket_id=NEW.bucket_id AND revision=NEW.revision))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_quota_revocations_row_identity BEFORE UPDATE ON authority_signing_quota_revocations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.bucket_kind IS NOT OLD.bucket_kind OR NEW.bucket_id IS NOT OLD.bucket_id OR NEW.revision IS NOT OLD.revision
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_quota_transition_heads_row_identity BEFORE UPDATE ON authority_signing_quota_transition_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.reservation_id IS NOT OLD.reservation_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_quota_transitions_no_replace BEFORE INSERT ON authority_signing_quota_transitions
WHEN EXISTS(SELECT 1 FROM authority_signing_quota_transitions WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND reservation_id=NEW.reservation_id AND revision=NEW.revision))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_quota_transitions_row_identity BEFORE UPDATE ON authority_signing_quota_transitions
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.reservation_id IS NOT OLD.reservation_id OR NEW.revision IS NOT OLD.revision
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_quota_usage_no_replace BEFORE INSERT ON authority_signing_quota_usage
WHEN EXISTS(SELECT 1 FROM authority_signing_quota_usage WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND reservation_id=NEW.reservation_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_quota_usage_row_identity BEFORE UPDATE ON authority_signing_quota_usage
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.reservation_id IS NOT OLD.reservation_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_results_no_replace BEFORE INSERT ON authority_signing_results
WHEN EXISTS(SELECT 1 FROM authority_signing_results WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND intent_id=NEW.intent_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_results_row_identity BEFORE UPDATE ON authority_signing_results
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.intent_id IS NOT OLD.intent_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_target_heads_no_replace BEFORE INSERT ON authority_signing_target_heads
WHEN EXISTS(SELECT 1 FROM authority_signing_target_heads WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_signing_target_heads_row_identity BEFORE UPDATE ON authority_signing_target_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.target_id IS NOT OLD.target_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_target_heads_no_delete BEFORE DELETE ON authority_signing_target_heads
BEGIN SELECT RAISE(ABORT,'retained authority record'); END;

CREATE TRIGGER authority_signing_work_events_row_identity BEFORE UPDATE ON authority_signing_work_events
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.job_id IS NOT OLD.job_id OR NEW.phase IS NOT OLD.phase OR NEW.revision IS NOT OLD.revision
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_signing_work_heads_row_identity BEFORE UPDATE ON authority_signing_work_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.job_id IS NOT OLD.job_id OR NEW.phase IS NOT OLD.phase
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_target_challenges_no_replace BEFORE INSERT ON authority_target_challenges
WHEN EXISTS(SELECT 1 FROM authority_target_challenges WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND challenge_id=NEW.challenge_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_target_challenges_row_identity BEFORE UPDATE ON authority_target_challenges
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.challenge_id IS NOT OLD.challenge_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_target_clocks_no_replace BEFORE INSERT ON authority_target_clocks
WHEN EXISTS(SELECT 1 FROM authority_target_clocks WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_target_clocks_row_identity BEFORE UPDATE ON authority_target_clocks
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.target_id IS NOT OLD.target_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_target_clocks_no_delete BEFORE DELETE ON authority_target_clocks
BEGIN SELECT RAISE(ABORT,'retained authority record'); END;

CREATE TRIGGER authority_target_key_revocations_no_replace BEFORE INSERT ON authority_target_key_revocations
WHEN EXISTS(SELECT 1 FROM authority_target_key_revocations WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND key_fingerprint=NEW.key_fingerprint))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_target_key_revocations_row_identity BEFORE UPDATE ON authority_target_key_revocations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.key_fingerprint IS NOT OLD.key_fingerprint
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_target_keys_no_replace BEFORE INSERT ON authority_target_keys
WHEN EXISTS(SELECT 1 FROM authority_target_keys WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND key_fingerprint=NEW.key_fingerprint))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_target_keys_row_identity BEFORE UPDATE ON authority_target_keys
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.key_fingerprint IS NOT OLD.key_fingerprint
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_target_metadata_no_replace BEFORE INSERT ON authority_target_metadata
WHEN EXISTS(SELECT 1 FROM authority_target_metadata WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id AND sequence=NEW.sequence) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND challenge_id=NEW.challenge_id) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND receipt_id=NEW.receipt_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_target_metadata_row_identity BEFORE UPDATE ON authority_target_metadata
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.receipt_id IS NOT OLD.receipt_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_target_metadata_heads_no_replace BEFORE INSERT ON authority_target_metadata_heads
WHEN EXISTS(SELECT 1 FROM authority_target_metadata_heads WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_target_metadata_heads_row_identity BEFORE UPDATE ON authority_target_metadata_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.target_id IS NOT OLD.target_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_target_metadata_heads_no_delete BEFORE DELETE ON authority_target_metadata_heads
BEGIN SELECT RAISE(ABORT,'retained authority record'); END;

CREATE TRIGGER authority_target_pin_heads_no_replace BEFORE INSERT ON authority_target_pin_heads
WHEN EXISTS(SELECT 1 FROM authority_target_pin_heads WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_target_pin_heads_row_identity BEFORE UPDATE ON authority_target_pin_heads
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.target_id IS NOT OLD.target_id
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

CREATE TRIGGER authority_target_pin_heads_no_delete BEFORE DELETE ON authority_target_pin_heads
BEGIN SELECT RAISE(ABORT,'retained authority record'); END;

CREATE TRIGGER authority_target_pins_no_replace BEFORE INSERT ON authority_target_pins
WHEN EXISTS(SELECT 1 FROM authority_target_pins WHERE (rowid=NEW.rowid) OR (org_id=NEW.org_id AND certificate_fingerprint=NEW.certificate_fingerprint) OR (org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id AND revision=NEW.revision))
BEGIN SELECT RAISE(ABORT,'retained authority identity collision'); END;

CREATE TRIGGER authority_target_pins_row_identity BEFORE UPDATE ON authority_target_pins
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.target_id IS NOT OLD.target_id OR NEW.revision IS NOT OLD.revision
BEGIN SELECT RAISE(ABORT,'immutable authority row identity'); END;

-- The genesis head is empty; subsequent heads advance exactly one unsigned
-- big-endian sequence and identify the retained event linked to the old head.
CREATE TRIGGER authority_audit_heads_genesis BEFORE INSERT ON authority_audit_heads
WHEN (NEW.sequence=x'0000000000000000' AND NEW.event_hash=zeroblob(32)
 AND NOT EXISTS(SELECT 1 FROM authority_audit WHERE org_id=NEW.org_id AND project_id=NEW.project_id)) IS NOT 1
BEGIN SELECT RAISE(ABORT,'invalid authority audit genesis'); END;
CREATE TRIGGER authority_audit_heads_advance BEFORE UPDATE ON authority_audit_heads
WHEN (((substr(hex(NEW.sequence),1,0)=substr(hex(OLD.sequence),1,0) AND substr(hex(OLD.sequence),1,1)!='F' AND substr(hex(NEW.sequence),1,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),1,1)),1) AND substr(hex(OLD.sequence),2)='FFFFFFFFFFFFFFF' AND substr(hex(NEW.sequence),2)='000000000000000') OR (substr(hex(NEW.sequence),1,1)=substr(hex(OLD.sequence),1,1) AND substr(hex(OLD.sequence),2,1)!='F' AND substr(hex(NEW.sequence),2,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),2,1)),1) AND substr(hex(OLD.sequence),3)='FFFFFFFFFFFFFF' AND substr(hex(NEW.sequence),3)='00000000000000') OR (substr(hex(NEW.sequence),1,2)=substr(hex(OLD.sequence),1,2) AND substr(hex(OLD.sequence),3,1)!='F' AND substr(hex(NEW.sequence),3,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),3,1)),1) AND substr(hex(OLD.sequence),4)='FFFFFFFFFFFFF' AND substr(hex(NEW.sequence),4)='0000000000000') OR (substr(hex(NEW.sequence),1,3)=substr(hex(OLD.sequence),1,3) AND substr(hex(OLD.sequence),4,1)!='F' AND substr(hex(NEW.sequence),4,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),4,1)),1) AND substr(hex(OLD.sequence),5)='FFFFFFFFFFFF' AND substr(hex(NEW.sequence),5)='000000000000') OR (substr(hex(NEW.sequence),1,4)=substr(hex(OLD.sequence),1,4) AND substr(hex(OLD.sequence),5,1)!='F' AND substr(hex(NEW.sequence),5,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),5,1)),1) AND substr(hex(OLD.sequence),6)='FFFFFFFFFFF' AND substr(hex(NEW.sequence),6)='00000000000') OR (substr(hex(NEW.sequence),1,5)=substr(hex(OLD.sequence),1,5) AND substr(hex(OLD.sequence),6,1)!='F' AND substr(hex(NEW.sequence),6,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),6,1)),1) AND substr(hex(OLD.sequence),7)='FFFFFFFFFF' AND substr(hex(NEW.sequence),7)='0000000000') OR (substr(hex(NEW.sequence),1,6)=substr(hex(OLD.sequence),1,6) AND substr(hex(OLD.sequence),7,1)!='F' AND substr(hex(NEW.sequence),7,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),7,1)),1) AND substr(hex(OLD.sequence),8)='FFFFFFFFF' AND substr(hex(NEW.sequence),8)='000000000') OR (substr(hex(NEW.sequence),1,7)=substr(hex(OLD.sequence),1,7) AND substr(hex(OLD.sequence),8,1)!='F' AND substr(hex(NEW.sequence),8,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),8,1)),1) AND substr(hex(OLD.sequence),9)='FFFFFFFF' AND substr(hex(NEW.sequence),9)='00000000') OR (substr(hex(NEW.sequence),1,8)=substr(hex(OLD.sequence),1,8) AND substr(hex(OLD.sequence),9,1)!='F' AND substr(hex(NEW.sequence),9,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),9,1)),1) AND substr(hex(OLD.sequence),10)='FFFFFFF' AND substr(hex(NEW.sequence),10)='0000000') OR (substr(hex(NEW.sequence),1,9)=substr(hex(OLD.sequence),1,9) AND substr(hex(OLD.sequence),10,1)!='F' AND substr(hex(NEW.sequence),10,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),10,1)),1) AND substr(hex(OLD.sequence),11)='FFFFFF' AND substr(hex(NEW.sequence),11)='000000') OR (substr(hex(NEW.sequence),1,10)=substr(hex(OLD.sequence),1,10) AND substr(hex(OLD.sequence),11,1)!='F' AND substr(hex(NEW.sequence),11,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),11,1)),1) AND substr(hex(OLD.sequence),12)='FFFFF' AND substr(hex(NEW.sequence),12)='00000') OR (substr(hex(NEW.sequence),1,11)=substr(hex(OLD.sequence),1,11) AND substr(hex(OLD.sequence),12,1)!='F' AND substr(hex(NEW.sequence),12,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),12,1)),1) AND substr(hex(OLD.sequence),13)='FFFF' AND substr(hex(NEW.sequence),13)='0000') OR (substr(hex(NEW.sequence),1,12)=substr(hex(OLD.sequence),1,12) AND substr(hex(OLD.sequence),13,1)!='F' AND substr(hex(NEW.sequence),13,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),13,1)),1) AND substr(hex(OLD.sequence),14)='FFF' AND substr(hex(NEW.sequence),14)='000') OR (substr(hex(NEW.sequence),1,13)=substr(hex(OLD.sequence),1,13) AND substr(hex(OLD.sequence),14,1)!='F' AND substr(hex(NEW.sequence),14,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),14,1)),1) AND substr(hex(OLD.sequence),15)='FF' AND substr(hex(NEW.sequence),15)='00') OR (substr(hex(NEW.sequence),1,14)=substr(hex(OLD.sequence),1,14) AND substr(hex(OLD.sequence),15,1)!='F' AND substr(hex(NEW.sequence),15,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),15,1)),1) AND substr(hex(OLD.sequence),16)='F' AND substr(hex(NEW.sequence),16)='0') OR (substr(hex(NEW.sequence),1,15)=substr(hex(OLD.sequence),1,15) AND substr(hex(OLD.sequence),16,1)!='F' AND substr(hex(NEW.sequence),16,1)=substr('123456789ABCDEF',instr('0123456789ABCDEF',substr(hex(OLD.sequence),16,1)),1) AND substr(hex(OLD.sequence),17)='' AND substr(hex(NEW.sequence),17)='')) AND EXISTS(
 SELECT 1 FROM authority_audit a WHERE a.org_id=OLD.org_id AND a.project_id=OLD.project_id
 AND a.sequence=NEW.sequence AND a.event_hash=NEW.event_hash AND a.previous_hash=OLD.event_hash)
 AND NOT EXISTS(SELECT 1 FROM authority_audit a WHERE a.org_id=OLD.org_id AND a.project_id=OLD.project_id AND a.sequence>NEW.sequence)) IS NOT 1
BEGIN SELECT RAISE(ABORT,'invalid authority audit head advance'); END;

-- Indexed reservation witnesses keep live obligation checks independent of lifetime history.
CREATE INDEX authority_signing_reservation_intent_lookup ON authority_signing_intents(org_id,project_id,reservation_id);

CREATE TABLE authority_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_identity TEXT NOT NULL CHECK(schema_identity = 'fw.authority-store/v1')
) STRICT;
INSERT INTO authority_metadata VALUES(1, 'fw.authority-store/v1');
CREATE TABLE authority_projects (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL,
    security_revision INTEGER NOT NULL CHECK(security_revision BETWEEN 1 AND 2147483647),
    PRIMARY KEY(org_id, project_id)
) STRICT;
CREATE TABLE authority_principals (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, principal_id TEXT NOT NULL,
    issuer TEXT NOT NULL, subject TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at >= 0),
    PRIMARY KEY(org_id, project_id, principal_id),
    UNIQUE(org_id, project_id, issuer, subject),
    FOREIGN KEY(org_id, project_id) REFERENCES authority_projects
) STRICT;
CREATE TABLE authority_credentials (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, credential_id TEXT NOT NULL,
    principal_id TEXT NOT NULL, key_fingerprint BLOB NOT NULL CHECK(length(key_fingerprint) = 32),
    credential_bytes BLOB NOT NULL CHECK(length(credential_bytes) BETWEEN 1 AND 65536),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
    state TEXT NOT NULL CHECK(state IN ('pending','active','revoked')),
    not_before INTEGER NOT NULL CHECK(not_before >= 0), not_after INTEGER NOT NULL CHECK(not_after > not_before),
    pinned_at INTEGER NOT NULL CHECK(pinned_at >= 0), activated_at INTEGER, revoked_at INTEGER,
    PRIMARY KEY(org_id, project_id, credential_id),
    FOREIGN KEY(org_id, project_id, principal_id) REFERENCES authority_principals,
    CHECK((state = 'pending' AND activated_at IS NULL AND revoked_at IS NULL)
       OR (state = 'active' AND activated_at IS NOT NULL AND revoked_at IS NULL)
       OR (state = 'revoked' AND revoked_at IS NOT NULL))
) STRICT;
CREATE TABLE authority_activations (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, activation_id TEXT NOT NULL,
    credential_id TEXT NOT NULL, credential_revision INTEGER NOT NULL,
    state_bytes BLOB NOT NULL CHECK(length(state_bytes) BETWEEN 1 AND 262144),
    issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 10), consumed_at INTEGER,
    PRIMARY KEY(org_id, project_id, activation_id),
    FOREIGN KEY(org_id, project_id, credential_id) REFERENCES authority_credentials
) STRICT;
CREATE TABLE authority_roles (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, membership_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner','network_reviewer','service_reviewer','security_reviewer')),
    not_before INTEGER NOT NULL CHECK(not_before >= 0), not_after INTEGER NOT NULL CHECK(not_after > not_before),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
    granted_at INTEGER NOT NULL CHECK(granted_at >= 0), revoked_at INTEGER,
    PRIMARY KEY(org_id, project_id, membership_id),
    FOREIGN KEY(org_id, project_id, principal_id) REFERENCES authority_principals
) STRICT;
CREATE UNIQUE INDEX authority_current_roles ON authority_roles(org_id,project_id,principal_id,role) WHERE revoked_at IS NULL;
CREATE TABLE authority_requirements (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL,
    requirements_hash BLOB NOT NULL CHECK(length(requirements_hash) = 32),
    profile TEXT NOT NULL CHECK(profile IN ('lab_owner','team_dual','team_high_risk')),
    max_age INTEGER NOT NULL CHECK(max_age BETWEEN 60 AND 86400),
    author_may_approve INTEGER NOT NULL CHECK(author_may_approve IN (0,1)),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 16384),
    PRIMARY KEY(org_id, project_id, requirements_hash),
    FOREIGN KEY(org_id, project_id) REFERENCES authority_projects
) STRICT;
CREATE TABLE authority_requirement_roles (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, requirements_hash BLOB NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner','network_reviewer','service_reviewer','security_reviewer')),
    PRIMARY KEY(org_id, project_id, requirements_hash, role),
    FOREIGN KEY(org_id, project_id, requirements_hash) REFERENCES authority_requirements
) STRICT;
CREATE TABLE authority_plans (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, plan_id TEXT NOT NULL,
    plan_kind TEXT NOT NULL CHECK(plan_kind IN ('add_access_lease','policy_change')),
    plan_hash BLOB NOT NULL CHECK(length(plan_hash) = 32),
    requirements_hash BLOB NOT NULL CHECK(length(requirements_hash) = 32),
    author_id TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK(created_at >= 0), valid_until INTEGER NOT NULL CHECK(valid_until > created_at),
    registered_at INTEGER NOT NULL CHECK(registered_at >= created_at),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 262144),
    PRIMARY KEY(org_id, project_id, plan_id), UNIQUE(org_id, project_id, plan_hash),
    FOREIGN KEY(org_id, project_id, requirements_hash) REFERENCES authority_requirements
) STRICT;
CREATE TABLE authority_plan_retirements (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, plan_id TEXT NOT NULL, retired_at INTEGER NOT NULL,
    PRIMARY KEY(org_id, project_id, plan_id),
    FOREIGN KEY(org_id, project_id, plan_id) REFERENCES authority_plans
) STRICT;
CREATE TABLE authority_challenges (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, challenge_id TEXT NOT NULL,
    principal_id TEXT NOT NULL, plan_id TEXT NOT NULL, credential_id TEXT NOT NULL, membership_id TEXT NOT NULL,
    role_revision INTEGER NOT NULL, credential_revision INTEGER NOT NULL, security_revision INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner','network_reviewer','service_reviewer','security_reviewer')),
    decision TEXT NOT NULL CHECK(decision IN ('approve','reject')),
    challenge_hash BLOB NOT NULL CHECK(length(challenge_hash) = 32),
    nonce_hash BLOB NOT NULL CHECK(length(nonce_hash) = 32),
    payload_hash BLOB NOT NULL CHECK(length(payload_hash) = 32),
    payload_bytes BLOB NOT NULL CHECK(length(payload_bytes) BETWEEN 1 AND 8192),
    state_bytes BLOB NOT NULL CHECK(length(state_bytes) BETWEEN 1 AND 262144),
    credential_bytes BLOB NOT NULL CHECK(length(credential_bytes) BETWEEN 1 AND 65536),
    issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 10), consumed_at INTEGER,
    PRIMARY KEY(org_id, project_id, challenge_id),
    UNIQUE(challenge_hash), UNIQUE(nonce_hash),
    FOREIGN KEY(org_id, project_id, principal_id) REFERENCES authority_principals,
    FOREIGN KEY(org_id, project_id, plan_id) REFERENCES authority_plans,
    FOREIGN KEY(org_id, project_id, credential_id) REFERENCES authority_credentials,
    FOREIGN KEY(org_id, project_id, membership_id) REFERENCES authority_roles
) STRICT;
CREATE TABLE authority_evidence (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL,
    evidence_hash BLOB NOT NULL CHECK(length(evidence_hash) = 32),
    challenge_id TEXT NOT NULL, credential_id TEXT NOT NULL, membership_id TEXT NOT NULL,
    pre_credential_bytes BLOB NOT NULL, post_credential_bytes BLOB NOT NULL,
    assertion_bytes BLOB NOT NULL CHECK(length(assertion_bytes) BETWEEN 1 AND 65536),
    proof_state_bytes BLOB NOT NULL, credential_registry_bytes BLOB NOT NULL, role_membership_bytes BLOB NOT NULL,
    admitted_at INTEGER NOT NULL,
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 262144),
    PRIMARY KEY(org_id, project_id, evidence_hash), UNIQUE(org_id,project_id,challenge_id),
    FOREIGN KEY(org_id,project_id,challenge_id) REFERENCES authority_challenges,
    FOREIGN KEY(org_id,project_id,credential_id) REFERENCES authority_credentials,
    FOREIGN KEY(org_id,project_id,membership_id) REFERENCES authority_roles
) STRICT;
CREATE TABLE authority_decisions (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL, approval_id TEXT NOT NULL,
    principal_id TEXT NOT NULL, challenge_id TEXT NOT NULL, plan_id TEXT NOT NULL,
    credential_id TEXT NOT NULL, membership_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('approve','reject')),
    idempotency_key TEXT NOT NULL, request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
    evidence_hash BLOB NOT NULL CHECK(length(evidence_hash)=32),
    content_hash BLOB NOT NULL CHECK(length(content_hash)=32),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 16384),
    PRIMARY KEY(org_id,project_id,approval_id), UNIQUE(org_id,project_id,challenge_id),
    UNIQUE(org_id,project_id,principal_id,idempotency_key),
    FOREIGN KEY(org_id,project_id,principal_id) REFERENCES authority_principals,
    FOREIGN KEY(org_id,project_id,challenge_id) REFERENCES authority_challenges,
    FOREIGN KEY(org_id,project_id,plan_id) REFERENCES authority_plans,
    FOREIGN KEY(org_id,project_id,evidence_hash) REFERENCES authority_evidence
) STRICT;
CREATE TABLE authority_audit_heads (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL,
    sequence BLOB NOT NULL CHECK(length(sequence)=8), event_hash BLOB NOT NULL CHECK(length(event_hash)=32),
    PRIMARY KEY(org_id,project_id),
    FOREIGN KEY(org_id,project_id) REFERENCES authority_projects
) STRICT;
CREATE TABLE authority_audit (
    org_id TEXT NOT NULL, project_id TEXT NOT NULL,
    sequence BLOB NOT NULL CHECK(length(sequence)=8),
    event_hash BLOB NOT NULL CHECK(length(event_hash)=32), previous_hash BLOB NOT NULL CHECK(length(previous_hash)=32),
    kind TEXT NOT NULL, resource_id TEXT NOT NULL, recorded_at INTEGER NOT NULL CHECK(recorded_at>=0),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 16384),
    PRIMARY KEY(org_id,project_id,sequence), UNIQUE(org_id,project_id,event_hash),
    FOREIGN KEY(org_id,project_id) REFERENCES authority_projects
) STRICT;
CREATE TRIGGER authority_credential_identity_immutable BEFORE UPDATE ON authority_credentials
WHEN NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.credential_id!=OLD.credential_id
 OR NEW.principal_id!=OLD.principal_id OR NEW.key_fingerprint!=OLD.key_fingerprint
 OR NEW.not_before!=OLD.not_before OR NEW.not_after!=OLD.not_after OR NEW.pinned_at!=OLD.pinned_at
 OR OLD.state='revoked' OR NEW.revision!=OLD.revision+1 OR NEW.state='pending'
 OR (OLD.state='active' AND NEW.activated_at IS NOT OLD.activated_at)
 OR (OLD.state='pending' AND NEW.state='active' AND (NEW.activated_at IS NULL OR NEW.activated_at<OLD.pinned_at))
 OR (NEW.state='revoked' AND (NEW.credential_bytes!=OLD.credential_bytes OR NEW.activated_at IS NOT OLD.activated_at OR NEW.revoked_at<OLD.pinned_at))
BEGIN SELECT RAISE(ABORT,'immutable credential identity'); END;
CREATE TRIGGER authority_role_identity_immutable BEFORE UPDATE ON authority_roles
WHEN NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.membership_id!=OLD.membership_id
 OR NEW.principal_id!=OLD.principal_id OR NEW.role!=OLD.role OR NEW.not_before!=OLD.not_before
 OR NEW.not_after!=OLD.not_after OR NEW.granted_at!=OLD.granted_at OR OLD.revoked_at IS NOT NULL
 OR NEW.revoked_at IS NULL OR NEW.revoked_at<OLD.granted_at OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'immutable role identity'); END;
CREATE TRIGGER authority_challenge_transition BEFORE UPDATE ON authority_challenges
WHEN NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.challenge_id IS NOT OLD.challenge_id
 OR NEW.principal_id IS NOT OLD.principal_id OR NEW.plan_id IS NOT OLD.plan_id OR NEW.credential_id IS NOT OLD.credential_id
 OR NEW.membership_id IS NOT OLD.membership_id OR NEW.role_revision IS NOT OLD.role_revision OR NEW.credential_revision IS NOT OLD.credential_revision
 OR NEW.security_revision IS NOT OLD.security_revision OR NEW.role IS NOT OLD.role OR NEW.decision IS NOT OLD.decision
 OR NEW.challenge_hash IS NOT OLD.challenge_hash OR NEW.nonce_hash IS NOT OLD.nonce_hash OR NEW.payload_hash IS NOT OLD.payload_hash
 OR NEW.payload_bytes IS NOT OLD.payload_bytes OR NEW.state_bytes IS NOT OLD.state_bytes OR NEW.credential_bytes IS NOT OLD.credential_bytes
 OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at OR OLD.consumed_at IS NOT NULL
 OR NOT ((NEW.attempts=OLD.attempts+1 AND NEW.consumed_at IS NULL)
      OR (NEW.attempts=OLD.attempts AND OLD.attempts<10 AND NEW.consumed_at IS NOT NULL AND NEW.consumed_at>=OLD.issued_at AND NEW.consumed_at<OLD.expires_at))
BEGIN SELECT RAISE(ABORT,'immutable challenge or invalid transition'); END;
CREATE TRIGGER authority_activation_transition BEFORE UPDATE ON authority_activations
WHEN NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.activation_id IS NOT OLD.activation_id
 OR NEW.credential_id IS NOT OLD.credential_id OR NEW.credential_revision IS NOT OLD.credential_revision
 OR NEW.state_bytes IS NOT OLD.state_bytes OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at
 OR OLD.consumed_at IS NOT NULL
 OR NOT ((NEW.attempts=OLD.attempts+1 AND NEW.consumed_at IS NULL)
      OR (NEW.attempts=OLD.attempts AND OLD.attempts<10 AND NEW.consumed_at IS NOT NULL AND NEW.consumed_at>=OLD.issued_at AND NEW.consumed_at<OLD.expires_at))
BEGIN SELECT RAISE(ABORT,'immutable activation or invalid transition'); END;
CREATE TRIGGER authority_security_revision_monotonic BEFORE UPDATE ON authority_projects
WHEN NEW.org_id IS NOT OLD.org_id OR NEW.project_id IS NOT OLD.project_id OR NEW.security_revision!=OLD.security_revision+1
BEGIN SELECT RAISE(ABORT,'authority revision must increase'); END;

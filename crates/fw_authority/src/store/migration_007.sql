-- Signing coordination mechanics only. Migration creates no protected signer,
-- production qualification, target generation or quota authority.
CREATE TABLE authority_signing_target_heads (
 org_id TEXT NOT NULL,project_id TEXT NOT NULL,target_id TEXT NOT NULL,
 epoch BLOB NOT NULL CHECK(length(epoch)=8),generation BLOB NOT NULL CHECK(length(generation)=8),
 last_intent_id TEXT,updated_at INTEGER NOT NULL,
 PRIMARY KEY(org_id,project_id,target_id),
 FOREIGN KEY(org_id,project_id) REFERENCES authority_projects,
 FOREIGN KEY(org_id,project_id,last_intent_id) REFERENCES authority_signing_intents
) STRICT;
CREATE TABLE authority_signing_intents (
 org_id TEXT NOT NULL,project_id TEXT NOT NULL,intent_id TEXT NOT NULL,request_id TEXT NOT NULL,
 target_id TEXT NOT NULL,plan_id TEXT NOT NULL,
 plan_hash BLOB NOT NULL CHECK(length(plan_hash)=32),
 approval_set_hash BLOB NOT NULL CHECK(length(approval_set_hash)=32),
 inputs_hash BLOB NOT NULL CHECK(length(inputs_hash)=32),
 epoch BLOB NOT NULL CHECK(length(epoch)=8),generation BLOB NOT NULL CHECK(length(generation)=8),
 reservation_id TEXT NOT NULL,job_id TEXT NOT NULL,
 created_at INTEGER NOT NULL,valid_until INTEGER NOT NULL CHECK(valid_until>created_at AND valid_until-created_at<=300),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 131072),
 PRIMARY KEY(org_id,project_id,intent_id),
 UNIQUE(org_id,project_id,request_id),
 UNIQUE(org_id,project_id,target_id,epoch,generation),
 FOREIGN KEY(org_id,project_id,plan_id) REFERENCES authority_plans,
 FOREIGN KEY(org_id,project_id,reservation_id) REFERENCES authority_signing_quota_reservations
) STRICT;
CREATE INDEX authority_signing_plan_history ON authority_signing_intents(org_id,project_id,plan_id,created_at DESC,intent_id DESC);
CREATE TABLE authority_signing_jobs (
 org_id TEXT NOT NULL,project_id TEXT NOT NULL,job_id TEXT NOT NULL,intent_id TEXT NOT NULL,
 payload_hash BLOB NOT NULL CHECK(length(payload_hash)=32),
 created_at INTEGER NOT NULL,deadline INTEGER NOT NULL,
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 131072),
 PRIMARY KEY(org_id,project_id,job_id),UNIQUE(org_id,project_id,intent_id),
 FOREIGN KEY(org_id,project_id,intent_id) REFERENCES authority_signing_intents
) STRICT;
CREATE TABLE authority_signing_results (
 org_id TEXT NOT NULL,project_id TEXT NOT NULL,intent_id TEXT NOT NULL,
 grant_hash BLOB NOT NULL CHECK(length(grant_hash)=32),result_hash BLOB NOT NULL CHECK(length(result_hash)=32),
 finalized_at INTEGER NOT NULL,
 grant_bytes BLOB NOT NULL CHECK(length(grant_bytes) BETWEEN 1 AND 262144),
 result_bytes BLOB NOT NULL CHECK(length(result_bytes) BETWEEN 1 AND 262144),
 PRIMARY KEY(org_id,project_id,intent_id),
 FOREIGN KEY(org_id,project_id,intent_id) REFERENCES authority_signing_intents
) STRICT;
CREATE TRIGGER authority_signing_intents_no_update BEFORE UPDATE ON authority_signing_intents BEGIN SELECT RAISE(ABORT,'immutable signing intent'); END;
CREATE TRIGGER authority_signing_intents_no_delete BEFORE DELETE ON authority_signing_intents BEGIN SELECT RAISE(ABORT,'retained signing intent'); END;
CREATE TRIGGER authority_signing_jobs_no_update BEFORE UPDATE ON authority_signing_jobs BEGIN SELECT RAISE(ABORT,'immutable signing job'); END;
CREATE TRIGGER authority_signing_jobs_no_delete BEFORE DELETE ON authority_signing_jobs BEGIN SELECT RAISE(ABORT,'retained signing job'); END;
CREATE TRIGGER authority_signing_results_no_update BEFORE UPDATE ON authority_signing_results BEGIN SELECT RAISE(ABORT,'immutable signing result'); END;
CREATE TRIGGER authority_signing_results_no_delete BEFORE DELETE ON authority_signing_results BEGIN SELECT RAISE(ABORT,'retained signing result'); END;
CREATE TABLE authority_signing_quota_pins (
 org_id TEXT NOT NULL, bucket_kind TEXT NOT NULL CHECK(bucket_kind IN ('root','project')),
 bucket_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
 root_id TEXT NOT NULL, pinned_at INTEGER NOT NULL CHECK(pinned_at>=0),
 pin_hash BLOB NOT NULL CHECK(length(pin_hash)=32),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 32768),
 PRIMARY KEY(org_id,bucket_kind,bucket_id,revision)
) STRICT;
CREATE TABLE authority_signing_quota_heads (
 org_id TEXT NOT NULL, bucket_kind TEXT NOT NULL, bucket_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 PRIMARY KEY(org_id,bucket_kind,bucket_id),
 FOREIGN KEY(org_id,bucket_kind,bucket_id,revision) REFERENCES authority_signing_quota_pins
) STRICT;
CREATE TABLE authority_signing_quota_revocations (
 org_id TEXT NOT NULL, bucket_kind TEXT NOT NULL, bucket_id TEXT NOT NULL,
 revision INTEGER NOT NULL, revoked_at INTEGER NOT NULL CHECK(revoked_at>=0),
 PRIMARY KEY(org_id,bucket_kind,bucket_id,revision),
 FOREIGN KEY(org_id,bucket_kind,bucket_id,revision) REFERENCES authority_signing_quota_pins
) STRICT;
CREATE TABLE authority_signing_quota_clocks (
 org_id TEXT NOT NULL, bucket_kind TEXT NOT NULL CHECK(bucket_kind IN ('root','project')),
 bucket_id TEXT NOT NULL, observed_at INTEGER NOT NULL CHECK(observed_at>=0),
 PRIMARY KEY(org_id,bucket_kind,bucket_id)
) STRICT;
CREATE TABLE authority_signing_quota_reservations (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, reservation_id TEXT NOT NULL,
 root_id TEXT NOT NULL, plan_id TEXT NOT NULL,
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
 CHECK(state!='released' OR (active_slots=0 AND dispatch_slots=0))
) STRICT;
CREATE UNIQUE INDEX authority_signing_quota_lease_identity
 ON authority_signing_quota_reservations(org_id,lease_id) WHERE lease_id IS NOT NULL;
CREATE INDEX authority_signing_quota_root_accounting
 ON authority_signing_quota_reservations(org_id,root_id,issued_at)
 WHERE state='released' AND lease_id IS NOT NULL;
CREATE INDEX authority_signing_quota_project_accounting
 ON authority_signing_quota_reservations(org_id,project_id,issued_at)
 WHERE state='released' AND lease_id IS NOT NULL;
CREATE INDEX authority_signing_quota_root_held
 ON authority_signing_quota_reservations(org_id,root_id)
 WHERE state IN ('reserved','issued','unknown') OR (state='active' AND lease_id IS NOT NULL);
CREATE INDEX authority_signing_quota_project_held
 ON authority_signing_quota_reservations(org_id,project_id)
 WHERE state IN ('reserved','issued','unknown') OR (state='active' AND lease_id IS NOT NULL);
CREATE TABLE authority_signing_quota_destinations (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, reservation_id TEXT NOT NULL,
 asset_id TEXT NOT NULL,
 PRIMARY KEY(org_id,project_id,reservation_id,asset_id),
 FOREIGN KEY(org_id,project_id,reservation_id) REFERENCES authority_signing_quota_reservations
) STRICT;
CREATE TABLE authority_signing_quota_usage (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, reservation_id TEXT NOT NULL,
 charged_at INTEGER NOT NULL CHECK(charged_at>=0),
 cost_hash BLOB NOT NULL CHECK(length(cost_hash)=32),
 PRIMARY KEY(org_id,project_id,reservation_id),
 FOREIGN KEY(org_id,project_id,reservation_id) REFERENCES authority_signing_quota_reservations
) STRICT;
CREATE INDEX authority_signing_quota_usage_window
 ON authority_signing_quota_usage(org_id,charged_at);
CREATE TRIGGER authority_signing_quota_pins_no_update BEFORE UPDATE ON authority_signing_quota_pins BEGIN SELECT RAISE(ABORT,'immutable quota pin'); END;
CREATE TRIGGER authority_signing_quota_pins_no_delete BEFORE DELETE ON authority_signing_quota_pins BEGIN SELECT RAISE(ABORT,'immutable quota pin'); END;
CREATE TRIGGER authority_signing_quota_revocations_no_update BEFORE UPDATE ON authority_signing_quota_revocations BEGIN SELECT RAISE(ABORT,'immutable quota revocation'); END;
CREATE TRIGGER authority_signing_quota_revocations_no_delete BEFORE DELETE ON authority_signing_quota_revocations BEGIN SELECT RAISE(ABORT,'immutable quota revocation'); END;
CREATE TRIGGER authority_signing_quota_destinations_no_update BEFORE UPDATE ON authority_signing_quota_destinations BEGIN SELECT RAISE(ABORT,'immutable quota destination'); END;
CREATE TRIGGER authority_signing_quota_destinations_no_delete BEFORE DELETE ON authority_signing_quota_destinations BEGIN SELECT RAISE(ABORT,'immutable quota destination'); END;
CREATE TRIGGER authority_signing_quota_usage_no_update BEFORE UPDATE ON authority_signing_quota_usage BEGIN SELECT RAISE(ABORT,'immutable quota usage'); END;
CREATE TRIGGER authority_signing_quota_usage_no_delete BEFORE DELETE ON authority_signing_quota_usage BEGIN SELECT RAISE(ABORT,'immutable quota usage'); END;
CREATE TRIGGER authority_signing_quota_reservations_no_delete BEFORE DELETE ON authority_signing_quota_reservations BEGIN SELECT RAISE(ABORT,'retained quota reservation'); END;
CREATE TRIGGER authority_signing_quota_reservations_immutable
 BEFORE UPDATE OF org_id,project_id,reservation_id,root_id,plan_id,plan_hash,lease_id,lease_seconds,cost_hash,cost_bytes,snapshot_bytes,reserved_at,reserved_until ON authority_signing_quota_reservations
 BEGIN SELECT RAISE(ABORT,'immutable quota reservation inputs'); END;
CREATE TRIGGER authority_signing_quota_reservations_issuance
 BEFORE UPDATE OF issued_at ON authority_signing_quota_reservations
 WHEN OLD.issued_at IS NOT NULL OR NEW.issued_at IS NULL
 BEGIN SELECT RAISE(ABORT,'immutable quota issuance time'); END;
CREATE TRIGGER authority_signing_quota_clocks_no_delete BEFORE DELETE ON authority_signing_quota_clocks BEGIN SELECT RAISE(ABORT,'retained quota clock'); END;
CREATE TRIGGER authority_signing_quota_clocks_monotonic
 BEFORE UPDATE ON authority_signing_quota_clocks
 WHEN NEW.org_id!=OLD.org_id OR NEW.bucket_kind!=OLD.bucket_kind OR NEW.bucket_id!=OLD.bucket_id OR NEW.observed_at<OLD.observed_at
 BEGIN SELECT RAISE(ABORT,'monotonic quota clock'); END;
CREATE TABLE authority_signing_work_heads (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, job_id TEXT NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('signer','dispatch')),
 state TEXT NOT NULL,
 revision BLOB NOT NULL CHECK(length(revision)=8),
 claim_generation BLOB NOT NULL CHECK(length(claim_generation)=8),
 claim_hash BLOB CHECK(claim_hash IS NULL OR length(claim_hash)=32),
 worker_id TEXT, claim_until INTEGER,
 attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 5),
 available_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 PRIMARY KEY(org_id,project_id,job_id,phase),
 FOREIGN KEY(org_id,project_id,job_id) REFERENCES authority_signing_jobs,
 CHECK((phase='signer' AND state IN ('prepared','claimed','ready','cancelled')) OR
       (phase='dispatch' AND state IN ('queued','claimed','unknown','delivered'))),
 CHECK((state='claimed' AND claim_hash IS NOT NULL AND worker_id IS NOT NULL AND claim_until IS NOT NULL)
    OR (state!='claimed' AND claim_hash IS NULL AND worker_id IS NULL AND claim_until IS NULL))
) STRICT;
CREATE TABLE authority_signing_work_events (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, job_id TEXT NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('signer','dispatch')),
 state TEXT NOT NULL, revision BLOB NOT NULL CHECK(length(revision)=8),
 claim_generation BLOB NOT NULL CHECK(length(claim_generation)=8),
 claim_hash BLOB CHECK(claim_hash IS NULL OR length(claim_hash)=32),
 worker_id TEXT, claim_until INTEGER,
 attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 5),
 available_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('created','claimed','renewed','retried','cancelled','finalized','unknown','delivered')),
 PRIMARY KEY(org_id,project_id,job_id,phase,revision),
 FOREIGN KEY(org_id,project_id,job_id) REFERENCES authority_signing_jobs
) STRICT;
CREATE TABLE authority_signing_outbox (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, job_id TEXT NOT NULL,
 intent_id TEXT NOT NULL, grant_hash BLOB NOT NULL CHECK(length(grant_hash)=32),
 grant_bytes BLOB NOT NULL CHECK(length(grant_bytes) BETWEEN 1 AND 262144),
 created_at INTEGER NOT NULL,
 PRIMARY KEY(org_id,project_id,job_id),
 UNIQUE(org_id,project_id,intent_id),
 FOREIGN KEY(org_id,project_id,job_id) REFERENCES authority_signing_jobs,
 FOREIGN KEY(org_id,project_id,intent_id) REFERENCES authority_signing_results
) STRICT;
CREATE TABLE authority_signing_deliveries (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, job_id TEXT NOT NULL,
 grant_hash BLOB NOT NULL CHECK(length(grant_hash)=32),
 result_hash BLOB NOT NULL CHECK(length(result_hash)=32),
 result_bytes BLOB NOT NULL CHECK(length(result_bytes) BETWEEN 1 AND 262144),
 recorded_at INTEGER NOT NULL,
 PRIMARY KEY(org_id,project_id,job_id),
 FOREIGN KEY(org_id,project_id,job_id) REFERENCES authority_signing_outbox
) STRICT;
CREATE TRIGGER authority_signing_work_events_immutable_update BEFORE UPDATE ON authority_signing_work_events BEGIN SELECT RAISE(ABORT,'immutable signing work event'); END;
CREATE TRIGGER authority_signing_work_events_immutable_delete BEFORE DELETE ON authority_signing_work_events BEGIN SELECT RAISE(ABORT,'immutable signing work event'); END;
CREATE TRIGGER authority_signing_outbox_immutable_update BEFORE UPDATE ON authority_signing_outbox BEGIN SELECT RAISE(ABORT,'immutable signing outbox'); END;
CREATE TRIGGER authority_signing_outbox_immutable_delete BEFORE DELETE ON authority_signing_outbox BEGIN SELECT RAISE(ABORT,'immutable signing outbox'); END;
CREATE TRIGGER authority_signing_deliveries_immutable_update BEFORE UPDATE ON authority_signing_deliveries BEGIN SELECT RAISE(ABORT,'immutable signing delivery'); END;
CREATE TRIGGER authority_signing_deliveries_immutable_delete BEFORE DELETE ON authority_signing_deliveries BEGIN SELECT RAISE(ABORT,'immutable signing delivery'); END;

//! Canonical diagnostics resolved in the same transaction as readiness.
//! Accepted target history never becomes a production permission.
use super::*;
use crate::{AuthorityGate as Gate, authority_gate_codes};

pub const SIGNING_READINESS_V3_REQUIRED: &str = "SIGNING_READINESS_V3_REQUIRED";

#[derive(Debug, Serialize)]
pub struct TargetBootstrapReadiness {
    pub state: String,
    pub target_id: String,
    pub confirmation_revision: String,
    pub accepted_epoch: String,
    pub highest_generation: String,
    pub confirmation_hash: String,
    pub observed_at: String,
    pub admitted_at: String,
    pub valid_until: String,
    pub current_confirmation_eligibility: bool,
    pub current_for_plan: bool,
    pub signing_allowed: bool,
    pub dispatch_allowed: bool,
}

#[derive(Debug, Serialize)]
pub struct SigningReadinessV3 {
    #[serde(flatten)]
    pub snapshot: SigningReadinessV2,
    pub bootstrap_authorization_hash: Option<String>,
    pub target_bootstrap: Option<TargetBootstrapReadiness>,
}

#[derive(Default)]
pub(super) struct Context {
    pub bootstrap_authorization_hash: Option<String>,
    pub target_bootstrap: Option<TargetBootstrapReadiness>,
    pub valid_until: Option<i64>,
}

impl AuthorityStore {
    /// Canonical current prerequisites and retained target history. The read
    /// advances existing clocks but creates no reservation, grant or dispatch.
    pub fn signing_readiness_v3(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<SigningReadinessV3> {
        self.observe_registry_time(tenant, now)?;
        let mut context = Context::default();
        let mut snapshot = self.signing_readiness_snapshot_with_context(
            tenant,
            plan_id,
            verifier,
            now,
            Some(&mut context),
        )?;
        snapshot.snapshot.schema_version = "fw.signing-readiness/v3".into();
        Ok(SigningReadinessV3 {
            snapshot,
            bootstrap_authorization_hash: context.bootstrap_authorization_hash,
            target_bootstrap: context.target_bootstrap,
        })
    }
}

pub(super) fn gates_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan: &Value,
    now: i64,
    context: &mut Context,
) -> Result<Vec<String>> {
    let mut gates = authority_gate_codes(&[
        Gate::BuildIdentityRequired,
        Gate::NativeQualificationRequired,
        Gate::PolicySignerKeyRequired,
        Gate::ProtectedSignerUnavailable,
    ]);
    match bootstrap_origin::current_origin(tx, tenant, now) {
        Ok(origin) => context.valid_until = Some(origin.not_after),
        Err(AuthorityError::Binding | AuthorityError::Time) => {
            gates.push(Gate::BootstrapApprovalOriginRequired.code().into());
        }
        Err(error) => return Err(error),
    }
    let authorization = authority_registry::bootstrap_for_plan_in_tx(tx, tenant, plan, now)?;
    if let Some((digest, deadline)) = authorization {
        context.bootstrap_authorization_hash = Some(digest);
        context.valid_until = Some(
            context
                .valid_until
                .map_or(deadline, |end| end.min(deadline)),
        );
    } else {
        gates.push(Gate::BootstrapAuthorizationRequired.code().into());
    }
    let target =
        target_bootstrap::target_status_in_tx(tx, tenant, crate::string(plan, "target_id")?, now)?;
    let current_for_plan = if let Some(status) = &target {
        // The current authorization resolver has already checked the exact
        // plan epoch, review baseline and capabilities. A validated receipt's
        // authorization hash binds those same immutable manifest inputs.
        status.current_confirmation_eligibility
            && status.accepted_epoch == crate::string(plan, "authority_epoch")?
            && context.bootstrap_authorization_hash.as_deref()
                == Some(status.authorization_hash.as_str())
    } else {
        false
    };
    if !current_for_plan {
        gates.push(Gate::TargetEpochConfirmationRequired.code().into());
    }
    if plan["change_kind"] == "add_access_lease" {
        gates.push(Gate::WorkloadSourceAttestationRequired.code().into());
    }
    if let Some(status) = target {
        if current_for_plan {
            let deadline = crate::timestamp(&status.valid_until)?;
            context.valid_until = Some(
                context
                    .valid_until
                    .map_or(deadline, |end| end.min(deadline)),
            );
        }
        context.target_bootstrap = Some(TargetBootstrapReadiness {
            state: status.state,
            target_id: status.target_id,
            confirmation_revision: status.confirmation_revision,
            accepted_epoch: status.accepted_epoch,
            highest_generation: status.highest_generation,
            confirmation_hash: status.confirmation_hash,
            observed_at: status.observed_at,
            admitted_at: status.admitted_at,
            valid_until: status.valid_until,
            current_confirmation_eligibility: status.current_confirmation_eligibility,
            current_for_plan,
            signing_allowed: false,
            dispatch_allowed: false,
        });
    }
    Ok(gates)
}

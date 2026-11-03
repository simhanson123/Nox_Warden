//! Trusted local recovery of the retained project pin after lost command output.
//! This reports the CAS head even when expired or revoked; it grants no current
//! eligibility and deliberately neither observes clocks nor appends an audit.
use super::*;

impl AuthorityStore {
    /// Read the validated retained project quota head within the authenticated
    /// local administrator's tenant. This maintenance read changes no state.
    pub fn read_signing_project_quota(&mut self, tenant: &AuthorityTenant) -> Result<Value> {
        let tx = self.connection.transaction()?;
        security_revision(&tx, tenant)?;
        let pin = signing_quota::project_pin_recovery(&tx, tenant)?;
        let state = json!({
            "schema_version": "fw.signing-project-quota-state/v1",
            "org_id": tenant.org_id,
            "project_id": tenant.project_id,
            "current_pin": pin,
            "signing_allowed": false,
            "dispatch_allowed": false
        });
        tx.commit()?;
        Ok(state)
    }
}

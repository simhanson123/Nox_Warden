//! Closed inputs for the explicit isolated Linux target-bootstrap command.
pub use fw_authority::TargetBootstrapBundle;
use fw_authority::{RegistryTrustKey, TargetBootstrapKeyPin};
use serde::{Deserialize, Serialize};

pub const TARGET_BOOTSTRAP_CONFIG_SCHEMA: &str = "fw.isolated-target-bootstrap-config/v1";
pub const TARGET_BOOTSTRAP_BUNDLE_SCHEMA: &str = "fw.target-bootstrap-bundle/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBootstrapConfig {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub state_dir: String,
    pub bootstrap_trust: RegistryTrustKey,
    pub target_key_pin: TargetBootstrapKeyPin,
    pub seed_file: String,
}

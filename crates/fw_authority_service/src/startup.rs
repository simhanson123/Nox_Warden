//! Closed diagnostics: never retain or display filesystem/crypto/database errors.
use crate::Failure;

#[derive(Clone, Copy, Debug)]
pub enum StartupStage {
    Arguments,
    Config,
    SessionKey,
    Origin,
    Database,
    Trust,
    UiAssets,
    ReviewEvidence,
    RuntimeKey,
    Bind,
    Listener,
}
impl StartupStage {
    fn diagnostic(self) -> (&'static str, &'static str) {
        match self {
            Self::Arguments => ("arguments", "AUTHORITY_ARGUMENTS_REJECTED"),
            Self::Config => ("config", "AUTHORITY_CONFIG_REJECTED"),
            Self::SessionKey => ("session_key", "AUTHORITY_SESSION_KEY_REJECTED"),
            Self::Origin => ("origin", "AUTHORITY_ORIGIN_REJECTED"),
            Self::Database => ("database", "AUTHORITY_DATABASE_REJECTED"),
            Self::Trust => ("trust", "AUTHORITY_TRUST_REJECTED"),
            Self::UiAssets => ("ui_assets", "AUTHORITY_UI_ASSETS_REJECTED"),
            Self::ReviewEvidence => ("review_evidence", "AUTHORITY_REVIEW_EVIDENCE_REJECTED"),
            Self::RuntimeKey => ("runtime_key", "AUTHORITY_RUNTIME_KEY_UNAVAILABLE"),
            Self::Bind => ("bind", "AUTHORITY_BIND_UNAVAILABLE"),
            Self::Listener => ("listener", "AUTHORITY_LISTENER_STOPPED"),
        }
    }
}
#[derive(Debug)]
pub struct StartupError {
    stage: StartupStage,
    pub(crate) failure: Failure,
}
impl StartupError {
    pub fn new(stage: StartupStage) -> Self {
        Self {
            stage,
            failure: Failure::Invalid,
        }
    }
}
impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (stage, code) = self.stage.diagnostic();
        write!(f, "AUTHORITY_STARTUP stage={stage} code={code}")
    }
}
impl std::error::Error for StartupError {}
pub(crate) fn at<T>(
    stage: StartupStage,
    operation: impl FnOnce() -> crate::Result<T>,
) -> std::result::Result<T, StartupError> {
    operation().map_err(|failure| StartupError { stage, failure })
}

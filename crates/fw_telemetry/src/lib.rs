//! Network-free telemetry consent and aggregation core. No packet, identity,
//! policy, signer or executor dependency exists. There is no built-in collector
//! URL and no sender. A future isolated worker must persist consent securely,
//! enforce HTTP limits/cancellation and re-check permits immediately at dispatch.
use chrono::{Datelike, NaiveDate};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use zeroize::Zeroize;

pub const NOTICE_VERSION: &str = "f.telemetry-notice/v1";
const MAX_QUEUE: usize = 6;
const MAX_QUEUE_BYTES: usize = 65_536;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TelemetryError {
    #[error("TELEMETRY_DISABLED")]
    Disabled,
    #[error("CONSENT_REVISION_CONFLICT")]
    RevisionConflict,
    #[error("INVALID_TELEMETRY_CONFIGURATION")]
    Configuration,
    #[error("INVALID_TELEMETRY_REPORT")]
    Report,
    #[error("SECURE_RANDOM_UNAVAILABLE")]
    Random,
}
type Result<T> = std::result::Result<T, TelemetryError>;
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Categories {
    pub adoption: bool,
    pub diagnostics: bool,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Adoption,
    Diagnostics,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequest {
    pub enabled: bool,
    pub categories: Categories,
    pub consent_notice_version: String,
    pub endpoint_policy_digest: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub schema_version: String,
    pub enabled: bool,
    pub categories: Categories,
    pub endpoint: Option<String>,
    pub endpoint_policy_digest: Option<String>,
    pub consent_notice_version: String,
    pub consent_recorded_at: Option<String>,
    pub consent_revision: u64,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            schema_version: "f.telemetry-config/v1".into(),
            enabled: false,
            categories: Categories::default(),
            endpoint: None,
            endpoint_policy_digest: None,
            consent_notice_version: NOTICE_VERSION.into(),
            consent_recorded_at: None,
            consent_revision: 0,
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub enum DiagnosticEvent {
    ValidationFailure,
    DeploymentFailure,
    UnknownCommit,
    RecoveryFailure,
    IntegrationFailure,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Diagnostics {
    pub validation_failure_count: u16,
    pub deployment_failure_count: u16,
    pub unknown_commit_count: u16,
    pub recovery_failure_count: u16,
    pub integration_failure_count: u16,
    pub counts_saturated: bool,
}
impl Diagnostics {
    fn record(&mut self, event: DiagnosticEvent) {
        let count = match event {
            DiagnosticEvent::ValidationFailure => &mut self.validation_failure_count,
            DiagnosticEvent::DeploymentFailure => &mut self.deployment_failure_count,
            DiagnosticEvent::UnknownCommit => &mut self.unknown_commit_count,
            DiagnosticEvent::RecoveryFailure => &mut self.recovery_failure_count,
            DiagnosticEvent::IntegrationFailure => &mut self.integration_failure_count,
        };
        if *count == 9999 {
            self.counts_saturated = true;
        } else {
            *count += 1;
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Linux,
    Windows,
    Macos,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseChannel {
    DesignPreview,
    LabPreview,
    Prerelease,
    Stable,
    Dev,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentProfile {
    Lab,
    Host,
    RoutedGateway,
    Team,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Adoption {
    pub os_family: OsFamily,
    pub version_major_minor: String,
    pub release_channel: ReleaseChannel,
    pub deployment_profile: DeploymentProfile,
}
impl Adoption {
    fn validate(&self) -> bool {
        let parts = self.version_major_minor.split('.').collect::<Vec<_>>();
        parts.len() == 2
            && parts.iter().all(|p| {
                !p.is_empty()
                    && p.len() <= 4
                    && p.bytes().all(|b| b.is_ascii_digit())
                    && (p.len() == 1 || !p.starts_with('0'))
            })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Payload {
    Adoption(Adoption),
    Diagnostics(Diagnostics),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema_version: String,
    pub report_id: String,
    pub subject_id: String,
    pub day_utc: String,
    pub category: Category,
    pub deletion_token_sha256: String,
    pub payload: Payload,
}
struct MonthlyIdentity {
    subject: [u8; 32],
    deletion_token: [u8; 32],
    last_used_day: NaiveDate,
}
impl Drop for MonthlyIdentity {
    fn drop(&mut self) {
        self.subject.zeroize();
        self.deletion_token.zeroize();
    }
}
#[derive(Clone)]
struct Queued {
    revision: u64,
    day: NaiveDate,
    report: Report,
}
/// Private permit fields prevent a worker from constructing an unconsented
/// outbound message. Revocation changes the revision, invalidating old permits.
#[derive(Debug, Clone)]
pub struct SendPermit {
    revision: u64,
    report_id: String,
}
#[derive(Default)]
pub struct Telemetry {
    configuration: Configuration,
    consent_seed: Option<[u8; 32]>,
    consent_generation: u64,
    identities: BTreeMap<(u64, i32, u32), MonthlyIdentity>,
    counts: BTreeMap<NaiveDate, Diagnostics>,
    queue: VecDeque<Queued>,
    completed: BTreeMap<(NaiveDate, Category), String>,
    queue_loss: bool,
}
fn random() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| TelemetryError::Random)?;
    Ok(bytes)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest_valid(s: &str) -> bool {
    s.len() == 71
        && s.starts_with("sha256:")
        && s[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn date(s: &str) -> Result<NaiveDate> {
    let d = NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| TelemetryError::Report)?;
    if d.format("%Y-%m-%d").to_string() != s {
        return Err(TelemetryError::Report);
    }
    Ok(d)
}
impl Telemetry {
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn queued_count(&self) -> usize {
        self.queue.len()
    }
    pub fn queue_loss(&self) -> bool {
        self.queue_loss
    }
    /// Only call from an OS-protected admin configuration path. This is not a
    /// remote endpoint setter. Every material change revokes prior consent.
    pub fn configure_endpoint(
        &mut self,
        endpoint: Option<&str>,
        policy_digest: Option<&str>,
    ) -> Result<()> {
        if endpoint.is_some() != policy_digest.is_some() {
            return Err(TelemetryError::Configuration);
        }
        if let Some(s) = endpoint {
            let u = url::Url::parse(s).map_err(|_| TelemetryError::Configuration)?;
            if u.scheme() != "https"
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
                || u.query().is_some()
                || u.fragment().is_some()
                || !policy_digest.is_some_and(digest_valid)
            {
                return Err(TelemetryError::Configuration);
            }
        }
        let endpoint = endpoint.map(str::to_owned);
        let digest = policy_digest.map(str::to_owned);
        if self.configuration.endpoint != endpoint
            || self.configuration.endpoint_policy_digest != digest
        {
            self.disable()?;
            self.configuration.endpoint = endpoint;
            self.configuration.endpoint_policy_digest = digest;
        }
        Ok(())
    }
    /// The caller authenticates installation-wide telemetry management capability
    /// and checks HTTP If-Match/idempotency before entering this pure core.
    pub fn record_consent(
        &mut self,
        request: ConsentRequest,
        expected_revision: u64,
        now: &str,
    ) -> Result<()> {
        if expected_revision != self.configuration.consent_revision {
            return Err(TelemetryError::RevisionConflict);
        }
        if !request.enabled {
            return self.disable();
        }
        if request.consent_notice_version != NOTICE_VERSION
            || request.endpoint_policy_digest != self.configuration.endpoint_policy_digest
            || self.configuration.endpoint.is_none()
            || (!request.categories.adoption && !request.categories.diagnostics)
        {
            return Err(TelemetryError::Configuration);
        }
        let t =
            chrono::DateTime::parse_from_rfc3339(now).map_err(|_| TelemetryError::Configuration)?;
        if now.len() != 20 || !now.ends_with('Z') {
            return Err(TelemetryError::Configuration);
        }
        let next = self
            .configuration
            .consent_revision
            .checked_add(1)
            .ok_or(TelemetryError::Configuration)?;
        let generation = self
            .consent_generation
            .checked_add(1)
            .ok_or(TelemetryError::Configuration)?;
        let seed = random()?;
        self.clear_pending();
        if let Some(mut old) = self.consent_seed.take() {
            old.zeroize();
        }
        self.consent_seed = Some(seed);
        self.consent_generation = generation;
        self.configuration.enabled = true;
        self.configuration.categories = request.categories;
        self.configuration.consent_recorded_at = Some(t.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        self.configuration.consent_revision = next;
        Ok(())
    }
    fn clear_pending(&mut self) {
        self.queue.clear();
        self.counts.clear();
        self.completed.clear();
        self.queue_loss = false;
    }
    pub fn disable(&mut self) -> Result<()> {
        let next = self
            .configuration
            .consent_revision
            .checked_add(1)
            .ok_or(TelemetryError::Configuration)?;
        self.configuration.enabled = false;
        self.configuration.categories = Categories::default();
        self.configuration.consent_recorded_at = None;
        self.configuration.consent_revision = next;
        self.clear_pending();
        if let Some(mut seed) = self.consent_seed.take() {
            seed.zeroize();
        }
        Ok(())
    }
    fn enabled(&self, c: Category) -> bool {
        self.configuration.enabled
            && match c {
                Category::Adoption => self.configuration.categories.adoption,
                Category::Diagnostics => self.configuration.categories.diagnostics,
            }
    }
    pub fn record_event(&mut self, day: &str, event: DiagnosticEvent) -> Result<bool> {
        if !self.enabled(Category::Diagnostics) {
            return Ok(false);
        }
        let day = date(day)?;
        if !self.counts.contains_key(&day) && self.counts.len() >= 4 {
            self.queue_loss = true;
            return Ok(false);
        }
        self.counts.entry(day).or_default().record(event);
        Ok(true)
    }
    /// Signals loss from the future worker's bounded enum channel.
    pub fn mark_event_loss(&mut self, day: &str) -> Result<()> {
        if self.enabled(Category::Diagnostics) {
            let day = date(day)?;
            if self.counts.len() < 4 || self.counts.contains_key(&day) {
                self.counts.entry(day).or_default().counts_saturated = true;
            }
        }
        Ok(())
    }
    pub fn prune(&mut self, today: &str) -> Result<()> {
        let today = date(today)?;
        self.queue.retain(|q| {
            let age = (today - q.day).num_days();
            (1..=3).contains(&age)
        });
        self.counts.retain(|d, _| {
            let age = (today - *d).num_days();
            (0..=3).contains(&age)
        });
        self.completed
            .retain(|(d, _), _| (today - *d).num_days() <= 3);
        self.identities
            .retain(|_, id| (today - id.last_used_day).num_days() <= 35);
        Ok(())
    }
    /// Creates at most one immutable queued body per consent/day/category. The
    /// returned preview is local only; retry uses the identical report UUID/body.
    pub fn prepare_report(
        &mut self,
        day: &str,
        today: &str,
        category: Category,
        adoption: Option<Adoption>,
    ) -> Result<Report> {
        if !self.enabled(category) {
            return Err(TelemetryError::Disabled);
        }
        self.prune(today)?;
        let day = date(day)?;
        let today = date(today)?;
        let consent_day = self
            .configuration
            .consent_recorded_at
            .as_ref()
            .and_then(|s| s.get(..10))
            .ok_or(TelemetryError::Configuration)?;
        if day < date(consent_day)?
            || !(1..=3).contains(&(today - day).num_days())
            || self.completed.contains_key(&(day, category))
        {
            return Err(TelemetryError::Report);
        }
        if let Some(q) = self
            .queue
            .iter()
            .find(|q| q.day == day && q.report.category == category)
        {
            return Ok(q.report.clone());
        }
        let payload = match category {
            Category::Adoption => {
                let v = adoption.ok_or(TelemetryError::Report)?;
                if !v.validate() {
                    return Err(TelemetryError::Report);
                }
                Payload::Adoption(v)
            }
            Category::Diagnostics => {
                if adoption.is_some() {
                    return Err(TelemetryError::Report);
                }
                let mut v = self.counts.get(&day).cloned().unwrap_or_default();
                v.counts_saturated |= self.queue_loss;
                Payload::Diagnostics(v)
            }
        };
        let identity_key = (self.consent_generation, day.year(), day.month());
        if let std::collections::btree_map::Entry::Vacant(e) = self.identities.entry(identity_key) {
            e.insert(MonthlyIdentity {
                subject: random()?,
                deletion_token: random()?,
                last_used_day: today,
            });
        }
        let identity = self
            .identities
            .get_mut(&identity_key)
            .ok_or(TelemetryError::Random)?;
        identity.last_used_day = today;
        let report = Report {
            schema_version: "f.telemetry-report/v1".into(),
            report_id: uuid::Uuid::new_v4().to_string(),
            subject_id: hex(&identity.subject),
            day_utc: day.to_string(),
            category,
            deletion_token_sha256: hex(&Sha256::digest(identity.deletion_token)),
            payload,
        };
        let bytes = serde_json::to_vec(&report).map_err(|_| TelemetryError::Report)?;
        if bytes.len() > 4096 {
            return Err(TelemetryError::Report);
        }
        let total = self
            .queue
            .iter()
            .map(|q| serde_json::to_vec(&q.report).map_or(4096, |b| b.len()))
            .sum::<usize>();
        if self.queue.len() >= MAX_QUEUE || total + bytes.len() > MAX_QUEUE_BYTES {
            if let Some(old) = self.queue.pop_front() {
                self.completed
                    .insert((old.day, old.report.category), old.report.report_id);
            }
            self.queue_loss = true;
        }
        self.queue.push_back(Queued {
            revision: self.configuration.consent_revision,
            day,
            report: report.clone(),
        });
        Ok(report)
    }
    pub fn permit(&self, report_id: &str) -> Result<SendPermit> {
        let q = self
            .queue
            .iter()
            .find(|q| q.report.report_id == report_id)
            .ok_or(TelemetryError::Report)?;
        if !self.enabled(q.report.category) || q.revision != self.configuration.consent_revision {
            return Err(TelemetryError::Disabled);
        }
        Ok(SendPermit {
            revision: q.revision,
            report_id: report_id.to_owned(),
        })
    }
    /// Recheck at dispatch, under the same synchronization as config mutation.
    /// This does not send. Worker must cancel its in-flight HTTP on disable.
    pub fn authorized_report(&self, permit: &SendPermit) -> Result<&Report> {
        if permit.revision != self.configuration.consent_revision {
            return Err(TelemetryError::Disabled);
        }
        let q = self
            .queue
            .iter()
            .find(|q| q.report.report_id == permit.report_id)
            .ok_or(TelemetryError::Report)?;
        if !self.enabled(q.report.category) {
            return Err(TelemetryError::Disabled);
        }
        Ok(&q.report)
    }
    pub fn mark_delivered(&mut self, permit: &SendPermit) -> Result<()> {
        let report = self.authorized_report(permit)?.clone();
        let day = date(&report.day_utc)?;
        self.queue
            .retain(|q| q.report.report_id != report.report_id);
        self.completed
            .insert((day, report.category), report.report_id);
        Ok(())
    }
}
impl Drop for Telemetry {
    fn drop(&mut self) {
        if let Some(seed) = self.consent_seed.as_mut() {
            seed.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> String {
        format!("sha256:{}", "a".repeat(64))
    }
    fn enabled(categories: Categories) -> Telemetry {
        let mut t = Telemetry::default();
        t.configure_endpoint(Some("https://collector.example.test/v1"), Some(&policy()))
            .unwrap();
        t.record_consent(
            ConsentRequest {
                enabled: true,
                categories,
                consent_notice_version: NOTICE_VERSION.into(),
                endpoint_policy_digest: Some(policy()),
            },
            t.configuration().consent_revision,
            "2026-10-01T12:00:00Z",
        )
        .unwrap();
        t
    }
    fn adoption() -> Adoption {
        Adoption {
            os_family: OsFamily::Linux,
            version_major_minor: "0.1".into(),
            release_channel: ReleaseChannel::LabPreview,
            deployment_profile: DeploymentProfile::Lab,
        }
    }
    #[test]
    fn default_off_has_no_endpoint_aggregation_or_send_permit() {
        let mut t = Telemetry::default();
        assert!(!t.configuration().enabled);
        assert_eq!(t.configuration().endpoint, None);
        assert!(
            !t.record_event("2026-10-29", DiagnosticEvent::ValidationFailure)
                .unwrap()
        );
        assert_eq!(
            t.prepare_report(
                "2026-10-29",
                "2026-10-30",
                Category::Adoption,
                Some(adoption())
            ),
            Err(TelemetryError::Disabled)
        );
        assert!(t.permit("anything").is_err());
        assert_eq!(t.queued_count(), 0);
    }
    #[test]
    fn endpoint_is_protected_https_and_missing_policy_cannot_enable() {
        let mut t = Telemetry::default();
        for url in [
            "http://example.test",
            "https://user:pass@example.test",
            "https://example.test/?secret=1",
            "https://example.test/#x",
        ] {
            assert_eq!(
                t.configure_endpoint(Some(url), Some(&policy())),
                Err(TelemetryError::Configuration)
            );
        }
        assert_eq!(
            t.record_consent(
                ConsentRequest {
                    enabled: true,
                    categories: Categories {
                        adoption: true,
                        diagnostics: false
                    },
                    consent_notice_version: NOTICE_VERSION.into(),
                    endpoint_policy_digest: None
                },
                0,
                "2026-10-01T00:00:00Z"
            ),
            Err(TelemetryError::Configuration)
        );
    }
    #[test]
    fn categories_are_independent_and_payload_is_an_allowlist() {
        let mut t = enabled(Categories {
            adoption: false,
            diagnostics: true,
        });
        t.record_event("2026-10-29", DiagnosticEvent::UnknownCommit)
            .unwrap();
        assert_eq!(
            t.prepare_report(
                "2026-10-29",
                "2026-10-30",
                Category::Adoption,
                Some(adoption())
            ),
            Err(TelemetryError::Disabled)
        );
        let r = t
            .prepare_report("2026-10-29", "2026-10-30", Category::Diagnostics, None)
            .unwrap();
        let value = serde_json::to_value(&r).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 7);
        assert_eq!(value["payload"].as_object().unwrap().len(), 6);
        assert_eq!(value["payload"]["unknown_commit_count"], 1);
        assert!(value.get("deletion_token").is_none());
        let mut poisoned = value;
        poisoned["payload"]["request_id"] = serde_json::json!("private");
        assert!(serde_json::from_value::<Report>(poisoned).is_err());
    }
    #[test]
    fn disable_invalidates_acquired_permits_purges_queue_and_reconsent_rotates_identity() {
        let mut t = enabled(Categories {
            adoption: true,
            diagnostics: true,
        });
        let old = t
            .prepare_report(
                "2026-10-29",
                "2026-10-30",
                Category::Adoption,
                Some(adoption()),
            )
            .unwrap();
        let permit = t.permit(&old.report_id).unwrap();
        assert_eq!(t.authorized_report(&permit).unwrap(), &old);
        t.disable().unwrap();
        assert_eq!(t.authorized_report(&permit), Err(TelemetryError::Disabled));
        assert_eq!(t.queued_count(), 0);
        t.record_consent(
            ConsentRequest {
                enabled: true,
                categories: Categories {
                    adoption: true,
                    diagnostics: false,
                },
                consent_notice_version: NOTICE_VERSION.into(),
                endpoint_policy_digest: Some(policy()),
            },
            t.configuration().consent_revision,
            "2026-10-29T12:00:00Z",
        )
        .unwrap();
        let new = t
            .prepare_report(
                "2026-10-29",
                "2026-10-30",
                Category::Adoption,
                Some(adoption()),
            )
            .unwrap();
        assert_ne!(new.subject_id, old.subject_id);
        assert_ne!(new.deletion_token_sha256, old.deletion_token_sha256);
    }
    #[test]
    fn stale_consent_and_policy_changes_do_not_expand_permission() {
        let mut t = enabled(Categories {
            adoption: true,
            diagnostics: false,
        });
        let old = t.configuration().consent_revision;
        t.configure_endpoint(Some("https://new.example.test/v1"), Some(&policy()))
            .unwrap();
        assert!(!t.configuration().enabled);
        assert_eq!(
            t.record_consent(
                ConsentRequest {
                    enabled: true,
                    categories: Categories {
                        adoption: true,
                        diagnostics: false
                    },
                    consent_notice_version: NOTICE_VERSION.into(),
                    endpoint_policy_digest: Some(policy())
                },
                old,
                "2026-10-29T00:00:00Z"
            ),
            Err(TelemetryError::RevisionConflict)
        );
    }
    #[test]
    fn report_retry_is_identical_and_delivered_day_cannot_be_duplicated() {
        let mut t = enabled(Categories {
            adoption: true,
            diagnostics: false,
        });
        let first = t
            .prepare_report(
                "2026-10-29",
                "2026-10-30",
                Category::Adoption,
                Some(adoption()),
            )
            .unwrap();
        assert_eq!(
            first,
            t.prepare_report(
                "2026-10-29",
                "2026-10-30",
                Category::Adoption,
                Some(adoption())
            )
            .unwrap()
        );
        let p = t.permit(&first.report_id).unwrap();
        t.mark_delivered(&p).unwrap();
        assert_eq!(
            t.prepare_report(
                "2026-10-29",
                "2026-10-30",
                Category::Adoption,
                Some(adoption())
            ),
            Err(TelemetryError::Report)
        );
    }
    #[test]
    fn reports_require_complete_recent_dates_and_no_preconsent_data() {
        let mut t = enabled(Categories {
            adoption: true,
            diagnostics: false,
        });
        for day in [
            "2026-10-30",
            "2026-10-31",
            "2026-10-26",
            "2026-02-30",
            "2026-9-29",
        ] {
            assert_eq!(
                t.prepare_report(day, "2026-10-30", Category::Adoption, Some(adoption())),
                Err(TelemetryError::Report)
            );
        }
        assert_eq!(
            t.prepare_report(
                "2026-09-30",
                "2026-10-02",
                Category::Adoption,
                Some(adoption())
            ),
            Err(TelemetryError::Report)
        );
    }
    #[test]
    fn counts_saturate_and_months_have_independent_ids() {
        let mut t = enabled(Categories {
            adoption: true,
            diagnostics: true,
        });
        for _ in 0..10_001 {
            t.record_event("2026-10-31", DiagnosticEvent::DeploymentFailure)
                .unwrap();
        }
        let oct = t
            .prepare_report("2026-10-31", "2026-11-02", Category::Diagnostics, None)
            .unwrap();
        let Payload::Diagnostics(ref d) = oct.payload else {
            panic!("wrong category")
        };
        assert_eq!(d.deployment_failure_count, 9999);
        assert!(d.counts_saturated);
        let nov = t
            .prepare_report(
                "2026-11-01",
                "2026-11-02",
                Category::Adoption,
                Some(adoption()),
            )
            .unwrap();
        assert_ne!(oct.subject_id, nov.subject_id);
        let json = serde_json::to_string(&nov).unwrap();
        assert!(!json.contains("deletion_token\":"));
        assert_eq!(nov.subject_id.len(), 64);
    }
    #[test]
    fn expiry_prunes_queued_reports_and_patch_versions_are_rejected() {
        let mut t = enabled(Categories {
            adoption: true,
            diagnostics: false,
        });
        let mut a = adoption();
        a.version_major_minor = "0.1.6".into();
        assert_eq!(
            t.prepare_report("2026-10-29", "2026-10-30", Category::Adoption, Some(a)),
            Err(TelemetryError::Report)
        );
        t.prepare_report(
            "2026-10-29",
            "2026-10-30",
            Category::Adoption,
            Some(adoption()),
        )
        .unwrap();
        t.prune("2026-11-02").unwrap();
        assert_eq!(t.queued_count(), 0);
    }
}

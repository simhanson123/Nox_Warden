//! Certificate-based, observe-only target enrollment. Transport certificates
//! never grant policy-signing or native firewall authority.
mod files;
pub use files::{init_controller_pki, load_controller_pki};

use chrono::{DateTime, Utc};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{Id, PKey, Private, Public},
    rand::rand_bytes,
    stack::Stack,
    x509::{
        X509, X509NameBuilder, X509PurposeId, X509Req, X509StoreContext,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
        store::X509StoreBuilder,
        verify::{X509VerifyFlags, X509VerifyParam},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const MAX_TIME: i64 = 253_402_300_799;
const CERT_SECONDS: i64 = 86_400;
const RENEW_SECONDS: i64 = 28_800;
const MAX_PEM: usize = 32_768;

#[derive(Debug, Error)]
pub enum EnrollmentError {
    #[error("invalid enrollment material: {0}")]
    Invalid(&'static str),
    #[error("certificate or key verification failed")]
    Verification,
    #[error("certificate validity window is invalid")]
    Time,
    #[error("cryptographic operation failed")]
    Crypto(#[from] openssl::error::ErrorStack),
    #[error("private enrollment file operation failed")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, EnrollmentError>;

// Deliberately no Debug: the request contains a one-use enrollment secret.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub schema_version: String,
    pub request_id: String,
    pub token: String,
    pub csr_pem: String,
    pub expected_key_fingerprint: String,
    pub nonce: String,
    pub platform: String,
    pub agent_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentResponse {
    pub schema_version: String,
    pub request_id: String,
    pub target_id: String,
    pub certificate_chain_pem: String,
    pub trust_bundle_hash: String,
    pub authority_epoch: String,
    pub issued_at: String,
    pub expires_at: String,
    pub renew_after: String,
    pub mode: String,
}

/// Public metadata plus explicit secret PEM; do not log or serialize the struct.
pub struct DeviceIdentity {
    pub private_key_pem: String,
    pub csr_pem: String,
    pub key_fingerprint: String,
}

pub struct ValidatedCsr {
    public_key: PKey<Public>,
    csr_hash: String,
    key_fingerprint: String,
}
impl ValidatedCsr {
    pub fn csr_hash(&self) -> &str {
        &self.csr_hash
    }
    pub fn key_fingerprint(&self) -> &str {
        &self.key_fingerprint
    }
}

/// Resolve all fields from a durable server-owned enrollment reservation.
/// The timestamp is fixed when reserving; retry must reuse it and the job ID.
#[derive(Clone, Debug)]
pub struct Issuance {
    pub request_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub job_id: String,
    pub issued_at: i64,
    pub authority_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetIdentity {
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub key_fingerprint: String,
    pub certificate_fingerprint: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// CA state is separate from all policy signing material. No Debug implementation.
pub struct CertificateAuthority {
    certificate: X509,
    key: PKey<Private>,
    certificate_pem: String,
}

pub struct ControllerPki {
    pub authority: CertificateAuthority,
    pub server_certificate_pem: String,
    pub server_private_key_pem: String,
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
pub fn valid_fingerprint(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && lower_hex(hex))
}
pub fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    rand_bytes(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| uuid.to_string() == value)
}
fn valid_time(value: i64) -> bool {
    (0..=MAX_TIME).contains(&value)
}
fn timestamp(value: i64) -> Result<String> {
    if !valid_time(value) {
        return Err(EnrollmentError::Time);
    }
    Ok(DateTime::<Utc>::from_timestamp(value, 0)
        .ok_or(EnrollmentError::Time)?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string())
}
fn parse_time(value: &str) -> Result<i64> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| EnrollmentError::Time)?;
    let seconds = parsed.timestamp();
    if timestamp(seconds)? != value {
        return Err(EnrollmentError::Time);
    }
    Ok(seconds)
}
fn asn1_timestamp(value: &openssl::asn1::Asn1TimeRef) -> Result<i64> {
    let epoch = Asn1Time::from_unix(0)?;
    let difference = epoch.diff(value)?;
    let result = i64::from(difference.days) * 86_400 + i64::from(difference.secs);
    if !valid_time(result) {
        return Err(EnrollmentError::Time);
    }
    Ok(result)
}
fn one_pem(value: &str, label: &str, max: usize) -> Result<()> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    if value.len() > max {
        return Err(EnrollmentError::Invalid("PEM size"));
    }
    let value = value.trim();
    if value.len() > max
        || !value.starts_with(&begin)
        || !value.ends_with(&end)
        || value.matches("-----BEGIN ").count() != 1
        || value.matches("-----END ").count() != 1
    {
        return Err(EnrollmentError::Invalid("expected one bounded PEM object"));
    }
    Ok(())
}
fn utf8_pem(value: Vec<u8>) -> Result<String> {
    String::from_utf8(value).map_err(|_| EnrollmentError::Invalid("PEM encoding"))
}
fn key_fingerprint<T: openssl::pkey::HasPublic>(key: &openssl::pkey::PKeyRef<T>) -> Result<String> {
    Ok(hash_bytes(&key.public_key_to_der()?))
}
fn require_ed25519<T: openssl::pkey::HasPublic>(key: &openssl::pkey::PKeyRef<T>) -> Result<()> {
    if key.id() != Id::ED25519 || key.raw_public_key()?.len() != 32 {
        return Err(EnrollmentError::Invalid(
            "only Ed25519 transport keys are supported",
        ));
    }
    Ok(())
}

pub fn generate_device_identity() -> Result<DeviceIdentity> {
    let key = PKey::generate_ed25519()?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "Nox device transport key")?;
    let mut builder = X509Req::builder()?;
    builder.set_version(0)?;
    builder.set_subject_name(&name.build())?;
    builder.set_pubkey(&key)?;
    builder.sign(&key, MessageDigest::null())?;
    Ok(DeviceIdentity {
        private_key_pem: utf8_pem(key.private_key_to_pem_pkcs8()?)?,
        csr_pem: utf8_pem(builder.build().to_pem()?)?,
        key_fingerprint: key_fingerprint(&key)?,
    })
}

pub fn load_device_identity(private_key_pem: &str, csr_pem: &str) -> Result<DeviceIdentity> {
    one_pem(private_key_pem, "PRIVATE KEY", MAX_PEM)?;
    let key = PKey::private_key_from_pem(private_key_pem.as_bytes())?;
    require_ed25519(&key)?;
    let fingerprint = key_fingerprint(&key)?;
    validate_csr(csr_pem, &fingerprint)?;
    Ok(DeviceIdentity {
        private_key_pem: private_key_pem.into(),
        csr_pem: csr_pem.into(),
        key_fingerprint: fingerprint,
    })
}

pub fn validate_csr(csr_pem: &str, expected_fingerprint: &str) -> Result<ValidatedCsr> {
    one_pem(csr_pem, "CERTIFICATE REQUEST", 16_384)?;
    if csr_pem.len() < 128 || !valid_fingerprint(expected_fingerprint) {
        return Err(EnrollmentError::Invalid("CSR or fingerprint"));
    }
    let request = X509Req::from_pem(csr_pem.as_bytes())?;
    if request.version() != 0 {
        return Err(EnrollmentError::Invalid("CSR version"));
    }
    let key = request.public_key()?;
    require_ed25519(&key)?;
    if !request.verify(&key)? || key_fingerprint(&key)? != expected_fingerprint {
        return Err(EnrollmentError::Verification);
    }
    Ok(ValidatedCsr {
        public_key: key,
        csr_hash: hash_bytes(csr_pem.as_bytes()),
        key_fingerprint: expected_fingerprint.into(),
    })
}

pub fn validate_request(request: &EnrollmentRequest) -> Result<ValidatedCsr> {
    if request.schema_version != "f.enrollment-request/v1"
        || !canonical_uuid(&request.request_id)
        || !(43..=256).contains(&request.token.len())
        || !request
            .token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        || request.nonce.len() != 64
        || !lower_hex(&request.nonce)
        || !["linux", "windows", "macos"].contains(&request.platform.as_str())
        || request.agent_version.is_empty()
        || request.agent_version.len() > 256
        || request.agent_version.chars().any(char::is_control)
    {
        return Err(EnrollmentError::Invalid("enrollment request"));
    }
    validate_csr(&request.csr_pem, &request.expected_key_fingerprint)
}

impl CertificateAuthority {
    pub fn from_pem(ca_pem: &str, ca_key_pem: &[u8], now: i64) -> Result<Self> {
        one_pem(ca_pem, "CERTIFICATE", MAX_PEM)?;
        let key_text = std::str::from_utf8(ca_key_pem)
            .map_err(|_| EnrollmentError::Invalid("CA key encoding"))?;
        one_pem(key_text, "PRIVATE KEY", MAX_PEM)?;
        let certificate = X509::from_pem(ca_pem.as_bytes())?;
        let key = PKey::private_key_from_pem(ca_key_pem)?;
        require_ed25519(&key)?;
        let public = certificate.public_key()?;
        // This enrollment root profile issues leaves only; init_controller_pki
        // always installs a self-signed CA with a zero-length intermediate path.
        if certificate.pathlen() != Some(0)
            || certificate.to_pem()? != ca_pem.as_bytes()
            || certificate.subject_key_id().is_none()
            || certificate.authority_key_id().is_none()
        {
            return Err(EnrollmentError::Invalid("enrollment CA profile"));
        }
        if !public.public_eq(&key)
            || !certificate.verify(&public)?
            || certificate.subject_name().to_der()? != certificate.issuer_name().to_der()?
        {
            return Err(EnrollmentError::Verification);
        }
        if !valid_time(now)
            || now < asn1_timestamp(certificate.not_before())?
            || now >= asn1_timestamp(certificate.not_after())?
        {
            return Err(EnrollmentError::Time);
        }
        Ok(Self {
            certificate,
            key,
            certificate_pem: ca_pem.into(),
        })
    }
    pub fn ca_certificate_pem(&self) -> &str {
        &self.certificate_pem
    }
    pub fn trust_bundle_hash(&self) -> String {
        hash_bytes(self.certificate_pem.as_bytes())
    }

    pub fn issue(&self, csr: &ValidatedCsr, issuance: &Issuance) -> Result<EnrollmentResponse> {
        if [
            &issuance.request_id,
            &issuance.org_id,
            &issuance.project_id,
            &issuance.target_id,
            &issuance.job_id,
        ]
        .iter()
        .any(|v| !canonical_uuid(v))
        {
            return Err(EnrollmentError::Invalid("server enrollment identity"));
        }
        let expires_at = issuance
            .issued_at
            .checked_add(CERT_SECONDS)
            .ok_or(EnrollmentError::Time)?;
        let renew_after = issuance
            .issued_at
            .checked_add(RENEW_SECONDS)
            .ok_or(EnrollmentError::Time)?;
        if !valid_time(issuance.issued_at)
            || !valid_time(expires_at)
            || issuance.issued_at < asn1_timestamp(self.certificate.not_before())?
            || expires_at > asn1_timestamp(self.certificate.not_after())?
        {
            return Err(EnrollmentError::Time);
        }
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        // 159 positive bits, domain-separated from other certificates. Stable job
        // identity plus immutable reservation fields makes issuance retry exact.
        let material = format!(
            "nox-enrollment-certificate-v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            issuance.job_id,
            issuance.org_id,
            issuance.project_id,
            issuance.target_id,
            csr.csr_hash(),
            issuance.issued_at,
            issuance.authority_epoch
        );
        let mut serial = Sha256::digest(material.as_bytes())[..20].to_vec();
        serial[0] &= 0x7f;
        if serial.iter().all(|byte| *byte == 0) {
            serial[19] = 1;
        }
        let serial = BigNum::from_slice(&serial)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", &issuance.target_id)?;
        builder.set_subject_name(&name.build())?;
        builder.set_issuer_name(self.certificate.subject_name())?;
        builder.set_pubkey(&csr.public_key)?;
        builder.set_not_before(Asn1Time::from_unix(issuance.issued_at)?.as_ref())?;
        builder.set_not_after(Asn1Time::from_unix(expires_at)?.as_ref())?;
        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
        builder.append_extension(ExtendedKeyUsage::new().client_auth().build()?)?;
        let uri = format!(
            "urn:nox:target:{}:{}:{}",
            issuance.org_id, issuance.project_id, issuance.target_id
        );
        let san = SubjectAlternativeName::new()
            .uri(&uri)
            .build(&builder.x509v3_context(Some(&self.certificate), None))?;
        builder.append_extension(san)?;
        let subject_key_id = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(Some(&self.certificate), None))?;
        builder.append_extension(subject_key_id)?;
        let authority_key_id = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(Some(&self.certificate), None))?;
        builder.append_extension(authority_key_id)?;
        builder.sign(&self.key, MessageDigest::null())?;
        let leaf = builder.build();
        verify_chain(
            &leaf,
            &self.certificate,
            issuance.issued_at,
            X509PurposeId::SSL_CLIENT,
        )?;
        Ok(EnrollmentResponse {
            schema_version: "f.enrollment-response/v1".into(),
            request_id: issuance.request_id.clone(),
            target_id: issuance.target_id.clone(),
            certificate_chain_pem: format!("{}{}", utf8_pem(leaf.to_pem()?)?, self.certificate_pem),
            trust_bundle_hash: self.trust_bundle_hash(),
            authority_epoch: issuance.authority_epoch.to_string(),
            issued_at: timestamp(issuance.issued_at)?,
            expires_at: timestamp(expires_at)?,
            renew_after: timestamp(renew_after)?,
            mode: "observe".into(),
        })
    }
}

fn verify_chain(leaf: &X509, root: &X509, now: i64, purpose: X509PurposeId) -> Result<()> {
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(root.clone())?;
    let mut params = X509VerifyParam::new()?;
    params.set_time(now as _);
    params.set_purpose(purpose)?;
    params.set_flags(X509VerifyFlags::X509_STRICT | X509VerifyFlags::CHECK_SS_SIGNATURE)?;
    store.set_param(&params)?;
    let store = store.build();
    let chain = Stack::new()?;
    let mut context = X509StoreContext::new()?;
    if !context.init(&store, leaf, &chain, |ctx| ctx.verify_cert())? {
        return Err(EnrollmentError::Verification);
    }
    Ok(())
}

/// Decode identity only after authenticating the TLS chain. This helper alone
/// does not establish trust, registry membership, validity or non-revocation.
pub fn certificate_identity(der: &[u8]) -> Result<TargetIdentity> {
    if der.len() > MAX_PEM {
        return Err(EnrollmentError::Invalid("certificate size"));
    }
    let certificate = X509::from_der(der)?;
    if certificate.to_der()? != der {
        return Err(EnrollmentError::Invalid("certificate trailing bytes"));
    }
    let public = certificate.public_key()?;
    require_ed25519(&public)?;
    let names = certificate
        .subject_alt_names()
        .ok_or(EnrollmentError::Verification)?;
    if names.len() != 1 {
        return Err(EnrollmentError::Verification);
    }
    let uri = names
        .get(0)
        .and_then(|name| name.uri())
        .ok_or(EnrollmentError::Verification)?;
    let parts: Vec<_> = uri.split(':').collect();
    if parts.len() != 6
        || parts[..3] != ["urn", "nox", "target"]
        || parts[3..].iter().any(|v| !canonical_uuid(v))
    {
        return Err(EnrollmentError::Verification);
    }
    Ok(TargetIdentity {
        org_id: parts[3].into(),
        project_id: parts[4].into(),
        target_id: parts[5].into(),
        key_fingerprint: key_fingerprint(&public)?,
        certificate_fingerprint: hash_bytes(der),
        issued_at: asn1_timestamp(certificate.not_before())?,
        expires_at: asn1_timestamp(certificate.not_after())?,
    })
}

pub fn verify_enrollment_response(
    response: &EnrollmentResponse,
    identity: &DeviceIdentity,
    ca_pem: &str,
    expected_target_id: &str,
    now: i64,
) -> Result<TargetIdentity> {
    one_pem(ca_pem, "CERTIFICATE", MAX_PEM)?;
    if response.schema_version != "f.enrollment-response/v1"
        || response.mode != "observe"
        || !canonical_uuid(&response.request_id)
        || !canonical_uuid(expected_target_id)
        || response.target_id != expected_target_id
        || response.trust_bundle_hash != hash_bytes(ca_pem.as_bytes())
        || !valid_time(now)
        || response.certificate_chain_pem.len() > MAX_PEM
        || response
            .authority_epoch
            .parse::<u64>()
            .map(|n| n.to_string())
            .ok()
            .as_deref()
            != Some(response.authority_epoch.as_str())
    {
        return Err(EnrollmentError::Invalid("enrollment response"));
    }
    let root = X509::from_pem(ca_pem.as_bytes())?;
    let chain = X509::stack_from_pem(response.certificate_chain_pem.as_bytes())?;
    if chain.len() != 2 || chain[1].to_der()? != root.to_der()? {
        return Err(EnrollmentError::Verification);
    }
    // Require exactly the issuer's canonical two PEM blocks, not ignored junk.
    let canonical = [chain[0].to_pem()?, chain[1].to_pem()?].concat();
    if canonical != response.certificate_chain_pem.as_bytes() {
        return Err(EnrollmentError::Verification);
    }
    verify_chain(&chain[0], &root, now, X509PurposeId::SSL_CLIENT)?;
    let target = certificate_identity(&chain[0].to_der()?)?;
    let local = load_device_identity(&identity.private_key_pem, &identity.csr_pem)?;
    let issued = parse_time(&response.issued_at)?;
    let expires = parse_time(&response.expires_at)?;
    let renew = parse_time(&response.renew_after)?;
    if target.target_id != expected_target_id
        || target.key_fingerprint != local.key_fingerprint
        || identity.key_fingerprint != local.key_fingerprint
        || target.issued_at != issued
        || target.expires_at != expires
        || issued > now
        || now >= expires
        || expires.checked_sub(issued) != Some(CERT_SECONDS)
        || renew.checked_sub(issued) != Some(RENEW_SECONDS)
    {
        return Err(EnrollmentError::Verification);
    }
    Ok(target)
}

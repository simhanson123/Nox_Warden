//! Local-owner passkey ceremonies using the maintained `webauthn-rs` verifier.
//!
//! Serialized ceremony state belongs only in protected server storage. This
//! adapter does not consume challenges, assign roles, establish sessions or
//! authorize policy approval: its caller must perform those atomic checks.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, time::Duration};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Webauthn, WebauthnBuilder,
};

pub const MAX_CREDENTIALS: usize = 8;
pub const CEREMONY_SECONDS: i64 = 300;
const RP_ID: &str = "localhost";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("WEBAUTHN_CONFIGURATION")]
    Configuration,
    #[error("WEBAUTHN_INPUT")]
    Input,
    #[error("WEBAUTHN_VERIFICATION")]
    Verification,
    #[error("WEBAUTHN_CREDENTIAL_STALE")]
    Stale,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Public-key material only. Private authenticator keys never reach the server.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    schema_version: String,
    principal_id: String,
    rp_id: String,
    passkey: Passkey,
}
impl Credential {
    pub fn id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.passkey.cred_id().as_slice())
    }
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    /// Stable key and identity binding for an independently provisioned registry.
    /// Counters, backup state and transport hints are intentionally excluded.
    /// This is an identity comparison, not proof of activation or authorization.
    pub fn key_fingerprint(&self) -> Result<String> {
        use webauthn_rs::prelude::{COSEAlgorithm, COSEKeyType, ECDSACurve};

        principal_uuid(&self.principal_id)?;
        self.validate(&self.principal_id)?;
        // Match the algorithms offered by this local verifier. A deserialized
        // record must not relabel an RSA key as ECDSA (or use an unsupported
        // algorithm) merely because OpenSSL can decode its key material.
        let public_key = self.passkey.get_public_key();
        let supported_key = match (public_key.type_, &public_key.key) {
            (COSEAlgorithm::ES256, COSEKeyType::EC_EC2(key)) => {
                key.curve == ECDSACurve::SECP256R1
                    && (1..=33).contains(&key.x.len())
                    && (1..=33).contains(&key.y.len())
            }
            (COSEAlgorithm::RS256, COSEKeyType::RSA(key)) => {
                // The pinned registration profile supports 2048-bit RSA with
                // a three-byte exponent. Checking the high bit also rejects a
                // weak modulus padded to the expected serialized length.
                key.n.len() == 256
                    && key.n.as_slice()[0] & 0x80 != 0
                    && key.n.as_slice()[255] & 1 != 0
                    && key.e[2] & 1 != 0
                    && key.e != [0, 0, 1]
            }
            _ => false,
        };
        if !supported_key {
            return Err(Error::Input);
        }
        // DER SubjectPublicKeyInfo canonicalizes the public key rather than
        // fingerprinting mutable Passkey JSON or COSE coordinate encodings.
        let der = public_key
            .get_openssl_pkey()
            .map_err(|_| Error::Input)?
            .public_key_to_der()
            .map_err(|_| Error::Input)?;
        if der.len() > 8192 {
            return Err(Error::Input);
        }
        let binding = serde_json::json!({
            "principal_id": self.principal_id,
            "rp_id": self.rp_id,
            "credential_id": self.id(),
            "algorithm": self.passkey.cred_algorithm(),
            "spki_der": URL_SAFE_NO_PAD.encode(der),
        });
        let mut bytes = b"fw.webauthn-key-binding.v1\0".to_vec();
        bytes.extend(fw_contracts::canonical_bytes(&binding).map_err(|_| Error::Input)?);
        Ok(fw_contracts::hash_bytes(&bytes))
    }
    fn validate(&self, principal: &str) -> Result<()> {
        if self.schema_version != "fw.local-passkey/v1"
            || self.principal_id != principal
            || self.rp_id != RP_ID
            || self.passkey.cred_id().is_empty()
            || self.passkey.cred_id().len() > 1024
        {
            return Err(Error::Input);
        }
        Ok(())
    }
}

/// Never return this value in an HTTP response or a browser cookie.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationState {
    schema_version: String,
    principal_id: String,
    origin: String,
    inner: PasskeyRegistration,
}
/// Never return this value in an HTTP response or a browser cookie.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationState {
    schema_version: String,
    principal_id: String,
    origin: String,
    credentials: Vec<Credential>,
    inner: PasskeyAuthentication,
}
/// Server-only state for an externally derived, domain-separated challenge.
/// This is deliberately not interchangeable with ordinary login state.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundAuthenticationState {
    schema_version: String,
    principal_id: String,
    origin: String,
    challenge: [u8; 32],
    credentials: Vec<Credential>,
    inner: PasskeyAuthentication,
}
pub struct RegistrationCeremony {
    /// JSON object containing `publicKey`, for navigator.credentials.create.
    pub options: Value,
    pub state: RegistrationState,
}
pub struct AuthenticationCeremony {
    /// JSON object containing `publicKey`, for navigator.credentials.get.
    pub options: Value,
    pub state: AuthenticationState,
}
pub struct BoundAuthenticationCeremony {
    /// JSON object containing `publicKey`, for navigator.credentials.get.
    pub options: Value,
    pub state: BoundAuthenticationState,
}

/// The unsigned browser extension outputs are admitted but never authority.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientExtensions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredentialProperties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uvm: Option<Vec<[u32; 3]>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProperties {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistrationResponse {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: RegistrationAuthenticatorResponse,
    #[serde(default)]
    pub client_extension_results: ClientExtensions,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistrationAuthenticatorResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub attestation_object: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthenticationResponse {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AuthenticationAuthenticatorResponse,
    #[serde(default)]
    pub client_extension_results: ClientExtensions,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthenticationAuthenticatorResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
}

pub struct WebAuthn {
    origin: String,
    inner: Webauthn,
}
impl WebAuthn {
    /// This release only serves the console-owned, loopback local profile.
    /// IP origins and remote origins are deliberately unsupported.
    pub fn new(origin: &str) -> Result<Self> {
        let url = Url::parse(origin).map_err(|_| Error::Configuration)?;
        if url.scheme() != "http"
            || url.host_str() != Some(RP_ID)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || url.origin().ascii_serialization() != origin
        {
            return Err(Error::Configuration);
        }
        let inner = WebauthnBuilder::new(RP_ID, &url)
            .map_err(|_| Error::Configuration)?
            .rp_name("Firewall management")
            .allow_subdomains(false)
            .allow_any_port(false)
            .timeout(Duration::from_secs(CEREMONY_SECONDS as u64))
            .build()
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            origin: origin.into(),
            inner,
        })
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn rp_id(&self) -> &str {
        RP_ID
    }

    pub fn begin_registration(
        &self,
        principal_id: &str,
        display_name: &str,
        existing: &[Credential],
    ) -> Result<RegistrationCeremony> {
        let principal = principal_uuid(principal_id)?;
        if display_name.trim().is_empty()
            || display_name.len() > 128
            || display_name.chars().any(char::is_control)
            || existing.len() >= MAX_CREDENTIALS
        {
            return Err(Error::Input);
        }
        validate_credentials(existing, principal_id)?;
        let excluded = existing
            .iter()
            .map(|c| c.passkey.cred_id().clone())
            .collect();
        let (options, inner) = self
            .inner
            .start_passkey_registration(principal, principal_id, display_name, Some(excluded))
            .map_err(|_| Error::Verification)?;
        Ok(RegistrationCeremony {
            options: serde_json::to_value(options).map_err(|_| Error::Input)?,
            state: RegistrationState {
                schema_version: "fw.passkey-registration/v1".into(),
                principal_id: principal_id.into(),
                origin: self.origin.clone(),
                inner,
            },
        })
    }
    pub fn finish_registration(
        &self,
        state: &RegistrationState,
        response: &RegistrationResponse,
    ) -> Result<Credential> {
        principal_uuid(&state.principal_id)?;
        if state.origin != self.origin || state.schema_version != "fw.passkey-registration/v1" {
            return Err(Error::Stale);
        }
        let raw_id = validate_id(&response.id, &response.raw_id, &response.type_)?;
        validate_client_data(
            &response.response.client_data_json,
            "webauthn.create",
            &self.origin,
        )?;
        decode(&response.response.attestation_object, 32_768)?;
        validate_extensions(&response.client_extension_results)?;
        if response.response.transports.as_ref().is_some_and(|v| {
            v.len() > 6
                || v.iter().any(|s| {
                    !["usb", "nfc", "ble", "internal", "hybrid", "smart-card"].contains(&s.as_str())
                })
        }) {
            return Err(Error::Input);
        }
        let reg: RegisterPublicKeyCredential =
            serde_json::from_value(serde_json::to_value(response).map_err(|_| Error::Input)?)
                .map_err(|_| Error::Input)?;
        let passkey = self
            .inner
            .finish_passkey_registration(&reg, &state.inner)
            .map_err(|_| Error::Verification)?;
        if passkey.cred_id().as_slice() != raw_id {
            return Err(Error::Verification);
        }
        Ok(Credential {
            schema_version: "fw.local-passkey/v1".into(),
            principal_id: state.principal_id.clone(),
            rp_id: RP_ID.into(),
            passkey,
        })
    }
    pub fn begin_authentication(
        &self,
        principal_id: &str,
        credentials: &[Credential],
    ) -> Result<AuthenticationCeremony> {
        principal_uuid(principal_id)?;
        if credentials.is_empty() {
            return Err(Error::Input);
        }
        validate_credentials(credentials, principal_id)?;
        let keys: Vec<_> = credentials.iter().map(|c| c.passkey.clone()).collect();
        let (options, inner) = self
            .inner
            .start_passkey_authentication(&keys)
            .map_err(|_| Error::Verification)?;
        Ok(AuthenticationCeremony {
            options: serde_json::to_value(options).map_err(|_| Error::Input)?,
            state: AuthenticationState {
                schema_version: "fw.passkey-authentication/v1".into(),
                principal_id: principal_id.into(),
                origin: self.origin.clone(),
                credentials: credentials.to_vec(),
                inner,
            },
        })
    }
    pub fn finish_authentication(
        &self,
        state: &AuthenticationState,
        response: &AuthenticationResponse,
        current: &Credential,
    ) -> Result<Credential> {
        if state.origin != self.origin || state.schema_version != "fw.passkey-authentication/v1" {
            return Err(Error::Stale);
        }
        self.finish_authentication_for(
            &state.principal_id,
            &state.credentials,
            &state.inner,
            response,
            current,
            None,
        )
    }

    /// Start verification of a caller-derived, domain-separated challenge.
    /// The caller must derive this digest from its validated immutable payload
    /// and a fresh random nonce of at least 32 bytes. A client-selected digest
    /// is not acceptable. This method does not establish consent or authority.
    pub fn begin_bound_authentication(
        &self,
        principal_id: &str,
        credentials: &[Credential],
        expected_challenge: [u8; 32],
    ) -> Result<BoundAuthenticationCeremony> {
        principal_uuid(principal_id)?;
        if credentials.is_empty() {
            return Err(Error::Input);
        }
        validate_credentials(credentials, principal_id)?;
        let keys: Vec<_> = credentials.iter().map(|c| c.passkey.clone()).collect();
        let (options, inner) = self
            .inner
            .start_passkey_authentication_with_challenge(&keys, expected_challenge)
            .map_err(|_| Error::Verification)?;
        Ok(BoundAuthenticationCeremony {
            options: serde_json::to_value(options).map_err(|_| Error::Input)?,
            state: BoundAuthenticationState {
                schema_version: "fw.bound-passkey-authentication/v1".into(),
                principal_id: principal_id.into(),
                origin: self.origin.clone(),
                challenge: expected_challenge,
                credentials: credentials.to_vec(),
                inner,
            },
        })
    }

    /// Verify a bound proof against a freshly rederived expected challenge.
    /// The caller must atomically consume its challenge and persist the returned
    /// credential update; a successful signature alone is not policy approval.
    pub fn finish_bound_authentication(
        &self,
        state: &BoundAuthenticationState,
        response: &AuthenticationResponse,
        current: &Credential,
        expected_challenge: [u8; 32],
    ) -> Result<Credential> {
        if state.origin != self.origin
            || state.schema_version != "fw.bound-passkey-authentication/v1"
            || state.challenge != expected_challenge
        {
            return Err(Error::Stale);
        }
        self.finish_authentication_for(
            &state.principal_id,
            &state.credentials,
            &state.inner,
            response,
            current,
            Some(&expected_challenge),
        )
    }

    fn finish_authentication_for(
        &self,
        principal_id: &str,
        credentials: &[Credential],
        inner: &PasskeyAuthentication,
        response: &AuthenticationResponse,
        current: &Credential,
        expected_challenge: Option<&[u8; 32]>,
    ) -> Result<Credential> {
        let principal = principal_uuid(principal_id)?;
        validate_credentials(credentials, principal_id)?;
        current.validate(principal_id)?;
        let raw_id = validate_id(&response.id, &response.raw_id, &response.type_)?;
        if current.passkey.cred_id().as_slice() != raw_id {
            return Err(Error::Verification);
        }
        let saved = credentials
            .iter()
            .find(|c| c.id() == response.id)
            .ok_or(Error::Verification)?;
        // The library's challenge embeds its credential snapshot. A changed
        // counter/backup state must not be checked using an older snapshot.
        if serde_json::to_value(saved).map_err(|_| Error::Input)?
            != serde_json::to_value(current).map_err(|_| Error::Input)?
        {
            return Err(Error::Stale);
        }
        let challenge = validate_client_data(
            &response.response.client_data_json,
            "webauthn.get",
            &self.origin,
        )?;
        if expected_challenge.is_some_and(|expected| challenge != expected) {
            return Err(Error::Verification);
        }
        let auth_data = decode(&response.response.authenticator_data, 16_384)?;
        if auth_data.len() < 37 {
            return Err(Error::Input);
        }
        decode(&response.response.signature, 2048)?;
        if let Some(handle) = &response.response.user_handle
            && decode(handle, 64)? != principal.as_bytes()
        {
            return Err(Error::Verification);
        }
        validate_extensions(&response.client_extension_results)?;
        let assertion: PublicKeyCredential =
            serde_json::from_value(serde_json::to_value(response).map_err(|_| Error::Input)?)
                .map_err(|_| Error::Input)?;
        let result = self
            .inner
            .finish_passkey_authentication(&assertion, inner)
            .map_err(|_| Error::Verification)?;
        if !result.user_verified() {
            return Err(Error::Verification);
        }
        let mut updated = current.clone();
        updated
            .passkey
            .update_credential(&result)
            .ok_or(Error::Verification)?;
        Ok(updated)
    }
}

fn principal_uuid(value: &str) -> Result<uuid::Uuid> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| Error::Input)?;
    if id.to_string() != value || id.is_nil() {
        return Err(Error::Input);
    }
    Ok(id)
}
fn validate_credentials(values: &[Credential], principal: &str) -> Result<()> {
    if values.len() > MAX_CREDENTIALS {
        return Err(Error::Input);
    }
    let mut ids = BTreeSet::new();
    for value in values {
        value.validate(principal)?;
        if !ids.insert(value.id()) {
            return Err(Error::Input);
        }
    }
    Ok(())
}
fn decode(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > maximum * 4 / 3 + 4 {
        return Err(Error::Input);
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| Error::Input)?;
    if bytes.is_empty() || bytes.len() > maximum || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::Input);
    }
    Ok(bytes)
}
fn validate_id(id: &str, raw: &str, type_: &str) -> Result<Vec<u8>> {
    if id != raw || type_ != "public-key" {
        return Err(Error::Input);
    }
    decode(id, 1024)
}
fn validate_extensions(ext: &ClientExtensions) -> Result<()> {
    if ext.uvm.as_ref().is_some_and(|v| v.len() > 16)
        || ext.cred_protect.is_some_and(|n| !(1..=3).contains(&n))
    {
        return Err(Error::Input);
    }
    Ok(())
}
fn validate_client_data(encoded: &str, expected_type: &str, origin: &str) -> Result<Vec<u8>> {
    let bytes = decode(encoded, 8192)?;
    // Parse strictly to reject ambiguous duplicate JSON keys while preserving
    // the original external clientDataJSON bytes for library signature checks.
    let data = fw_contracts::parse_value(&bytes).map_err(|_| Error::Input)?;
    if !data.is_object()
        || data["type"] != expected_type
        || data["origin"] != origin
        || data.get("crossOrigin").is_some_and(|v| v != false)
        || data.get("topOrigin").is_some()
    {
        return Err(Error::Verification);
    }
    decode(data["challenge"].as_str().ok_or(Error::Verification)?, 128)
        .map_err(|_| Error::Verification)
}

#[cfg(test)]
mod tests;

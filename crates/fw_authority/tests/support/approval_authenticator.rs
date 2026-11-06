//! Test-only software authenticator: actual P-256 signatures, no human approval.
//! Nothing in this fixture is linked into a production authority service.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fw_webauthn::{
    AuthenticationAuthenticatorResponse, AuthenticationResponse, ClientExtensions,
    RegistrationAuthenticatorResponse, RegistrationResponse,
};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const ORIGIN: &str = "http://localhost:8787";
pub const PRINCIPAL: &str = "11111111-1111-4111-8111-111111111111";

pub struct Authenticator {
    key: PKey<Private>,
    public: Vec<u8>,
    id: Vec<u8>,
    principal: uuid::Uuid,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateTestCache {
    schema_version: String,
    principal_id: String,
    credential_id: String,
    private_key_der: String,
}

impl Authenticator {
    /// Synthetic fixture only. The caller must retain this secret object only
    /// in private disposable storage; never log, report or provision it.
    #[allow(dead_code)]
    pub fn private_test_cache(&self) -> Value {
        serde_json::to_value(PrivateTestCache {
            schema_version: "fw.disposable-software-authenticator-cache/v1".into(),
            principal_id: self.principal.to_string(),
            credential_id: URL_SAFE_NO_PAD.encode(&self.id),
            private_key_der: URL_SAFE_NO_PAD.encode(
                self.key
                    .private_key_to_der()
                    .unwrap_or_else(|_| panic!("private test cache rejected")),
            ),
        })
        .unwrap_or_else(|_| panic!("private test cache rejected"))
    }

    /// Restore only the synthetic fixture key corresponding to the already
    /// pinned public credential. This creates no enrollment or owner authority.
    #[allow(dead_code)]
    pub fn from_private_test_cache(value: &Value) -> Self {
        let bytes = fw_contracts::canonical_bytes(value)
            .unwrap_or_else(|_| panic!("private test cache rejected"));
        let cache: PrivateTestCache = fw_contracts::parse_strict_with_limit(&bytes, 8192)
            .unwrap_or_else(|_| panic!("private test cache rejected"));
        assert!(
            cache.schema_version == "fw.disposable-software-authenticator-cache/v1",
            "private test cache rejected"
        );
        let principal = uuid::Uuid::parse_str(&cache.principal_id)
            .unwrap_or_else(|_| panic!("private test cache rejected"));
        assert!(
            principal.to_string() == cache.principal_id,
            "private test cache rejected"
        );
        let id = URL_SAFE_NO_PAD
            .decode(&cache.credential_id)
            .unwrap_or_else(|_| panic!("private test cache rejected"));
        let der = URL_SAFE_NO_PAD
            .decode(&cache.private_key_der)
            .unwrap_or_else(|_| panic!("private test cache rejected"));
        assert!(
            id.len() == 32
                && der.len() <= 2048
                && URL_SAFE_NO_PAD.encode(&id) == cache.credential_id
                && URL_SAFE_NO_PAD.encode(&der) == cache.private_key_der,
            "private test cache rejected"
        );
        let key = PKey::private_key_from_der(&der)
            .unwrap_or_else(|_| panic!("private test cache rejected"));
        let ec = key
            .ec_key()
            .unwrap_or_else(|_| panic!("private test cache rejected"));
        assert!(
            ec.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
            "private test cache rejected"
        );
        let public = ec
            .public_key()
            .to_bytes(
                ec.group(),
                PointConversionForm::UNCOMPRESSED,
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap_or_else(|_| panic!("private test cache rejected"));
        Self {
            key,
            public,
            id,
            principal,
        }
    }

    pub fn new(principal: &str) -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let public = key
            .public_key()
            .to_bytes(
                &group,
                PointConversionForm::UNCOMPRESSED,
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap();
        // The authority crate does not need UUID's random-generation feature.
        let mut id = vec![0; 32];
        openssl::rand::rand_bytes(&mut id).unwrap();
        Self {
            key: PKey::from_ec_key(key).unwrap(),
            public,
            id,
            principal: uuid::Uuid::parse_str(principal).unwrap(),
        }
    }

    fn client_data(options: &Value, kind: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": kind,
            "challenge": options["publicKey"]["challenge"],
            "origin": origin,
            "crossOrigin": false
        }))
        .unwrap()
    }

    pub fn registration(&self, options: &Value) -> RegistrationResponse {
        let cose = Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(2)),
            (Cbor::Integer(3), Cbor::Integer(-7)),
            (Cbor::Integer(-1), Cbor::Integer(1)),
            (Cbor::Integer(-2), Cbor::Bytes(self.public[1..33].to_vec())),
            (Cbor::Integer(-3), Cbor::Bytes(self.public[33..65].to_vec())),
        ]));
        let mut auth_data = Sha256::digest(b"localhost").to_vec();
        auth_data.push(0x45); // UP, UV, and attested credential data.
        auth_data.extend_from_slice(&0_u32.to_be_bytes());
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.id);
        auth_data.extend(serde_cbor_2::to_vec(&cose).unwrap());
        let attestation = Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
        ]));
        RegistrationResponse {
            id: URL_SAFE_NO_PAD.encode(&self.id),
            raw_id: URL_SAFE_NO_PAD.encode(&self.id),
            type_: "public-key".into(),
            response: RegistrationAuthenticatorResponse {
                client_data_json: URL_SAFE_NO_PAD.encode(Self::client_data(
                    options,
                    "webauthn.create",
                    ORIGIN,
                )),
                attestation_object: URL_SAFE_NO_PAD
                    .encode(serde_cbor_2::to_vec(&attestation).unwrap()),
                transports: Some(vec!["internal".into()]),
            },
            client_extension_results: ClientExtensions::default(),
        }
    }

    pub fn assertion(
        &self,
        options: &Value,
        counter: u32,
        flags: u8,
        origin: &str,
    ) -> AuthenticationResponse {
        let mut auth_data = Sha256::digest(b"localhost").to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut response = AuthenticationResponse {
            id: URL_SAFE_NO_PAD.encode(&self.id),
            raw_id: URL_SAFE_NO_PAD.encode(&self.id),
            type_: "public-key".into(),
            response: AuthenticationAuthenticatorResponse {
                client_data_json: URL_SAFE_NO_PAD.encode(Self::client_data(
                    options,
                    "webauthn.get",
                    origin,
                )),
                authenticator_data: URL_SAFE_NO_PAD.encode(auth_data),
                signature: String::new(),
                user_handle: Some(URL_SAFE_NO_PAD.encode(self.principal.as_bytes())),
            },
            client_extension_results: ClientExtensions::default(),
        };
        self.resign(&mut response);
        response
    }

    pub fn resign(&self, response: &mut AuthenticationResponse) {
        let mut signed = URL_SAFE_NO_PAD
            .decode(&response.response.authenticator_data)
            .unwrap();
        let original_client_data = URL_SAFE_NO_PAD
            .decode(&response.response.client_data_json)
            .unwrap();
        signed.extend_from_slice(&Sha256::digest(original_client_data));
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
        signer.update(&signed).unwrap();
        response.response.signature = URL_SAFE_NO_PAD.encode(signer.sign_to_vec().unwrap());
    }
}

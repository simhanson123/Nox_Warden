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

impl Authenticator {
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
        self.registration_at(options, ORIGIN)
    }
    pub fn registration_at(&self, options: &Value, origin: &str) -> RegistrationResponse {
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
                    origin,
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

    #[allow(dead_code)]
    pub fn cdp_credential(&self) -> Value {
        use base64::engine::general_purpose::STANDARD;
        json!({"credentialId":STANDARD.encode(&self.id),"isResidentCredential":false,"rpId":"localhost","privateKey":STANDARD.encode(self.key.private_key_to_pkcs8().unwrap()),"userHandle":STANDARD.encode(self.principal.as_bytes()),"signCount":0})
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

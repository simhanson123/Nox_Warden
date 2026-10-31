//! Authenticated, process-scoped audit pagination cursors. A valid MAC is not
//! authorization: the caller must also compare the authenticated scope, session,
//! route and requested filters before reading the bounded snapshot.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub(super) const SCHEMA: &str = "fw.audit-cursor/v1";
const MAX_CURSOR_BYTES: usize = 2048;
const TAG_BYTES: usize = 32;
const MAX_TIME: i64 = 253_402_300_799;
const MAX_LIFETIME: i64 = 900;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CursorClaims {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub principal_id: String,
    pub session_id: String,
    pub route: String,
    pub filter_after_sequence: u64,
    pub limit: usize,
    pub snapshot_sequence: u64,
    pub last_sequence: u64,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CursorError {
    Invalid,
    Expired,
    Internal,
}

type Result<T> = std::result::Result<T, CursorError>;

fn validate(claims: &CursorClaims) -> Result<()> {
    let uuid = |value: &str| uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value);
    if claims.schema_version != SCHEMA
        || ![
            &claims.org_id,
            &claims.project_id,
            &claims.principal_id,
            &claims.session_id,
        ]
        .into_iter()
        .all(|id| uuid(id))
        || claims.route.is_empty()
        || claims.route.len() > 128
        || !claims.route.bytes().all(|byte| byte.is_ascii_graphic())
        || !(1..=100).contains(&claims.limit)
        || claims.filter_after_sequence > claims.last_sequence
        || claims.last_sequence > claims.snapshot_sequence
        || !(0..=MAX_TIME).contains(&claims.issued_at)
        || claims.expires_at <= claims.issued_at
        || claims.expires_at > MAX_TIME
        || claims.expires_at - claims.issued_at > MAX_LIFETIME
    {
        return Err(CursorError::Invalid);
    }
    Ok(())
}

fn tag(payload: &[u8], secret: &[u8; TAG_BYTES]) -> Result<Vec<u8>> {
    let key = PKey::hmac(secret).map_err(|_| CursorError::Internal)?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), &key).map_err(|_| CursorError::Internal)?;
    signer.update(payload).map_err(|_| CursorError::Internal)?;
    let signature = signer.sign_to_vec().map_err(|_| CursorError::Internal)?;
    if signature.len() != TAG_BYTES {
        return Err(CursorError::Internal);
    }
    Ok(signature)
}

pub(super) fn encode(claims: &CursorClaims, secret: &[u8; TAG_BYTES]) -> Result<String> {
    validate(claims)?;
    let mut bytes = serde_json::to_vec(claims).map_err(|_| CursorError::Internal)?;
    let signature = tag(&bytes, secret)?;
    bytes.extend_from_slice(&signature);
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    if encoded.len() > MAX_CURSOR_BYTES {
        return Err(CursorError::Invalid);
    }
    Ok(encoded)
}

pub(super) fn decode(encoded: &str, secret: &[u8; TAG_BYTES], now: i64) -> Result<CursorClaims> {
    if encoded.is_empty()
        || encoded.len() > MAX_CURSOR_BYTES
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(CursorError::Invalid);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CursorError::Invalid)?;
    if bytes.len() <= TAG_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(CursorError::Invalid);
    }
    let (payload, signature) = bytes.split_at(bytes.len() - TAG_BYTES);
    if !bool::from(signature.ct_eq(tag(payload, secret)?.as_slice())) {
        return Err(CursorError::Invalid);
    }
    // Authenticate the original bytes before treating any embedded value as a
    // cursor claim. This also avoids returning an expiry oracle for forged data.
    let claims: CursorClaims = serde_json::from_slice(payload).map_err(|_| CursorError::Invalid)?;
    validate(&claims)?;
    if now < claims.issued_at {
        return Err(CursorError::Invalid);
    }
    if now >= claims.expires_at {
        return Err(CursorError::Expired);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> CursorClaims {
        CursorClaims {
            schema_version: SCHEMA.into(),
            org_id: uuid::Uuid::from_u128(1).to_string(),
            project_id: uuid::Uuid::from_u128(2).to_string(),
            principal_id: uuid::Uuid::from_u128(3).to_string(),
            session_id: uuid::Uuid::from_u128(4).to_string(),
            route: "/api/v1/audit/events".into(),
            filter_after_sequence: 10,
            limit: 50,
            snapshot_sequence: 200,
            last_sequence: 60,
            issued_at: 1_000,
            expires_at: 1_900,
        }
    }

    #[test]
    fn authenticated_roundtrip_retains_every_scope_and_snapshot_binding() {
        let expected = claims();
        let encoded = encode(&expected, &[7; 32]).unwrap();
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert!(encoded.len() <= MAX_CURSOR_BYTES);
        assert_eq!(decode(&encoded, &[7; 32], 1_100).unwrap(), expected);
        let mut large = claims();
        large.filter_after_sequence = u64::MAX - 100;
        large.last_sequence = u64::MAX - 50;
        large.snapshot_sequence = u64::MAX;
        assert_eq!(
            decode(&encode(&large, &[7; 32]).unwrap(), &[7; 32], 1_100).unwrap(),
            large
        );
    }

    #[test]
    fn altered_payload_tag_and_process_key_cannot_forge_a_cursor() {
        let encoded = encode(&claims(), &[7; 32]).unwrap();
        let original = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        for index in [0, original.len() - 1] {
            let mut altered = original.clone();
            altered[index] ^= 1;
            assert_eq!(
                decode(&URL_SAFE_NO_PAD.encode(altered), &[7; 32], 1_100),
                Err(CursorError::Invalid)
            );
        }
        assert_eq!(decode(&encoded, &[8; 32], 1_100), Err(CursorError::Invalid));
        assert_eq!(
            decode(
                &URL_SAFE_NO_PAD.encode(&original[..TAG_BYTES]),
                &[7; 32],
                1_100
            ),
            Err(CursorError::Invalid)
        );
    }

    #[test]
    fn expiry_and_clock_rollback_do_not_extend_the_snapshot_lifetime() {
        let encoded = encode(&claims(), &[7; 32]).unwrap();
        assert_eq!(decode(&encoded, &[7; 32], 999), Err(CursorError::Invalid));
        assert!(decode(&encoded, &[7; 32], 1_899).is_ok());
        assert_eq!(decode(&encoded, &[7; 32], 1_900), Err(CursorError::Expired));
        assert_eq!(
            decode(&encoded, &[7; 32], i64::MAX),
            Err(CursorError::Expired)
        );
    }

    #[test]
    fn malformed_or_oversized_transport_is_rejected_without_parsing_claims() {
        let encoded = encode(&claims(), &[7; 32]).unwrap();
        for value in [
            String::new(),
            format!("{encoded}="),
            "A".repeat(MAX_CURSOR_BYTES + 1),
            "not.a.cursor".into(),
            "A".into(),
        ] {
            assert_eq!(decode(&value, &[7; 32], 1_100), Err(CursorError::Invalid));
        }
        let mut invalid_json = b"{invalid json".to_vec();
        invalid_json.extend_from_slice(&[0; TAG_BYTES]);
        assert_eq!(
            decode(&URL_SAFE_NO_PAD.encode(invalid_json), &[7; 32], 1_100),
            Err(CursorError::Invalid)
        );
    }

    #[test]
    fn invalid_semantic_bounds_are_rejected_even_when_authentic() {
        let mut cases = Vec::new();
        let original = claims();
        for limit in [0, 101] {
            let mut value = original.clone();
            value.limit = limit;
            cases.push(value);
        }
        let mut value = original.clone();
        value.filter_after_sequence = 61;
        cases.push(value);
        let mut value = original.clone();
        value.last_sequence = 201;
        cases.push(value);
        let mut value = original.clone();
        value.expires_at = 1_901;
        cases.push(value);
        let mut value = original.clone();
        value.expires_at = value.issued_at;
        cases.push(value);
        let mut value = original.clone();
        value.issued_at = -1;
        cases.push(value);
        let mut value = original.clone();
        value.schema_version = "unknown".into();
        cases.push(value);
        let mut value = original.clone();
        value.session_id = "unbound".into();
        cases.push(value);
        let mut value = original.clone();
        value.route = "\n".into();
        cases.push(value);
        for invalid in cases {
            assert_eq!(encode(&invalid, &[7; 32]), Err(CursorError::Invalid));
            let mut bytes = serde_json::to_vec(&invalid).unwrap();
            bytes.extend_from_slice(&tag(&bytes, &[7; 32]).unwrap());
            assert_eq!(
                decode(&URL_SAFE_NO_PAD.encode(bytes), &[7; 32], 1_100),
                Err(CursorError::Invalid)
            );
        }
        let mut unknown = serde_json::to_value(original).unwrap();
        unknown["unchecked_scope"] = true.into();
        let mut bytes = serde_json::to_vec(&unknown).unwrap();
        bytes.extend_from_slice(&tag(&bytes, &[7; 32]).unwrap());
        assert_eq!(
            decode(&URL_SAFE_NO_PAD.encode(bytes), &[7; 32], 1_100),
            Err(CursorError::Invalid)
        );
    }
}

//! Authenticated, process-scoped collection pagination cursors. A valid MAC is not
//! authorization: the caller must also compare the authenticated scope, session,
//! route and requested filters before reading the bounded snapshot.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub(super) const SCHEMA: &str = "fw.collection-cursor/v1";
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
    pub eligible: bool,
    pub limit: usize,
    pub snapshot: fw_store::collections::CollectionSnapshot,
    pub after: fw_store::collections::CollectionKey,
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
        || claims.snapshot.version < 0
        || claims.snapshot.issued_at != claims.issued_at
        || !(0..=MAX_TIME).contains(&claims.after.created_at)
        || claims.after.id.is_empty()
        || claims.after.id.len() > 128
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
            route: "/api/v1/assets".into(),
            eligible: true,
            limit: 50,
            snapshot: fw_store::collections::CollectionSnapshot {
                version: 30,
                issued_at: 1000,
            },
            after: fw_store::collections::CollectionKey {
                created_at: 900,
                id: uuid::Uuid::from_u128(5).to_string(),
            },
            issued_at: 1000,
            expires_at: 1900,
        }
    }
    #[test]
    fn snapshot_scope_roundtrips_and_expires_at_fifteen_minutes() {
        let c = claims();
        let token = encode(&c, &[7; 32]).unwrap();
        assert_eq!(decode(&token, &[7; 32], 1899).unwrap(), c);
        assert_eq!(decode(&token, &[7; 32], 1900), Err(CursorError::Expired));
        assert_eq!(decode(&token, &[7; 32], 999), Err(CursorError::Invalid));
        assert_eq!(decode(&token, &[8; 32], 1100), Err(CursorError::Invalid));
    }
    #[test]
    fn changed_payload_tag_schema_and_bounds_are_rejected() {
        let token = encode(&claims(), &[7; 32]).unwrap();
        let original = URL_SAFE_NO_PAD.decode(&token).unwrap();
        for index in 0..original.len() {
            let mut changed = original.clone();
            changed[index] ^= 1;
            assert_eq!(
                decode(&URL_SAFE_NO_PAD.encode(changed), &[7; 32], 1100),
                Err(CursorError::Invalid)
            );
        }
        for n in [0, 101] {
            let mut c = claims();
            c.limit = n;
            assert_eq!(encode(&c, &[7; 32]), Err(CursorError::Invalid));
        }
        let mut c = claims();
        c.schema_version = "fw.audit-cursor/v1".into();
        assert_eq!(encode(&c, &[7; 32]), Err(CursorError::Invalid));
        let mut c = claims();
        c.snapshot.issued_at = 999;
        assert_eq!(encode(&c, &[7; 32]), Err(CursorError::Invalid));
        assert_eq!(
            decode(&"a".repeat(2049), &[7; 32], 1100),
            Err(CursorError::Invalid)
        );
    }
}

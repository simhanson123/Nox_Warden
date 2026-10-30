//! Bounded, duplicate-free JSON admission and the F-2.0 restricted JCS profile.
//!
//! Canonicalization preserves string bytes and array order. Domain-specific NFC
//! and set sorting must happen before hashing; signed payloads must never be
//! normalized again. The published contract uses ASCII property names and safe
//! JSON integers, so floating-point and non-ASCII property names are rejected.
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;

mod float_guard;

pub const MAX_BODY_BYTES: usize = 65_536;
/// Upper bound for explicit internal artifact/evidence admission. Public APIs
/// continue to use `MAX_BODY_BYTES` through `parse_value` / `parse_strict`.
pub const MAX_INTERNAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DEPTH: usize = 32;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("BODY_TOO_LARGE")]
    BodyTooLarge,
    #[error("INVALID_JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("INVALID_CANONICAL_VALUE: {0}")]
    Canonical(&'static str),
    #[error("INVALID_COUNTER")]
    Counter,
}

struct StrictSeed(usize);
struct StrictVisitor(usize);

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(StrictVisitor(self.0))
    }
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON with unique ASCII keys and safe integers")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        if v.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom("UNSAFE_JSON_INTEGER"));
        }
        Ok(Value::Number(Number::from(v)))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        if v > MAX_SAFE_INTEGER {
            return Err(E::custom("UNSAFE_JSON_INTEGER"));
        }
        Ok(Value::Number(Number::from(v)))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Value, E> {
        Err(E::custom("FLOAT_NOT_ALLOWED"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        if self.0 >= MAX_DEPTH {
            return Err(de::Error::custom("MAX_DEPTH_EXCEEDED"));
        }
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(StrictSeed(self.0 + 1))? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        if self.0 >= MAX_DEPTH {
            return Err(de::Error::custom("MAX_DEPTH_EXCEEDED"));
        }
        let mut values = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if !key.is_ascii() {
                return Err(de::Error::custom("NON_ASCII_PROPERTY"));
            }
            if values.contains_key(&key) {
                return Err(de::Error::custom("DUPLICATE_JSON_KEY"));
            }
            values.insert(key, access.next_value_seed(StrictSeed(self.0 + 1))?);
        }
        Ok(Value::Object(values))
    }
}

/// Strict syntax admission. Unknown-field rejection belongs to the destination
/// closed type; use `parse_strict::<YourDenyUnknownFieldsType>` for API objects.
pub fn parse_value(bytes: &[u8]) -> Result<Value, ContractError> {
    parse_value_with_limit(bytes, MAX_BODY_BYTES)
}

/// Internal callers must choose an explicit bounded budget; all strict syntax
/// checks remain identical to the public parser. A budget above 16 MiB is invalid.
pub fn parse_value_with_limit(bytes: &[u8], max_bytes: usize) -> Result<Value, ContractError> {
    if max_bytes == 0 || max_bytes > MAX_INTERNAL_BYTES || bytes.len() > max_bytes {
        return Err(ContractError::BodyTooLarge);
    }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let result = StrictSeed(0).deserialize(&mut d)?;
    d.end()?;
    Ok(result)
}

pub fn parse_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ContractError> {
    Ok(serde_json::from_value(parse_value(bytes)?)?)
}

pub fn parse_strict_with_limit<T: DeserializeOwned>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, ContractError> {
    Ok(serde_json::from_value(parse_value_with_limit(
        bytes, max_bytes,
    )?)?)
}

fn canonical_value(value: &Value, depth: usize, out: &mut Vec<u8>) -> Result<(), ContractError> {
    match value {
        Value::Object(values) => {
            if depth >= MAX_DEPTH {
                return Err(ContractError::Canonical("MAX_DEPTH_EXCEEDED"));
            }
            out.push(b'{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if !key.is_ascii() {
                    return Err(ContractError::Canonical("NON_ASCII_PROPERTY"));
                }
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key)?;
                out.push(b':');
                canonical_value(&values[*key], depth + 1, out)?;
            }
            out.push(b'}');
        }
        Value::Array(values) => {
            if depth >= MAX_DEPTH {
                return Err(ContractError::Canonical("MAX_DEPTH_EXCEEDED"));
            }
            out.push(b'[');
            for (i, value) in values.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_value(value, depth + 1, out)?;
            }
            out.push(b']');
        }
        Value::Number(number) => {
            let safe = number.as_u64().is_some_and(|n| n <= MAX_SAFE_INTEGER)
                || number
                    .as_i64()
                    .is_some_and(|n| n.unsigned_abs() <= MAX_SAFE_INTEGER);
            if !safe {
                return Err(ContractError::Canonical("UNSAFE_OR_FLOAT_NUMBER"));
            }
            serde_json::to_writer(out, number)?;
        }
        _ => serde_json::to_writer(out, value)?,
    }
    Ok(())
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    value.serialize(float_guard::FloatGuard(0))?;
    let mut bytes = Vec::new();
    canonical_value(&serde_json::to_value(value)?, 0, &mut bytes)?;
    Ok(bytes)
}

pub fn canonical_hash<T: Serialize>(value: &T) -> Result<String, ContractError> {
    Ok(hash_bytes(&canonical_bytes(value)?))
}

/// Hash exact bytes, suitable for already-signed evidence without reserialization.
pub fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Wire counters are decimal strings, avoiding JSON/JavaScript precision loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Counter(pub u64);

impl Counter {
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(ContractError::Counter);
        }
        value.parse().map(Self).map_err(|_| ContractError::Counter)
    }
    pub fn checked_next(self) -> Result<Self, ContractError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ContractError::Counter)
    }
}

impl Serialize for Counter {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Counter {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(de::Error::custom)
    }
}

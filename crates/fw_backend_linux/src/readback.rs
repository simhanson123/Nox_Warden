//! Conservative comparison for this crate's experimental TCP/UDP artifact.
//!
//! This is a bounded nft JSON interpretation, not a general nftables evaluator.
//! Unknown fields/expressions never yield a semantic match. The caller supplies
//! the trusted, unaltered original compiler artifact, a trusted observation time,
//! and nft output captured in UTC. Artifact origin and its desired policy hash
//! are not authenticated or reconstructed here. A single snapshot
//! bounds remaining token life; it cannot attest prior refreshes, ownership of
//! the transport, absence of other tables, or production authority.
use crate::Artifact;
use fw_contracts::canonical_hash;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Comparison {
    Match,
    Mismatch,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct ReadbackVerification {
    pub schema_version: &'static str,
    pub comparison: Comparison,
    pub expected_state_hash: String,
    /// The trusted artifact's desired policy hash after correspondence succeeds;
    /// this is not an independently reconstructed or authenticated policy hash.
    pub observed_semantic_hash: Option<String>,
    /// Hash of the canonical, unnormalized JSON snapshot, not stdout whitespace.
    pub readback_hash: Option<String>,
    pub reason_code: Option<&'static str>,
    pub rules_checked: usize,
    pub tokens_checked: usize,
    pub production_qualified: bool,
}

#[derive(Debug)]
enum Failure {
    Unknown(&'static str),
    Mismatch(&'static str),
}
type Result<T> = std::result::Result<T, Failure>;
fn unknown<T>(code: &'static str) -> Result<T> {
    Err(Failure::Unknown(code))
}
fn mismatch<T>(code: &'static str) -> Result<T> {
    Err(Failure::Mismatch(code))
}
fn object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>> {
    let map = value
        .as_object()
        .ok_or(Failure::Unknown("UNSUPPORTED_SHAPE"))?;
    if required.iter().any(|k| !map.contains_key(*k))
        || map
            .keys()
            .any(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
    {
        return unknown("UNSUPPORTED_FIELD");
    }
    Ok(map)
}
fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or(Failure::Unknown("UNSUPPORTED_VALUE"))
}
fn number(value: &Value, maximum: u64) -> Result<u64> {
    value
        .as_u64()
        .filter(|v| *v <= maximum)
        .ok_or(Failure::Unknown("UNSUPPORTED_NUMBER"))
}
fn singleton<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    Ok(&object(value, &[key], &[])?[key])
}
fn members(value: &Value) -> Result<Vec<&Value>> {
    if value.as_object().is_some_and(|v| v.contains_key("set")) {
        singleton(value, "set")?
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= 256)
            .map(|v| v.iter().collect())
            .ok_or(Failure::Unknown("UNSUPPORTED_SET"))
    } else {
        Ok(vec![value])
    }
}
fn protocol(value: &Value) -> Result<u64> {
    match value.as_str() {
        Some("tcp") => Ok(6),
        Some("udp") => Ok(17),
        Some(_) => unknown("UNSUPPORTED_PROTOCOL"),
        None => match number(value, 255)? {
            n @ (6 | 17) => Ok(n),
            _ => unknown("UNSUPPORTED_PROTOCOL"),
        },
    }
}
fn family(value: &Value) -> Result<&'static str> {
    match value.as_str() {
        Some("ipv4") => Ok("ipv4"),
        Some("ipv6") => Ok("ipv6"),
        _ => match value.as_u64() {
            Some(2) => Ok("ipv4"),
            Some(10) => Ok("ipv6"),
            _ => unknown("UNSUPPORTED_FAMILY"),
        },
    }
}
fn merge_ranges(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable();
    let mut result: Vec<(u128, u128)> = Vec::new();
    for (lo, hi) in ranges {
        if let Some(last) = result.last_mut() {
            if lo <= last.1.saturating_add(1) {
                last.1 = last.1.max(hi);
                continue;
            }
        }
        result.push((lo, hi));
    }
    result
}
fn ip(value: &Value) -> Result<(u128, u8)> {
    let address: IpAddr = text(value)?
        .parse()
        .map_err(|_| Failure::Unknown("UNSUPPORTED_ADDRESS"))?;
    Ok(match address {
        IpAddr::V4(v) => (u32::from(v) as u128, 32),
        IpAddr::V6(v) => (u128::from(v), 128),
    })
}
fn address_ranges(value: &Value) -> Result<(String, Vec<String>)> {
    let mut width = None;
    let mut ranges = Vec::new();
    for member in members(value)? {
        let (lo, hi, bits) = if member.is_string() {
            let (n, bits) = ip(member)?;
            (n, n, bits)
        } else if member.get("prefix").is_some() {
            let prefix = singleton(member, "prefix")?;
            object(prefix, &["addr", "len"], &[])?;
            let (n, bits) = ip(&prefix["addr"])?;
            let len = number(&prefix["len"], bits as u64)? as u32;
            let host_bits = bits as u32 - len;
            let host_mask = if host_bits == 128 {
                u128::MAX
            } else {
                (1u128 << host_bits) - 1
            };
            if n & host_mask != 0 {
                return unknown("NONCANONICAL_PREFIX");
            }
            (n, n | host_mask, bits)
        } else {
            let pair = singleton(member, "range")?
                .as_array()
                .filter(|v| v.len() == 2)
                .ok_or(Failure::Unknown("UNSUPPORTED_RANGE"))?;
            let (lo, bits) = ip(&pair[0])?;
            let (hi, other_bits) = ip(&pair[1])?;
            if bits != other_bits || lo > hi {
                return unknown("UNSUPPORTED_RANGE");
            }
            (lo, hi, bits)
        };
        if width.is_some_and(|w| w != bits) {
            return unknown("MIXED_ADDRESS_FAMILIES");
        }
        width = Some(bits);
        ranges.push((lo, hi));
    }
    let family = if width == Some(32) { "ipv4" } else { "ipv6" };
    Ok((
        family.into(),
        merge_ranges(ranges)
            .iter()
            .map(|(lo, hi)| format!("{lo:032x}-{hi:032x}"))
            .collect(),
    ))
}
fn port_ranges(value: &Value) -> Result<Vec<String>> {
    let mut ranges = Vec::new();
    for member in members(value)? {
        let (lo, hi) = if member.is_u64() {
            let n = number(member, 65535)?;
            (n, n)
        } else {
            let pair = singleton(member, "range")?
                .as_array()
                .filter(|v| v.len() == 2)
                .ok_or(Failure::Unknown("UNSUPPORTED_RANGE"))?;
            (number(&pair[0], 65535)?, number(&pair[1], 65535)?)
        };
        if lo > hi {
            return unknown("UNSUPPORTED_RANGE");
        }
        ranges.push((lo as u128, hi as u128));
    }
    Ok(merge_ranges(ranges)
        .iter()
        .map(|(lo, hi)| format!("{lo:05}-{hi:05}"))
        .collect())
}
fn flags(value: &Value) -> Result<u64> {
    if value.is_u64() {
        return number(value, 255);
    }
    let items: Vec<&Value> = match value.as_array() {
        Some(a) if !a.is_empty() && a.len() <= 8 => a.iter().collect(),
        Some(_) => return unknown("UNSUPPORTED_FLAGS"),
        None => vec![value],
    };
    let mut result = 0;
    for item in items {
        let bit = match text(item)? {
            "fin" => 1,
            "syn" => 2,
            "rst" => 4,
            "psh" => 8,
            "ack" => 16,
            "urg" => 32,
            "ecn" => 64,
            "cwr" => 128,
            _ => return unknown("UNSUPPORTED_FLAGS"),
        };
        if result & bit != 0 {
            return unknown("DUPLICATE_FLAG");
        }
        result |= bit;
    }
    Ok(result)
}
fn cutoff(value: &Value) -> Result<i64> {
    if let Some(n) = value.as_i64().filter(|n| *n >= 0) {
        return Ok(n);
    }
    let raw = text(value)?;
    let date = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S")
        .map_err(|_| Failure::Unknown("UNSUPPORTED_TIME"))?;
    if date.format("%Y-%m-%d %H:%M:%S").to_string() != raw {
        return unknown("UNSUPPORTED_TIME");
    }
    Ok(date.and_utc().timestamp())
}

#[derive(Debug, PartialEq, Eq)]
struct Rule {
    comment: String,
    matches: BTreeMap<String, Vec<String>>,
    verdict: String,
}
fn insert(
    matches: &mut BTreeMap<String, Vec<String>>,
    key: String,
    values: Vec<String>,
) -> Result<()> {
    if key == "ct.state" {
        if let Some(old) = matches.get_mut(&key) {
            old.retain(|v| values.contains(v));
            if old.is_empty() {
                return unknown("CONTRADICTORY_MATCH");
            }
            return Ok(());
        }
    }
    if matches.insert(key, values).is_some() {
        return unknown("DUPLICATE_MATCH");
    }
    Ok(())
}
fn normalize_rule(value: &Value) -> Result<Rule> {
    let expr = value["expr"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 32)
        .ok_or(Failure::Unknown("UNSUPPORTED_EXPRESSION"))?;
    let mut matches = BTreeMap::new();
    let mut inferred_family: Option<String> = None;
    let mut verdict = None;
    for (index, statement) in expr.iter().enumerate() {
        let map = statement
            .as_object()
            .filter(|v| v.len() == 1)
            .ok_or(Failure::Unknown("UNSUPPORTED_EXPRESSION"))?;
        if let Some((name, operand)) = map
            .iter()
            .find(|(k, _)| matches!(k.as_str(), "accept" | "drop"))
        {
            if index + 1 != expr.len() || !operand.is_null() {
                return unknown("UNSUPPORTED_VERDICT");
            }
            verdict = Some(name.clone());
            continue;
        }
        let condition = singleton(statement, "match")?;
        object(condition, &["left", "op", "right"], &[])?;
        let left = &condition["left"];
        let right = &condition["right"];
        let op = text(&condition["op"])?;
        let (key, values) = if let Some(meta) = left.get("meta") {
            singleton(left, "meta")?;
            object(meta, &["key"], &[])?;
            match text(&meta["key"])? {
                "time" if op == "<" => ("meta.time".into(), vec![cutoff(right)?.to_string()]),
                "nfproto" if op == "==" => ("meta.nfproto".into(), vec![family(right)?.into()]),
                "l4proto" if op == "==" => {
                    ("meta.l4proto".into(), vec![protocol(right)?.to_string()])
                }
                name @ ("iifname" | "oifname") if matches!(op, "==" | "in") => {
                    let mut names = BTreeSet::new();
                    for v in members(right)? {
                        let s = text(v)?;
                        if s.is_empty()
                            || s.len() > 15
                            || !s
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
                        {
                            return unknown("UNSUPPORTED_INTERFACE");
                        }
                        if !names.insert(s.to_owned()) {
                            return unknown("DUPLICATE_SET_MEMBER");
                        }
                    }
                    (format!("meta.{name}"), names.into_iter().collect())
                }
                _ => return unknown("UNSUPPORTED_META_MATCH"),
            }
        } else if let Some(ct) = left.get("ct") {
            singleton(left, "ct")?;
            object(ct, &["key"], &["dir", "family"])?;
            let name = text(&ct["key"])?;
            if !matches!(op, "==" | "in") {
                return unknown("UNSUPPORTED_CT_OPERATOR");
            }
            if matches!(name, "saddr" | "daddr" | "proto-dst") {
                if ct.get("dir").and_then(Value::as_str) != Some("original") {
                    return unknown("UNSUPPORTED_CT_DIRECTION");
                }
            } else if name == "protocol" {
                if ct.get("dir").is_some_and(|v| v != "original") || ct.get("family").is_some() {
                    return unknown("UNSUPPORTED_CT_FIELD");
                }
            } else if ct.get("dir").is_some() || ct.get("family").is_some() {
                return unknown("UNSUPPORTED_CT_FIELD");
            }
            match name {
                "saddr" | "daddr" => {
                    let (family, ranges) = address_ranges(right)?;
                    if inferred_family.as_ref().is_some_and(|f| f != &family)
                        || ct
                            .get("family")
                            .is_some_and(|f| f != if family == "ipv4" { "ip" } else { "ip6" })
                    {
                        return unknown("INCONSISTENT_ADDRESS_FAMILY");
                    }
                    inferred_family = Some(family);
                    (format!("ct.{name}"), ranges)
                }
                "proto-dst" => {
                    if ct.get("family").is_some() {
                        return unknown("UNSUPPORTED_CT_FIELD");
                    }
                    ("ct.proto-dst".into(), port_ranges(right)?)
                }
                "protocol" if right.as_str().is_some_and(|s| s.starts_with('@')) => {
                    let token = text(right)?.strip_prefix('@').unwrap();
                    if !token_name(token) {
                        return unknown("UNSUPPORTED_TOKEN_REFERENCE");
                    }
                    ("ct.protocol-token".into(), vec![token.to_owned()])
                }
                "protocol" if op == "==" => {
                    ("ct.protocol".into(), vec![protocol(right)?.to_string()])
                }
                "zone" if op == "==" => ("ct.zone".into(), vec![number(right, 65535)?.to_string()]),
                "direction" if op == "==" => {
                    let direction = match right.as_str() {
                        Some(s @ ("original" | "reply")) => s,
                        _ => return unknown("UNSUPPORTED_CT_DIRECTION"),
                    };
                    ("ct.direction".into(), vec![direction.into()])
                }
                "state" => {
                    let mut states = BTreeSet::new();
                    for state in members(right)? {
                        let state = text(state)?;
                        if !matches!(state, "new" | "established" | "invalid")
                            || !states.insert(state.to_owned())
                        {
                            return unknown("UNSUPPORTED_CT_STATE");
                        }
                    }
                    ("ct.state".into(), states.into_iter().collect())
                }
                _ => return unknown("UNSUPPORTED_CT_MATCH"),
            }
        } else if left.get("&").is_some() {
            if op != "==" {
                return unknown("UNSUPPORTED_FLAGS_OPERATOR");
            }
            let operands = singleton(left, "&")?
                .as_array()
                .filter(|a| a.len() == 2)
                .ok_or(Failure::Unknown("UNSUPPORTED_FLAGS"))?;
            let payload = singleton(&operands[0], "payload")?;
            object(payload, &["protocol", "field"], &[])?;
            if payload["protocol"] != "tcp" || payload["field"] != "flags" {
                return unknown("UNSUPPORTED_PAYLOAD");
            }
            (
                "tcp.flags".into(),
                vec![flags(&operands[1])?.to_string(), flags(right)?.to_string()],
            )
        } else {
            return unknown("UNSUPPORTED_EXPRESSION");
        };
        insert(&mut matches, key, values)?;
    }
    if let Some(family) = inferred_family {
        if let Some(actual) = matches.get("meta.nfproto") {
            if actual != &[family] {
                return unknown("INCONSISTENT_ADDRESS_FAMILY");
            }
        } else {
            matches.insert("meta.nfproto".into(), vec![family]);
        }
    }
    // libnftables can omit the scalar protocol comparison when the same
    // conntrack protocol is already checked against its singleton timeout set.
    // The set's protocol is checked independently below; a different scalar is
    // retained and will mismatch instead of being discarded.
    if matches.contains_key("ct.protocol-token")
        && matches.get("ct.protocol") == matches.get("meta.l4proto")
    {
        matches.remove("ct.protocol");
    }
    Ok(Rule {
        comment: text(&value["comment"])?.to_owned(),
        matches,
        verdict: verdict.ok_or(Failure::Unknown("MISSING_VERDICT"))?,
    })
}
fn token_name(name: &str) -> bool {
    name.strip_prefix("fw_live_").is_some_and(|s| {
        s.len() == 24
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[derive(Debug)]
struct Snapshot {
    table: Value,
    chains: BTreeMap<String, Value>,
    sets: BTreeMap<String, Value>,
    rules: BTreeMap<String, Vec<Rule>>,
}
fn snapshot(value: &Value, expected: bool, table: &str) -> Result<Snapshot> {
    let items = singleton(value, "nftables")?
        .as_array()
        .filter(|v| v.len() <= 50_000)
        .ok_or(Failure::Unknown("UNSUPPORTED_SNAPSHOT"))?;
    let mut result = Snapshot {
        table: Value::Null,
        chains: BTreeMap::new(),
        sets: BTreeMap::new(),
        rules: BTreeMap::new(),
    };
    let mut metainfo_seen = false;
    for item in items {
        let item = if expected {
            singleton(item, "add")?
        } else {
            item
        };
        let map = item
            .as_object()
            .filter(|v| v.len() == 1)
            .ok_or(Failure::Unknown("UNSUPPORTED_OBJECT"))?;
        let (kind, value) = map.iter().next().unwrap();
        if kind == "metainfo" && !expected {
            object(
                value,
                &["version", "release_name", "json_schema_version"],
                &[],
            )?;
            if metainfo_seen
                || value["json_schema_version"] != 1
                || !value["version"].is_string()
                || !value["release_name"].is_string()
            {
                return unknown("UNSUPPORTED_METAINFO");
            }
            metainfo_seen = true;
            continue;
        }
        let required: &[&str] = match kind.as_str() {
            "table" => &["family", "name"],
            "chain" => &["family", "table", "name", "type", "hook", "prio", "policy"],
            "set" => &["family", "table", "name", "type", "flags"],
            "rule" => &["family", "table", "chain", "expr", "comment"],
            _ => return unknown("UNSUPPORTED_OBJECT"),
        };
        let optional: &[&str] = match (kind.as_str(), expected) {
            ("set", false) => &["handle", "elem"],
            ("set", true) => &["elem"],
            (_, false) => &["handle"],
            (_, true) => &[],
        };
        object(value, required, optional)?;
        if let Some(handle) = value.get("handle") {
            number(handle, fw_contracts::MAX_SAFE_INTEGER)?;
        }
        if value["family"] != "inet" || (kind != "table" && value["table"] != table) {
            return mismatch("SCOPE_MISMATCH");
        }
        let mut clean = value.clone();
        clean.as_object_mut().unwrap().remove("handle");
        match kind.as_str() {
            "table" => {
                if !result.table.is_null() {
                    return unknown("DUPLICATE_TABLE");
                }
                result.table = clean;
            }
            "chain" => {
                let name = text(&value["name"])?;
                if result.chains.insert(name.to_owned(), clean).is_some() {
                    return unknown("DUPLICATE_CHAIN");
                }
            }
            "set" => {
                let name = text(&value["name"])?;
                if !token_name(name) || result.sets.len() >= 10_000 {
                    return unknown("UNSUPPORTED_SET");
                }
                if result.sets.insert(name.to_owned(), clean).is_some() {
                    return unknown("DUPLICATE_SET");
                }
            }
            "rule" => {
                let chain = text(&value["chain"])?;
                let rule = normalize_rule(value)?;
                result.rules.entry(chain.to_owned()).or_default().push(rule);
            }
            _ => unreachable!(),
        }
    }
    if result.table.is_null() {
        return mismatch("MISSING_TABLE");
    }
    Ok(result)
}
fn expected_cutoffs(snapshot: &Snapshot) -> Result<BTreeMap<String, i64>> {
    let mut cutoffs = BTreeMap::new();
    if snapshot
        .chains
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != ["input", "output"]
        || snapshot
            .rules
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != ["input", "output"]
    {
        return unknown("UNSUPPORTED_ARTIFACT_CHAINS");
    }
    for (name, chain) in &snapshot.chains {
        if chain["type"] != "filter"
            || chain["hook"] != *name
            || chain["prio"] != 0
            || chain["policy"] != "drop"
        {
            return unknown("UNSUPPORTED_ARTIFACT_CHAIN");
        }
    }
    for rules in snapshot.rules.values() {
        if rules.first().is_none_or(|r| r.comment != "invalid") {
            return unknown("MISSING_INVALID_GUARD");
        }
        for rule in rules {
            if rule.comment == "invalid" {
                if rule.verdict != "drop"
                    || rule.matches != BTreeMap::from([("ct.state".into(), vec!["invalid".into()])])
                {
                    return unknown("UNSUPPORTED_ARTIFACT_RULE");
                }
                continue;
            }
            let required = [
                "meta.nfproto",
                "meta.l4proto",
                "ct.direction",
                "ct.zone",
                "ct.saddr",
                "ct.daddr",
                "ct.proto-dst",
            ];
            if required.iter().any(|k| !rule.matches.contains_key(*k)) {
                return unknown("UNSUPPORTED_ARTIFACT_RULE");
            }
            if rule.matches["ct.zone"] != ["0"] {
                return unknown("UNSUPPORTED_ARTIFACT_ZONE");
            }
            if rule.comment.starts_with("allow:") && rule.verdict == "accept" {
                let token_name = rule
                    .matches
                    .get("ct.protocol-token")
                    .and_then(|v| v.first())
                    .ok_or(Failure::Unknown("MISSING_EXPIRY_GUARD"))?;
                let set = snapshot
                    .sets
                    .get(token_name)
                    .ok_or(Failure::Unknown("UNBOUND_TOKEN"))?;
                let (protocol, _, _) =
                    token(set, true)?.ok_or(Failure::Unknown("MISSING_ARTIFACT_TOKEN"))?;
                if rule.matches["meta.l4proto"] != [protocol.to_string()]
                    || rule.matches.contains_key("ct.protocol")
                    || !rule.matches.contains_key("ct.state")
                {
                    return unknown("UNSUPPORTED_ARTIFACT_PROTOCOL");
                }
                let cutoff = rule
                    .matches
                    .get("meta.time")
                    .and_then(|v| v.first())
                    .and_then(|v| v.parse::<i64>().ok())
                    .ok_or(Failure::Unknown("MISSING_EXPIRY_GUARD"))?;
                if cutoffs
                    .insert(token_name.clone(), cutoff)
                    .is_some_and(|old| old != cutoff)
                {
                    return unknown("INCONSISTENT_EXPIRY_GUARD");
                }
            } else if !rule.comment.starts_with("deny:")
                || rule.verdict != "drop"
                || rule.matches.contains_key("meta.time")
                || rule.matches.contains_key("ct.protocol-token")
                || rule.matches.get("ct.protocol") != rule.matches.get("meta.l4proto")
            {
                return unknown("UNSUPPORTED_ARTIFACT_RULE");
            }
        }
    }
    if cutoffs.keys().ne(snapshot.sets.keys()) {
        return unknown("UNBOUND_TOKEN");
    }
    Ok(cutoffs)
}
fn token(value: &Value, expected: bool) -> Result<Option<(u64, u64, u64)>> {
    if value["type"] != "inet_proto" || value["flags"] != serde_json::json!(["timeout"]) {
        return unknown("UNSUPPORTED_TOKEN_TYPE");
    }
    let Some(elements) = value.get("elem") else {
        return if expected {
            unknown("MISSING_ARTIFACT_TOKEN")
        } else {
            Ok(None)
        };
    };
    let elements = elements
        .as_array()
        .filter(|v| v.len() <= 1)
        .ok_or(Failure::Unknown("UNSUPPORTED_TOKEN_ELEMENTS"))?;
    if elements.is_empty() {
        return if expected {
            unknown("MISSING_ARTIFACT_TOKEN")
        } else {
            Ok(None)
        };
    }
    let item = singleton(&elements[0], "elem")?;
    object(
        item,
        if expected {
            &["val", "timeout"]
        } else {
            &["val", "timeout", "expires"]
        },
        &[],
    )?;
    let protocol = protocol(&item["val"])?;
    let timeout = number(&item["timeout"], 86400)?;
    if timeout == 0 {
        return unknown("UNBOUNDED_TOKEN");
    }
    let remaining = if expected {
        timeout
    } else {
        number(&item["expires"], 86400)?
    };
    Ok(Some((protocol, timeout, remaining)))
}

fn compare(artifact: &Artifact, readback: &Value, now: i64) -> Result<(usize, usize)> {
    if artifact.schema_version != "fw.experimental-nft/v1"
        || artifact.profile != "host-tcp-udp-lab"
        || artifact.compiler_version != env!("CARGO_PKG_VERSION")
        || artifact.production_qualified
        || now < 0
        || !artifact
            .desired_state_hash
            .strip_prefix("sha256:")
            .is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    {
        return unknown("UNSUPPORTED_ARTIFACT");
    }
    let expected = snapshot(&artifact.nft_json, true, &artifact.table)?;
    if expected.table["name"] != artifact.table
        || !artifact.table.strip_prefix("fw_").is_some_and(|s| {
            s.len() == 24
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return unknown("UNSUPPORTED_ARTIFACT_SCOPE");
    }
    let actual = snapshot(readback, false, &artifact.table)?;
    let cutoffs = expected_cutoffs(&expected)?;
    if expected.table != actual.table
        || expected.chains != actual.chains
        || expected.rules != actual.rules
    {
        return mismatch("NATIVE_STRUCTURE_MISMATCH");
    }
    if expected.sets.keys().ne(actual.sets.keys()) {
        return mismatch("TOKEN_SET_MISMATCH");
    }
    for (name, intended) in &expected.sets {
        let observed = &actual.sets[name];
        let mut left = intended.clone();
        let mut right = observed.clone();
        left.as_object_mut().unwrap().remove("elem");
        right.as_object_mut().unwrap().remove("elem");
        if left != right {
            return mismatch("TOKEN_STRUCTURE_MISMATCH");
        }
        let (expected_protocol, expected_timeout, _) = token(intended, true)?.unwrap();
        let cutoff = cutoffs[name];
        match token(observed, false)? {
            Some((protocol, timeout, remaining)) => {
                if protocol != expected_protocol
                    || timeout != expected_timeout
                    || remaining > timeout
                    || remaining > cutoff.saturating_sub(now).max(0) as u64
                {
                    return mismatch("TOKEN_LIFETIME_MISMATCH");
                }
                if remaining == 0 && now < cutoff {
                    return mismatch("TOKEN_EXPIRED_EARLY");
                }
            }
            None if now >= cutoff => {}
            None => return mismatch("TOKEN_MISSING_BEFORE_CUTOFF"),
        }
    }
    Ok((
        expected.rules.values().map(Vec::len).sum(),
        expected.sets.len(),
    ))
}

/// Compare the supported managed table against the trusted, unaltered original
/// compiler artifact. This API does not authenticate the artifact or recompute
/// its desired policy hash. The caller must supply a trusted observation time
/// and an nft JSON snapshot captured in UTC. Missing tokens are accepted only
/// after their absolute cutoff; a
/// conservative early timeout may therefore fail comparison before that cutoff.
/// Unknown/mismatched snapshots never acquire a semantic state hash.
pub fn verify_readback(
    artifact: &Artifact,
    readback: &Value,
    observed_at_unix: i64,
) -> ReadbackVerification {
    let readback_hash = canonical_hash(readback).ok();
    let result = if readback_hash.is_none() {
        unknown("INVALID_CANONICAL_READBACK")
    } else {
        compare(artifact, readback, observed_at_unix)
    };
    let (comparison, reason_code, rules_checked, tokens_checked) = match result {
        Ok((rules, tokens)) => (Comparison::Match, None, rules, tokens),
        Err(Failure::Mismatch(reason)) => (Comparison::Mismatch, Some(reason), 0, 0),
        Err(Failure::Unknown(reason)) => (Comparison::Unknown, Some(reason), 0, 0),
    };
    ReadbackVerification {
        schema_version: "fw.experimental-readback/v1",
        comparison,
        expected_state_hash: artifact.desired_state_hash.clone(),
        observed_semantic_hash: (comparison == Comparison::Match)
            .then(|| artifact.desired_state_hash.clone()),
        readback_hash,
        reason_code,
        rules_checked,
        tokens_checked,
        production_qualified: false,
    }
}

/// Strictly parsed token lifetimes for the portable installation's independent
/// monotonic deadline check. Callers still perform full structural verification.
pub(crate) fn remaining_token_lifetimes(
    readback: &Value,
    table: &str,
) -> std::result::Result<BTreeMap<String, Option<u64>>, ()> {
    let observed = snapshot(readback, false, table).map_err(|_| ())?;
    observed
        .sets
        .iter()
        .map(|(name, set)| {
            let remaining = token(set, false)
                .map_err(|_| ())?
                .map(|(_, _, remaining)| remaining);
            Ok((name.clone(), remaining))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compile, CompileContext};
    use fw_domain::Policy;
    use serde_json::json;

    const NOW: i64 = 1767225900;
    const CUTOFF: i64 = 1767226200;

    fn fixture() -> (Artifact, Value) {
        let mut policy = json!({"schema_version":"f.policy/v1","policy_id":"00000000-0000-4000-8000-000000000001","policy_revision":1,"org_id":"11111111-1111-4111-8111-111111111111","project_id":"22222222-2222-4222-8222-222222222222","target_id":"33333333-3333-4333-8333-333333333333","owner_id":"44444444-4444-4444-8444-444444444444","reason":"readback fixture","scope":{"family":"ipv4","direction":"input","source_asset_ids":["55555555-5555-4555-8555-555555555555"],"destination_asset_ids":["66666666-6666-4666-8666-666666666666"],"source_cidrs":["127.0.0.1/32"],"destination_cidrs":["127.0.0.1/32"],"transport":{"protocol":"tcp","destination_ports":[{"start":443,"end":443}]},"ingress_interfaces":["lo"],"egress_interfaces":[]},"log_mode":"none","action":"allow","lifetime":{"kind":"lease","not_before":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:10:00Z"}});
        let allow: Policy = serde_json::from_value(policy.clone()).unwrap();
        policy["policy_id"] = json!("00000000-0000-4000-8000-000000000002");
        policy["action"] = json!("deny");
        policy["scope"]["transport"]["destination_ports"] = json!([{"start":444,"end":444}]);
        policy["lifetime"] = json!({"kind":"review","not_before":"2026-01-01T00:00:00Z","review_at":"2026-01-01T00:01:00Z"});
        let deny: Policy = serde_json::from_value(policy).unwrap();
        let context = CompileContext {
            org_id: "11111111-1111-4111-8111-111111111111".into(),
            project_id: "22222222-2222-4222-8222-222222222222".into(),
            target_id: "33333333-3333-4333-8333-333333333333".into(),
            now_unix: NOW,
            clock_uncertainty_seconds: 0,
            elapsed_seconds: 0,
            commit_budget_seconds: 1,
        };
        let artifact = compile(&[allow, deny], &context).unwrap();
        let mut entries = vec![
            json!({"metainfo":{"version":"1.0.6","release_name":"fixture","json_schema_version":1}}),
        ];
        for (index, command) in artifact.nft_json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let mut entry = command["add"].clone();
            let (_, object) = entry.as_object_mut().unwrap().iter_mut().next().unwrap();
            object["handle"] = json!(index + 1);
            if let Some(elements) = object.get_mut("elem") {
                for element in elements.as_array_mut().unwrap() {
                    element["elem"]["expires"] = element["elem"]["timeout"].clone();
                }
            }
            entries.push(entry);
        }
        (artifact, json!({"nftables":entries}))
    }

    fn business_rule(snapshot: &mut Value) -> &mut Value {
        snapshot["nftables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|v| {
                v.get("rule").is_some_and(|r| {
                    r["comment"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("allow:"))
                })
            })
            .unwrap()
            .get_mut("rule")
            .unwrap()
    }
    fn first_set(snapshot: &mut Value) -> &mut Value {
        snapshot["nftables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|v| v.get("set").is_some())
            .unwrap()
            .get_mut("set")
            .unwrap()
    }
    fn reject(artifact: &Artifact, snapshot: &Value, now: i64) -> ReadbackVerification {
        let result = verify_readback(artifact, snapshot, now);
        assert_ne!(result.comparison, Comparison::Match, "{result:?}");
        assert!(result.observed_semantic_hash.is_none());
        result
    }

    #[test]
    fn matching_snapshot_binds_state_without_claiming_production_support() {
        let (artifact, snapshot) = fixture();
        let result = verify_readback(&artifact, &snapshot, NOW);
        assert_eq!(result.comparison, Comparison::Match, "{result:?}");
        assert_eq!(
            result.observed_semantic_hash,
            Some(artifact.desired_state_hash)
        );
        assert_eq!(result.rules_checked, 7);
        assert_eq!(result.tokens_checked, 1);
        assert!(!result.production_qualified);
    }

    #[test]
    fn known_nft_numeric_singleton_and_flags_forms_preserve_meaning() {
        let (artifact, mut snapshot) = fixture();
        for entry in snapshot["nftables"].as_array_mut().unwrap() {
            let Some(rule) = entry.get_mut("rule") else {
                continue;
            };
            let expressions = rule["expr"].as_array_mut().unwrap();
            expressions.retain(|e| e["match"]["left"]["meta"]["key"] != "nfproto");
            let has_token = expressions.iter().any(|e| {
                e["match"]["right"]
                    .as_str()
                    .is_some_and(|s| s.starts_with('@'))
            });
            if has_token {
                expressions.retain(|e| {
                    !(e["match"]["left"]["ct"]["key"] == "protocol" && e["match"]["right"] == 6)
                });
            }
            for expression in expressions {
                let Some(condition) = expression.get_mut("match") else {
                    continue;
                };
                if condition["left"]["meta"]["key"] == "l4proto" {
                    condition["right"] = json!(6);
                }
                if condition["left"]["meta"]["key"] == "time" {
                    condition["right"] = json!("2026-01-01 00:10:00");
                }
                if condition["left"]["ct"]["key"] == "protocol" {
                    condition["left"]["ct"]
                        .as_object_mut()
                        .unwrap()
                        .remove("dir");
                }
                if matches!(
                    condition["left"]["ct"]["key"].as_str(),
                    Some("saddr" | "daddr")
                ) {
                    condition["left"]["ct"]
                        .as_object_mut()
                        .unwrap()
                        .remove("family");
                    condition["right"] = json!("127.0.0.1");
                }
                if let Some(items) = condition["right"].get("set").and_then(Value::as_array) {
                    if items.len() == 1 {
                        condition["right"] = items[0].clone();
                    }
                }
                if condition["op"] == "in" {
                    condition["op"] = json!("==");
                }
                if condition["left"].get("&").is_some() {
                    condition["left"]["&"][1] = json!(["fin", "syn", "rst", "ack"]);
                    condition["right"] = json!("syn");
                }
            }
        }
        assert_eq!(
            verify_readback(&artifact, &snapshot, NOW).comparison,
            Comparison::Match
        );
        first_set(&mut snapshot)["elem"][0]["elem"]["val"] = json!(17);
        reject(&artifact, &snapshot, NOW);
    }

    #[test]
    fn missing_or_changed_checks_never_acquire_a_state_hash() {
        let (artifact, original) = fixture();
        let n = business_rule(&mut original.clone())["expr"]
            .as_array()
            .unwrap()
            .len();
        for index in 0..n {
            let mut snapshot = original.clone();
            let e = &business_rule(&mut snapshot)["expr"][index];
            // These two scalar guards can legitimately be supplied by typed
            // address operands or the verified singleton protocol token.
            if e["match"]["left"]["meta"]["key"] == "nfproto"
                || (e["match"]["left"]["ct"]["key"] == "protocol" && e["match"]["right"] == 6)
                || (e["match"]["left"]["ct"]["key"] == "state"
                    && e["match"]["right"].get("set").is_some())
            {
                continue;
            }
            business_rule(&mut snapshot)["expr"]
                .as_array_mut()
                .unwrap()
                .remove(index);
            reject(&artifact, &snapshot, NOW);
        }
        let mut snapshot = original.clone();
        let rule = business_rule(&mut snapshot);
        let scope = rule["expr"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["match"]["left"]["ct"]["key"] == "saddr")
            .unwrap();
        scope["match"]["right"] = json!({"prefix":{"addr":"127.0.0.0","len":8}});
        reject(&artifact, &snapshot, NOW);
    }

    #[test]
    fn rule_order_extra_rule_and_missing_deny_are_rejected() {
        let (artifact, original) = fixture();
        let mut snapshot = original.clone();
        let extra = business_rule(&mut snapshot).clone();
        snapshot["nftables"]
            .as_array_mut()
            .unwrap()
            .push(json!({"rule":extra}));
        reject(&artifact, &snapshot, NOW);
        let mut snapshot = original.clone();
        snapshot["nftables"].as_array_mut().unwrap().retain(|v| {
            !v["rule"]["comment"]
                .as_str()
                .is_some_and(|s| s.starts_with("deny:"))
        });
        reject(&artifact, &snapshot, NOW);
        let mut snapshot = original;
        let positions: Vec<usize> = snapshot["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .filter_map(|(i, v)| (v["rule"]["chain"] == "input").then_some(i))
            .collect();
        snapshot["nftables"]
            .as_array_mut()
            .unwrap()
            .swap(positions[1], positions[2]);
        reject(&artifact, &snapshot, NOW);
    }

    #[test]
    fn chain_priority_hook_policy_and_table_scope_are_bound() {
        let (artifact, original) = fixture();
        for (field, value) in [
            ("prio", json!(10)),
            ("hook", json!("forward")),
            ("policy", json!("accept")),
            ("type", json!("route")),
        ] {
            let mut snapshot = original.clone();
            let chain = snapshot["nftables"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| v.get("chain").is_some())
                .unwrap();
            chain["chain"][field] = value;
            reject(&artifact, &snapshot, NOW);
        }
        let mut snapshot = original;
        business_rule(&mut snapshot)["table"] = json!("another_table");
        reject(&artifact, &snapshot, NOW);
    }

    #[test]
    fn unsupported_expressions_and_fields_are_unknown() {
        let (artifact, original) = fixture();
        for expression in [
            json!({"counter":{"packets":0,"bytes":0}}),
            json!({"queue":null}),
            json!({"match":{"left":{"fib":{"result":"type"}},"op":"==","right":"local"}}),
        ] {
            let mut snapshot = original.clone();
            business_rule(&mut snapshot)["expr"]
                .as_array_mut()
                .unwrap()
                .insert(0, expression);
            assert_eq!(
                reject(&artifact, &snapshot, NOW).comparison,
                Comparison::Unknown
            );
        }
        let mut snapshot = original;
        business_rule(&mut snapshot)["unexpected"] = json!(true);
        assert_eq!(
            reject(&artifact, &snapshot, NOW).comparison,
            Comparison::Unknown
        );
    }

    #[test]
    fn expiration_does_not_refresh_tokens_or_erase_the_immutable_state() {
        let (artifact, original) = fixture();
        let mut snapshot = original.clone();
        first_set(&mut snapshot)
            .as_object_mut()
            .unwrap()
            .remove("elem");
        reject(&artifact, &snapshot, NOW);
        let expired = verify_readback(&artifact, &snapshot, CUTOFF);
        assert_eq!(expired.comparison, Comparison::Match);
        assert_eq!(
            expired.observed_semantic_hash,
            Some(artifact.desired_state_hash.clone())
        );
        let mut snapshot = original.clone();
        first_set(&mut snapshot)["elem"][0]["elem"]["timeout"] = json!(600);
        reject(&artifact, &snapshot, NOW);
        let mut snapshot = original;
        first_set(&mut snapshot)["elem"][0]["elem"]["expires"] = json!(2);
        reject(&artifact, &snapshot, CUTOFF - 1);
        reject(&artifact, &snapshot, CUTOFF);
    }

    #[test]
    fn absolute_guard_and_tcp_flags_cannot_be_relaxed() {
        let (artifact, original) = fixture();
        let mut snapshot = original.clone();
        let condition = business_rule(&mut snapshot)["expr"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["match"]["left"]["meta"]["key"] == "time")
            .unwrap();
        condition["match"]["right"] = json!(CUTOFF + 1);
        reject(&artifact, &snapshot, NOW);
        let mut snapshot = original;
        let condition = snapshot["nftables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .filter_map(|v| v.get_mut("rule"))
            .flat_map(|r| r["expr"].as_array_mut().unwrap())
            .find(|e| e["match"]["left"].get("&").is_some())
            .unwrap();
        condition["match"]["left"]["&"][1] = json!(2);
        reject(&artifact, &snapshot, NOW);
    }

    #[test]
    fn artifact_profile_must_be_recognized() {
        let (mut artifact, snapshot) = fixture();
        artifact.production_qualified = true;
        assert_eq!(
            reject(&artifact, &snapshot, NOW).comparison,
            Comparison::Unknown
        );
    }
}

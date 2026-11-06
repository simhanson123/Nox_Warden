//! Narrow, independently hashed management baseline for disposable Linux targets.
//! This profile has no business allows and establishes no production qualification.
use crate::{invalid, CompileError};
use fw_contracts::{canonical_bytes_with_limit, canonical_hash, hash_bytes};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::Ipv4Addr;

pub const BOOTSTRAP_PROFILE: &str = "isolated-linux-bootstrap-v1";
pub const BOOTSTRAP_BASELINE_SCHEMA: &str = "fw.isolated-bootstrap-management-baseline/v1";
pub const BOOTSTRAP_CAPABILITY_SCHEMA: &str = "fw.isolated-bootstrap-capability/v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapManagementBaseline {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub network_namespace: String,
    pub interface_name: String,
    pub interface_index: u32,
    pub local_address: String,
    pub peer_address: String,
    pub prefix_length: u8,
    pub management_tcp_port: u16,
    pub positive_udp_port: u16,
    pub negative_udp_port: u16,
    pub peer_probe_public_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapCapabilitySnapshot {
    pub schema_version: String,
    pub platform: String,
    pub backend: String,
    pub profile: String,
    pub kernel_release: String,
    pub architecture: String,
    pub nft_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapBaselineProgram {
    pub schema_version: String,
    pub management_baseline_hash: String,
    pub capability_hash: String,
    pub table: String,
    pub nft_json: Value,
}

pub struct VerifiedBootstrapReadback {
    readback_hash: String,
    program_hash: String,
}
impl VerifiedBootstrapReadback {
    pub fn readback_hash(&self) -> &str {
        &self.readback_hash
    }
    pub fn program_hash(&self) -> &str {
        &self.program_hash
    }
}

pub fn bootstrap_namespace_valid(value: &str) -> bool {
    value
        .strip_prefix("net:[")
        .and_then(|v| v.strip_suffix(']'))
        .is_some_and(|n| {
            n.parse::<u64>()
                .is_ok_and(|number| number > 0 && number.to_string() == n)
        })
}
fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}
impl BootstrapManagementBaseline {
    pub fn validate(&self) -> Result<(), CompileError> {
        if self.schema_version != BOOTSTRAP_BASELINE_SCHEMA
            || [&self.org_id, &self.project_id, &self.target_id]
                .iter()
                .any(|s| fw_domain::validate_uuid(s).is_err())
            || !bootstrap_namespace_valid(&self.network_namespace)
            || self.interface_name.is_empty()
            || self.interface_name.len() > 15
            || self.interface_name == "lo"
            || !self
                .interface_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || self.interface_index == 0
            || self.prefix_length != 30
            || self.management_tcp_port == 0
            || self.positive_udp_port == 0
            || self.negative_udp_port == 0
            || self.positive_udp_port == self.negative_udp_port
            || self.peer_probe_public_key == [0; 32]
        {
            return Err(invalid("isolated bootstrap baseline"));
        }
        let local: Ipv4Addr = self.local_address.parse().map_err(invalid)?;
        let peer: Ipv4Addr = self.peer_address.parse().map_err(invalid)?;
        let permitted = |address: Ipv4Addr| address.is_private() || address.is_documentation();
        if local.to_string() != self.local_address
            || peer.to_string() != self.peer_address
            || !permitted(local)
            || !permitted(peer)
            || local == peer
            || u32::from(local) & !3 != u32::from(peer) & !3
            || ![1, 2].contains(&(u32::from(local) & 3))
            || ![1, 2].contains(&(u32::from(peer) & 3))
        {
            return Err(invalid("isolated bootstrap point-to-point subnet"));
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<String, CompileError> {
        self.validate()?;
        canonical_hash(self).map_err(invalid)
    }
}
impl BootstrapCapabilitySnapshot {
    pub fn validate(&self) -> Result<(), CompileError> {
        if self.schema_version != BOOTSTRAP_CAPABILITY_SCHEMA
            || self.platform != "linux"
            || self.backend != "nftables"
            || self.profile != BOOTSTRAP_PROFILE
            || !["x86_64", "aarch64"].contains(&self.architecture.as_str())
            || !bounded_text(&self.kernel_release, 256)
            || !bounded_text(&self.nft_version, 256)
        {
            return Err(invalid("isolated bootstrap capability"));
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<String, CompileError> {
        self.validate()?;
        canonical_hash(self).map_err(invalid)
    }
}
impl BootstrapBaselineProgram {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CompileError> {
        canonical_bytes_with_limit(self, 131072).map_err(invalid)
    }
    pub fn hash(&self) -> Result<String, CompileError> {
        Ok(hash_bytes(&self.canonical_bytes()?))
    }
}

fn equal(left: Value, right: Value) -> Value {
    json!({"match":{"op":"==","left":left,"right":right}})
}
fn meta(key: &str) -> Value {
    json!({"meta":{"key":key}})
}
fn payload(protocol: &str, field: &str) -> Value {
    json!({"payload":{"protocol":protocol,"field":field}})
}

pub fn compile_bootstrap_baseline(
    baseline: &BootstrapManagementBaseline,
    capability: &BootstrapCapabilitySnapshot,
) -> Result<BootstrapBaselineProgram, CompileError> {
    baseline.validate()?;
    capability.validate()?;
    let scope = canonical_hash(&json!({"org_id":baseline.org_id,"project_id":baseline.project_id,"target_id":baseline.target_id})).map_err(invalid)?;
    let table = format!("fw_bootstrap_{}", &scope[7..31]);
    let mut entries = vec![json!({"add":{"table":{"family":"inet","name":table}}})];
    for chain in ["input", "output", "forward"] {
        entries.push(json!({"add":{"chain":{"family":"inet","table":table,"name":chain,"type":"filter","hook":chain,"prio":0,"policy":"drop"}}}));
    }
    for (protocol, number, port) in [
        ("tcp", 6, baseline.management_tcp_port),
        ("udp", 17, baseline.positive_udp_port),
    ] {
        let outgoing = vec![
            equal(meta("nfproto"), json!("ipv4")),
            equal(meta("oifname"), json!(baseline.interface_name)),
            equal(payload("ip", "saddr"), json!(baseline.local_address)),
            equal(payload("ip", "daddr"), json!(baseline.peer_address)),
            equal(meta("l4proto"), json!(number)),
            equal(payload(protocol, "dport"), json!(port)),
            json!({"accept":null}),
        ];
        let incoming = vec![
            equal(meta("nfproto"), json!("ipv4")),
            equal(meta("iifname"), json!(baseline.interface_name)),
            equal(payload("ip", "saddr"), json!(baseline.peer_address)),
            equal(payload("ip", "daddr"), json!(baseline.local_address)),
            equal(json!({"ct":{"key":"direction"}}), json!("reply")),
            equal(
                json!({"ct":{"key":"protocol","dir":"original"}}),
                json!(number),
            ),
            equal(
                json!({"ct":{"key":"saddr","family":"ip","dir":"original"}}),
                json!(baseline.local_address),
            ),
            equal(
                json!({"ct":{"key":"daddr","family":"ip","dir":"original"}}),
                json!(baseline.peer_address),
            ),
            equal(
                json!({"ct":{"key":"proto-dst","dir":"original"}}),
                json!(port),
            ),
            json!({"accept":null}),
        ];
        for (chain, expressions) in [("output", outgoing), ("input", incoming)] {
            entries.push(json!({"add":{"rule":{"family":"inet","table":table,"chain":chain,"expr":expressions}}}));
        }
    }
    Ok(BootstrapBaselineProgram {
        schema_version: "fw.isolated-bootstrap-nft-program/v1".into(),
        management_baseline_hash: baseline.hash()?,
        capability_hash: capability.hash()?,
        table,
        nft_json: json!({"nftables":entries}),
    })
}

fn exact_match<'a>(expression: &'a Value, left: &Value) -> Option<&'a Value> {
    let right = expression.get("match")?.get("right")?;
    (expression == &equal(left.clone(), right.clone())).then_some(right)
}

fn normalize_rule(expressions: &mut Vec<Value>) {
    // nft 1.0.6 omits protocol dependencies already enforced by these typed
    // payload selectors. Only recognize the captured IPv4/address + typed
    // TCP/UDP dport representation; do not discard arbitrary protocol guards.
    let ipv4 = ["saddr", "daddr"].iter().all(|field| {
        expressions.iter().any(|expression| {
            exact_match(expression, &payload("ip", field))
                .and_then(Value::as_str)
                .is_some_and(|value| value.parse::<std::net::Ipv4Addr>().is_ok())
        })
    });
    let transport = [("tcp", 6), ("udp", 17)]
        .into_iter()
        .filter(|(protocol, _)| {
            expressions.iter().any(|expression| {
                exact_match(expression, &payload(protocol, "dport"))
                    .and_then(Value::as_u64)
                    .is_some_and(|port| (1..=65535).contains(&port))
            })
        })
        .map(|(_, number)| number)
        .collect::<Vec<_>>();
    let mut removed_family = false;
    let mut removed_transport = false;
    expressions.retain(|expression| {
        if ipv4 && !removed_family && expression == &equal(meta("nfproto"), json!("ipv4")) {
            removed_family = true;
            false
        } else if ipv4
            && !removed_transport
            && transport.len() == 1
            && (expression == &equal(meta("l4proto"), json!(transport[0]))
                || expression
                    == &equal(
                        meta("l4proto"),
                        json!(if transport[0] == 6 { "tcp" } else { "udp" }),
                    ))
        {
            removed_transport = true;
            false
        } else {
            true
        }
    });
    for expression in expressions {
        let Some(matching) = expression.get_mut("match").and_then(Value::as_object_mut) else {
            continue;
        };
        // Connection protocol is direction-independent. nft omits the
        // original qualifier, and infers address family from the exact IPv4
        // selectors above. Reply direction or another family stays distinct.
        if ipv4 {
            if matching.get("left") == Some(&json!({"ct":{"key":"protocol","dir":"original"}})) {
                matching.insert("left".into(), json!({"ct":{"key":"protocol"}}));
            }
            for field in ["saddr", "daddr"] {
                if matching.get("left")
                    == Some(&json!({"ct":{"key":field,"family":"ip","dir":"original"}}))
                {
                    matching.insert("left".into(), json!({"ct":{"key":field,"dir":"original"}}));
                }
            }
        }
        if matching.get("left").is_some_and(|left| {
            left == &meta("l4proto") || left == &json!({"ct":{"key":"protocol"}})
        }) {
            let number = match matching.get("right").and_then(Value::as_str) {
                Some("tcp") => Some(6),
                Some("udp") => Some(17),
                _ => None,
            };
            if let Some(number) = number {
                matching.insert("right".into(), json!(number));
            }
        }
    }
}

fn normalized_objects(raw: &Value, input: bool) -> Result<Vec<Value>, CompileError> {
    let map = raw
        .as_object()
        .ok_or_else(|| invalid("bootstrap nft shape"))?;
    if map.len() != 1 {
        return Err(invalid("bootstrap nft top-level fields"));
    }
    let entries = map
        .get("nftables")
        .and_then(Value::as_array)
        .filter(|e| e.len() <= 32)
        .ok_or_else(|| invalid("bootstrap nft objects"))?;
    let mut result = Vec::new();
    for entry in entries {
        let mut entry = entry.clone();
        if input {
            entry = entry
                .get("add")
                .cloned()
                .ok_or_else(|| invalid("bootstrap nft command"))?;
        }
        let object = entry
            .as_object_mut()
            .filter(|o| o.len() == 1)
            .ok_or_else(|| invalid("bootstrap nft object"))?;
        if object.contains_key("metainfo") {
            let metadata = object["metainfo"]
                .as_object()
                .ok_or_else(|| invalid("bootstrap nft metainfo"))?;
            if metadata
                .keys()
                .any(|k| !["version", "release_name", "json_schema_version"].contains(&k.as_str()))
            {
                return Err(invalid("bootstrap nft metainfo fields"));
            }
            continue;
        }
        let (kind, body) = object
            .iter_mut()
            .next()
            .ok_or_else(|| invalid("bootstrap nft object"))?;
        let fields = body
            .as_object_mut()
            .ok_or_else(|| invalid("bootstrap nft fields"))?;
        for key in ["handle", "index"] {
            if let Some(value) = fields.remove(key) {
                if value.as_u64().is_none() {
                    return Err(invalid("bootstrap nft runtime metadata"));
                }
            }
        }
        let expected: &[&str] = match kind.as_str() {
            "table" => &["family", "name"],
            "chain" => &["family", "table", "name", "type", "hook", "prio", "policy"],
            "rule" => &["family", "table", "chain", "expr"],
            _ => return Err(invalid("bootstrap nft unsupported object")),
        };
        if fields.len() != expected.len() || expected.iter().any(|key| !fields.contains_key(*key)) {
            return Err(invalid("bootstrap nft field mismatch"));
        }
        if kind == "chain" && fields.get("prio") == Some(&json!("filter")) {
            fields.insert("prio".into(), json!(0));
        }
        if kind == "rule" {
            normalize_rule(
                fields
                    .get_mut("expr")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| invalid("bootstrap nft expressions"))?,
            );
        }
        result.push(entry);
    }
    // nft lists chains together with their rules. Chain declaration order has
    // no effect; the rule order inside each chain must remain exact.
    result.sort_by_key(|entry| {
        if let Some(table) = entry.get("table") {
            (0, table["name"].as_str().unwrap_or("").to_owned())
        } else if let Some(chain) = entry.get("chain") {
            (1, chain["name"].as_str().unwrap_or("").to_owned())
        } else {
            (2, entry["rule"]["chain"].as_str().unwrap_or("").to_owned())
        }
    });
    Ok(result)
}

/// Compares a complete `nft -j list ruleset` snapshot with the approved owned
/// objects. Runtime metadata and the bounded nft protocol-dependency forms are
/// normalized; foreign objects and extra or changed rule expressions fail.
pub fn verify_bootstrap_baseline_readback(
    baseline: &BootstrapManagementBaseline,
    capability: &BootstrapCapabilitySnapshot,
    raw: &Value,
) -> Result<VerifiedBootstrapReadback, CompileError> {
    let raw_bytes = canonical_bytes_with_limit(raw, 131072).map_err(invalid)?;
    let program = compile_bootstrap_baseline(baseline, capability)?;
    if normalized_objects(raw, false)? != normalized_objects(&program.nft_json, true)? {
        return Err(invalid("bootstrap baseline readback mismatch"));
    }
    Ok(VerifiedBootstrapReadback {
        readback_hash: hash_bytes(&raw_bytes),
        program_hash: program.hash()?,
    })
}

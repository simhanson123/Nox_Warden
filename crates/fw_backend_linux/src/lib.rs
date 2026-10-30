//! Experimental host-only nft JSON lowering. This crate never executes nft.
//!
//! The emitted artifact is intentionally NOT production qualified: native JSON
//! syntax, timer units, ICMP/PMTU, baseline, anti-spoof, and cross-manager behavior
//! must pass a disposable kernel lab before an execution adapter can admit it.
use fw_contracts::canonical_hash;
use fw_domain::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("INVALID_POLICY: {0}")]
    Invalid(String),
    #[error("UNSUPPORTED: {0}")]
    Unsupported(&'static str),
    #[error("BUDGET_EXCEEDED")]
    Budget,
    #[error("CLOCK_NOT_TRUSTED")]
    Clock,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileContext {
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub now_unix: i64,
    pub clock_uncertainty_seconds: u64,
    pub elapsed_seconds: u64,
    pub commit_budget_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub schema_version: String,
    pub compiler_version: String,
    pub profile: String,
    pub production_qualified: bool,
    pub table: String,
    pub desired_state_hash: String,
    pub nft_json: Value,
}

fn invalid(error: impl std::fmt::Display) -> CompileError {
    CompileError::Invalid(error.to_string())
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, CompileError> {
    value[key].as_str().ok_or_else(|| invalid(key))
}
fn timestamp(value: &Value, key: &str) -> Result<i64, CompileError> {
    chrono::DateTime::parse_from_rfc3339(string(value, key)?)
        .map(|t| t.timestamp())
        .map_err(invalid)
}
fn matching(left: Value, op: &str, right: Value) -> Value {
    json!({"match":{"left":left,"op":op,"right":right}})
}
fn ct(key: &str) -> Value {
    json!({"ct":{"key":key,"dir":"original"}})
}
fn address_set(value: &Value) -> Result<Value, CompileError> {
    let addresses = value.as_array().ok_or_else(|| invalid("CIDR list"))?;
    let mut prefixes = Vec::with_capacity(addresses.len());
    for address in addresses {
        let (addr, len) = address
            .as_str()
            .and_then(|s| s.split_once('/'))
            .ok_or_else(|| invalid("CIDR"))?;
        let len = len.parse::<u8>().map_err(invalid)?;
        prefixes.push(json!({"prefix":{"addr":addr,"len":len}}));
    }
    Ok(json!({"set":prefixes}))
}

/// Compile a complete candidate in deterministic policy order. Caller must have
/// already resolved asset IDs to the CIDR snapshot represented in each Policy.
/// This does not grant permission to execute the artifact.
pub fn compile(policies: &[Policy], context: &CompileContext) -> Result<Artifact, CompileError> {
    if policies.len() > 1000 {
        return Err(CompileError::Budget);
    }
    if context.now_unix < 0 || context.clock_uncertainty_seconds > 2 {
        return Err(CompileError::Clock);
    }
    let mut normalized = Vec::with_capacity(policies.len());
    let mut ids = BTreeSet::new();
    for policy in policies {
        policy.validate().map_err(invalid)?;
        let policy = policy.normalized().map_err(invalid)?;
        let value = serde_json::to_value(policy).map_err(invalid)?;
        if value["org_id"] != context.org_id
            || value["project_id"] != context.project_id
            || value["target_id"] != context.target_id
        {
            return Err(invalid("tenant or target mismatch"));
        }
        if !ids.insert(string(&value, "policy_id")?.to_owned()) {
            return Err(invalid("duplicate policy ID"));
        }
        if value["log_mode"] != "none" {
            return Err(CompileError::Unsupported(
                "native log modes require bounded rate-limit implementation",
            ));
        }
        if value["scope"]["direction"] == "forward" {
            return Err(CompileError::Unsupported("routed profile"));
        }
        if !matches!(
            value["scope"]["transport"]["protocol"].as_str(),
            Some("tcp" | "udp")
        ) {
            return Err(CompileError::Unsupported(
                "ICMP requires qualified parent-flow and baseline lowering",
            ));
        }
        if timestamp(&value["lifetime"], "not_before")? > context.now_unix {
            return Err(CompileError::Unsupported("future activation"));
        }
        normalized.push(value);
    }
    normalized.sort_by(|a, b| a["policy_id"].as_str().cmp(&b["policy_id"].as_str()));
    let state_hash = canonical_hash(&normalized).map_err(invalid)?;
    let scope_hash = canonical_hash(&json!([
        context.org_id,
        context.project_id,
        context.target_id
    ]))
    .map_err(invalid)?;
    let table = format!("fw_{}", &scope_hash[7..31]);
    let mut commands = vec![json!({"add":{"table":{"family":"inet","name":table}}})];
    for chain in ["input", "output"] {
        commands.push(json!({"add":{"chain":{"family":"inet","table":table,"name":chain,"type":"filter","hook":chain,"prio":0,"policy":"drop"}}}));
        commands.push(rule(
            &table,
            chain,
            vec![
                matching(json!({"ct":{"key":"state"}}), "==", json!("invalid")),
                json!({"drop":null}),
            ],
            "invalid",
        ));
    }
    // Deny entries are all emitted before any allows, independently in each hook.
    for action in ["deny", "allow"] {
        for policy in &normalized {
            if policy["action"] != action {
                continue;
            }
            let scope = &policy["scope"];
            let protocol = string(&scope["transport"], "protocol")?;
            let protocol_number = if protocol == "tcp" { 6 } else { 17 };
            let revision_hash = canonical_hash(policy).map_err(invalid)?;
            let token = format!("fw_live_{}", &revision_hash[7..31]);
            let mut time_guards = Vec::new();
            if action == "allow" {
                let expiry = timestamp(&policy["lifetime"], "expires_at")?;
                let budget = context
                    .clock_uncertainty_seconds
                    .checked_add(context.elapsed_seconds)
                    .and_then(|v| v.checked_add(context.commit_budget_seconds))
                    .ok_or(CompileError::Clock)?;
                let upper = context
                    .now_unix
                    .checked_add(i64::try_from(budget).map_err(|_| CompileError::Clock)?)
                    .ok_or(CompileError::Clock)?;
                if expiry <= upper {
                    continue;
                }
                let ttl = u64::try_from(expiry - upper).map_err(|_| CompileError::Clock)?;
                let cutoff = expiry - context.clock_uncertainty_seconds as i64;
                commands.push(json!({"add":{"set":{"family":"inet","table":table,"name":token,"type":"inet_proto","flags":["timeout"],"elem":[{"elem":{"val":protocol_number,"timeout":ttl}}]}}}));
                time_guards.push(matching(ct("protocol"), "in", json!(format!("@{token}"))));
                time_guards.push(matching(json!({"meta":{"key":"time"}}), "<", json!(cutoff)));
            }
            let input = scope["direction"] == "input";
            for reply in [false, true] {
                let chain = if input != reply { "input" } else { "output" };
                let family = if scope["family"] == "ipv4" {
                    "ip"
                } else {
                    "ip6"
                };
                let ports: Vec<Value> = scope["transport"]["destination_ports"]
                    .as_array()
                    .ok_or_else(|| invalid("ports"))?
                    .iter()
                    .map(|p| {
                        if p["start"] == p["end"] {
                            p["start"].clone()
                        } else {
                            json!({"range":[p["start"],p["end"]]})
                        }
                    })
                    .collect();
                let mut expr = vec![
                    matching(
                        json!({"meta":{"key":"nfproto"}}),
                        "==",
                        scope["family"].clone(),
                    ),
                    matching(json!({"meta":{"key":"l4proto"}}), "==", json!(protocol)),
                    matching(
                        json!({"ct":{"key":"direction"}}),
                        "==",
                        json!(if reply { "reply" } else { "original" }),
                    ),
                    matching(ct("protocol"), "==", json!(protocol_number)),
                    matching(json!({"ct":{"key":"zone"}}), "==", json!(0)),
                    matching(
                        json!({"ct":{"key":"saddr","family":family,"dir":"original"}}),
                        "in",
                        address_set(&scope["source_cidrs"])?,
                    ),
                    matching(
                        json!({"ct":{"key":"daddr","family":family,"dir":"original"}}),
                        "in",
                        address_set(&scope["destination_cidrs"])?,
                    ),
                    matching(ct("proto-dst"), "in", json!({"set":ports})),
                ];
                let interfaces = if input {
                    &scope["ingress_interfaces"]
                } else {
                    &scope["egress_interfaces"]
                };
                if !interfaces
                    .as_array()
                    .ok_or_else(|| invalid("interfaces"))?
                    .is_empty()
                {
                    expr.push(matching(
                        json!({"meta":{"key":if chain == "input" {"iifname"} else {"oifname"}}}),
                        "in",
                        json!({"set":interfaces}),
                    ));
                }
                if action == "allow" {
                    expr.extend(time_guards.clone());
                    if reply {
                        expr.push(matching(
                            json!({"ct":{"key":"state"}}),
                            "==",
                            json!("established"),
                        ));
                    } else {
                        expr.push(matching(
                            json!({"ct":{"key":"state"}}),
                            "in",
                            json!({"set":["new","established"]}),
                        ));
                    }
                }
                let comment = format!(
                    "{}:{}:{}",
                    action,
                    string(policy, "policy_id")?,
                    policy["policy_revision"]
                );
                if action == "allow" && protocol == "tcp" && !reply {
                    // NEW requires SYN without ACK/FIN/RST. Existing original
                    // packets still pass through current scope and time guards.
                    let mut established = expr.clone();
                    established.push(matching(
                        json!({"ct":{"key":"state"}}),
                        "==",
                        json!("established"),
                    ));
                    established.push(json!({"accept":null}));
                    commands.push(rule(&table, chain, established, &comment));
                    expr.push(matching(json!({"ct":{"key":"state"}}), "==", json!("new")));
                    expr.push(matching(
                        json!({"&":[{"payload":{"protocol":"tcp","field":"flags"}},23]}),
                        "==",
                        json!(2),
                    ));
                }
                expr.push(if action == "deny" {
                    json!({"drop":null})
                } else {
                    json!({"accept":null})
                });
                commands.push(rule(&table, chain, expr, &comment));
            }
        }
    }
    if commands.len() > 50_000 {
        return Err(CompileError::Budget);
    }
    let artifact = Artifact {
        schema_version: "fw.experimental-nft/v1".into(),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        profile: "host-tcp-udp-lab".into(),
        production_qualified: false,
        table,
        desired_state_hash: state_hash,
        nft_json: json!({"nftables":commands}),
    };
    if serde_json::to_vec(&artifact).map_err(invalid)?.len() > 16 * 1024 * 1024 {
        return Err(CompileError::Budget);
    }
    Ok(artifact)
}
fn rule(table: &str, chain: &str, expr: Vec<Value>, comment: &str) -> Value {
    json!({"add":{"rule":{"family":"inet","table":table,"chain":chain,"expr":expr,"comment":comment}}})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(action: &str, id: u8) -> Policy {
        let mut p = json!({"schema_version":"f.policy/v1","policy_id":format!("00000000-0000-4000-8000-{id:012}"),"policy_revision":1,"org_id":"11111111-1111-4111-8111-111111111111","project_id":"22222222-2222-4222-8222-222222222222","target_id":"33333333-3333-4333-8333-333333333333","owner_id":"44444444-4444-4444-8444-444444444444","reason":"test","scope":{"family":"ipv4","direction":"input","source_asset_ids":["55555555-5555-4555-8555-555555555555"],"destination_asset_ids":["66666666-6666-4666-8666-666666666666"],"source_cidrs":["192.0.2.0/24"],"destination_cidrs":["198.51.100.4/32"],"transport":{"protocol":"tcp","destination_ports":[{"start":443,"end":443}]},"ingress_interfaces":["eth0"],"egress_interfaces":[]},"log_mode":"none","action":action});
        p["lifetime"] = if action == "allow" {
            json!({"kind":"lease","not_before":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:10:00Z"})
        } else {
            json!({"kind":"review","not_before":"2026-01-01T00:00:00Z","review_at":"2026-01-01T00:01:00Z"})
        };
        serde_json::from_value(p).unwrap()
    }
    fn context() -> CompileContext {
        CompileContext {
            org_id: "11111111-1111-4111-8111-111111111111".into(),
            project_id: "22222222-2222-4222-8222-222222222222".into(),
            target_id: "33333333-3333-4333-8333-333333333333".into(),
            now_unix: 1767225900,
            clock_uncertainty_seconds: 2,
            elapsed_seconds: 0,
            commit_budget_seconds: 1,
        }
    }
    #[test]
    fn deterministic_order_and_deny_precedence() {
        let a = policy("allow", 1);
        let d = policy("deny", 2);
        let x = compile(&[a.clone(), d.clone()], &context()).unwrap();
        let y = compile(&[d, a], &context()).unwrap();
        assert_eq!(
            serde_json::to_value(&x).unwrap(),
            serde_json::to_value(y).unwrap()
        );
        for chain in ["input", "output"] {
            let comments: Vec<_> = x.nft_json["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["add"]["rule"]["chain"] == chain)
                .filter_map(|v| v["add"]["rule"]["comment"].as_str())
                .filter(|s| *s != "invalid")
                .collect();
            assert!(comments[0].starts_with("deny:"));
        }
        assert!(!x.production_qualified);
    }
    #[test]
    fn expires_without_reset_and_review_deny_remains() {
        let mut c = context();
        c.now_unix = 1767226200;
        let a = compile(&[policy("allow", 1), policy("deny", 2)], &c).unwrap();
        let rendered = serde_json::to_string(&a).unwrap();
        assert!(!rendered.contains("fw_live_"));
        assert!(rendered.contains("deny:"));
        assert!(!rendered.contains("accept"));
    }
    #[test]
    fn dual_guards_and_reverse_interface() {
        let a = compile(&[policy("allow", 1)], &context()).unwrap();
        let text = serde_json::to_string(&a).unwrap();
        for s in [
            "fw_live_", "timeout", "time", "oifname", "iifname", "reply", "original",
        ] {
            assert!(text.contains(s), "{s}");
        }
        assert!(!text.contains("flush"));
        assert!(!text.contains("shell"));
    }
    #[test]
    fn tenant_mismatch_and_untrusted_clock_reject() {
        let mut c = context();
        c.target_id = "00000000-0000-4000-8000-000000000000".into();
        assert!(compile(&[policy("allow", 1)], &c).is_err());
        let mut c = context();
        c.clock_uncertainty_seconds = 3;
        assert!(matches!(compile(&[], &c), Err(CompileError::Clock)));
    }
    #[test]
    fn unsupported_icmp_and_future_activation_never_produce_artifacts() {
        let mut value = serde_json::to_value(policy("allow", 1)).unwrap();
        value["scope"]["transport"] = json!({"protocol":"icmp","type":8,"code":0});
        let icmp: Policy = serde_json::from_value(value).unwrap();
        assert!(matches!(
            compile(&[icmp], &context()),
            Err(CompileError::Unsupported(_))
        ));
        let mut c = context();
        c.now_unix = 1767225599;
        assert!(matches!(
            compile(&[policy("allow", 1)], &c),
            Err(CompileError::Unsupported(_))
        ));
    }
    #[test]
    fn ipv6_udp_keeps_family_and_protocol_distinct() {
        let mut value = serde_json::to_value(policy("allow", 1)).unwrap();
        value["scope"]["family"] = json!("ipv6");
        value["scope"]["source_cidrs"] = json!(["2001:db8:1::/64"]);
        value["scope"]["destination_cidrs"] = json!(["2001:db8:2::2/128"]);
        value["scope"]["transport"]["protocol"] = json!("udp");
        let p: Policy = serde_json::from_value(value).unwrap();
        let a = compile(&[p], &context()).unwrap();
        let text = serde_json::to_string(&a.nft_json).unwrap();
        assert!(text.contains("ipv6"));
        assert!(text.contains("ip6"));
        assert!(text.contains("udp"));
        assert!(!text.contains("tcp"));
    }
    #[test]
    fn libnftables_json_timeout_is_seconds_not_netlink_milliseconds() {
        // Verified with real nft 1.0.6: timeout=3 disappears after four
        // monotonic seconds, while timeout=3000 still has 2995s remaining.
        let artifact = compile(&[policy("allow", 1)], &context()).unwrap();
        let timeout = artifact.nft_json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|command| command["add"]["set"]["elem"][0]["elem"]["timeout"].as_u64())
            .unwrap();
        assert_eq!(timeout, 297); // expiry - now - 2s uncertainty - 1s commit budget.
    }
}

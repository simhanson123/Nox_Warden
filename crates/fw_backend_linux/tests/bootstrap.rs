use fw_backend_linux::*;
use serde_json::{json, Value};

fn fixture() -> (BootstrapManagementBaseline, BootstrapCapabilitySnapshot) {
    let baseline = BootstrapManagementBaseline {
        schema_version: BOOTSTRAP_BASELINE_SCHEMA.into(),
        org_id: "11111111-1111-4111-8111-111111111111".into(),
        project_id: "22222222-2222-4222-8222-222222222222".into(),
        target_id: "33333333-3333-4333-8333-333333333333".into(),
        network_namespace: "net:[42]".into(),
        interface_name: "mgmt0".into(),
        interface_index: 2,
        local_address: "192.0.2.1".into(),
        peer_address: "192.0.2.2".into(),
        prefix_length: 30,
        management_tcp_port: 19443,
        positive_udp_port: 19444,
        negative_udp_port: 19445,
        peer_probe_public_key: [71; 32],
    };
    let capability = BootstrapCapabilitySnapshot {
        schema_version: BOOTSTRAP_CAPABILITY_SCHEMA.into(),
        platform: "linux".into(),
        backend: "nftables".into(),
        profile: BOOTSTRAP_PROFILE.into(),
        kernel_release: "6.1.0-synthetic-unit".into(),
        architecture: "x86_64".into(),
        nft_version: "nftables v1.0.6".into(),
    };
    (baseline, capability)
}
fn snapshot(program: &BootstrapBaselineProgram) -> Value {
    json!({"nftables":program.nft_json["nftables"].as_array().unwrap().iter().map(|entry|entry["add"].clone()).collect::<Vec<_>>()})
}

#[test]
fn bounded_management_program_defaults_to_drop_and_only_permits_exact_reply_tuples() {
    let (baseline, capability) = fixture();
    let program = compile_bootstrap_baseline(&baseline, &capability).unwrap();
    let entries = program.nft_json["nftables"].as_array().unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry["add"]["chain"]["policy"] == "drop")
            .count(),
        3
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry["add"].get("rule").is_some())
            .count(),
        4
    );
    let outgoing: Vec<_> = entries
        .iter()
        .filter(|entry| entry["add"]["rule"]["chain"] == "output")
        .collect();
    assert_eq!(outgoing.len(), 2);
    assert!(!serde_json::to_string(&program.nft_json)
        .unwrap()
        .contains("19445"));
    for entry in entries
        .iter()
        .filter(|entry| entry["add"]["rule"]["chain"] == "input")
    {
        assert!(entry["add"]["rule"]["expr"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["match"]["left"] == json!({"ct":{"key":"direction"}})
                && e["match"]["right"] == "reply"));
    }
    let mut changed = baseline.clone();
    changed.peer_probe_public_key = [72; 32];
    assert_ne!(
        program.hash().unwrap(),
        compile_bootstrap_baseline(&changed, &capability)
            .unwrap()
            .hash()
            .unwrap()
    );
}

#[test]
fn readback_accepts_runtime_handles_but_rejects_extra_allow_and_changed_scope() {
    let (baseline, capability) = fixture();
    let program = compile_bootstrap_baseline(&baseline, &capability).unwrap();
    let mut raw = snapshot(&program);
    raw["nftables"].as_array_mut().unwrap().insert(
        0,
        json!({"metainfo":{"version":"1.0.6","release_name":"synthetic","json_schema_version":1}}),
    );
    for (index, entry) in raw["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .skip(1)
        .enumerate()
    {
        entry.as_object_mut().unwrap().values_mut().next().unwrap()["handle"] = json!(index + 1);
    }
    let verified = verify_bootstrap_baseline_readback(&baseline, &capability, &raw).unwrap();
    assert_eq!(verified.program_hash(), program.hash().unwrap());
    let mut broadened = raw.clone();
    broadened["nftables"].as_array_mut().unwrap().push(json!({"rule":{"family":"inet","table":program.table,"chain":"output","expr":[{"accept":null}]}}));
    assert!(verify_bootstrap_baseline_readback(&baseline, &capability, &broadened).is_err());
    let mut scope = baseline.clone();
    scope.peer_address = "192.0.2.1".into();
    assert!(verify_bootstrap_baseline_readback(&scope, &capability, &raw).is_err());
    let mut unknown = raw;
    unknown["nftables"][1]["table"]["flags"] = json!(["dormant"]);
    assert!(verify_bootstrap_baseline_readback(&baseline, &capability, &unknown).is_err());
}

#[test]
fn actual_nft106_readback_preserves_exact_tuple_semantics_despite_implicit_protocol_guards() {
    // Public kernel snapshot captured from the isolated lab after the approved
    // batch was installed. The original run refused it and retained UNKNOWN;
    // this fixture is a parser regression, not a passing native qualification.
    let captured: Value =
        serde_json::from_str(include_str!("fixtures/bootstrap-nft-1.0.6-readback.json")).unwrap();
    let baseline: BootstrapManagementBaseline =
        serde_json::from_value(captured["baseline"].clone()).unwrap();
    let capability: BootstrapCapabilitySnapshot =
        serde_json::from_value(captured["capability"].clone()).unwrap();
    let raw = &captured["ruleset"];
    let verified = verify_bootstrap_baseline_readback(&baseline, &capability, raw).unwrap();
    assert_eq!(
        verified.program_hash(),
        compile_bootstrap_baseline(&baseline, &capability)
            .unwrap()
            .hash()
            .unwrap()
    );
    let mut variants = Vec::new();
    // Every actual match remains necessary: interface, address, reply direction,
    // original connection tuple and transport port may not disappear.
    for (object, entry) in raw["nftables"].as_array().unwrap().iter().enumerate() {
        if let Some(expressions) = entry["rule"]["expr"].as_array() {
            for index in 0..expressions.len() {
                let mut changed = raw.clone();
                changed["nftables"][object]["rule"]["expr"]
                    .as_array_mut()
                    .unwrap()
                    .remove(index);
                variants.push(changed);
            }
            for (index, expression) in expressions.iter().enumerate() {
                if let Some(left) = expression.get("match").and_then(|value| value.get("left")) {
                    if left.get("ct").is_some() {
                        let mut changed = raw.clone();
                        changed["nftables"][object]["rule"]["expr"][index]["match"]["left"]["ct"]
                            ["dir"] = json!("reply");
                        variants.push(changed);
                    }
                    if left["payload"]["protocol"] == "ip" {
                        let mut changed = raw.clone();
                        changed["nftables"][object]["rule"]["expr"][index]["match"]["left"]
                            ["payload"]["protocol"] = json!("ip6");
                        variants.push(changed);
                    }
                }
            }
        }
    }
    let objects = raw["nftables"].as_array().unwrap();
    let input = objects
        .iter()
        .position(|entry| entry["rule"]["chain"] == "input")
        .unwrap();
    let output = objects
        .iter()
        .position(|entry| {
            entry["rule"]["chain"] == "output"
                && entry["rule"]["expr"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|expression| {
                        expression["match"]["left"]
                            == json!({"payload":{"protocol":"tcp","field":"dport"}})
                    })
        })
        .unwrap();
    let original_address = objects[input]["rule"]["expr"]
        .as_array()
        .unwrap()
        .iter()
        .position(|expression| {
            expression["match"]["left"] == json!({"ct":{"key":"saddr","dir":"original"}})
        })
        .unwrap();
    let destination_port = objects[output]["rule"]["expr"]
        .as_array()
        .unwrap()
        .iter()
        .position(|expression| {
            expression["match"]["left"] == json!({"payload":{"protocol":"tcp","field":"dport"}})
        })
        .unwrap();
    for family in ["ipv6", "inet"] {
        let mut changed = raw.clone();
        changed["nftables"][input]["rule"]["expr"]
            .as_array_mut()
            .unwrap()
            .insert(
                0,
                json!({"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":family}}),
            );
        variants.push(changed);
    }
    let mut broadened = raw.clone();
    broadened["nftables"][input]["rule"]["expr"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"accept":null}));
    variants.push(broadened);
    let mut changed = raw.clone();
    changed["nftables"][input]["rule"]["expr"][original_address]["match"]["left"]["ct"]["family"] =
        json!("ip6");
    variants.push(changed);
    let mut changed = raw.clone();
    changed["nftables"][output]["rule"]["expr"][destination_port]["match"]["left"]["payload"]
        ["protocol"] = json!("udp");
    variants.push(changed);
    for (index, changed) in variants.iter().enumerate() {
        assert!(
            verify_bootstrap_baseline_readback(&baseline, &capability, changed).is_err(),
            "changed observation {index}"
        );
    }
}

#[test]
fn isolated_profile_does_not_accept_loopback_public_routes_or_unqualified_platform_aliases() {
    let (baseline, capability) = fixture();
    for changed in [
        BootstrapManagementBaseline {
            interface_name: "lo".into(),
            ..baseline.clone()
        },
        BootstrapManagementBaseline {
            local_address: "8.8.8.1".into(),
            peer_address: "8.8.8.2".into(),
            ..baseline.clone()
        },
        BootstrapManagementBaseline {
            prefix_length: 24,
            ..baseline.clone()
        },
        BootstrapManagementBaseline {
            negative_udp_port: baseline.positive_udp_port,
            ..baseline.clone()
        },
        BootstrapManagementBaseline {
            network_namespace: "net:[0042]".into(),
            ..baseline.clone()
        },
    ] {
        assert!(compile_bootstrap_baseline(&changed, &capability).is_err());
    }
    let mut changed = capability;
    changed.profile = "common-host-v1".into();
    assert!(compile_bootstrap_baseline(&baseline, &changed).is_err());
}

#[test]
fn public_program_and_readback_reject_oversize_or_deep_typed_values() {
    let (baseline, capability) = fixture();
    let mut program = compile_bootstrap_baseline(&baseline, &capability).unwrap();
    program.nft_json = json!({"oversize": "x".repeat(131072)});
    assert!(program.canonical_bytes().is_err());
    assert!(program.hash().is_err());
    assert!(verify_bootstrap_baseline_readback(&baseline, &capability, &program.nft_json).is_err());
    let mut deep = Value::Null;
    for _ in 0..fw_contracts::MAX_DEPTH + 1 {
        deep = Value::Array(vec![deep]);
    }
    program.nft_json = deep;
    assert!(program.canonical_bytes().is_err());
    assert!(verify_bootstrap_baseline_readback(&baseline, &capability, &program.nft_json).is_err());
}

#!/usr/bin/env python3
"""Offline contract checks. Requires jsonschema>=4.23,<5. No runtime/crypto claim."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def walk_refs(value, root):
    if isinstance(value, dict):
        if "$ref" in value:
            ref = value["$ref"]
            assert ref.startswith("#/"), f"nonlocal reference: {ref}"
            target = root
            for part in ref[2:].split("/"):
                target = target[part.replace("~1", "/").replace("~0", "~")]
        for child in value.values():
            walk_refs(child, root)
    elif isinstance(value, list):
        for child in value:
            walk_refs(child, root)


def rewrite(value, prefix, destination="#/$defs/"):
    if isinstance(value, dict):
        return {key: destination + prefix + item[8:] if key == "$ref" and item.startswith("#/$defs/")
                else rewrite(item, prefix, destination) for key, item in value.items()}
    if isinstance(value, list):
        return [rewrite(item, prefix, destination) for item in value]
    return value


def closed_objects(value):
    if isinstance(value, dict):
        if value.get("type") == "object":
            assert value.get("additionalProperties") is False, "open object schema"
        for child in value.values():
            closed_objects(child)
    elif isinstance(value, list):
        for child in value:
            closed_objects(child)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="Optional JSON report output; stdout is always emitted.")
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    core_folder = folder / "F_기준자료" / "F_개발계약"
    if not core_folder.is_dir():
        core_folder = folder.parent / "F_개발계약"
    paths = {"extension": folder / "F_확장계약_스키마.json",
             "openapi": folder / "F_OpenAPI.json",
             "core": core_folder / "F_계약_스키마.json",
             "fixture": core_folder / "F_계약_예제.json"}
    schema, api, core, fixture = (read_json(paths[name]) for name in ("extension", "openapi", "core", "fixture"))
    results = []

    def check(name, function):
        try:
            function()
            results.append({"name": name, "passed": True})
        except Exception as exc:
            results.append({"name": name, "passed": False, "error": f"{type(exc).__name__}: {exc}"})

    check("json_schema_2020_12_metaschema", lambda: Draft202012Validator.check_schema(schema))
    check("extension_local_refs", lambda: walk_refs(schema, schema))
    check("openapi_local_refs", lambda: walk_refs(api, api))
    check("closed_object_schemas", lambda: closed_objects(schema["$defs"]))

    def core_parity():
        assert len(core["$defs"]) == 25
        for name, definition in core["$defs"].items():
            assert schema["$defs"]["Core_" + name] == rewrite(definition, "Core_"), name
        assert schema["x-core-contract-sha256"] == hashlib.sha256(paths["core"].read_bytes()).hexdigest()
    check("core_25_definitions_unchanged", core_parity)

    def api_parity():
        assert api["components"]["schemas"] == rewrite(schema["$defs"], "", "#/components/schemas/")
        assert api["x-core-contract-sha256"] == schema["x-core-contract-sha256"]
    check("openapi_schema_parity", api_parity)

    def api_structure():
        assert api["openapi"] == "3.1.0"
        ids = []
        for route, methods in api["paths"].items():
            for method, operation in methods.items():
                ids.append(operation["operationId"])
                assert operation["x-required-capability"]
                params = [api["components"]["parameters"][x["$ref"].split("/")[-1]] if "$ref" in x else x
                          for x in operation["parameters"]]
                assert {x["name"] for x in params if x["in"] == "path"} == set(re.findall(r"{([^}]+)}", route))
                if method != "get":
                    assert any(x["name"] == "Idempotency-Key" and x["required"] for x in params)
                assert any(str(status).startswith("2") for status in operation["responses"])
        assert len(ids) == len(set(ids))
    check("openapi_operation_parameters_and_idempotency", api_structure)

    def sample(name, definition, value, expected):
        def verify():
            validator = Draft202012Validator({"$schema": schema["$schema"], "$defs": schema["$defs"],
                                              "$ref": "#/$defs/" + definition}, format_checker=FormatChecker())
            errors = list(validator.iter_errors(value))
            assert (not errors) == expected, f"expected valid={expected}; errors={[e.message for e in errors[:2]]}"
        check(name, verify)

    uuid = "10000000-0000-4000-8000-000000000001"
    digest, now = "sha256:" + "a" * 64, "2026-10-30T00:00:00Z"
    plan_ref = {"plan_kind": "add_access_lease", "plan_id": uuid, "plan_hash": digest}
    active = {"operation_id": uuid, "kind": "deploy", "state": "active", "plan_ref": plan_ref,
              "receipt": fixture["receipts"][0], "completed_at": now}
    sample("deploy_active_positive", "OperationView", active, True)
    other = copy.deepcopy(active)
    keys = {"schema_version", "receipt_id", "grant_id", "grant_hash", "plan_hash", "target_id", "authority_epoch", "target_generation", "recorded_at"}
    other["receipt"] = {k: v for k, v in other["receipt"].items() if k in keys}
    other["receipt"].update(state="unknown", reason_code="RESULT_UNKNOWN", observed_state_hash=None, verified_at=None)
    sample("active_with_unknown_receipt_rejected", "OperationView", other, False)
    other = copy.deepcopy(active); other["state"] = "succeeded"
    sample("deploy_succeeded_rejected", "OperationView", other, False)
    other = copy.deepcopy(active); other["receipt"] = None
    sample("active_null_receipt_rejected", "OperationView", other, False)
    other = {"operation_id": uuid, "kind": "validate", "state": "succeeded", "plan_ref": plan_ref, "completed_at": now}
    sample("validate_succeeded_positive", "OperationView", other, True)
    other = {**other, "state": "active"}
    sample("validate_active_rejected", "OperationView", other, False)
    plan = {"plan_kind": "add_access_lease", "plan_hash": digest, "plan": fixture["plan"], "approval_state": "approved", "approval_set_hash": digest}
    sample("approved_plan_positive", "PlanView", plan, True)
    sample("approved_null_hash_rejected", "PlanView", {**plan, "approval_set_hash": None}, False)
    sample("approval_required_positive", "PlanView", {**plan, "approval_state": "approval_required", "approval_set_hash": None}, True)
    sample("approval_required_nonnull_hash_rejected", "PlanView", {**plan, "approval_state": "approval_required"}, False)
    mutation = {"op": "add_deny", "policy": fixture["requested_policies"][0]}
    sample("add_deny_with_allow_rejected", "PolicyMutation", mutation, False)
    mutation = copy.deepcopy(mutation); mutation["policy"]["action"] = "deny"
    mutation["policy"]["lifetime"] = {"kind": "review", "not_before": now, "review_at": "2026-11-01T00:00:00Z"}
    sample("add_deny_positive", "PolicyMutation", mutation, True)
    sample("unknown_property_rejected", "PolicyMutation", {**mutation, "bypass": True}, False)
    sample("unsupported_feature_positive", "FeatureSupport", {"state": "unsupported", "reason_code": "NOT_VERIFIED", "evidence_hash": None}, True)
    sample("supported_null_evidence_rejected", "FeatureSupport", {"state": "supported", "reason_code": None, "evidence_hash": None}, False)
    sample("unobserved_fresh_rejected", "Freshness", {"observed_at": None, "stale_after_seconds": 60, "stale": False, "source": "target"}, False)
    sample("allowed_with_denial_reason_rejected", "ActionPermission", {"action_id": "deployments.create", "allowed": True, "reason_code": "DENIED"}, False)
    completion = {"work_item_id": uuid, "claim_generation": "1", "result_hash": digest, "accepted_at": now, "candidate_request_id": None, "deployment_authorized": False}
    sample("worker_unprivileged_positive", "WorkCompletionReceipt", completion, True)
    sample("worker_deployment_authorized_rejected", "WorkCompletionReceipt", {**completion, "deployment_authorized": True}, False)
    target = {"target_id": uuid, "name": "test", "platform": "macos", "enforcement_backend": "nftables", "capability_version": "f.target-capability/v1", "profile": "host", "state": "observe_only", "desired_state_hash": None, "observed_state_hash": None, "capability_hash": digest, "authority_epoch": "1", "generation": "1", "observed_at": None}
    sample("platform_backend_mismatch_rejected", "TargetView", target, False)
    sample("macos_network_extension_positive", "TargetView", {**target, "enforcement_backend": "macos_network_extension"}, True)

    report = {"schema_version": "f.extended-contract-checks/v1", "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "passed": sum(x["passed"] for x in results), "failed": sum(not x["passed"] for x in results),
              "definitions": len(schema["$defs"]), "paths": len(api["paths"]), "operations": sum(len(x) for x in api["paths"].values()),
              "inputs": {key: {"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for key, path in paths.items()},
              "checks": results,
              "not_proven": ["full OpenAPI conformance beyond checked structure", "cryptographic authenticity", "WebAuthn correctness", "atomic database quota", "worker runtime fencing", "complete candidate composition", "OS packet enforcement", "product readiness"]}
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.report:
        args.report.write_text(output, encoding="utf-8")
    print(output, end="")
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(run())

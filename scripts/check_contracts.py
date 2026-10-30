#!/usr/bin/env python3
"""Check the preserved wire-contract baseline and its positive/negative fixtures.

This is contract evidence only. Rust admission/evaluator tests are executed by
`cargo test --workspace --locked`; neither check qualifies a native firewall.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPECS = ROOT / "docs/specs"


def read(path: Path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key in {path.name}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique)


def rewrite_refs(value):
    if isinstance(value, dict):
        return {k: (v.replace("#/$defs/", "#/$defs/Core_") if k == "$ref" else rewrite_refs(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [rewrite_refs(v) for v in value]
    return value


def main() -> int:
    checks = []
    try:
        manifest = read(SPECS / "F_패키지목록.json")
        for entry in manifest["files"]:
            source = (SPECS / entry["path"]).resolve()
            if not source.is_relative_to(SPECS.resolve()):
                raise ValueError("manifest path escapes specification root")
            if hashlib.sha256(source.read_bytes()).hexdigest() != entry["sha256"]:
                raise ValueError(f"preserved specification drift: {entry['path']}")
        checks.append({"name": "preserved_specification_hashes", "passed": True, "count": len(manifest["files"])})

        core = read(SPECS / "F_기준자료/F_개발계약/F_계약_스키마.json")
        extended = read(SPECS / "F_확장계약_스키마.json")
        checked = 0
        for name, definition in core["$defs"].items():
            alias = "Core_" + name
            if alias in extended["$defs"]:
                if rewrite_refs(copy.deepcopy(definition)) != extended["$defs"][alias]:
                    raise ValueError(f"core/extended schema drift: {name}")
                checked += 1
        if not checked:
            raise ValueError("zero core definitions checked")
        checks.append({"name": "core_schema_compatibility", "passed": True, "count": checked})

        commands = [
            ("core_reference_fixtures", [sys.executable, str(SPECS / "F_기준자료/F_개발계약/F_참조검증기.py"), "--self-test"]),
            ("extended_contract_fixtures", [sys.executable, str(SPECS / "F_확장계약_검증기.py")]),
        ]
        for name, command in commands:
            run = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
            if run.returncode:
                raise ValueError(f"{name} exited {run.returncode}: {run.stderr or run.stdout}")
            report = json.loads(run.stdout)
            if report.get("failed", 1) or report.get("passed", 0) <= 0:
                raise ValueError(f"{name} did not execute a passing suite")
            checks.append({"name": name, "passed": True, "count": report["passed"]})
    except (OSError, ValueError, KeyError) as error:
        checks.append({"name": "contract_check", "passed": False, "detail": str(error)})
    result = {"schema_version": "fw.contract-check/v1", "passed": sum(c["passed"] for c in checks),
              "failed": sum(not c["passed"] for c in checks), "checks": checks,
              "native_enforcement_verified": False}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

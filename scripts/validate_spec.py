#!/usr/bin/env python3
"""Validate design artifacts; never changes firewall or cloud state."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import unquote
from jsonschema import Draft202012Validator, FormatChecker


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique)


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def pointer(document, ref):
    if not ref.startswith("#/"):
        raise ValueError("nonlocal reference: " + ref)
    current = document
    for part in ref[2:].split("/"):
        current = current[part.replace("~1", "/").replace("~0", "~")]
    return current


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    checks = []

    def run(name, action):
        try:
            detail = action()
            checks.append({"name": name, "status": "PASS", "detail": detail})
        except Exception as exc:
            checks.append({"name": name, "status": "FAIL", "detail": str(exc)})

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    documents = {}
    for path in sorted(root.rglob("*.json")):
        if path.name in {"F_개발명세_검증결과.json", "F_패키지목록.json"}:
            continue
        def parse(path=path):
            documents[path.relative_to(root).as_posix()] = read(path)
            return "UTF-8; no duplicate keys"
        run("json:" + path.relative_to(root).as_posix(), parse)

    for filename in ["F_확장계약_스키마.json", "F_기본설정_스키마.json", "F_내부통신_스키마.json"]:
        def validate_schema(filename=filename):
            doc = documents[filename]
            Draft202012Validator.check_schema(doc)
            refs = [node["$ref"] for node in walk(doc) if "$ref" in node]
            for ref in refs:
                pointer(doc, ref)
            return {"definitions": len(doc.get("$defs", {})), "resolved_refs": len(refs)}
        run("schema:" + filename, validate_schema)

    def openapi():
        doc = documents["F_OpenAPI.json"]
        require(doc["openapi"].startswith("3.1."), "OpenAPI 3.1 required")
        refs = [node["$ref"] for node in walk(doc) if "$ref" in node]
        for ref in refs:
            pointer(doc, ref)
        ids = []
        methods = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
        for path, item in doc["paths"].items():
            for method, operation in item.items():
                if method not in methods:
                    continue
                ids.append(operation["operationId"])
                parameters = item.get("parameters", []) + operation.get("parameters", [])
                declared = {p["name"] for p in parameters if p.get("in") == "path" and p.get("required")}
                require(set(re.findall(r"\{([^}]+)\}", path)) <= declared, "path parameter missing: " + path)
                require(bool(operation.get("responses")), "response missing: " + path)
        require(len(ids) == len(set(ids)), "duplicate operationId")
        return {"paths": len(doc["paths"]), "operations": len(ids), "resolved_refs": len(refs), "scope": "reference/operation structure; not full OAS conformance or live API"}
    run("openapi:structure", openapi)

    def core_compat():
        core_path = root / "F_기준자료/F_개발계약/F_계약_스키마.json"
        original = read(core_path)
        extended = documents["F_확장계약_스키마.json"]
        def remap(value):
            if isinstance(value, dict):
                return {k: (v.replace("#/$defs/", "#/$defs/Core_", 1) if k == "$ref" and isinstance(v, str) and v.startswith("#/$defs/") else remap(v)) for k, v in value.items()}
            if isinstance(value, list):
                return [remap(x) for x in value]
            return value
        for key, value in original["$defs"].items():
            require(extended["$defs"]["Core_" + key] == remap(value), "core changed: " + key)
        digest = hashlib.sha256(core_path.read_bytes()).hexdigest()
        declared = extended.get("x-core-contract-sha256", "")
        require(declared in {digest, "sha256:" + digest}, "core source hash differs")
        return {"unchanged_definitions": len(original["$defs"]), "sha256": digest}
    run("core:backward_compatibility", core_compat)

    def locales():
        messages = documents["F_기본문구.json"]["messages"]
        require(set(messages) == {"en", "ko", "ja", "es", "zh-Hans", "zh-Hant"}, "locale set differs")
        english = messages["en"]
        for locale, values in messages.items():
            require(set(values) == set(english), "locale keys differ: " + locale)
            for key, value in values.items():
                require(isinstance(value, str) and bool(value.strip()), "empty translation")
                require(set(re.findall(r"\{([a-zA-Z_][\w]*)", value)) == set(re.findall(r"\{([a-zA-Z_][\w]*)", english[key])), "interpolation differs: " + locale + ":" + key)
        return {"locales": len(messages), "keys_per_locale": len(english), "native_language_review": "NOT_RUN"}
    run("locales:keys_and_interpolation", locales)

    def config():
        validator = Draft202012Validator(documents["F_기본설정_스키마.json"], format_checker=FormatChecker())
        example = documents["F_기본설정_예제.json"]
        validator.validate(example)
        variants = []
        remote = copy.deepcopy(example)
        remote["controller"]["bind_address"] = "0.0.0.0"
        variants.append(remote)
        telemetry = copy.deepcopy(example)
        telemetry["telemetry"]["enabled"] = True
        variants.append(telemetry)
        unknown = copy.deepcopy(example)
        unknown["unknown_field"] = True
        variants.append(unknown)
        auth = copy.deepcopy(example)
        auth["controller"]["authentication_required"] = False
        variants.append(auth)
        for index, variant in enumerate(variants):
            require(not validator.is_valid(variant), "unsafe config accepted: " + str(index))
        return {"positive": 1, "negative_rejected": len(variants), "runtime_security_checks": "NOT_RUN"}
    run("config:positive_and_negative", config)

    def internal():
        validator = Draft202012Validator(documents["F_내부통신_스키마.json"], format_checker=FormatChecker())
        example = documents["F_내부통신_예제.json"]
        validator.validate(example)
        variants = []
        command = copy.deepcopy(example)
        command["body"]["command"] = "arbitrary-command"
        variants.append(command)
        wrong_kind = copy.deepcopy(example)
        wrong_kind["kind"] = "dispatch"
        variants.append(wrong_kind)
        numeric_epoch = copy.deepcopy(example)
        numeric_epoch["authority_epoch"] = 1
        variants.append(numeric_epoch)
        for variant in variants:
            require(not validator.is_valid(variant), "invalid internal envelope accepted")
        return {"positive": 1, "negative_rejected": len(variants), "mTLS_and_runtime_authorization": "NOT_RUN"}
    run("internal:positive_and_negative", internal)

    def core_tests():
        directory = root / "F_기준자료/F_개발계약"
        with tempfile.TemporaryDirectory(prefix="fw-spec-check-") as temporary:
            report_path = Path(temporary) / "core.json"
            result = subprocess.run([sys.executable, str(directory / "F_참조검증기.py"), "--self-test", "--report", str(report_path)], cwd=directory, capture_output=True, text=True, encoding="utf-8", timeout=90)
            require(result.returncode == 0, "core reference failed: " + result.stderr[-1500:] + result.stdout[-1000:])
            report = read(report_path)
            return {"returncode": 0, "summary": {k: v for k, v in report.items() if not isinstance(v, (dict, list))}, "runtime": "NOT_TESTED"}
    run("core:reference_self_test", core_tests)

    def extension_tests():
        with tempfile.TemporaryDirectory(prefix="fw-extension-check-") as temporary:
            report_path = Path(temporary) / "extension.json"
            result = subprocess.run([sys.executable, str(root / "F_확장계약_검증기.py"), "--report", str(report_path)], cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=60)
            require(result.returncode == 0, "extension checks failed: " + result.stderr[-1500:])
            report = read(report_path)
            require(report["failed"] == 0, "extension negative cases failed")
            return {"passed": report["passed"], "failed": report["failed"], "scope": "shape/static checks only"}
    run("extension:reference_self_test", extension_tests)

    def links():
        checked = 0
        for path in root.glob("F_*.md"):
            if path.name in {"F_README.md", "F_AGENTS.md", "F_SKILL.md"}:
                continue
            content = path.read_text(encoding="utf-8-sig")
            require(len(re.findall(r"^```", content, re.M)) % 2 == 0, "unclosed code fence: " + path.name)
            for target in re.findall(r"\]\(([^)]+)\)", content):
                target = target.strip("<>").split("#", 1)[0]
                if not target or re.match(r"[a-zA-Z]+:", target):
                    continue
                resolved = (path.parent / unquote(target)).resolve()
                require(resolved.is_relative_to(root), "link escapes package: " + path.name + ":" + target)
                require(resolved.exists(), "missing link: " + path.name + ":" + target)
                checked += 1
        return {"local_markdown_links": checked}
    run("docs:local_links_and_fences", links)

    def required():
        prefixes = [f"F_{n:02d}_" for n in range(13)]
        for prefix in prefixes:
            require(any(root.glob(prefix + "*.md")), "missing specification: " + prefix)
        for filename in ["F_AGENTS.md", "F_SKILL.md", "F_저장소_내보내기.py", "F_Codex_시작프롬프트.txt"]:
            require((root / filename).is_file(), "missing file: " + filename)
        require((root / "F_AGENTS.md").stat().st_size < 32768, "AGENTS exceeds default byte budget")
        skill = (root / "F_SKILL.md").read_text(encoding="utf-8")
        require(skill.startswith("---\nname: firewall-install\n"), "skill frontmatter missing")
        return "13 numbered specs, agent instructions, installation skill, exporter"
    run("package:required_files", required)

    report = {"schema_version": "f.spec-validation/v1", "checked_at": datetime.now(timezone.utc).isoformat(), "status": "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL", "passed": sum(x["status"] == "PASS" for x in checks), "failed": sum(x["status"] == "FAIL" for x in checks), "checks": checks, "not_tested": ["firewall implementation", "real cryptographic authority", "database concurrency", "Linux kernel", "Windows WFP driver", "macOS Network Extension", "cloud deployment", "installer", "browser runtime", "native-language translation review"]}
    if args.report:
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "passed": report["passed"], "failed": report["failed"], "failures": [x for x in checks if x["status"] == "FAIL"]}, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

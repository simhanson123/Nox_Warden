#!/usr/bin/env python3
"""Copy the self-contained specification into a NEW repository directory."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    destination = args.destination.resolve()
    if destination == source or destination.is_relative_to(source) or source.is_relative_to(destination):
        raise SystemExit("Destination must be separate from the source package.")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise SystemExit("Destination must be absent or an empty directory. No files overwritten.")
    manifest_path = source / "F_패키지목록.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    inputs = []
    for item in manifest["files"]:
        relative = Path(item["path"])
        path = (source / relative).resolve()
        if relative.is_absolute() or not path.is_relative_to(source) or path.is_symlink():
            raise SystemExit("Invalid manifest path: " + str(relative))
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise SystemExit("Missing or modified package file: " + str(relative))
        inputs.append((path, relative))
    inputs.append((manifest_path, Path(manifest_path.name)))
    destination.mkdir(parents=True, exist_ok=True)
    for path, relative in inputs:
        target = destination / "docs/specs" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    aliases = {
        "F_AGENTS.md": "AGENTS.md",
        "F_README.md": "README.md",
        "F_명세_검증기.py": "scripts/validate_spec.py",
        "F_SKILL.md": "skills/firewall-install/SKILL.md",
        "F_기준자료/F_GitHub_공개준비/F_LICENSE.txt": "LICENSE",
        "F_기준자료/F_GitHub_공개준비/F_NOTICE.txt": "NOTICE",
        "F_기준자료/F_GitHub_공개준비/F_SECURITY.md": "SECURITY.md",
        "F_기준자료/F_GitHub_공개준비/F_CONTRIBUTING.md": "CONTRIBUTING.md",
        "F_기준자료/F_GitHub_공개준비/F_GOVERNANCE.md": "GOVERNANCE.md",
        "F_기준자료/F_FUNDING.yml": ".github/FUNDING.yml.example"
    }
    for original, relative in aliases.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / original, target)
    (destination / ".gitignore").write_text("/state/\n/target/\n/web/node_modules/\n/web/dist/\n.env\n.env.*\n!.env.example\n*.key\n*.pfx\n*.p12\n__pycache__/\n/reports/local/\n", encoding="utf-8")
    (destination / "REPOSITORY_EXPORT.json").write_text(json.dumps({"spec_version": "F-2.0", "copied_spec_files": len(inputs), "aliases": aliases, "git_created": False, "published": False, "firewall_installed": False}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "EXPORTED", "spec_files": len(inputs), "standard_aliases": len(aliases), "destination": str(destination), "next": "Read AGENTS.md; run python scripts/validate_spec.py --root docs/specs"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

# Verification and implementation status

This directory keeps a concise status summary, the [task ledger](task-ledger.json)
and [specification provenance](spec-import.json). Generated logs, screenshots,
raw JSON reports and repeated execution records are ignored by Git. Local runs
may write here; CI retains its HTTP, CLI and Linux smoke reports as downloadable
GitHub Actions artifacts for seven days. CI logs and check status remain attached
to their workflow runs. Keep tests and reproduction commands in source control.

Previously committed raw reports remain in Git history; routine cleanup does not
rewrite that history. The original supplied specification remains unchanged in
`docs/specs`; its bundled design fixtures are source material, not new run logs.

## Verified baseline

[CI at commit 0d17feb](https://github.com/simhanson123/Nox_Warden/actions/runs/41014262778)
passed the core, HTTP, CLI and isolated Linux checks. The earlier failures at
`1cf1951` were caused by a CLI test directory inheriting public permissions from
GitHub's default umask. The positive fixture now explicitly creates a private
parent; production credential permission checks remain intact.

| Check | Baseline result | Reproduce from repository root |
| --- | --- | --- |
| Original specification | 27 checks passed | `python scripts/validate_spec.py --root docs/specs` |
| Reference contracts | 52 core and 28 extended fixtures passed | `python scripts/check_contracts.py` |
| Rust workspace | 158 tests passed | `cargo test --workspace --locked` |
| HTTP/OpenAPI | 24 checks passed | `python scripts/smoke_control.py` |
| Real-controller CLI | 11 checks passed | `python scripts/smoke_cli.py` |
| Linux runner | 4 regressions passed | `python -m unittest discover -s native/linux -p test_runner.py` |
| Isolated Linux kernel | 53 checks, including 40 packet probes, passed | `python scripts/linux-lab.py --report reports/linux-lab.json` |

Run `source scripts/dev-env.sh` first. `bash scripts/check.sh` also checks formatting,
Clippy, frontend types, locale parity, component tests and the web build.
Build `fw_control` and `fw_cli` before their smoke checks. The Linux lab requires
Docker and an isolated namespace with NET_ADMIN; see the
[Linux lab instructions](../native/linux/README.md). Browser test setup is in the
[web instructions](../web/README.md).

## Current UI scope

English is the first-visit default. A user's explicit language selection persists.
Selectable locales are English, Korean, Japanese, Spanish, German, French,
Simplified Chinese and Traditional Chinese. The original six-locale source
specification is preserved; this expanded policy follows the latest user decision.
Local validation of this change passed: 27 UI tests, eight catalogs with 169
matching keys/placeholders, type checking and the production build. Fifteen
live Chromium checks passed, including English startup with a Korean browser
preference and explicit locale persistence across reloads. The full repository
check also passed. Detailed outputs stay local; the pull request links CI results.

## Release boundary

The product is a partial development implementation. The controller remains
observe-only. Linux loopback smoke does not certify a production host firewall.
Full Linux qualification, Windows WFP/callout and macOS Network Extension
implementation/qualification, production authority/enrollment/watchdog integration,
signed installers and full accessibility/translation acceptance remain incomplete.
Human translation review has not been completed. See the
[implementation overview](../docs/implementation.md) and
[platform status](../docs/platform-support.md) for the current limits.

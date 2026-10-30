# Repository instructions

This repository is the F-2.0 development specification for a native, open-source firewall. Read `docs/specs/F_00_시작안내.md` and the precedence table in `docs/specs/F_01_제품_구현_기준.md` first. The public brand is not final; use neutral `fw_*` module identifiers. Latest explicit user decisions take precedence over the preserved specification package; do not rewrite the original files under `docs/specs` to erase that history.

## Product requirements

- Native installation and host enforcement on Linux, Windows/Windows Server, and macOS are required. A browser client or a Linux VM on another OS is not equivalent.
- Use nftables, Windows WFP with the required callout, and macOS Network Extension. Do not ship a PF fallback on macOS.
- Preserve default deny, explicit deny precedence, current valid allow union, expiry for established connections, immutable plan approval, independent signing/quota, durable epoch/generation, and conservative UNKNOWN recovery.
- AI proposes and reads evidence; it cannot approve itself or directly run privileged firewall commands.
- Apache-2.0 applies to original project work; keep dependency notices. Telemetry defaults OFF. Donation is optional and does not gate security features.
- Human UI and agents must share structured evidence. English (`en`) is the default interface language, including first visits from non-English browsers. Preserve an explicitly saved supported language choice. Additional locales are `ko`, `ja`, `es`, `de`, `fr`, `zh-Hans` and `zh-Hant`; this user decision extends the original six-locale specification. Never translate wire identifiers or signature bytes.
- Cloud VM/native installation, restricted hosting, WordPress integration, npm distribution, and agent skills have different authority boundaries. Read F_11 for those tasks.

## Work procedure

Follow task IDs and dependencies in `docs/specs/F_08_Codex_Cloud_작업계획.md`. Implement a testable slice per change. Update affected schemas, API, docs, tests, and migration together. Run the applicable checks and report exact commands/results. A skipped native OS test is not a pass. Do not call the product complete after Linux alone works.

The bundled Python validator checks design artifacts only. Product commands listed in F_08 become required after their corresponding implementation task creates them. Do not invent passing output or create empty programs merely to make a command succeed.

Keep core pure logic separate from OS writes. Do not run integration firewall tests on a developer's active network or the agent's control connection. Use the disposable lab and explicit OS runner. A mock, cross-compile, or JSON validation is not kernel qualification.

Do not fetch a script from the internet and execute it blindly. Use pinned dependencies and verify release provenance. Never commit secrets, signing keys, account/bank details, personal addresses, or interview documents. Do not automatically create paid cloud resources, publish packages, enable donations, or deploy production firewall changes merely because a development task exists. Continue all authorized local implementation and checks without redundant confirmation.

## Validation entry point

From the repository root, the design-only check is:

```sh
python scripts/validate_spec.py --root docs/specs
```

The environment must provide `jsonschema>=4.23,<5`; pin its exact resolved version in M00. Source code checks and native runner commands are specified in F_08. Retain failing evidence locally or as a bounded CI artifact while fixing its cause; do not weaken invariants to pass tests. Raw evidence does not need a source commit.

## Completion report

Report changed behavior, relevant task IDs, checks and their outcomes, material limitations, and useful evidence links concisely. Keep implementation status distinct from design intent and release certification. Commit source, tests, reproducible commands, a short verification summary in `reports/README.md`, the compact task ledger and original specification provenance. Do not continuously commit development diaries, raw logs, screenshots, repeated generated reports or transient failures. Keep those outputs in ignored local paths; CI may retain explicitly selected reports as artifacts for seven days. This user decision supersedes earlier instructions to persist every development record in the repository. Create focused branches, commit verified changes, push and merge reviewed changes into `main` after required checks within the authorized development workflow, without repeatedly asking the user to perform routine Git operations. Use functional commit and pull-request titles that explain the resulting behavior; avoid internal specification IDs, phase labels and test-fixture jargon in public titles. Consolidate routine fixups instead of publishing a development diary. Do not automatically delete remote branches: a previous deletion was rejected by automatic approval review, and deletion requires separate authorization. Do not rewrite shared history unless the user explicitly authorizes that scope.

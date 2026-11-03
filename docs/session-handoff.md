# Resume Nox_Warden from the repository

Repository: <https://github.com/simhanson123/Nox_Warden>.
Read this file, [startup prompt](session-start-prompt.txt), `AGENTS.md`,
[continuity](review-continuity.md), [task ledger](../reports/task-ledger.json),
[verification](../reports/README.md) and [implementation](implementation.md).
No previous chat, attachment, temporary file, agent mailbox or cached binary is
needed. Preserve a dirty worktree and resolve the current branch/HEAD remotely.

## Baselines and completed scope

PR20 reviewed head: `9e021b31171ae19ff8c9e7eba400d8dd4630a001`;
comparison base: `09ef6a866632a9a6e12e2af799cb18b8b55daca9`;
implementation merge: `6eb68a9251b76ac164f8efb0fa5ad5ded1336564`.
The original Claude Opus5.5 report remains byte-identical, SHA256
`abc796dce74778372c613c253d2891037ca386430d475ea7a8040a97c415aa2c`.
Do not request that same review again or claim its private probes were rerun.

Documentation handoff [PR21](https://github.com/simhanson123/Nox_Warden/pull/21)
head `c09176537e582c24eac1ae9701b58b382cdc90cc` had successful CI41446221692
and merged as `2219c9ffe64fc0f4a967f3af69e84cdcc15aaff3`.
Its remote branch `docs/pr20-review-handoff` is retained. The integrated product
follow-up starts at that merge on `fix/authority-history-and-project-quota`.
Resolve its latest PR/head and required check status from GitHub; do not infer
completion from an older test count. Current executions belong in reports/README.

The follow-up implements authority schema11 history/audit integrity and schema12
project-only general-policy quota, preserving migrations001–010 and all original
specification/review bytes. See [N1–N7 corrections](pr20-follow-up.md),
[quota design](project-policy-quota-design.md), [storage](authority-store.md),
[coordination](signing-coordination.md) and [operator commands](signing-coordination-cli.md).

- Retained rowid/PK/alternate-key replacement is refused; audit heads advance only
  to exact successors, and ordered quota history keeps genesis and witnesses.
- Each work mutation consumes unique retained audit evidence and atomically
  projects its head. Canonical UUID and retained dispatch/delivery/claim times
  agree between SQL and runtime validation.
- Exact SQLite metadata, including autoindexes, is compared with an independent
  reference. Full open/maintenance validation rejects broken reference graphs;
  live admission validates the indexed obligations it uses.
- Missing or ambiguous historical audit matches stop migration with source and
  private backup intact. No job/audit/completion authority or refund is invented.
- Schema12 preserves old rowids and canonical v1 bytes, with FK-safe maintenance,
  rollback and explicit version2 project-only codecs. Old rooted and new rootless
  obligations share project capacity. “Rootless” does not mean unprivileged OS execution.
- Administrator revision CAS permits original-root A → project-only → A;
  another root B is always refused. Initially project-only projects remain so.
- Issued, UNKNOWN and unsigned-delivered obligations stay held through expiry,
  restart and rolling-window advancement. Retained jobs observe their original
  root clock after configuration changes.
- Explicit v2 CLI/API/readiness and eight-locale UI show current scope and retained
  UNKNOWN history. V1 retained bytes and wire keys remain compatible; core without
  provenance now correctly reports quota unavailable. Production permissions stay false.
- The intermittent CLI authentication test now uses the persisted authentication
  timestamp. A deterministic one-second mismatch test preserves the production
  freshness requirement and verifies403 before valid revocation succeeds.

Fresh fixtures independently reproduced N1–N7 at the old implementation. The
N2 public-API reproduction became a permanent refusal regression. An actual old
binary created both a public-API principal/audit DB and a two-job signed fixture
DB, upgraded through schema12 with exact rowid/BLOB preservation. The signed
fixture uses development test authority, not production qualification. Other
legacy fixtures reconstruct historical schema around genuine lifecycle data;
do not describe every fixture as old-binary-created.

## Working decisions

Use GPT-6.1 Sol at ultra reasoning for workers; the lead orchestrates. Split file
ownership and implement substantial integrated batches. Run focused necessary
regressions while implementing, then one combined independent review and full
validation. Avoid repeated small handoffs/full-suite waits. Fix found defects
within the batch. Commit/push/open PR/finish CI/merge after required checks within
the authorized development workflow; keep remote branches and shared history.

The next user-mediated external review uses **Claude Opus5.5 only**, covering the
actual new fixed base/head in one complete copyable prompt. Preparing that prompt
is not execution; internal agents are not a Claude review. The current prompt is
linked from [review prompts](review-prompts.md) and the follow-up PR.

Keep compact verification and task state in Git; no raw logs, screenshots or
repeated development diary. Do not reuse historical checks as new passes.

## Product boundary and next development

The management application observes/records requests; it still does not protect
host traffic. The separate Linux executor actually applies nftables and tests
packets in disposable labs. Production integration remains unfinished. Observe
is a startup safety mode, never the final firewall acceptance criterion.

Next work follows F_08 dependencies: complete core semantic-review/native/signing
integration with a single absolute lease window and signed workload/delegation
authority; protected bootstrap/accounts, generation initialization and independent
signer; qualified build/native evidence; authenticated dispatch, completion and
reconciliation; Linux host lifecycle/watchdog/installer/recovery. Windows/Windows
Server WFP+callout and macOS Network Extension must be implemented and tested on
actual supported platforms. No PF fallback or Linux-VM substitute for another OS.
External audit anchors, PostgreSQL/OIDC, rotation, evidence export/restore/retention,
remaining APIs/UI/accessibility, signed installers and seven-provider acceptance
remain in the ledger. Do not estimate completion from test totals.

English default, saved language choice and eight locales remain required.
Apache-2.0, telemetry OFF, optional non-gating donation and AI self-approval ban
remain. Keep production signing/dispatch closed until their protection and
identity paths exist. Use disposable labs, never host/control-network firewall
experiments. Paid resources, package publication and production deployment are
outside this development authorization.

## Recreate and validate

Read the current Cloud runtime/network skill and current readiness; inspect the
network policy and tools afresh. Follow README pins and locks, source
`scripts/dev-env.sh`, and run `bash scripts/check.sh`, the shared-umask check and
relevant real runtime commands in reports/README. Current tested environment used
Rust1.99.1, Node24.19.0, npm11.9.0, Python3.12.14, system Chromium154 and the managed
Docker socket. Those observations are not guarantees for a new environment.
Unavailable native/browser checks are NOT_RUN, never PASS.

# Resume Nox_Warden without the previous conversation

This is the durable entry point for a new Codex Cloud session. The user's latest
request is to continue development after receiving the PR #20 external review
and preserve everything needed when the current conversation/workspace disappears.
The [startup prompt](session-start-prompt.txt) can be pasted into the new session.
No previous chat, uploaded attachment, `/tmp` directory, agent mailbox, local
database, generated binary or seven-day CI artifact is required to understand
the next task.

## Exact checkpoint

Repository: <https://github.com/simhanson123/Nox_Warden>.

| Item | Fixed identity |
| --- | --- |
| Latest implemented batch | [PR #20](https://github.com/simhanson123/Nox_Warden/pull/20) |
| Comparison base | `09ef6a866632a9a6e12e2af799cb18b8b55daca9` |
| Reviewed implementation head | `9e021b31171ae19ff8c9e7eba400d8dd4630a001` |
| Implementation merge on main | `6eb68a9251b76ac164f8efb0fa5ad5ded1336564` |
| PR CI | [41425943304 — success](https://github.com/simhanson123/Nox_Warden/actions/runs/41425943304) |
| Main CI | [41429434650 — success](https://github.com/simhanson123/Nox_Warden/actions/runs/41429434650) |
| Current authority schema | 10 |
| Handoff branch | `docs/pr20-review-handoff` |

The reviewed head and implementation merge have identical source trees. The
handoff branch adds documentation and supplied review evidence; it does not
implement the new N1–N7 fixes or rootless policy quota. Its commit is deliberately
not embedded here, to avoid a self-referential commit identifier. Resolve the
branch from GitHub and report `git rev-parse HEAD` when resuming. If it has merged,
start from current main after confirming these files are present.

Check whether the handoff branch has an open PR and finish its required checks
and merge before basing the product follow-up on main. A handoff PR is only
documentation/review evidence; its existence or green CI does not fix N1–N7.
The final user message supplies the pushed handoff commit and PR link. Query
their current state instead of assuming a pending CI run survived the session.

Keep remote branches. Do not reset a dirty workspace, force-push shared history,
run cleanup commands quoted in external reports, or assume another session's
worktree paths exist.

## Read these sources

1. `AGENTS.md`, `docs/specs/F_00_시작안내.md` and the precedence table in
   `docs/specs/F_01_제품_구현_기준.md`.
2. This document, [review continuity](review-continuity.md),
   [task ledger](../reports/task-ledger.json), [verification](../reports/README.md)
   and [implementation boundaries](implementation.md).
3. [Original PR20 review](reviews/pr20-claude-review.md),
   [follow-up acceptance requirements](pr20-follow-up.md),
   [signing coordination](signing-coordination.md), [authority store](authority-store.md).
4. [Prepared project-only quota design](project-policy-quota-design.md).
5. F_03/F_04/F_07/F_08/F_12 and other original specifications for the touched scope.

The original specification package and all published authority migrations through
010 are historical inputs. Add a new migration; do not edit old SQL to make a
damaged database appear valid. Keep original review bytes unchanged too.

## User decisions that survive the session

- Continue substantial integrated implementation batches with disjoint parallel
  ownership and one consolidated independent review. Correct reproduced defects;
  do not repeatedly stop for small handoffs or routine permission requests.
- Commit, push, open PRs and merge reviewed changes after required checks within
  the authorized development workflow. Preserve remote branches and shared history.
- Use **Claude Opus 5.5 only** for the next user-mediated external review. Internal
  independent agents are available; do not label their work as a Claude execution.
  Print a complete copyable external prompt with fixed base/head at that handoff.
- Keep compact task/verification state in Git; raw logs/screenshots are not a
  development diary. Preserve supplied review originals as attributed evidence.
- Product: native Linux nftables, Windows/Windows Server WFP with callout, and
  macOS Network Extension. No PF fallback or Linux-VM substitute for another OS.
- English default, saved locale preference retained, eight locales:
  `en`, `ko`, `ja`, `es`, `de`, `fr`, `zh-Hans`, `zh-Hant`.
- Apache-2.0; telemetry OFF by default; optional donations never gate security.
- AI may propose/read evidence; it cannot approve itself or gain privileged
  firewall authority. Production signing/dispatch remain closed. No paid resources,
  package publication, production deployment or active-host firewall tests are
  implied by this development authorization.

## What is implemented, and what the new report changes

PR20 retains original AccessRequest/Envelope/Delegation and per-plan bindings,
uses the full original requested duration for cost, adds trusted-local provenance
CLI commands and eight-locale readiness, and upgrades authority storage to schema10.
Issued capacity remains held after unsigned delivery, expiry and reopening;
UNKNOWN history cannot justify a return to issued. Schema10 checks all 45 current
signing guards and protects work/accounting-head identities. This is development
infrastructure, not production authorization.

The newly received Claude report reviews that exact PR20 head. It confirms the
PR19 F1–F4 corrections and reports **seven Low findings N1–N7**, with no reported
Critical/High/Medium or blocker to continued development. Those conclusions are
external review statements, not proof that no other issue exists. **N1–N7 are open.**
Earlier internal review/CI success must not be used to mark them fixed.

The report is 17,167 bytes, SHA-256
`abc796dce74778372c613c253d2891037ca386430d475ea7a8040a97c415aa2c`.
Its private probe sources and worktrees were not supplied. Do not say they were
rerun or try to recover them from the report's machine-specific `/tmp` paths.
Fresh source assessment and any narrow local reproduction are identified in
[the follow-up document](pr20-follow-up.md), separately from Claude's execution.

## Next concrete implementation

Start with **authority history/audit integrity and migration parity (M02/M03)**:
independently reproduce N1–N7, implement the coherent protections in a new schema
migration plus runtime validation, keep regression evidence, and perform relevant
checks and consolidated independent review. N1/N2/N7 retention and N5 migration
validation are foundations for the next quota-table rebuild. N3/N4 require careful
transaction ordering; a local audit row does not authenticate a malicious DB writer.
Include the reported CLI diagnostic wording and investigate the timing-test failure
without weakening production freshness rules. See the exact acceptance matrix.

Then implement **project-only general-policy quota (M02/M03/M05/M06)** with
versioned configuration/snapshots and shared accounting across retained rooted and
new rootless obligations. Here rootless means no delegation root, not unprivileged
OS enforcement. The prepared design is not implemented. Choose migration numbers
from the actual current schema after the security work; do not reserve schema11
for rootless work or assume the old 45-guard/15-affected-trigger counts still hold.

Keep issued, UNKNOWN and unsigned delivered obligations held throughout both
batches. Authenticated completion receipts are a later protocol dependency;
never solve capacity accumulation by treating an unsigned completion as proof.

## Recreate tools and verification

Use the current managed-cloud runtime/network skill when available. Inspect
current readiness; do not assume previous credentials, Docker, browser caches or
toolchains survived. Follow [README prerequisites](../README.md#run-locally):
Rust 1.99.1, Node 24.19.0, npm 11.9.0, pinned Python requirements, OpenSSL headers
and pkg-config. On Linux x86_64, the repository's checksum-pinned
`scripts/install-rust.sh` installs Rust if needed; source `scripts/dev-env.sh`
from the repo root. Use the existing lockfiles and vendor checks.

For an implementation batch, use `bash scripts/check.sh`, the explicit shared
umask test and applicable real runtime commands in [reports/README](../reports/README.md).
The full check invokes the intentionally ignored cancellation CLI test separately.
Check the browser executable/version rather than reusing the reviewer's absolute
path. Docker suites run only in disposable namespaces with the supported lab.
Unavailable OS/Docker/browser checks are NOT_RUN, never PASS.

Last implementation validation: Rust workspace 800, reduced features 32, explicit
CLI process 1, UI 180; shared-umask authority/service 406. Final PR CI retained
12 passing runtime reports: HTTP24, CLI13, enrollment23, metadata41, catalogue11,
passkey76, login14, audit21, authority40, Linux66/40 packets, signed Linux98/43
packets, native evidence33/5 captures. These are historical baseline counts;
new changes require new results. The supplied Claude report independently records
its own executions and explicitly did not run the three Docker suites.

For this documentation handoff, 27 specification checks, diff whitespace,
review byte/hash preservation, ledger JSON and 102 local Markdown references
were checked. A separate reviewer found no blocking handoff inconsistency and
ran the portable N2 instructions from a fresh directory successfully, reproducing
the same unfixed defect. Full product suites were not rerun for these doc-only edits.

## Remaining product scope

The product is not release ready. After the next two batches, retain the ledger's
core semantic/native/signing integration, single absolute lease window, signed
workload/delegation authority, protected bootstrap/accounts and independent signer,
authenticated executor completion/reconciliation, build identity and qualified
observation, Linux host lifecycle/watchdog/installer, actual Windows/macOS native
implementation, PostgreSQL/OIDC/credential rotation, remaining APIs/UI/accessibility,
evidence export/restore/retention, installers and seven-provider acceptance.
Do not infer a completion percentage from test counts or mark the product complete
after Linux lab success. Follow F_08 dependencies and keep the compact ledger current.

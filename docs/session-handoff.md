# Resume Nox_Warden from the repository

Repository: <https://github.com/simhanson123/Nox_Warden>.
Read this file, [startup prompt](session-start-prompt.txt), `AGENTS.md`,
[continuity](review-continuity.md), [task ledger](../reports/task-ledger.json),
[verification](../reports/README.md) and [implementation](implementation.md).
No previous chat, attachment, temporary file, agent mailbox or cached binary is
needed. Preserve a dirty worktree and resolve the current branch/HEAD remotely.

## Current signer durability and target-confirmation follow-up

PR28 now integrates the retained PR26/27 history into `main`, but is not merged.
Its first real CI42277449076 passed through protected signer and failed target
namespace setup at marker1/packet0. Bounded diagnostic and parallel CI follow-up
is in progress; see the current verification report. Do not infer the exact
OS restriction or a remote PASS from the earlier local results. Read the PR28
completion record for the actual later head/run/merge/main-CI outcome.

Branch `feat/target-authority-confirmation` starts at PR27 head
`5fc576f672c2e0671164b73a667e3452b99ea82a`, tree
`719b80f88255921711ede7b4f4da81876568f7e3`. The change repairs SQLite lock-safe
signer durability, revoked-key reporting and independent project approval-origin
binding. Schema16 adds origin and target confirmation history while preserving
published SQL001–015 and old signed bytes.

The new isolated Linux path verifies owner-authorized bootstrap material, retains
a separate durable journal, applies a compiled non-loopback management baseline
and measures signed peer probes and full kernel readback. The authority retains
the verified target confirmation and actual epoch predecessor. CLI, readiness v3
and eight-locale UI distinguish accepted history from current eligibility.
Policy signing and dispatch remain false. The explicit
`isolated-linux-bootstrap-v1` profile does not establish installed host protection.

The [received PR27 review](reviews/pr27-claude-review.md) is preserved as 17,066
bytes, 207 CRLF endings, SHA256
`8b4fa4e6d84ec7c755b3489309bb72a2e31e8fed1bc0634408c010348fd19357`.
Its private probes were not supplied. New exact-source reproduction and normal
corrected regressions address S-1; the earlier PR27 passing suite missed that
lifecycle. Read [the correction contract](pr27-follow-up.md),
[target contracts](target-authority-confirmation.md) and
[current verification](../reports/README.md). All 21 selected local stages passed, plus applicable Python/timeout controls
after a lab-only helper correction. Reports bind 18 stages to the original source
and 3 to the corrected snapshot; product Rust/UI source is identical across them.
Old PR27 counts are not reused. Independent source/evidence/binary and15-report
artifact audits passed with no mismatch; exact receipts are in the reports.

PR26 and PR27 remain open dependencies. Their last recorded runs42150829408 and
42216796210 failed before execution because of billing. Local tests establish no
remote PASS, merge or main CI. Resolve the new feature's exact head/tree, stacked
PR and CI from its retained completion record. Preserve remote branches/shared
history. Use Sol6.1 ultra implementation and Astra ultra architecture/independent
review, disjoint ownership and one consolidated batch review.

Next substantial work: qualified production inputs and policy-signer trust,
authenticated dispatch/completion/reconciliation and installed Linux lifecycle.
Windows WFP/callout and macOS Network Extension remain mandatory native tracks.
[Remaining acceptance](remaining-work.md) gives concrete completion conditions;
there is no defensible percentage or date.

## PR27 protected authority and signer checkpoint (historical)

Branch `feat/protected-signing-authority` starts at
`dded7e94e84ef0e59a0552e961c5c57eaaabdd81`. The lead rechecked that PR26
is open/unmerged at that head, `main` is
`a624a1e684a8fc0065ac4f4609101410f56c50bb`, and the PR check is blocked
before execution by billing. The new branch depends on unmerged PR26; never
claim a remote PASS, merge or separate main CI from local results.

The [received follow-up review](reviews/pr26-follow-up-claude-review.md) targets
that head/tree `9108060e91b2cf9659b598e5f670f095f72f3305` against
`3866ceaa2b86da3ea3653da338d433a23a02b283`. It confirms F1–F3, retains
F4's protected-storage boundary and reports no development blocker. Its original
15,477 bytes, 193 CRLF endings and SHA256
`5fdd4046a0cde498d3e91b1589db8a2613e07883307782a75113ae1ad8deafaa`
are preserved. Private probes were not supplied; all four native/Docker suites
were NOT_RUN there. The new batch addresses Low D6a/D6b and records the
[whole-database legacy conflict recovery boundary](authority-store.md#conflicting-legacy-core-windows-and-recovery).

Owner-authorized bootstrap, signed workload registry, original envelope/delegation
staging and independent signer/peer-authenticated IPC are implemented for the
explicit local profile. All 20 fresh final local stages and independent evidence/
artifact review passed on the same 427-input digest; current exact counts and
commands are in [reports](../reports/README.md). Bootstrap records
advance only local pending history. Trusted target epoch/generation initialization
remains unavailable, and bootstrap admission remains pending target durable
epoch/baseline/probe confirmation; missing production build/native qualification
continues to block signing and dispatch. Exact implemented contracts and fresh
validation belong in the current ledger/reports. Prior counts below remain
historical and must not be reused for changed source. Keep all published
SQL001–014, specifications and original reviews byte-identical.
This batch adds SQL015; after publication, preserve SQL015 and its schema/guard
contract too. Future schema changes require a new migration.
The feature's resulting head/tree, stacked PR and remote CI are resolved from
the retained branch's PR completion record; local completion does not establish
those remote outcomes. Continue with required PR26/stacked-PR CI and, after merge,
separate main CI, then the target-confirmation/dispatch batch in the ledger.

<a id="current-pr26-review-follow-up"></a>

## PR26 review follow-up checkpoint (historical)

PR26 remains on `feat/core-access-enforcement`. The supplied
[Claude review](reviews/pr26-claude-review.md) targets
`3866ceaa2b86da3ea3653da338d433a23a02b283`, tree
`7f349ae2b22d1c19464454bcec8eb079d15614ef`, against
`a624a1e684a8fc0065ac4f4609101410f56c50bb`. It is preserved byte-for-byte:
15,748 bytes, 162 CRLF endings, SHA256
`7f82e555c1c734c9592b7ec3ddf96a4c65891b18815a02e00b45c0c6a1cba37d`.
Read [the follow-up contract](pr26-follow-up.md). Its private probe sources were
not supplied or rerun; its native Docker suites were NOT_RUN. The reported
old-binary migration is external evidence, separate from repository fixtures.

That follow-up batch fixes F1 in both registration orders, adds strict current
window eligibility without changing historical accounting, validates closed
input shape before F2 clock observation, preserves F3's explicit strict upgrade
and clarifies F4's protected-storage boundary. Native work adds an independent
reference pin, exact refusal-stage assertions, a correctly sized forged signature
and positive/negative expiry checks with independent token lifetime lower bounds.
Published SQL001–014, specifications and old evidence bytes remain unchanged.
No missing window/approval/completion is invented and no issued capacity refunded.

New baseline regressions independently reproduced F1 (both orders) and F2 against
the reviewed production source. Final local follow-up verification passed:
workspace Rust957, separate CLI1, reduced32, UI211/11 files and both builds;
shared-umask541, each full Rust total excluding two nested worker summaries and
retaining three ignored declarations. All runtime reports passed, including
Linux66/40 packets, signed98/43, core85/26/two captures, native33/five captures,
authority browser43 and the actual old-API incompatible DB refusal/byte-preservation
probe. The frozen 406-input digest is
`c533bbc57909184dc29fe3a1bbed2574a5c230f0e7be006644806a2409015302`.
Independent source and evidence review found no remaining finding in this scope.
Read the current ledger/reports for detailed qualifications; the checkpoint
counts below are historical. PR26's initial CI42036443828 attempt1 was blocked before any execution by
an account billing lock (zero steps/artifacts), and it remains unmerged at this
checkpoint. The retained PR completion record must pin the corrected head/tree,
new PR CI and, after merge, separate main CI. Preserve the remote branch/history;
do not change billing or bypass CI to claim completion.

## Reviewed PR26 core-access checkpoint

Comparison base: PR25 merge `a624a1e684a8fc0065ac4f4609101410f56c50bb`.
Reviewed PR25 head: `89684e055f01a1c87113e4ea4a713ebbff77afe1`;
both trees are `880986d4b29384cb947b780e32edde75981a5f1d`.
PR CI41945354850 and main CI41950760489 succeeded. The complete
[received PR25 review](reviews/pr25-claude-review.md) is preserved as 14,448 bytes,
SHA256 `64665ea1d47a3c5342b983d1152579e478faeafa19e8134d9f8ab691ecdcb771`.
It confirms I1/T1–T3 and reports no security defect or development blocker.
Its minor accuracy issues are [qualified separately](pr25-review-assessment.md).
Do not request that unchanged review again or claim its private probes were rerun.

The implemented batch on `feat/core-access-enforcement` adds exact core full-state review,
one immutable absolute lease window, native compilation and isolated core
execution, and connected CLI/API/UI evidence. Schema14 and source implementation
are complete. Final local validation passed: `bash scripts/check.sh` ran 943
workspace Rust tests, 1 explicit CLI test, 32 reduced-feature tests and 211 UI
tests in 11 files, plus both UI production builds and static/Python checks.
The shared-umask authority/service suite passed 530 tests. Both Rust totals
exclude two nested migration-worker summaries and retain 3 intentionally ignored
declarations. Fresh workspace binaries/examples also built successfully.

| Fresh runtime suite | Passing checks | Actual execution |
| --- | ---: | --- |
| HTTP / CLI / separate CLI protocol | 24 / 13 / 5 | CLI protocol uses a separate synthetic fixture |
| Enrollment API / browser / metadata | 23 / 25 / 41 | TLS services and retained evidence |
| Catalogue / passkeys / login admission | 11 / 76 / 14 | Browser and virtual CTAP2 |
| Audit / authority browser | 21 / 43 | Real services and retained core review |
| Isolated Linux / signed Linux | 66 / 98 | 40 / 43 actual packet probes |
| Core-access Linux | 72 | 24 actual packet probes and 2 signed captures |
| Native evidence | 33 | 5 actual kernel captures; 0 packet probes |

All four lab containers were removed; the final inventory had zero containers
and no executing test services. The final 406-input source digest is
`788e81beffa32cd4c0ed2717ed640ece69ecf5cf8935187883343cf547c28bbf`.
Consolidated independent internal review covered 59 source files with no findings;
this is not a new Claude execution. The ignored local summary at
`/tmp/nox-core-enforcement-verify-xh25ji5c/final-results/verification-summary.json`
has SHA256 `4214872ce333dcdc47cd0a5a347374f408124bea6b30a9036b1e634582cebced`.
Reproducible commands and qualifications remain in the ledger/reports.

This local handoff precedes the feature commit, PR, CI and merge; none is claimed
complete here. Retain their later exact head/tree, PR checks, merge and separate
main CI in the feature PR completion record and complete Claude prompt.
These local results do not qualify production enforcement. See
[the contracts and boundaries](core-access-enforcement.md). Preserve
published SQL001–013 and old provenance/policy-change bytes. Migration must not
invent a legacy window or approval. Production workload/delegation/bootstrap
and signer authority remain unavailable; new evidence cannot open dispatch.
The pinned nftables 1.0.6 anonymous multiport `ct.proto-dst` readback remains
unqualified; the lab's equivalent scalar fixture does not establish multiport
support. Finish the authorized commit/PR/CI/merge and separate main CI, and hand
off one consolidated Claude review; retain remote branches and shared history.

## Completed PR24 review follow-up (PR25)

PR24 head `ac027412c88eade8d3674c75c2ba6203df023ee6` merged as
`59c70ac32fd10e4d5ef6b63cc7f54f4eb5759fe8`, with tree
`66f60c567ccabd12acd9af68d1edfefe60498fc5`. PR CI41819099169 and main
CI41824170284 both succeeded. The received [Claude PR24 review](reviews/pr24-claude-review.md)
is preserved as 15,585 original bytes, SHA256
`ac296f8794e1f74a020eff6f0c155a61d1ddd5bae709fc2c20a0d69924af1501`.
It confirms the original R1–R4 cases fixed and reports no development blocker.
Do not request that unchanged review again or claim its private probes were rerun.

The integrated batch is `fix/validated-clock-and-rollback-coverage`, based
on that merge. [I1/T1–T3](pr24-follow-up.md) concern verified retained-clock
selection, semantic-test reachability and precise rollback coverage. The native
review-evidence fault already existed; restore actual missing coverage rather
than treating every external statement as established. Implementation, focused
checks, independent internal review and fresh full local validation are complete
(905 workspace Rust, 510 shared-umask, 190 UI and all isolated runtime labs).
PR25 and its separate main CI succeeded at the exact head/merge above; its PR
retains the completed record and historical prompt. The current
ledger/reports preserve detailed evidence. Published
SQL001–013 and original specs/reviews remain unchanged. Keep operational signing
and dispatch closed, durable clock floors and issued capacity intact.

## Completed PR23 review follow-up (PR24)

PR23 head `8b9c3ef71f30b21de9ecfd2d6118f99da32b2f4f` merged as
`4cef6acf7e46289b156fcd56ad0ab2f2920fabd6`, with the same tree.
PR CI41580876482 and main CI41584624128 both succeeded. The user supplied
[Claude's complete PR23 review](reviews/pr23-claude-review.md), preserved as
15,349 original uploaded bytes including CRLF, SHA256
`9a3f3072a976beef60d158906d493a41bbe464e97f176406cef77719a282657e`.
Do not request that fixed review again. Its temporary private probes are absent.

The completed correction batch is `fix/live-authority-integrity`, based on that
merge. [R1–R4](pr23-follow-up.md) concern coordinated live quota/index hiding,
surplus work audits, and complete validation cost/write-lock duration. New
independent baseline fixtures reproduce R1–R3; the initial separate R4 harness
failed before runtime and supplies no measurements. Source and commands are in
[the local reproduction](reviews/pr23-local-repro.md). Implementation, focused
regressions, independent internal review and fresh canonical/shared-umask/runtime/
browser/Linux checks are complete. PR24 head, merge and both successful CI runs
are fixed in the current section above; its PR body preserves the completion
record and historical Claude prompt. The ledger and reports preserve local
results, separately from the new follow-up. Do not reuse previous counts. Keep
published SQL001–013 and original reports/specs.

The correction combines snapshot-bound conditional validation, complete relevant
work-audit correspondence and reduced full-validation lock/cost. A change counter
is not external authentication; quick_check does not prove index membership.
Production signing/dispatch remain closed and issued capacity is not refunded.
The PR24 external review was subsequently received and is recorded above. The
I1/T1–T3 review was subsequently received for PR25. The next review targets the
new core-access batch in one Claude-only request.

## Completed PR22 review follow-up (PR23)


PR22 head `2cccdb3ba1f22fd461c53bc350bb2d1bc07fffd0` merged as
`d54021a9df32c0a041c52002b05a0e9d64058c0f`, with the same tree.
Its PR CI41564239539 passed; post-merge main CI41566909739 failed in the short
metadata-input expiry test setup. Do not label that main run successful.
The user supplied [Claude's complete PR22 review](reviews/pr22-claude-review.md).
Its D1–D6 correction batch starts at that merge on `fix/quota-open-integrity`;
resolve the latest PR/head/checks remotely. The
[correction matrix](pr22-follow-up.md) and latest reports/ledger record its status.

Schema13 adds full retained and physical validation at open/maintenance, bounded
independent reservation/head accounting, exact-next atomic audit head projection,
event-owned work/audit bindings and uniquely ordered legacy audit backfill.
The trusted local CLI can read the retained current project-pin revision after
lost output; repeated readiness path prefixes are rejected. Existing SQL001–012
and specifications are unchanged. New fixtures are independent of Claude's private
probe sources; the preserved report's test counts are external historical results.
The metadata timing fix changes the test setup, not production freshness rules.

The PR23 external review was subsequently received and is recorded above.
Do not request the already received PR22 or PR23 fixed review again or treat
internal review as Claude. The prior PR body retains its historical prompt.

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

Use GPT-6.1 Sol at ultra for implementation and GPT-6 Astra at ultra for
architecture and independent review; the lead orchestrates. Split file
ownership and implement substantial integrated batches. Run focused necessary
regressions while implementing, then one combined independent review and full
validation. Avoid repeated small handoffs/full-suite waits. Fix found defects
within the batch. Commit/push/open PR/finish CI/merge after required checks within
the authorized development workflow; keep remote branches and shared history.

Each user-mediated external review uses **Claude Opus5.5 only**, covering the
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

Next work follows F_08 dependencies: complete production core signing integration
with signed workload/delegation authority; protected bootstrap/accounts,
generation initialization and independent
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

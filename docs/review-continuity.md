# Review continuity and recovered development baseline

This compact handoff records the review history supplied by the user after a
conversation was lost on 2026-11-01. It preserves review scope and outstanding
questions, not a transcript or raw test logs. Current implementation and remaining
work belong in [the task ledger](../reports/task-ledger.json),
[verification summary](../reports/README.md) and
[implementation overview](implementation.md).

For a new session, start with [the complete handoff](session-handoff.md).

## Received PR25 consolidated review

The user supplied [Claude Opus5.5's PR25 review](reviews/pr25-claude-review.md)
for `89684e055f01a1c87113e4ea4a713ebbff77afe1` against
`59c70ac32fd10e4d5ef6b63cc7f54f4eb5759fe8`. Merge
`a624a1e684a8fc0065ac4f4609101410f56c50bb` has the same tree.
PR CI41945354850 and separate main CI41950760489 both succeeded. Preserve all
14,448 uploaded bytes, including 159 CRLF endings and progress notes, SHA256
`64665ea1d47a3c5342b983d1152579e478faeafa19e8134d9f8ab691ecdcb771`.

The report confirms I1/T1–T3 and identifies no security defect or development
blocker. Its focused/full/browser results are attributed external evidence;
Docker labs are NOT_RUN there and its private probes are unavailable here.
[Source-qualified corrections](pr25-review-assessment.md) cover the zero-match
prompt filter, overlap in the thirteen-condition approval matrix, table-mutation
rather than SQL-text recording, snapshot scope and temporary test-authorizer
replacement. The report's blanket final-IMMEDIATE wording is also qualified:
retained-intent read uses a validated DEFERRED final snapshot. No raw report is
rewritten. The correct exact transition test freshly passed once; this does not
validate the next feature.

Proceed with the integrated core-access semantic/native/absolute-window and
operator evidence batch. Do not repeat external review of unchanged PR25 or
promote structural provenance/lab evidence into protected production authority.

## Received PR24 consolidated review

The user supplied [Claude Opus5.5's PR24 review](reviews/pr24-claude-review.md)
for `ac027412c88eade8d3674c75c2ba6203df023ee6` against
`4cef6acf7e46289b156fcd56ad0ab2f2920fabd6`. Its main merge is
`59c70ac32fd10e4d5ef6b63cc7f54f4eb5759fe8`, with the identical tree.
PR CI41819099169 and main CI41824170284 both succeeded. Preserve all 15,585
uploaded bytes, including CRLF and opening notes, SHA256
`ac296f8794e1f74a020eff6f0c155a61d1ddd5bae709fc2c20a0d69924af1501`.

The report confirms R1–R4 corrected under their original reproductions and
finds no confirmed security defect or development blocker. Claude directly reran
its old R2 case and a peer D1 variant; other matrices and release measurements
are attributed to its parallel reviewers. Their private probes are unavailable
here. External Rust900/CLI1/reduced32/UI190/umask505 are historical results,
and external Docker checks are NOT_RUN. The external reviewer reports its own
initial unwrap panics and zero-match filters as harness/brief errors.

The [follow-up assessment](pr24-follow-up.md) addresses unchecked retained-clock
selection (I1), signature/generation test reachability (T1), actual transition
fault rollback (T2), and missing intermediate approval faults (T3). Source review
qualifies T3: the existing native suite already included review-evidence INSERT
among 12 fault stages. The removed `not_after += 1` changed a reference pin on
healthy retry; it was not observation corruption. Preserve the original report
and record this correction separately. I2 trusted local writes and I3 database-
wide quarantine remain explicit boundaries. New validation belongs in reports;
no previous or attributed count is a new pass.

## Received PR23 consolidated review

The user supplied [Claude Opus5.5's PR23 review](reviews/pr23-claude-review.md)
for `8b9c3ef71f30b21de9ecfd2d6118f99da32b2f4f` against
`d54021a9df32c0a041c52002b05a0e9d64058c0f`. Its main merge is
`4cef6acf7e46289b156fcd56ad0ab2f2920fabd6`, with the identical tree.
PR CI41580876482 and main CI41584624128 both passed. The newly uploaded text is
preserved byte-for-byte, including CRLF and opening notes: 15,349 bytes, SHA256
`9a3f3072a976beef60d158906d493a41bbe464e97f176406cef77719a282657e`.

The report confirms D1–D6 corrected under their original counterexamples and
reports four Low follow-ups: coordinated live quota projection corruption (R1),
coordinated live index corruption (R2), surplus unbound work audits (R3), and
full-validation scaling/write-lock availability (R4). Claude directly reproduced
R2; its parallel reviewers supplied R1/R3 and R4 measurements. The supplied
private sources and logs are unavailable. The report's Docker checks are NOT_RUN;
the project's previous lab/CI passes are separate evidence.

Source assessment supports the mechanisms with three qualifications:
`quick_check(table)` does not prove complete index/table correspondence (it can
report some nonpartial-index count damage); the audit bijection must cover exact
work-mutation kinds rather than all signing audits; and the
reported scaling numbers do not establish the cause of a separate SQLITE_BUSY
failure. New baseline probes independently reproduce R1 (eight variants), R2
(four variants) and R3 (two variants). Their three passing vulnerability
assertions demonstrate defects, not passing security regressions. A separate R4
baseline harness failed compilation before runtime and produced no measurements.
See [preserved new reproduction source](reviews/pr23-local-repro.md) and the
[integrated correction scope](pr23-follow-up.md). Current implementation and
new validation results belong in the ledger and verification summary.

## Received PR22 consolidated review

The user supplied [Claude Opus5.5's complete PR22 review](reviews/pr22-claude-review.md)
for `2cccdb3ba1f22fd461c53bc350bb2d1bc07fffd0` against
`2219c9ffe64fc0f4a967f3af69e84cdcc15aaff3`; its merge is
`d54021a9df32c0a041c52002b05a0e9d64058c0f` with the same tree.
The pasted text is preserved as UTF-8/LF, SHA256
`174db04e57e473b21484ecf27415794e1911d50263a967052692178c1c2d2775`.
It is not a byte claim about an unavailable original attachment.

The report confirms the original N1–N7 reproductions corrected and reports six
new defects: D1 Low–Medium (directly reproduced by Claude), D2–D6 Low (parallel
reviewers). D1 hides held capacity by changing a head after removing/restoring its
guard; D5 exposes incomplete open validation. D2 corrupts physical index contents
while retaining exact SQL. D3/D4 concern audit sequencing and pre-staged work
bindings; D6 rejects valid same-second legacy renewals. All were open at receipt.
The [correction matrix](pr22-follow-up.md) distinguishes new local reproductions
from external private probes, which have not been obtained or rerun.

Claude's workspace851, explicit CLI1, reduced32, UI190, shared-umask456 and browser
results are attributed external executions, not checks on the new fixes. Docker
Linux/native suites were not run in that review. Local current verification must
be recorded separately. PR22's PR CI41564239539 succeeded; post-merge main
CI41566909739 failed in a short-lived metadata test setup and is not a PASS.
The follow-up preserves production auth conditions while correcting that fixture.

## Integrated follow-up after PR20

The schema11/schema12 follow-up implements N1–N7 history/audit corrections and
project-only quota together. New independent baseline fixtures reproduced every
finding; current regressions require mutation refusal, retained evidence or
fail-closed migration/read behavior. Original migration001–010 and the supplied
review remain unchanged. The old private reviewer probes were not used.

Internal GPT-6.1 Sol reviewers checked the integrated storage/runtime/API/UI
changes. They caught and prompted corrections to imported reservation history,
an accidental lifetime job ceiling, failure injection that was blocked too early,
retained-root clock observation after cutover and initial-job transaction ordering.
This is internal review, not a new Claude execution. Exact executed checks and
current CI belong in [verification](../reports/README.md). The subsequent PR22
Claude review was received and is recorded above; it identified the D1–D6 follow-up.

The following PR20 section records the state **when that report was received**.
Its open statuses are historical; current disposition is in the
[follow-up matrix](pr20-follow-up.md) and task ledger.

## Received PR20 review (historical checkpoint)

The user supplied Claude Opus 5.5's [complete PR20 report](reviews/pr20-claude-review.md)
for `9e021b31171ae19ff8c9e7eba400d8dd4630a001` against
`09ef6a866632a9a6e12e2af799cb18b8b55daca9`. PR20 merged as
`6eb68a9251b76ac164f8efb0fa5ad5ded1336564` with the same source tree. Its final
[PR CI](https://github.com/simhanson123/Nox_Warden/actions/runs/41425943304) and
[main CI](https://github.com/simhanson123/Nox_Warden/actions/runs/41429434650)
passed. The report is preserved verbatim, including CRLF and opening progress
notes: 17,167 bytes, SHA-256
`abc796dce74778372c613c253d2891037ca386430d475ea7a8040a97c415aa2c`.

Claude reports F1–F4 corrected and seven Low findings N1–N7, with no reported
Critical/High/Medium or blocker to continuing development. **All seven were open at receipt**; CI and prior internal review did not resolve those findings.
N1/N3/N6 include Claude's direct reproduction; N2/N5/N7 were attributed to its
migration reviewer without a Claude rerun. N4 is reported confirmed within the
combined review, without a separately identified direct rerun. Preserve this
distinction instead of attributing every parallel probe to Claude itself.

The report records one failed full check (exit101), five passing isolated retries
and a passing full rerun (800 workspace, one explicit CLI process,32 reduced,
180 UI), plus406 shared-umask,41 metadata and40 authority-browser checks.
Its initial browser mismatch and corrected explicit executable selection are
environment observations. Its load/fresh-auth explanation for the test failure
is a hypothesis, not a root cause established here. Source inspection identifies
another possible one-second credential/session timestamp boundary to investigate.
The report did not execute Docker/Linux/native-evidence suites, actual old-binary
upgrade fixtures, multiprocess races or crash injection. Those are not external
passes; previous project's isolated CI runs are separate evidence.

The handoff session independently reproduced **N2** through real public principal
provisioning and audit APIs: two retained audit events became one while both
principals remained, all trigger SQL stayed unchanged, FK checks stayed clean,
and current/reopened audit verification accepted the shorter history. The
[portable reproduction](reviews/pr20-local-audit-repro.md) is newly written local
evidence, not Claude's private source. N1/N3/N4/N5/N6/N7 received source assessment
only in this handoff; their external counterexamples were not freshly executed.
No product fix or rootless implementation is included in this handoff branch.

[Follow-up requirements](pr20-follow-up.md) and the
[project-only quota preparation](project-policy-quota-design.md) are durable
instructions for the next session. Fix history/audit/migration foundations before
building on them. Historical sections below describe their recorded checkpoints;
old “pending review” statements do not supersede this received PR20 status.

## Received PR #18 external reviews

The user supplied Claude Opus 5.5, GLM 5.3 and GLM 5.3 Flash reports for
`4c0b65ee4399b500a83011426255be54bdc10654`, compared with
`956de27f4833138da15d0621e0c4163591374826`. PR #18 merged as
`5a7551d1d7a59a8f92f74dc972953e5162fd5a90`; the reviewed head and merge have
the same file tree. The [three original reports](reviews/pr18-external-reviews.md)
are preserved verbatim with source hashes. Reviewer names, executions and
temporary paths remain user-supplied evidence; their private probe sources were
not provided and must not be described as rerun by this session.

| Report | Supplied result and disposition |
| --- | --- |
| Claude Opus 5.5 | One confirmed Low finding: a normal SQL UPDATE can release an issued reservation's slots while lifecycle reads still report ready/queued. This is the concrete correction target. Separately reported trust-scope, expired-cancellation, heartbeat, dispatch and schema-validation observations require checking and scoped follow-up. |
| GLM 5.3 | No confirmed defect within its storage/concurrency/recovery scope. Reported 713 workspace and 32 reduced-feature Rust tests, 156 UI tests, 319 shared-umask authority tests, Linux 66/40 and signed Linux 98/43 checks/packets, and 39 new probe assertions. These are external results with overlapping subsets. |
| GLM 5.3 Flash | No confirmed defect within its CLI/HTTP/UI scope. Reported UI 156, CLI 15, HTTP 33 plus startup 5, authority browser 40, passkey 76, metadata 41 and enrollment browser 25. Its initial unsafe generated-file permissions and corrected probe failures are retained in the original report. |

The two no-finding reports do not negate Claude's reproduced SQL counterexample.
A state allowlist alone cannot close it: a release, active-state transition or
slot change must agree with retained work, issuance and delivery evidence before
accounting can exclude that reservation. Expiry is not cancellation evidence.
The follow-up starts from the PR #18 merge and preserves `migration_007.sql`;
new implementation and verification belong in the task ledger and verification
summary, separate from these three historical reports.

## Reservation-integrity follow-up review

The reservation-integrity follow-up merged as
[PR #19](https://github.com/simhanson123/Nox_Warden/pull/19). Its fixed review
target is `2ef3aecec27fee6a5c89a63c3b975057bef2e598`, compared with
`5a7551d1d7a59a8f92f74dc972953e5162fd5a90`; the merge is
`09ef6a866632a9a6e12e2af799cb18b8b55daca9`, with the same file tree as the head.
The user selected **Claude Opus 5.5 only** for the consolidated external review
and supplied its [complete report](reviews/pr19-claude-review.md). The upload is
preserved byte-for-byte, including its opening progress notes and original CRLF
line endings: 19,378 bytes, SHA-256
`255d2afcd641b5b86d5c0d54be300326bd7d0b614b961a0e6ebae9e3ef433e9f`.
The PR body retains the earlier three-model prompt history, which does not imply
those models reviewed PR #19.
`docs/review-prompts.md` retains historical PR #16 material below its current-status notice; do not reuse those old targets for a later follow-up.

The follow-up independently reproduced L1 against the unchanged PR #18 tree,
then retained the opposite regression using a real signing fixture and intact
production guards. Schema 8 binds quota projections and indexed accounting
membership to immutable transitions and their work/issuance/delivery evidence.
The admin cancellation command, exact dispatch signature checks and bounded
heartbeat renewals are described in [signing coordination](signing-coordination.md).

Separate internal reviewers found three additional inconsistencies while the
batch was integrated: a cancellation event without a matching current work head
could support release; a corrupted legacy delivery receipt could migrate even
though normal lifecycle reads rejected it; and an already-open connection could
lose indexed accounting membership after its delete guard was removed. Each was
corrected and the same independently failing counterexample passed afterward.
The corrections respectively require complete head/event agreement, validate
the full lifecycle before committing migration imports, and check the exact
bounded set of live accounting guards. These are newly executed internal reviews,
not fresh executions by the named external models. No further confirmed blocker
remained within those reviewed scopes at that time; the subsequent external
report below identifies additional gaps.

PR #19 checked schema definitions at open and migration and checked its specified
live accounting membership guards. F2 and F3 below identify gaps in that guard
set and schema-name filter. Neither those checks nor their follow-up authenticate
every byte against an attacker able to replace the whole database and trust keys.
The [verification summary](../reports/README.md) records the completed integrated
checks without adding overlapping focused test counts.

## Received PR #19 findings and independent follow-up

The supplied report marks the original L1 and internal counterexamples A/B
resolved, and counterexample C resolved within the documented ten-guard scope.
It reports three Low findings directly reproduced by Claude and a fourth Low
finding reproduced only by Claude's migration subagent. It reports no Critical,
High or Medium findings. These severity and execution statements are attributed
external evidence, not a new local verification result.

| Finding | Supplied reproduction | Local follow-up status |
| --- | --- | --- |
| F1: forged delivery evidence releases an issued dispatch slot with ordinary SQL and all guards present | Claude directly reproduced accepted forged work event/head/delivery/active transition, a new reservation after reopening, and consistent lifecycle output | Independently reproduced; issued capacity remains held after unsigned delivery, including expiry/reopen; new work guards and accounting-head identity protections rechecked |
| F2: live accounting guard list omits the transition-evidence trigger | Claude directly reproduced an unsupported active transition and new admission after removing that trigger, including after restoring it and reopening | Independently reproduced; all 45 signing guards checked against canonical definitions, and restored-guard false active records cannot return capacity |
| F3: `NOT LIKE 'sqlite_%'` excludes user-created schema objects such as `sqliteX_hidden` | Claude directly reproduced same-version migration accepting a hidden trigger with the standard binary; the migration subagent additionally reported v7-to-v8 acceptance | Independently reproduced with the real CLI; exact reserved-prefix filtering rejects lookalike triggers, tables, views and indexes while preserving source/backup behavior |
| F4: legacy UNKNOWN reservation can be relabeled issued before migration | Reproduced only by Claude's migration subagent; Claude explicitly did not rerun it. Slots and costs were retained | Independently reproduced; any prior UNKNOWN rejects an issued relabel in live reads and backed-up migration, including reclaimed dispatch heads |

The report's workspace, reduced-feature, CLI process, UI, shared-umask and
HTTP/browser results remain external executions. It records corrected probe and
environment failures before its final passes; overlapping focused counts must
not be added to the full totals. Docker-dependent Linux, signed Linux and native
evidence suites were not run by that reviewer. The external probe source, logs,
tool installations and temporary worktrees were not supplied. This session has
not rerun those private probes, and the report's cleanup commands are preserved
as source text rather than instructions to execute. Independent local probes and
their outcomes must be recorded separately when completed.

## Development continuing alongside the fixed PR #19 review

The core-access provenance batch starts from PR #19 merge
`09ef6a866632a9a6e12e2af799cb18b8b55daca9` on
`feat/core-access-provenance`, now
[PR #20](https://github.com/simhanson123/Nox_Warden/pull/20). At receipt of the
external report its head was `df957cd9d91717c9db0b2f65759b299fc484ceb3`, CI was
still in progress, and the PR had not merged. That schema 9 checkpoint's
[CI run](https://github.com/simhanson123/Nox_Warden/actions/runs/41415827668)
subsequently passed. PR #20 was held as a draft during the security follow-up; that
earlier run does not verify the new changes. Claude's report reviews the fixed
PR #19 head above; it does not review this schema 9 or schema 10 work. Separate local probes reproduced F1–F4 and the corrections passed focused and
independent rechecks. These executions are separate from the external report.

Schema 9 adds immutable original request/envelope/delegation retention and
per-plan bindings, full original duration cost, delegated-root/quota-root matching,
trusted local registration/lookup and separate readiness blockers. It preserves
all deployed migrations 001–008 and the original specification package. The
complete core semantic-review/native/signing profile and rootless policy quota
profile remain follow-up work. Production preparation, signing and dispatch
remain closed. Newly executed checks and independent internal review outcomes
belong in the task ledger and verification summary, separate from the supplied
external report and its reported test executions.

The schema 10 follow-up preserves published migrations 001–009 and physical
legacy slot/evidence bytes while retaining one effective dispatch slot for all
issued reservations, including historical unsigned `active`/`delivered` rows.
New work-state and head guards, claimed-head delivery admission, complete live
guard checks, the literal SQLite reserved-prefix filter and legacy UNKNOWN
history checks address the reported boundaries. A recorded delivery cannot
authenticate native activation, resolve uncertainty or return issued capacity.
An authenticated receipt protocol remains unavailable. Fresh follow-up integration passed 800 workspace Rust tests, 32 reduced-feature
tests, one explicit cancellation CLI process test and 180 UI tests. Independent
review additionally corrected accounting-head replacement, nullable historical
metadata projection, contradictory UI states and missing complete lifecycle
validation on v8/v9 upgrade. Each confirmed case was rechecked after correction.
Shared-umask and runtime checks are recorded in the verification summary; no pass
from the schema 9 checkpoint or external PR #19 report is substituted for them. Rootless quota work remains the next
separate batch; its read-only foreign-key design review has not implemented it.

## PR #18 integrated implementation review

The subsequent durable-signing batch starts from PR #17 merge `956de27`.
Its implementation, checked commands and remaining production gates are recorded
in [signing coordination](signing-coordination.md) and the task ledger. A new
three-way internal review covered transactions/signatures, quota/job lifecycle
and CLI/API/UI. It reproduced a mutable generation-head rollback inconsistency;
the correction checks the latest immutable intent and passed the same independent
counterexample. The CLI example's authority origin was also corrected. These are
new internal review results, not an extension of the supplied Claude/GLM reports.
The preserved original package was rechecked: all 52 manifest entries match their
byte lengths and SHA-256 digests, with 53 total files retained.

## Design source and precedence

The full F-2.0 package is preserved in [docs/specs](specs/F_00_시작안내.md),
including the twelve numbered domain specifications, OpenAPI, schemas, validators,
fixtures, and historical design material. The uploaded archive is
`F_Codex_최종개발명세패키지.zip`, SHA-256
`5af71db69b180433b04cc1c2d4768586218410e2f0d523a01ffcc142cc031b85`;
[import provenance](../reports/spec-import.json) records the same digest.

Recovery checks performed on 2026-11-01 found all 53 archive files tracked under
`docs/specs`, byte-for-byte equal to both the archive and the extracted original
at `/workspace/nox-spec/F_Codex_개발명세`. There were no missing, extra or changed
files. All 52 entries in `F_패키지목록.json` matched their byte lengths and SHA-256
digests; the manifest excludes itself. These are preservation checks, not product
tests. The original design's statements about implementation status describe its
2026-10-30 publication, not current engineering progress.

Implementation follows the latest explicit user decisions, then the precedence
table in [F_01](specs/F_01_제품_구현_기준.md), the domain F-2.0 contracts and the
historical F-1.0 principles. [AGENTS.md](../AGENTS.md) retains the later English
default, eight-locale and compact-evidence decisions. Task dependencies and
acceptance gates come from [F_08](specs/F_08_Codex_Cloud_작업계획.md).

## Exact review baseline

The recovered clean checkout was `d5cb339a8fa4a63d0c1cebad7a3609ed932798ce`.
It is a merge with parents `98490ca1df5588a968d64403fc54dab9e4c95a88` and
`f626e04051d32aa268699dc8b6fbfccb4c8950c4`. The latter is the supplied PR #13
review target. Both target and merge have the identical Git tree
`d3df0261f4cdb203ef065b01e341637421f0a818`.

The PR #13 comparison against `98490ca1df5588a968d64403fc54dab9e4c95a88` is
31 files, 3,617 insertions and 238 deletions. It contains **two commits**,
`2919296` and `f626e04`; the supplied Flash report's “one commit” description
omitted the final Unicode-backup correction.

Read-only GitHub API checks recovered the older PR #5 review target as
`14569f0f2dbcd107290f09a350a17b99bd4186ce`, the first commit after base
`82bf8dc0e3df38172736f64171dd39885f084bec`. Its final head was
`1c77e29af505999dcf6588874cb45b1c6ba45d99`, which added audit pagination and
denial summaries; the merge was `78f7ff069e9ce077212eb4d5b47dbee353c85af1`.
The three historical source paths cited by Claude were read at the original
`14569f0` revision and match the reported audit-count refusal, 16-slot CLI limit
and immediate owner reservation. The report predates that PR's final correction.

GitHub reports successful CI for [the PR #13 head](https://github.com/simhanson123/Nox_Warden/actions/runs/41194600996)
and [the recovered merge](https://github.com/simhanson123/Nox_Warden/actions/runs/41195415153).
These are observed remote run statuses, not fresh local executions or proof that
every optional suite ran. Reviewer identities remain user-supplied attribution.

## Supplied test history versus checked evidence

| Supplied review | Reported execution | Recovery assessment |
| --- | --- | --- |
| Claude, PR #5 `14569f0` | 280 workspace Rust tests; 27 design checks; 48 passkey browser checks; 43 UI tests | Historical source findings checked through GitHub; reported executions not independently rerun. Do not apply these counts to the later PR head or current HEAD. |
| GLM 5.3, PR #13 `f626e04` | 565 Rust tests across configurations; 89 UI tests; 196 focused tests under umask `0002`; Linux labs 66/98 checks with 40/43 actual packet probes; private probes A/B 16/15 | Checked source and committed summary support the stated scope. 565 reconciles as 542 workspace plus 23 no-default-feature tests. Private external probes and execution logs were not recovered or rerun by the history audit. |
| GLM 5.3 Flash, same PR #13 | UI 89; startup 5; diagnostic 6; passkey 71; login-admission 14; catalogue 11; authority 31 after fixing inherited ACL modes; enrollment browser 25 | Counts agree with retained suites and summary. First authority-smoke failure was reported as unsafe generated UI permissions; rejection must remain enforced. Catalogue flakiness was not reproduced, so its original cause remains unproven. |

This history audit checked source, test definitions, hashes and Git relationships;
it did **not** rerun these product suites. New runs must record their own exact
revision, commands and outcomes in the verification summary. External reports
saying “no confirmed defect within scope” do not certify the whole product.
Docker namespace packet tests do not qualify an installed host, Windows or macOS;
virtual CTAP2 tests do not certify physical authenticators or human consent.

## Received PR #15 independent reviews

The user subsequently supplied all three requested reports for target
`43146fd753ab288f8e1618f5fdead6b8b2093d3b`, compared with
`f400d03f0bca873d42a1af114fb4632e2357d03a`. They do not review the subsequent
native-evidence batch, merged as PR #16 at
`06de39878d8fff40afec1c93f2bcbef982da149d` (reviewed head `feab5c3`).
Their temporary probe sources and logs were not supplied; reported runs below
remain attributed external evidence, separate from our executable regressions.

| Reviewer | Reported checks and conclusion |
| --- | --- |
| Claude Opus 5.5 | 209 focused Rust tests, real Ed25519 noncanonical/signature/rebinding counterexamples and 41 metadata process checks passed; no confirmed defect within scope. Forward clock error can durably block a target until time catches up; recovery documentation was missing, and this scenario was not executed by the reviewer. |
| GLM 5.3 Flash | 95 UI tests; 76 passkey, 25 enrollment-browser, 41 metadata and 31 authority-browser checks; authority first rejected inherited `0646` assets, then passed with corrected generated-file modes. Confirmed silent successful admin output loss on closed stdout; observed agent/help panic and missing startup-stage retention in the smoke report. |
| GLM 5.3 | 603 workspace +23 reduced-feature Rust tests, 229 under shared umask, Linux suites 66/98 with 40/43 real packets, 41 metadata checks and new private probes C/D 47/8. Independently confirmed the same admin output-loss defect. UI was 94/95 with intermittent target-catalogue timeout; do not record this run as an all-green check. |

Both GLMs reproduced buffered compact JSON returning exit 0 on `/dev/full` or
a closed pipe after a real store commit. This is one shared reliability finding,
not two independent product bugs. The correction must explicitly check final
stdout flush, preserve post-commit state and give fixed output-failure diagnostics.
An unchanged `web/` diff excludes an introduced UI source change in PR #15; it
does not prove the intermittent test timeout is exclusively environmental or
identify its cause. The follow-up independently reproduced admin exit 0 after commit and agent/help
panic after output failure. It adds checked stdout flush, safe fixed diagnostics,
retained private proof/DB state, and preserved closed startup stage/code before
smoke cleanup. Reopened-store regressions cover future target and project audit
floors without lowering them. Catalogue tests retain their original timeout and
65-record flow while replacing expensive global accessible-name searches with
scoped queries and equivalent selected-record accessibility assertions; the
reported external intermittent timeout itself remains unreproduced locally.

A separate verification worker freshly reran the recovered `d5cb339` baseline
on 2026-11-01 before implementation changes. The repository check passed 542
workspace Rust tests, 23 no-default-feature tests, 89 UI tests and its design,
contract and diagnostic checks; the `0002` umask authority run passed 196 tests.
All nine HTTP/CLI/browser suites matched their recorded counts and passed.
The fresh runtime was Node 24.19.0, npm 11.9.0, Python 3.12.14 and Chromium
154.0.8037.57, differing from the supplied external environments. Local evidence
is `/tmp/nox-baseline-runtime/summary.json` and `/tmp/nox-baseline-{check,build,umask}.log`;
these transient paths are not durable source artifacts. This rerun is separate
from the read-only history audit and did not recreate the external private probes.

## Disposition of the older findings at the recovered baseline

| Finding | Status at `d5cb339` | Evidence and next action |
| --- | --- | --- |
| Audit view fails when event count exceeds page limit | Fixed in implementation; retained regression coverage | `fw_control/src/audit.rs` authenticates bounded snapshot cursors and calls `list_audit_page`; its test traverses 110 events in pages of 25. `scripts/smoke_audit.py` exercises HTTP, MCP and browser continuation. Re-run the affected suites when changing audit paths. |
| Anonymous CLI creation can fill 16 pending slots and append audit events | Still a documented availability limitation | `fw_control/src/cli_auth.rs` retains requests for five minutes and records each admitted creation. `docs/passkey-login.md` explicitly documents queue exhaustion. Public passkey-login ticket hardening does not resolve this separate CLI queue. |
| First registration closes bootstrap before first signed login; losing that key leaves no recovery | Behavior remains; wording clarified, recovery not implemented | `fw_store/src/passkeys.rs` reserves the owner during registration. `docs/passkey-login.md` explicitly documents pending-key loss and lack of a recovery workflow. Do not silently reopen bootstrap or delete the database as a fix. A recovery design must preserve ownership and audit evidence. |

PR #13 source retains regression coverage for current-candidate filtering and
quorum limits, interruption rollback, named-set withdrawal, backup/sidecar path
collisions, expired enrollment reservations, authenticated connection capacity,
CLI session provenance and nonce/key epochs. Their tests remain required when
touching the corresponding paths. The independent security review checklist is
in [authority-store.md](authority-store.md#reproduction-and-independent-review).
The expired-enrollment test preserves the old reservation's replay bindings and
allows a separately authorized invitation; it does not implement retention cleanup.

## Resume and review loop

The recovery follow-up was merged as [PR #14](https://github.com/simhanson123/Nox_Warden/pull/14),
main `f400d03f0bca873d42a1af114fb4632e2357d03a`. Its full CI passed, and it
resolved anonymous CLI storage/audit exhaustion while retaining fresh browser
approval, then added durable independently recomposed policy review evidence.
PR #15 added independent target pins and signed metadata; PR #16 added retained
compilation and signed native observations. The received PR #15 findings are
addressed together on the PR #16 source. Current commands, executed results and
the next signer/quota dependency are maintained in the task ledger and
verification summary rather than a continuing chat transcript.

1. Record the actual checkout SHA and diff; read the task ledger and current
   implementation boundaries before selecting work along F_08 dependencies.
2. Give parallel agents disjoint file ownership and explicit review scopes.
   Treat the three supplied reviews as evidence to check, not blanket approval.
3. Implement a substantial coherent batch across parallel components and run
   necessary automated checks. The user's latest preference is one consolidated
   independent review after the integrated batch works, rather than repeated
   small review handoffs. External reviewers can examine a fixed prior commit
   while new work continues on a separate branch.
4. Correct reproducible failures, repeat the affected checks, then run the
   integration checks required by the change. Record unavailable prerequisites
   and unrun native tests explicitly.
5. Update the compact ledger, verification summary and applicable contracts/docs
   together; retain raw logs and private fixtures in ignored local paths.

At the recovered baseline the controller is observe-only. Production authority
bootstrap, trusted artifact admission, independent signer/quota transactions,
protected accounts and authenticated IPC/host dispatch remain a major unfinished
chain. Linux host lifecycle qualification, Windows WFP/callout, macOS Network
Extension, signed installers, full UI acceptance and provider deployment remain
separate acceptance work. Neither the recovered conversation history nor passing
lab tests remove those gates.

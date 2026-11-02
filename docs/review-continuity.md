# Review continuity and recovered development baseline

This compact handoff records the review history supplied by the user after a
conversation was lost on 2026-11-01. It preserves review scope and outstanding
questions, not a transcript or raw test logs. Current implementation and remaining
work belong in [the task ledger](../reports/task-ledger.json),
[verification summary](../reports/README.md) and
[implementation overview](implementation.md).

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
The user subsequently selected **Claude Opus 5.5 only** for the consolidated
external review. A complete combined prompt was supplied in the conversation;
no report from that review has been received. The PR body retains the earlier
three-model prompt history, which does not imply those models reviewed PR #19.
The older local `docs/review-prompts.md` is historical PR #16 material; do not
reuse its target for this follow-up.

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
remained within those reviewed scopes.

Full schema validation occurs at open and migration. The live accounting check
covers its specified membership guards; it does not authenticate every byte
against an attacker able to replace the whole database and retained trust keys.
The [verification summary](../reports/README.md) records the completed integrated
checks without adding overlapping focused test counts.

## Work continuing during the PR #19 review

The core-access provenance batch starts from PR #19 merge
`09ef6a866632a9a6e12e2af799cb18b8b55daca9` on
`feat/core-access-provenance`. Claude's review target remains the fixed PR #19
head above; new development must not silently change that scope or be described
as externally reviewed.

Schema 9 adds immutable original request/envelope/delegation retention and
per-plan bindings, full original duration cost, delegated-root/quota-root matching,
trusted local registration/lookup and separate readiness blockers. It preserves
all deployed migrations 001–008 and the original specification package. The
complete core semantic-review/native/signing profile and rootless policy quota
profile remain follow-up work. Production preparation, signing and dispatch
remain closed. Newly executed checks and independent internal review outcomes
belong in the task ledger and verification summary, separate from the pending
external report.

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

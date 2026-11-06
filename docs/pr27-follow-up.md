# Signer durability and target-authority follow-up

## Received evidence

The user supplied the complete [Claude Opus5.5 PR27 review](reviews/pr27-claude-review.md)
on 2026-11-07 (Asia/Seoul). Its comparison base is
`dded7e94e84ef0e59a0552e961c5c57eaaabdd81`; its target is
`5fc576f672c2e0671164b73a667e3452b99ea82a`, tree
`719b80f88255921711ede7b4f4da81876568f7e3`. The original 17,066 bytes,
207 CRLF endings and SHA256
`8b4fa4e6d84ec7c755b3489309bb72a2e31e8fed1bc0634408c010348fd19357`
are preserved, including its opening progress notes.

The review's author directly reproduced the SQLite lock-release mechanism and
attributes the actual signer commit-loss, differing duplicate bootstrap DSSE and
SIGBUS cases to a parallel reviewer. Those private probe sources and logs were
not supplied here. They are accepted external findings, not newly executed local
reproductions. Fresh baseline probes, corrected-code results and independent
review must be recorded separately in [reports](../reports/README.md) and the
[ledger](../reports/task-ledger.json).

The report's canonical/shared-umask/build/browser results are attributed external
evidence. Its protected signer smoke returned NOT_RUN/exit2 with zero checks;
Linux, signed, core and native-evidence Docker labs were also NOT_RUN there.
The report separately describes real signer probes under numeric UIDs. Neither
statement replaces a new complete protected Docker run after correction. Our
previous 20-stage local PASS remains true historical evidence; it did not cover
S-1's SQLite descriptor/external-reader lifecycle and does not disprove the defect.

PR26 and PR27 remain open/unmerged. PR27 CI42216796210 attempt1 failed before
execution because of billing, with zero steps/artifacts. PR26's latest recorded
run42150829408 had the same billing limitation. Local tests, external review and
this new branch establish no remote CI PASS, merge or main-CI result.

## New independent reproduction and focused correction

The validation coordinator independently built the exact reviewed `5fc576f`
archive offline in an isolated target. A separate read-only check compared all
488 extracted Git blobs with that commit, with no mismatches. The fresh baseline
signer SHA256 is
`cb6bd0e6808765e0e342ed04acc025988f3810efb132ef85e62e9f2de79bac3b`.
Its new local report is `REPRODUCED`, SHA256
`a7c32a4463624a7b5ead271211698292324565823e2c7fa20b904061be244d9c`:
main/SHM locks were lost, an ordinary closing reader removed sidecars, returned
authorization/clock state was lost after SIGTERM, a different second valid DSSE
was issued, and a bounded polling case observed SIGBUS. These are newly executed
local counterexamples, not the reviewer's unavailable private probes. The
container was removed. An initial image-selector setup error executed zero
product tests; an earlier status-only polling attempt did not observe SIGBUS and
is retained separately from the complete reproduction.

Corrected normal regressions passed `cargo fmt --all --check` and
`cargo test --locked -p fw_signer`: seven library and two startup tests, with one
ignored subprocess helper. The actual protected Docker process run passed
55 checks and exactly 17 operator CLI invocations, with zero packet probes and
production signing/dispatch false. It binds an unchanged 432-input snapshot,
SHA256 `d0b164d2061934f8fafafbe245339aa2a1754c5cdb000c0cb722b83eb9189f5c`;
report SHA256 is
`c3a1311f4bc91e83007ed73c41c5f71cd105d2be9265a48a756aeafd66fc9661`.

Main and SHM DMS locks stayed BLOCKED at startup, after status and after restart
retry. The ordinary external reader closed before authorization. After lost
output/exact retry, the signer was immediately terminated without any SQLite
poll/checkpoint that could hide the defect. The exact authorization and clock
floor remained durable across restarts; observed floors were
1793979939 → 1793979940 → 1793979941. The container was removed. This proves the
tested normal SIGTERM/restart behavior in tmpfs, not host power-loss recovery.
It cleared the focused S-1 dependency. The integrated source now passed57
protected-signer checks/18 actual CLI calls and the selected local suite in
reports/README.md. The final lab-only timeout correction and separate source
binding are explicit there; this focused checkpoint is not reused as final proof.

Permanent lock regressions are in
[linux_locking_tests.rs](../crates/fw_signer/src/linux_locking_tests.rs), and the
normal process flow is in
[protected_signer_lab.py](../native/linux/protected_signer_lab.py). Run the latter
through `python scripts/smoke_protected_signer.py --report reports/protected-signer-smoke.json`
in managed disposable Docker. No old crash-stress replay is needed for the
normal corrected regression.

## Accepted correction contract

| Finding | Required behavior and evidence |
| --- | --- |
| S-1, High; original development blocker | Preserve SQLite's process-owned POSIX locks. After SQLite opens its database/WAL/SHM, validation must not independently open and close those same inodes in that process. Retain protected ownership/path/device/inode checks using a lock-safe mechanism. Prove an external DMS lock remains blocked, then exercise external read → authorization → termination/restart with exact retained DSSE bytes, audit and clock floor. Polling readers must not cause corruption, lost commits or SIGBUS. |
| R-1, Low | Re-pinning a revoked registry trust key must explicitly report refusal or revoked state. It must never return a misleading fresh `pinned` success or revive current authority. Preserve ordinary non-revoked exact retry semantics. |
| L1, Low | Bind approval origin to independently authorized organization/project authority. A caller's new `--approval-origin` or a challenge's own origin cannot establish that pin. Status, proof admission, authorization import and signer must enforce the same origin. Migration must not invent trust from ambiguous historical ceremonies. |
| L2, Low/informational | Share documented gate semantics across registry/core status, readiness and signer status. Preserve every false signing/dispatch flag; consistent diagnostics do not supply a missing build identity, target receipt or qualification. |

S-1 must be corrected and independently reproduced/regression-tested before
building target authority on the signer. A passing startup/UID/frame test alone
does not establish durable commit or exact retry. Existing file protection,
distinct UID peer authentication, bounded closed frames and deadlines remain
required; disabling those checks is not an acceptable lock fix.

The focused-verified source correction inspects database/WAL/SHM with metadata-only
`fstatat(..., AT_SYMLINK_NOFOLLOW)`. Config/key descriptors are opened before
SQLite, retained for bounded `pread`, and checked against path identities; startup
aliases with SQLite files are refused and SQLite drops first. This is a source
assessment; the separate fresh lifecycle evidence is recorded above. Later
source changes still require their own coordinated validation.

Correcting future file checks cannot reconstruct commits already lost by an old
process. Preserve the original database/sidecars and returned signed objects as
restricted evidence; do not manufacture missing approvals, clock floors, audits
or quota refunds. The tools supply no automatic reconstruction or production
restore ceremony. A returned old bootstrap object remains pending evidence, not
permission to bypass current retained authority or target confirmation.

## Explicit approval-origin administration

The L1 implementation uses a new schema16 origin-pin registry and head, initially empty.
Pinning is explicit trusted OOB provisioning with revision/CAS and exact retry.
Each legacy15 challenge receives a separate binding record with NULL origin
revision classifying unpinned history. Its bytes/proof remain historical and
cannot become current even if an operator later pins the same origin. New
challenges bind the current pin revision,
rotation invalidates older bindings, and supplied origin must match the independent
pin. Executed results belong in the verification summary.

Trusted local origin administration is
`pin-bootstrap-approval-origin` with strict stdin `{ "pin": ..., "expected_revision": null }`
for the initial pin (canonical uint64 string for later CAS), and
`read-bootstrap-approval-origin` with `{}`. Both take database/org/project only.
Existing `--approval-origin` ceremony input must match that retained pin and
cannot create it. The full pin
uses `fw.bootstrap-approval-origin-pin/v1` with `org_id`, `project_id`, `revision`,
`origin`, its derived `rp_id`, `not_before` and `not_after`. Pinning returns
`fw.bootstrap-approval-origin-status/v1`; reading returns
`fw.bootstrap-approval-origin-query/v1` with `pin` status or null and false
policy flags. Fixed command errors are `BOOTSTRAP_ORIGIN_PIN_REJECTED` and
`BOOTSTRAP_ORIGIN_STATUS_REJECTED`; malformed strict input uses
`REGISTRY_INPUT_REJECTED`. Neither supplying these public labels nor matching an
existing challenge substitutes for independent OOB trust provisioning.

An exact retry of an already consumed proof can acknowledge its original
proof/hash with `replayed:true` after origin rotation, with closed permissions
and no new proof/counter/audit. That historical acknowledgement does not restore
`owner_approved`; read the current manifest/origin status to assess eligibility.
An unconsumed challenge bound to an older revision must refuse, even if the
same origin returns at a newer revision; a fresh ceremony is required. Old
workload/authorization exact retries likewise preserve history without promotion.
The CLI regressions distinguish consumed historical acknowledgement, an
unconsumed stale challenge and a fresh current ceremony. Correcting an initial
historical-retry test expectation did not weaken origin admission.

The deliberate [v15 migration fixture](../crates/fw_authority/tests/fixtures/authority-v15-owner-bootstrap.json)
contains 18 tables/52 public synthetic rows, 79,202 bytes, SHA256
`68754c509071e2a175b6207a9e00e2c65b91877e62d72a28ea3433a44b67db1e`.
It comes from the normal 17-command released5fc owner-proof/bootstrap flow, with
all488 original Git blobs verified and a fresh offline build. Its provenance
records exact binary/image/generator hashes; private key/seed/config files are
excluded. This is purposeful regression input, not a raw test log.
[authority_v15_fixture.py](../native/linux/authority_v15_fixture.py) records the
normal generator; [origin_migration_tests.rs](../crates/fw_authority/src/store/origin_migration_tests.rs)
reconstructs released15 schema and inserts the exact typed cells/rowids, then
checks migration/history/backup and three late rollback phases. This is a
reconstructed test database from actual old public-flow cells, not an archived
whole SQLite file. Reproduce with
`cargo test --locked -p fw_authority --lib origin_migration_tests`; actual results
belong in the verification summary.

L2 uses shared `AuthorityGate`/`authority_gate_codes` semantics, including the
missing core `BUILD_IDENTITY_REQUIRED`. Readiness v3 exposes contextual reasons
and retained target confirmation. Published v1/v2 wire shapes remain exact legacy projections;
unsupported later states must refuse explicitly instead of silently omitting
meaning. Diagnostics and a newer version still supply no production permission.
The signer preserves the exact `status`/`fw.signer-status/v1` legacy labels and
adds explicit `status_v2`/`fw.signer-status/v2` for shared canonical gate codes.
Both use the strict v1 request envelope; no process-status response establishes
target eligibility. Executed versioned-path validation is recorded separately
from implementation in the verification summary.

The additional [released15 purpose-alias fixture](../crates/fw_authority/tests/fixtures/authority-v15-cross-purpose-alias.json)
is 87,044 bytes with 22 nonempty tables/57 typed rows, SHA256
`4e193a7d80ea7aad6f262506abfe58796944119dbdcb2de9bb6f777df3c7407d`.
Four actual old-admin commands validate the original store, admit the public
cross-purpose alias and validate/read it again; no signer/private keys are
transferred. [The normal producer](../native/linux/authority_v15_alias_fixture.py)
reconstructs the public healthy export using the released15 schema. The new
migration regression requires whole-database refusal and preserves original
rowids/types/bytes/schema and the private backup/manifest. This is deliberate
compatibility input, not a raw log or automatic repair tool. The original healthy
fixture remains byte-identical; actual test results belong in reports.

## Informational assessment and scope

I-1 concerns an extra cardinality restriction between `asset_ids` and
`asset_revision_hashes`. The original specification treats them as separate
bounded sets, not index-paired entries. Compatibility must be assessed against
those original contracts without inventing an asset-to-revision association.
The agreed correction removes only the equal-array-length restriction; each
original set's bounds/uniqueness and independent source-attestation requirement
remain.

I-2 is reported source reasoning, not an externally reproduced counterexample:
unverified additional DSSE signatures can remain in immutable envelope bytes and
change first-registration conflict behavior. The agreed new registry admission
profile accepts exactly one authoritative signature and explicitly refuses new
multi-signature admission. Original F schemas still allow their published multiple
signatures; retained old multi-signature/history bytes and primary-signature
validation stay unchanged. This restriction is not complete co-signature identity
support; that protocol remains later work. The new target-confirmation development
contract likewise uses exactly one authoritative signature. Implementation and
regressions must verify the profile without rewriting published schemas/history.

L3 is addressed by the target-confirmation path. A local pending head is not an
executor-confirmed target epoch. Chained rotation must not skip the durable old
epoch/generation, reset existing signing state or erase issued/UNKNOWN obligations.
Any supported transition needs the target's authenticated receipt and exact
predecessor/freshness checks; unsupported cutover must refuse explicitly.

The `accept()` error/serial slow-client observations and D6's theoretical rare
timing refusal remain availability assessments. They have no supplied new local
reproduction yet. Do not relabel them as proven signing bypasses or loosen the
original timing and recovery budgets to make a test pass.

## Next integrated boundary

The integrated change connects durable target epoch acceptance, authenticated
receipts and fresh management/positive/negative probe evidence to CLI/readiness.
[Target confirmation](target-authority-confirmation.md) defines the precise
contracts, supported generation0 rotation and recovery limits.

F12 has no bootstrap-specific target receipt shape. New explicit development
contracts preserve the grant-specific `f.receipt/v1`. The management compiler
uses a real non-loopback veth/namespace path; old loopback artifacts with empty
management paths are not relabeled as baseline `B`. Source implementation,
actual execution and final validation are distinct.

Confirmation must keep management baseline `B` separate from full StateIR,
preserve original `[S,E)` and quota obligations, reject wrong tenant/target/key,
stale predecessor, replay and revoked authority, and survive output loss/restart.
Qualified build/observer/native evidence, policy signer key trust and actual
workload-source attestation remain independent requirements. No caller boolean,
local fixture or pending authorization may open production policy signing or
dispatch. See [the remaining acceptance sequence](remaining-work.md).

Published SQL001–015, their schema/guard contracts, specifications and existing
review bytes remain unchanged. New schema behavior requires a new migration.
One coordinated validation owner runs Cargo/runtime suites; one consolidated
independent review follows the integrated change. Raw logs/private harnesses stay
outside source commits.

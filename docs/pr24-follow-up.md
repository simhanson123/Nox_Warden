# Validated signing-clock reads and precise rollback coverage

This batch starts at PR24 merge `59c70ac32fd10e4d5ef6b63cc7f54f4eb5759fe8`
on `fix/validated-clock-and-rollback-coverage`. The reviewed PR24 head is
`ac027412c88eade8d3674c75c2ba6203df023ee6`, compared with
`4cef6acf7e46289b156fcd56ad0ab2f2920fabd6`; its merge has the same tree.
PR CI41819099169 and separate main CI41824170284 succeeded. These are historical
checks of PR24, not validation of this follow-up.

## Received evidence and qualifications

The [complete supplied PR24 review](reviews/pr24-claude-review.md) is preserved
as all 15,585 uploaded bytes, including 167 CRLF endings and opening notes:
SHA256 `ac296f8794e1f74a020eff6f0c155a61d1ddd5bae709fc2c20a0d69924af1501`.
The report confirms R1–R4 fixed under their original counterexamples, with no
confirmed security defect or blocker to continuing development. It reports Low
test-coverage findings T1–T3 and an informational unchecked read I1. I2 describes
the existing same-connection trusted-write boundary; I3 describes global
quarantine when the authority database is corrupt.

Claude directly reran its old R2 case and a peer-connection D1 variant. Its
parallel reviewers supplied additional live-integrity/clock/work-audit/scaling
results. Their private sources are unavailable here. The report's passing counts
and release-build measurements are attributed external results; its Docker
Linux/signed/native checks were NOT_RUN. That does not replace or invalidate
PR24's separate successful project CI/lab evidence. Node22 in the external
review differs from this project's pinned Node24.19.0.

The report explicitly attributes its first counterexample panics and two zero-test
filter invocations to its own harness/brief. Corrected filters are `work_audit`
and `projection_integrity`; a filtered command with exit0 and no tests is not
verification. New focused runs must require a nonzero executed count.

## Source assessment and implemented scope

| Item | Baseline finding and correction |
| --- | --- |
| I1 | Three intent/job selections used the private connection's unchecked `query_row` before observing retained quota clocks. They now read validated snapshots and compare bindings again in the final validated transaction. The unchecked wrapper method is removed. Independently committed clock floors, historical root scope and refusal semantics remain required. The report's precisely timed transient wrong-clock observation is a hypothesis, not a confirmed authorization bypass. |
| T1 | The old combined signature/generation fixture tainted its own connection before reading. Separate genuine lifecycles now mutate through a peer, preserve exact schema, assert the intended signature or current target-head error, and verify healthy repair. Historical signed-intent reads and current generation eligibility have distinct contracts. |
| T2 | An added transition trigger caused early schema refusal. That test now states its actual scope; a separate unchanged-schema test denies the intended transition INSERT, records preceding writes and checks retained bytes, allowed independent clock floors, healthy retry/replay and held issued capacity. |
| T3, approval | Actual gaps included credential/challenge UPDATE, evidence/decision writes, approval set/member/head/admission-result writes and audit-head trigger authorization. A 13-condition private fault matrix restores these stages, including two distinct human approvals and the second member insertion. |
| T3, native | The existing private native suite already covered 12 stages, including a real review-evidence INSERT fault. Preserve that coverage; restore the removed reference-pin expiry change on healthy retry in both the schema-refusal integration case and the genuine late-audit case. |

The external T3 statement that private late faults target only audit INSERT is
broader than the source supports. At reviewed PR24, `native_authority_atomicity_tests`
already denied `authority_plan_review_evidence` INSERT after earlier plan,
requirement and audit writes. Its 12 stages covered core provenance, review
registration, native compilation/challenge/admission, reference/observer pins,
metadata, transport pin and pending/active review login. Those cases do not need
to be reinvented as new fixes.

The removed `not_after += 1` at pre-PR24 `native_evidence.rs:754` changed a
`NativeReferencePin` supplied to a successful retry after refusal. It was not a
retained-observation corruption case. Restoring that exact changed-input retry
preserves the original intended coverage without substituting a different test.

Private authorizers reject statements at preparation. Tests must prove that the
selected operation was reached and identify actual preceding writes; they must
not claim a row was inserted by the denied statement. The earliest credential
UPDATE has no preceding application writes. Denial of the audit-head UPDATE is
inside trigger authorization during audit-statement preparation. Separate later
audit cases prove rollback of previously executed audit/head changes.

## Verification and preserved boundaries

Implementation, focused checks, independent internal source review and fresh
canonical/shared-umask/runtime/browser/Linux verification are complete. Exact
new results belong in [reports](../reports/README.md) and the
[ledger](../reports/task-ledger.json); resolve the retained branch PR for its
head/PR CI/merge/separate main CI completion record and fixed external prompt.
No old count is a new PASS. Source guards/schema, private test-hook reachability,
unchanged rowid/storage types/BLOB bytes, repair/reopen/retry controls and
persistent clock-on-refusal behavior are part of the checks.

Published SQL001–013, original specifications and earlier review bytes stay
unchanged. No migration or new production fault switch is needed. Production
signing/dispatch remain closed; no issued/UNKNOWN/unsigned-delivered capacity is
refunded and no audit/work/completion evidence is manufactured.

Full validation still grows with retained history. Same-process trusted-code
writes, direct DB/WAL byte tampering, global corruption quarantine and external
audit anchoring retain their documented boundaries. This batch does not qualify
production host enforcement or implement Windows/macOS backends.

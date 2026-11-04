# Live authority integrity and validation cost

This batch starts at PR23 merge
`4cef6acf7e46289b156fcd56ad0ab2f2920fabd6` on
`fix/live-authority-integrity`. That base merge has the same tree as reviewed PR23 head
`8b9c3ef71f30b21de9ecfd2d6118f99da32b2f4f`, compared by Claude with
`d54021a9df32c0a041c52002b05a0e9d64058c0f`.
PR23 CI41580876482 and merged-main CI41584624128 succeeded; those runs do not
validate this follow-up.

## Received evidence

The [complete supplied review](reviews/pr23-claude-review.md) preserves the
uploaded text byte-for-byte, including CRLF and opening progress notes:
15,349 bytes, SHA256
`9a3f3072a976beef60d158906d493a41bbe464e97f176406cef77719a282657e`.
The review reports the original D1–D6 counterexamples corrected and four new
Low findings. R2 was directly reproduced by Claude; R1/R3 and R4's scaling
measurements are attributed to its parallel reviewers. The particular busy
failure was observed by Claude, but its connection to the scaling measurement
is not an independently established cause.

The supplied private probe sources, temporary worktrees and logs are unavailable.
New local reproductions and regressions must be identified separately. The
reviewer's deletion of active build directories is an acknowledged operator
error, not a product failure. Its final 873 Rust/478 shared-umask/190 UI results
and Docker NOT_RUN remain attributed historical executions. Node22 in that
review differs from this repository's pinned Node24.19.0.

## Correction scope

| Finding | Baseline source mechanism | Required correction and evidence |
| --- | --- | --- |
| R1: both quota projections hidden | Live admission compares two mutable indexed memberships and validates only the resulting rows | Detect an out-of-band database change before sensitive work and validate the exact transaction snapshot; independently reproduce joint projection hiding for rooted and project-only obligations |
| R2: both membership indexes emptied | Exact schema SQL does not prove physical index contents; existing live check omits physical integrity | Refuse restored-SQL physical corruption on an already-open handle; bind any cached validation to actual connection/snapshot changes and exercise races and failure/rollback |
| R3: surplus work audit | Current validation checks event/binding counts but not surplus recognized work-mutation audits | Require the complete relevant audit/event/binding correspondence, preserving unrelated intent/result/quota audit kinds and normal atomic audit-first writes |
| R4: costly full validation holds writer reservation | Existing open uses an immediate transaction while replaying retained history | Validate existing databases in a consistent read snapshot, retain serialized initialization/upgrades, reduce repeated validation overhead and measure actual scaling/concurrent writer progress |

`PRAGMA quick_check(table)` is not a replacement for index/table correspondence
verification. A new minimal SQLite experiment with an omitted partial-index entry
returned `ok` for global/table quick checks and an index-entry error for
global/table integrity checks. The actual bundled SQLite3.50.2 project fixture
detects the emptied nonpartial reservation index's entry count with quick_check,
while quick_check of the emptied partial head index still returns `ok`. These
observations distinguish detectable count damage from complete correspondence;
neither is a rerun of Claude's private probe source.

The implementation must not trade R1/R2 for a complete lifetime replay on every
unchanged local transaction. A connection-local validation cache needs explicit
snapshot binding, peer-change invalidation, local unsafe-mutation handling and
failure/rollback rules. An SQLite change counter is not a cryptographic trust
anchor. Healthy writes by another connection cannot simply be assumed trusted.
Long retained history still requires work during a complete integrity check;
benchmark results must distinguish primitive fixtures from full lifecycles.

## Preservation and verification

Published schema SQL001–013, original specifications and prior reviews stay
unchanged. No audit/work/completion evidence may be invented or discarded, and
issued, UNKNOWN or unauthenticated delivered capacity remains held. Rooted and
project-only jobs keep their original scope and clocks. Production signer and
dispatch gates stay closed.

Implementation, independent internal review and fresh local verification are
complete. The [normal-history measurements](authority-validation-performance.md)
record actual before/after values and their limits. Exact fresh commands,
results and remaining limits are in
[the verification summary](../reports/README.md) and
[task ledger](../reports/task-ledger.json). The retained branch's PR records the
fixed head, PR/main CI and the next complete Claude-only prompt. The separate
[local reproduction](reviews/pr23-local-repro.md) preserves newly written baseline
probes. No previous check count is a new PASS; full validation still grows with
retained history and may repeat under contention.

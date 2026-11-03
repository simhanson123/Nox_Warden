# PR22 review corrections

The user supplied [Claude Opus 5.5's complete report](reviews/pr22-claude-review.md)
for `2cccdb3ba1f22fd461c53bc350bb2d1bc07fffd0`, compared with
`2219c9ffe64fc0f4a967f3af69e84cdcc15aaff3`. The reviewed tree merged as
`d54021a9df32c0a041c52002b05a0e9d64058c0f`. This follow-up starts at that merge
on `fix/quota-open-integrity`. Migrations001–012, the original specifications,
and previous reports remain unchanged.

The report was pasted into the conversation, rather than supplied as an original
file. The complete pasted text is retained as UTF-8 with LF line endings; its
repository SHA256 is
`174db04e57e473b21484ecf27415794e1911d50263a967052692178c1c2d2775`.
This hash identifies our preserved copy, not an unavailable external file.
Claude directly reproduced D1; D2–D6 are attributed to its parallel reviewers.
Their private temporary probes are unavailable here. New local fixtures are
independently authored and must not be described as those probes rerun.

## Required correction and evidence

| Finding | Required behavior | Regression boundary |
| --- | --- | --- |
| D1: hidden held head after exact guard restoration | Full open checks every reservation, current transition, head and retained lifecycle; bounded live accounting compares independent reservation and head membership | Reserved, issued, UNKNOWN and unsigned active policy; rooted/project-only; same connection, reopen and maintenance |
| D2: empty physical partial index with restored SQL | Open and maintenance check SQLite physical integrity without repairing source; live admission cross-checks independent indexes | Exact schema still matches; table row survives, partial-index row disappears; denial and unchanged source |
| D3: audit head+2 insertion | Require exact unsigned successor, previous hash and nondecreasing retained time; append and head projection are atomic | FK/recursive combinations, gap/rewind, all carry positions, signed boundary and u64 exhaustion |
| D4: orphan binding with FK disabled and later stale consumption | A work event creates its unique audit binding atomically and consumes the current audit head; no separate binding staging | FK OFF, event absence, intervening audit, audit reuse and rollback |
| D5: reservation without intent | Full open and live reads reject a committed reservation without its exact intent/job | Production lifecycle verification; narrow uncommitted initializer never applies to ordinary reads |
| D6: legitimate same-second legacy renewals | Use the unique complete monotonic event/audit bijection for each tenant/job/phase; require equal counts, order, exact kind/time and canonical evidence | Two normal renewals succeed unchanged; missing, surplus or reordered evidence refuses with original/backup preserved |

The schema13 batch also adds a trusted local current project-pin read for lost
CLI output, rejects repeated HTTP route prefixes, and documents incomplete
backup-pair recovery. Readiness scope continues to describe current configuration;
historical jobs retain their own scope and clocks. No new readiness wire version
or UI meaning is introduced for that observational limitation.

The new D5 fixture creates a committed reservation with neither an intent nor a
job. On the archived PR22 tree, both open and same-version maintenance accept this
shape; the actual non-test administrator binary confirmed maintenance acceptance.
The test-only primitive-quota exemption was explicitly false. This differs from
Claude's supplied D5 variant, where maintenance refused, and does not claim to
reconstruct that unavailable private probe. Schema13 rejects both missing
intent/job evidence and inconsistent retained projections.

## Verification discipline

New checks and exact outcomes belong in [verification](../reports/README.md) and
the [ledger](../reports/task-ledger.json). External851/456/190 counts and earlier
local Linux66/40, signed98/43 and native33/5 are historical evidence, not results
for this change. Source review, genuine old-binary-created fixtures and fixtures
reconstructed with published migration SQL must be distinguished.

PR22's PR CI41564239539 passed, but its post-merge main CI41566909739 failed at
`metadata_admin::slow_stdin_does_not_use_command_start_time_to_accept_expired_proof`:
the four-second fixture expired before the child reached the input scenario.
The correction must keep proof acceptance at command start and rejection after
stdin expiry meaningful, without weakening production authentication or freshness.

Local audit consistency cannot authenticate a maliciously replaced whole DB or
replace an external anchor. No missing audit, work or completion evidence may be
fabricated; issued/UNKNOWN/unsigned-delivered capacity is never refunded.
Production signing/dispatch remain closed. The remaining native/protected-host
work in the [handoff](session-handoff.md) is still required.

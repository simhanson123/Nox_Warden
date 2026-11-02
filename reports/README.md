# Verification and implementation status

Keep source, regression tests, reproducible commands, this summary, the
[task ledger](task-ledger.json) and [specification provenance](spec-import.json)
in Git. Raw reports, logs and screenshots are ignored. Selected smoke reports
remain downloadable for seven days from [GitHub Actions](https://github.com/simhanson123/Nox_Warden/actions/workflows/ci.yml).
The supplied specification and fixtures under `docs/specs` remain unchanged.

## Reproduce

Install the [build prerequisites](../README.md#run-locally), Python browser
requirements and Chromium as described in the [passkey guide](../docs/passkey-login.md).
Run from the repository root:

```sh
source scripts/dev-env.sh
umask 0022
bash scripts/check.sh
cargo build --locked -p fw_control -p fw_cli -p fw_agent -p fw_authority -p fw_authority_service --bins --examples
python scripts/smoke_control.py
python scripts/smoke_cli.py
python crates/fw_cli/tests/smoke_login.py
python scripts/smoke_passkeys.py
python scripts/smoke_login_admission.py
python scripts/smoke_audit.py
python scripts/smoke_catalogue_navigation.py --controller-binary target/debug/fw_control
python scripts/smoke_enrollment.py --browser
python scripts/smoke_enrollment.py --authority-metadata --report reports/target-metadata-smoke.json
python scripts/smoke_authority_review.py --service-binary target/debug/fw_authority_service --fixture-binary target/debug/examples/review_fixture
python scripts/linux-lab.py --report reports/linux-lab.json
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
python scripts/smoke_native_evidence.py --report reports/native-evidence-smoke.json
```

Browser suites start actual loopback services and use Chromium CDP virtual CTAP2
authenticators. Native suites require Docker and run only in disposable network
namespaces with NET_ADMIN; they do not change the host firewall. A missing native
or browser prerequisite is not a passing check.

## Verified scope

The integrated repository check passes **777 workspace Rust tests, 32 authority
tests without default features, and 158 UI tests**. It also passes formatting,
Clippy, frontend types, both production UI builds, 27 specification checks,
52 core and 28 extended contract fixtures, nine Linux runner regressions,
six catalogue-diagnostic, thirteen authority-smoke diagnostic and
three native-evidence diagnostic regressions, plus
vendored-source verification. English remains the default. Eight controller
catalogues have 229 messages each; eight authority catalogues have 153, with
complete key and placeholder parity. Human translation acceptance is pending.

The following full runtime matrix was completed for PR #19. Fresh checks for
the current provenance batch are recorded in its section below.

| Runtime suite | Passing checks | Exercised boundary |
| --- | ---: | --- |
| Controller HTTP | 24 | Actual HTTP routes and original OpenAPI contracts |
| CLI / separate protocol fixture | 13 / 5 | Login, bounded list continuation and hostile-server refusal |
| Passkey browser | 76 | Durable owner enrollment, key lifecycle, logout, CLI handoff, anonymous ticket floods and delegated-session restrictions |
| Login admission browser | 14 | 1,005 anonymous options requests, valid earlier proof, replay refusal and restart |
| Audit HTTP/MCP/browser | 21 | Bounded denial evidence and stable snapshot pagination |
| Catalogue browser | 11 | 65 assets, complete list traversal, page size, refresh and asset-picker continuation |
| TLS enrollment/browser | 25 | Ed25519 certificates, mTLS, reports, service creation and revocation; CI nonbrowser subset has 23 |
| Independently pinned target metadata | 41 | Existing 23 enrollment checks plus 18 signed-metadata checks across real agent/admin processes, explicit fixture pin, tamper/tenant refusal, reopen, replay and revocation |
| Independent authority browser | 40 | Actual service, virtual passkey decisions, current quorum, dissent, restart and blocked signing readiness |
| Isolated Linux compiler/readback | 66 | Includes 40 actual IPv4/IPv6 TCP/UDP packet probes |
| Signed Linux execution | 98 | Includes 43 actual packet probes, expiry and interrupted submission/recovery |
| Retained native evidence | 33 | Five actual signed kernel captures across MATCH, MISMATCH, UNKNOWN and restoration; independent admission, replay, revocation, strict failure diagnostics and cleanup |

The recovered baseline and prior metadata batch were verified separately. The
native-evidence batch comparison base was merged PR #15, `43146fd`, whose
[full main CI passed](https://github.com/simhanson123/Nox_Warden/actions/runs/41278538402).
That native-evidence batch freshly passed the repository check (650+23 Rust, 125 UI),
authority/service tests under `umask 0002` (258), the real authority browser (36),
native evidence processes (33 with five captures), and signed Linux execution
(98 with 43 actual packets). The reviewed PR #16 head `feab5c3` also passed the complete
[remote CI](https://github.com/simhanson123/Nox_Warden/actions/runs/41283362174),
including every listed nonbrowser enrollment and runtime suite, before merge
`06de398`. Its source tree equals the tested head. These results predate the
subsequent external-review reliability follow-up.
The [review handoff](../docs/review-continuity.md) distinguishes supplied external
reports from fresh executions. Earlier external private probes were not recovered
or claimed as reproduced. All three external PR #15 reports have since been supplied; they cover that fixed earlier target and identify a shared admin stdout failure plus adjacent diagnostics follow-up.

## Original core-access cost provenance

The next M02/M03/M05 batch starts at PR #19 merge `09ef6a8`, on a separate
branch while the user requests Claude Opus 5.5 review of fixed PR #19 head
`2ef3aec` against `5a7551d`. No new external review result has been received.
PR #19's [complete CI](https://github.com/simhanson123/Nox_Warden/actions/runs/41397285225)
passed and its final target is unchanged by this work.

Authority schema 9 retains the complete original access request, envelope and
delegation, an immutable lease identity and per-plan hash bindings. Closed,
bounded contracts verify tenant/principal/workload references, original asset
membership, scope exclusions and lifetimes. Original request identity,
organization lease identity and tenant idempotency cannot be rebound. Exact
registration retries add no audit; compatible later plans reuse the original
evidence. Historical reads revalidate stored bytes and projections after expiry.

Core costs use the full original request duration and destination set even if
the plan has only seconds left. Independently configured root identity must
match, and all five current root ceilings must be no larger than the original
delegation's limits. The trusted-local CLI imports and reads bounded summaries,
checks stdout delivery, and preserves a committed import after output failure.
Eight-locale readiness separates missing provenance from the still unavailable
core signing profile; signing and dispatch remain false.

Explicit private-backup migration preserves existing schema 8 evidence and all
five quota states, with no invented provenance. Known-schema validation covers
the new tables and guards; migration failure retains the original and backup.
Original migrations 001–008 and the specification package remain unchanged.

Independent internal review reproduced SQLite `INSERT OR REPLACE` bypassing
update/delete immutability guards with recursive triggers disabled. The fix
blocks every identity collision before replacement, including explicit hidden
rowid conflicts. Permanent regressions cover primary and alternate
unique identities. The reviewer reran the same original counterexample and
explicit rowid variants: all were refused, with original status, reopen and
audit preserved.
Separate independent probes passed concurrent schema 8 migration, expiry while
waiting for stdin, and hostile JSON/UTF-8 input. These are internal executions,
not Claude's pending external review.

`bash scripts/check.sh` passed **777 workspace Rust tests, 32 reduced-feature
Rust tests, 158 UI tests and one separately executed cancellation CLI process
test**. The ordinary workspace run intentionally ignores that one process test;
it is not counted as passed until the separate invocation. Formatting, Clippy,
TypeScript, both production UI builds, original contracts/specifications, locale
parity, diagnostic regressions and vendored-source checks passed. Focused tests
are overlapping subsets, not extra totals. The shared-umask authority/service
run passed **383** tests, with the same one separately covered ignored process
case. Fresh actual runtime checks passed **40 authority browser checks, 41
metadata checks and 33 native-evidence checks with five kernel captures**. The
disposable native container was removed. Broader Linux packet and unrelated
controller runtime checks remain part of the required remote PR workflow.

Provenance is not verified delegation/envelope approval, workload authentication
or human approval. Core semantic review, native binding, a single retained
absolute lease window across later plans and the core signing profile remain
incomplete. Rootless general-policy quota is the next separate batch; protected
authority bootstrap, OS/IPC isolation, signer/delivery deployment and native
platform qualification remain required.

## Reservation integrity and explicit cancellation

The PR #18 follow-up starts at `5a7551d`. Authority schema 8 adds immutable
quota transitions tied to work, issuance and delivery evidence, plus guarded
indexed accounting membership. Ordinary state/slot UPDATE cannot refund an
issued or UNKNOWN reservation; a damaged reservation projection cannot hide
from accounting. Ten live accounting guards are checked without replacing the
bounded indexes with a history scan. Opening and migration also validate the
complete actual schema. Migration 007 and all 53 original specification files
remain byte-for-byte unchanged (52 manifest entries verified).

Explicit migration with a validated private backup preserves legacy proof,
receipt and audit bytes. Unproven releases, corrupted delivery receipts and
mismatched outbox timestamps roll back with the original and backup preserved.
The trusted-local `cancel-signing-job` command handles expired unissued work,
fences claimed workers and retains committed cancellation after stdout failure.
Issued and UNKNOWN work remains nonrefundable. Dispatch dequeue verifies real
Ed25519 and the exact prepared payload. Heartbeat repeats at the same deadline
write no event; each claim generation permits at most 32 strict extensions.

Fresh validation: `bash scripts/check.sh` **728 workspace Rust + 32 reduced-feature
Rust, 156 UI**, plus **one separately executed successful-cancellation CLI process
test** that is intentionally ignored by the ordinary workspace invocation.
Formatting, Clippy, TypeScript, both UI builds, design/contracts/locales/vendor
checks and the existing diagnostic suites pass. The shared-umask authority/service
command passes **334**; its one ignored process case is covered separately by
`check.sh`, not counted as passed there. Focused suites are overlapping subsets,
not additional totals.

All runtime suites in the table above were freshly executed: HTTP 24, CLI 13
and protocol fixture 5, passkey 76, login admission 14, audit 21, catalogue 11,
enrollment browser 25, authority browser 40, metadata 41, Linux 66/40 actual
packets, signed Linux 98/43 actual packets and native evidence 33/5 actual
captures. Authority, metadata, signed Linux and native evidence were repeated
after schema stabilization and a fresh binary build. Disposable containers were
removed; the host firewall was unchanged. A first Docker build could not write
the default Buildx activity directory; a writable task-specific `BUILDX_CONFIG`
resolved setup with the required CA mount and verification intact.

The original L1 SQL exploit was reproduced against archived PR #18 source before
correcting it. Independent internal review then reproduced and closed orphan
cancellation evidence, corrupted legacy delivery migration, and missing live
accounting-head guard cases; each reviewer reran the same failing counterexample
after correction. The supplied external reports remain preserved separately in
[their original text](../docs/reviews/pr18-external-reviews.md). Those named models
have not yet reviewed this follow-up. Early implementation checks caught a
private fixture calling a deliberately closed public worker, a future-dated CLI
fixture and stale schema-version binaries; corrected fixtures and fresh builds
passed without changing production gates. Raw logs stay outside source.

This is M02/M03/M05 hardening, not protected signer/dispatch deployment, original
core-request/rootless cost binding, PostgreSQL, or native host/Windows/macOS
qualification. Trust-key replacement together with the whole database remains
outside the retained-signature guarantee.

## Durable signing coordination

Based on PR #17 merge `956de27`, schema 7 now prepares current approval,
retained review/metadata/baseline, independent generation, quota reservation and
immutable signer job in one transaction. Exact signed-result verification and
current-state rechecks precede grant/issuance/outbox/audit finalization. Work
claims fence stale workers, retries preserve signed bytes, cancellation proves
no issuance, and UNKNOWN keeps capacity after expiry. The trusted local CLI and
authenticated eight-locale readiness panel expose blockers and retained history.

Fresh local checks: `bash scripts/check.sh` **713+32 Rust, 156 UI**;
`umask 0002; cargo test --locked -p fw_authority -p fw_authority_service`
**319**; authority browser **40**; metadata processes **41**; native evidence
**33 with five actual captures**; signed Linux lab **98 with 43 packet probes**.
The native-only run initially lacked the pinned Rust environment and did not run;
loading `scripts/dev-env.sh` resolved it. The signed lab's initial image build
needed writable `BUILDX_CONFIG=/tmp/nox-linux-buildx`; its complete rerun passed.
No test or permission check was weakened. The other runtime rows above retain
previously executed results and are also covered by remote CI; they were not all
repeated locally for this batch. Raw logs and reports remain outside source.

Three independent internal review slices covered transaction/signature,
quota/lifecycle and surface boundaries. They reproduced a generation-head reset
that disagreed with retained intent history. The fix compares the latest immutable
epoch/generation/intent and rejects reset, missing and older valid heads; the
same independent counterexample passed afterward, as did two new real-fixture
regressions. A CLI origin example was corrected to the authority service default.
Independent reruns included contract 9, quota 15, job lifecycle 11, CLI process 5,
UI 30 and HTTP 3 checks; these overlap the main suites and are not added to totals.
No remaining blocker was identified within those review scopes.

Production prepare/worker paths still refuse: protected bootstrap, trusted target
generation initialization, build identity, native qualification and deployed
signer/delivery verification are absent. Successful mechanics use private
`cfg(test)` witnesses, actual P-256 approvals and Ed25519 evidence/results.
Core access cost binding and rootless policy preparation remain unsupported.
See [coordination boundaries](../docs/signing-coordination.md) and the
[administration guide](../docs/signing-coordination-cli.md). The original 53 design
files remain unchanged; all 52 manifest entries were rechecked by size and hash.

## Received-review reliability follow-up

All three supplied PR #15 reviews are recorded at their exact earlier target.
Both GLMs identified the same buffered stdout defect. Against merged PR #16,
actual admin commands reproduced exit 0 despite `/dev/full` or a closed reader,
while agent/help output panicked. Both commands now check writes and final flush;
Unix output uses a checked duplicate handle to preserve `EBADF` instead of the
standard stdout wrapper that masks it. Full destinations, read-only handles and
broken pipes return fixed errors without losing committed DB or proof state.
A valid writable `/dev/null` remains allowed. Rust can normalize pre-exec closed
stdio to that valid sink; this is not an error detectable after startup.

The actual-process regressions verify unchanged canonical bytes, lost challenge
quota, immutable receipt replay, private verifiable proof survival and refusal to
overwrite an existing proof. Future-clock regressions reopen the database,
exercise every target operation, demonstrate the separate project audit fence,
and recover only when trusted time reaches the existing floors. There is no
immediate clock-reset or qualified epoch-recovery API; the runbook preserves this
remaining availability limitation.

Authority smoke reports retain only bounded closed startup diagnostics before
temporary cleanup. Success requires the exact two normal startup messages plus
all browser checks; unknown output, missing completion, child exit or report
write failure cannot pass. Actual unsafe `0646` assets still fail with the saved
`ui_assets` stage. Catalogue tests reduce measured global accessible-name query
cost while preserving 65 records, accessibility assertions and the original
5-second limit. The supplied intermittent timeout was not reproduced locally;
its underlying cause remains unproven.

A consolidated independent review found the remaining read-only stdout case;
the corrected code passed that reviewer's separate 49-check process/diagnostic
probe, two clock tests, thirteen diagnostic tests and eleven catalogue tests.
The original external private C/D probes were not recovered or rerun. Source
changes were followed by the full repository check (658+23 Rust, 125 UI),
shared-umask authority/service tests (264), actual authority browser (36),
metadata processes (41) and native processes (33 with five signed captures).

## Security and persistence coverage

Authority test directories and private fixture files receive `0700`/`0600` at
creation. This preserves production rejection of unsafe paths while making the
fixtures independent of permissive umasks and inherited default ACLs. The
focused authority/service fixture suite passed under `0002`, `0022` and an actual
inherited default ACL; CI separately reruns it under `0002`. Deliberately unsafe
permission, symlink and hardlink rejection cases remain active.

Five startup regressions cover fixed stage/code diagnostics, including actual
executable arguments, non-UTF8 arguments, unsafe/missing UI and an occupied port.
A disposable POSIX default-ACL reproduction created an actual `0646` UI file:
startup rejected it with the fixed `ui_assets` code and left its mode unchanged.
The [installation guide](../docs/authority-review-service.md#file-modes-inherited-acls-and-startup-diagnostics)
describes required modes and ACL inspection. Catalogue smoke reports closed
failure phases/categories without exception text or private paths; six Python
tests cover sanitization and report-write failure. Explicit locator deadlines
and save/detail readiness do not establish the original intermittent failure's
cause.

Controller bootstrap reads require a separate in-memory session proof; a cookie
alone cannot disclose that proof or register the owner. CLI browser views withhold
the terminal confirmation code and polling secret. Public login options use
bounded encrypted tickets without allocating shared pending database slots;
successful proof verification, durable consumption, counters and mandatory audit
commit atomically. Tampering, bounded decompression, maximum sizes, zero-counter
replay, independent connections and injected failures are covered. This is
bounded admission testing, not sustained CPU/network saturation qualification.

Server-owned session provenance prevents an exchanged CLI session from adding or
revoking owner keys or authorizing another terminal, even during the original UV
freshness window. Ordinary controller reads/writes remain available. Tests cover
borrowed registration proofs, spoofed type headers, logout/expiry/revocation and
promotion only after a new verified WebAuthn login.

Anonymous CLI initiation now retains no pending request or replay-key cache and
writes no durable success audit. The passkey smoke creates 1,005 requests, checks
unchanged audit counts and completes a previously issued request. Bounded AEAD
tickets conceal the short code and polling-secret hashes and bind origin,
tenant, principal, request and time. Only fresh browser interaction allocates
protected attempt/approval/consumption state. Regressions cover wrong-code
limits, tampering, request substitution, expiry, restart, key epochs and nonce
exhaustion. Wall/monotonic time floors prevent expired replay fences from
reappearing after clock rollback. A real concurrent-logout barrier test checks
that authorizer validation, mandatory audit and delegated-session insertion
share the session-registry lock. Audit failure issues no session. The browser
removes the encrypted URL fragment while preserving the memory-held ticket
through keyboard skip navigation. Sustained CPU/HTTP/database saturation and
exhaustion by an authenticated owner remain outside this bounded guarantee.

Controller login tickets and authority envelopes use non-clonable, checked nonce
allocators and domain-separated epoch keys, with at most 65,536 encryptions per
derived key. Old unexpired tickets remain decryptable across issuance epochs;
there is no flood-evicted key cache. Tests cover rollover, concurrent allocation,
exhaustion, tampering, purpose/origin separation and restart. This bounds issued
encryption usage, not arbitrary failed-verification attempts or CPU saturation.

[Audit snapshots](../docs/audit-log.md) and [catalogue snapshots](../docs/catalogue-pagination.md)
bind continuation to the session, tenant, filters, limit and original deadline.
Tests cover traversal beyond 100 rows, byte caps, mutation isolation, projection
integrity, migration, clock rollback and concurrent capability renewal. Current
certificate and report eligibility is checked by both service writes and pickers.

[Authority schema 6](../docs/authority-store.md) preserves original signatures,
immutable plans, credential snapshots and public-key tombstones. Explicit
migrations validate private online backups before changing known older schemas;
they never infer trusted epochs or human identities from plans. The tests cover
real P-256 signatures, restart, exact retries, aliases, current revocation,
retained proofs after counter advancement and atomic rollback. A separate
first-open stress run passed 1,600 fresh-database races after bounded WAL retries.

Migration preflight rejects source/backup/manifest and SQLite sidecar collisions
before opening either database. It also rejects preexisting destination sidecars.
Tests preserve source schema/history on refusal and cover case variants, parent
aliases, reverse/manifest collisions and the documented ASCII maintenance-name
profile. Unicode parent directories remain usable. Expired device reservations
retain retry/replay bindings; a reopened-store regression confirms they cannot
issue certificates and do not block a separately authorized new invitation.

Nine durable-review regressions cover atomic plan/requirements/evidence/audit
admission, exact retry, concurrent import, reopen, corrupted bindings and times,
missing evidence, checked approval gates and validated schema-3 backup migration
with rollback on foreign-key failure. Three service regressions retain review
after removing source/config, tolerate expired or retired configured plans, and
reject ambiguous tenant mappings. The shared verifier retains full state
recomposition and bounded bytes/depth; no legacy plan receives invented evidence.
These are semantic review guarantees, not compiler/native gate attestation or
permission to sign or dispatch.

[Target metadata](../docs/target-metadata.md) has 11 shared Ed25519 protocol
tests, seven device process tests, 20 authority persistence regressions and ten
local admin process tests (the latter also exercise the native command workflow). They cover strict canonical bytes, signature and
identity substitutions, protected file/certificate binding, non-UTF8 diagnostics,
bounded stdin, explicit namespace initialization, pin CAS/tombstones, schema-4
backup migration, challenge quota, atomic audit failure, concurrent exact retry,
expiry/revocation and retained clock fences. A reproduced same-key certificate
renewal defect is fixed: an old signature cannot be relabeled as a new pin
revision through coherent receipt/projection corruption. Delayed-stdin admission
samples current time after input and rejects an actually expired proof. The
optional 41-check process smoke derives its synthetic independent public pin from
an actually enrolled certificate; it never exports private keys or changes a
host firewall. Separate reviewers examined protocol, store, CLI paths and smoke
failure assertions; requested external models were not called.

Metadata evidence authenticates its device key and exact bytes, without machine
attestation, qualified enforcement or policy authority. The local operator must
independently maintain pin/certificate trust and revocation. A signed unverified
report cannot satisfy a native gate. Production baseline/gate qualification,
durable signer/quota integration and protected dispatch remain unfinished.

The [native evidence workflow](../docs/native-evidence.md) adds independent
recompilation from the retained reviewed plan and explicitly pinned lab
references. The candidate must match the exact plan artifact hash; device metadata
and lab capability hashes remain distinct. A purpose-scoped observer signs
captured raw nft state and installation/clock context. The authority rechecks
signatures and actual correspondence, records negative/unknown observations
without an observed state hash, and atomically advances consumption, receipts,
head and audit. Current checks revalidate metadata, reference/observer pins,
plan, exclusive expiry and the target-global head. Earlier plan observations
remain visible as history when another plan replaces that head.

Coverage includes real Ed25519 signatures, canonical bounds, TTL refresh,
platform substitution, bidirectional transport/observer key separation,
permanent key ownership, revision/head CAS, competing connections, audit rollback,
clock fences after failed or expired requests, zero epoch/generation, retained
proof/projection corruption and validated schema-5 backup migration. The separate
API checks live reviewer/proof/origin/tenant boundaries and returns summaries
without raw captures. Its eight-locale UI checks plan/response binding, current
versus historical evidence, local expiry and request-delay/clock rollback.

One consolidated independent review covered the complete batch. Three reproduced
findings were corrected: an earlier plan's retained observation disappeared from
its display after a different plan advanced the target head; valid zero
epoch/generation values were refused by the admin CLI; and request latency was
omitted from displayed freshness when the client clock moved backward. These
reviewers ran focused independent reproductions, separately from the implementation
tests. The user subsequently supplied all three external PR #15 reviews. They cover
their fixed earlier target, not this native-evidence batch; their results and
follow-up are retained separately in review-continuity.

The actual Docker/process smoke uses synthetic independent trust, five signed
kernel captures and no host firewall changes. In this environment the older
pinned Debian image emits a nonfatal GLIBC_2.39 weak-version loader warning for
the host-built executable. Only that exact single leading warning is classified
separately; unexpected stderr, repeated warnings, panic or a missing refusal
remain failures. Three Python regressions enforce that distinction. This is not
portable binary or installed-host qualification.

Compilation correspondence does not attest the plan's declared compiler/validator
build identity. Signed lab observations do not establish protected kernel
provenance, production management baseline qualification or authority to sign
and dispatch. Both result constants remain false, and read-only evidence refresh
never submits a passkey decision or promotes a human approval into native evidence.

Authority audit checks include rollback of a genuine zero-counter activation
when audit time moves backward, plus restart, independent tenants, exact retries,
missing heads, gaps, broken links, tampered projections/hashes, oversized storage
and legacy backward history. New appends verify the indexed tail and reject time
regression within the mutation transaction. The read-only verifier streams one
consistent tenant snapshot without rewriting old history. It has no external
checkpoint and cannot detect a coherently replaced entire database. These checks
are SQL/API failure and corruption tests, not power-loss qualification.

Independent quorum tests cover Lab/Team/high-risk roles, canonical distinct
humans, author exclusion, non-greedy role matching, terminal dissent, expiry,
withdrawal, role/key/basis changes, concurrent last reviewers and injected write
failures. Decision consumption, proof, immutable approval-set members, current
head, historical receipt and audit commit in one transaction. Current reads
revalidate the head; historical receipts never renew authority. A current read
is a snapshot, not reserved permission for a future signing transaction.

Candidate aggregation excludes withdrawn or currently ineligible votes and
deduplicates canonical human/role pairs before the 64-candidate bound. Original
proofs are reverified, while a scoped SQLite instruction budget bounds historical
lookup cost. Tests reproduce 64 duplicate votes followed by 63 withdrawals and an
independent final vote, distinct-candidate overflow, and full admission rollback
and exact retry after query interruption. Named-set withdrawal commits a retained
tombstone and audit atomically; withdrawing an old set cannot invalidate a
different current head, and an unchanged selection cannot silently be reminted.

The [independent review service](../docs/authority-review-service.md) has 30
HTTP/P-256 regressions plus five review-adapter tests. It requires separately
pinned private authority trust and a distinct origin. Tests cover exact
Host/Origin, cookie plus memory proof, tenant isolation, bounded requests,
anonymous admission floods, counter/revision replay, mandatory-audit rollback,
complete immutable before/after evidence and refusal of missing or oversized
review content. Runtime routes never provision keys, roles, epochs or human maps.

Nine executable TCP/P-256 tests and two connection-phase/race tests cover fresh
login and verified requests with 64 idle sockets, verified requests with 64 slow
public bodies, forged/missing proof, revoked/missing/revision-stale cached
sessions, logout, absolute deadlines, recovery and disconnected blocking-job
permit retention. The original idle/socket and shared-public-body starvation
cases were reproduced against the previous executable before the fix.
The 8+8 work reservation protects admission capacity; shared runtime work and
fresh public sign-in still have no availability guarantee under sustained local
TCP/CPU/database saturation. No protected OS deployment is inferred.

The [authority UI](../docs/authority-review-ui.md) has a separate build and 65
unit/catalogue tests within the UI total. It requires explicit consent, a current
role and a fresh decision-bound assertion. Uncertain requests allow exact retry;
401 clears pending browser authority and requires explicit sign-in. The real
browser suite covers approval, later fresh signed rejection by the same reviewer,
terminal dissent after restart, stale independent epoch, missing evidence,
keyboard navigation and cleanup. Actual HTTP plan, requirements, approve/reject
decision and current human approval-set objects also validate against both
preserved schema documents. Mutated copies must reject unknown fields, invalid
UUID/calendar dates and a rejection member inside an approval set. This does not
cover access-lease plans or delegated sets. Expired approvals permit fresh review when the
current store returns Pending. Set identity, hashes, bindings and deadlines must
match the current detail response before the UI displays verified quorum.

The [Linux lab](../native/linux/README.md) covers actual compilation, packet
behavior, expiry and semantic kernel readback, including tamper/restore. The
[signed execution lab](../docs/signed-linux-execution.md) covers verified grants,
durable native material, actual apply/probe confirmation, established and new
connection expiry, restrictive crash recovery and generation fencing. The native
writer inherits the journal lock so an orphan writer cannot race fresh recovery.
Immutable recovery attempts preserve original deadlines; fresh fenced observations
can close genuinely unapplied work without reclassifying historical confirmation
or rollback as NotApplied. Interrupted preparation, submission and recovery are
exercised, including parent/child process termination. Both suites remove
their containers successfully. Signing and approval inputs are synthetic test
fixtures; no lab result establishes production authority or installed-host safety.

## Remaining acceptance

The controller remains **observe-only**. A separately provisioned local review
service can now retain signed decisions and complete verified quorums, but
production authority bootstrap, protected OS-account/IPC deployment, independent
signer transactions and authenticated host dispatch remain incomplete. The
same writable account cannot provide the required process/trust isolation.

Physical authenticators, human review/consent, full accessibility and translation
acceptance are not qualified by virtual-authenticator tests. Full Linux
crash/reboot/coexistence and hung-owner watchdog qualification, Windows WFP/callout,
macOS Network Extension, signed installation/update/removal, complete F_07
acceptance receipts/aggregate gates and provider deployment remain outstanding.
Authenticated CLI-handoff budget exhaustion, sustained local resource attacks
and local recovery after loss of all owner keys remain documented limitations.
See the [implementation overview](../docs/implementation.md),
[platform status](../docs/platform-support.md) and [task ledger](task-ledger.json).

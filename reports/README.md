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

The integrated repository check passes **650 workspace Rust tests, 23 authority
tests without default features, and 125 UI tests**. It also passes formatting,
Clippy, frontend types, both production UI builds, 27 specification checks,
52 core and 28 extended contract fixtures, nine Linux runner regressions,
six catalogue-diagnostic regressions and
three native-evidence diagnostic regressions, plus
vendored-source verification. English remains the default. Eight controller
catalogues have 229 messages each; eight authority catalogues have 96, with
complete key and placeholder parity. Human translation acceptance is pending.

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
| Independent authority browser | 36 | Actual service, virtual passkey decisions, current quorum, dissent and restart |
| Isolated Linux compiler/readback | 66 | Includes 40 actual IPv4/IPv6 TCP/UDP packet probes |
| Signed Linux execution | 98 | Includes 43 actual packet probes, expiry and interrupted submission/recovery |
| Retained native evidence | 33 | Five actual signed kernel captures across MATCH, MISMATCH, UNKNOWN and restoration; independent admission, replay, revocation, strict failure diagnostics and cleanup |

The recovered baseline and prior metadata batch were verified separately. The
current comparison base is merged PR #15, `43146fd`, whose
[full main CI passed](https://github.com/simhanson123/Nox_Warden/actions/runs/41278538402).
This integrated batch freshly passed the repository check (650+23 Rust, 125 UI),
authority/service tests under `umask 0002` (258), the real authority browser (36),
native evidence processes (33 with five captures), and signed Linux execution
(98 with 43 actual packets). Other runtime rows retain their suite expectations;
CI reruns every listed nonbrowser enrollment and runtime suite on the reviewed PR.
The [review handoff](../docs/review-continuity.md) distinguishes supplied external
reports from fresh executions. Earlier external private probes were not recovered
or claimed as reproduced. The current external reviews still target PR #15.

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

[Target metadata](../docs/target-metadata.md) adds 11 shared Ed25519 protocol
tests, five device process tests, 18 authority persistence regressions and three
local admin process tests. They cover strict canonical bytes, signature and
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
tests. The user's external PR #15 reviews remain pending and cover their fixed
earlier target, not this new batch.

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

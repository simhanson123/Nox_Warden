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
cargo build --locked -p fw_control -p fw_cli -p fw_agent -p fw_authority_service --bins --examples
python scripts/smoke_control.py
python scripts/smoke_cli.py
python crates/fw_cli/tests/smoke_login.py
python scripts/smoke_passkeys.py
python scripts/smoke_login_admission.py
python scripts/smoke_audit.py
python scripts/smoke_catalogue_navigation.py --controller-binary target/debug/fw_control
python scripts/smoke_enrollment.py --browser
python scripts/smoke_authority_review.py --service-binary target/debug/fw_authority_service --fixture-binary target/debug/examples/review_fixture
python scripts/linux-lab.py --report reports/linux-lab.json
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
```

Browser suites start actual loopback services and use Chromium CDP virtual CTAP2
authenticators. Native suites require Docker and run only in disposable network
namespaces with NET_ADMIN; they do not change the host firewall. A missing native
or browser prerequisite is not a passing check.

## Verified scope

The integrated repository check passes **542 workspace Rust tests, 23 authority
tests without default features, and 89 UI tests**. It also passes formatting,
Clippy, frontend types, both production UI builds, 27 specification checks,
52 core and 28 extended contract fixtures, nine Linux runner regressions,
six catalogue-diagnostic regressions and
vendored-source verification. English remains the default. Eight controller
catalogues have 229 messages each; eight authority catalogues have 58, with
complete key and placeholder parity. Human translation acceptance is pending.

| Runtime suite | Passing checks | Exercised boundary |
| --- | ---: | --- |
| Controller HTTP | 24 | Actual HTTP routes and original OpenAPI contracts |
| CLI / separate protocol fixture | 13 / 5 | Login, bounded list continuation and hostile-server refusal |
| Passkey browser | 71 | Durable owner enrollment, key lifecycle, logout, CLI handoff and delegated-session restrictions |
| Login admission browser | 14 | 1,005 anonymous options requests, valid earlier proof, replay refusal and restart |
| Audit HTTP/MCP/browser | 21 | Bounded denial evidence and stable snapshot pagination |
| Catalogue browser | 11 | 65 assets, complete list traversal, page size, refresh and asset-picker continuation |
| TLS enrollment/browser | 25 | Ed25519 certificates, mTLS, reports, service creation and revocation; CI nonbrowser subset has 23 |
| Independent authority browser | 31 | Actual service, virtual passkey decisions, current quorum, dissent and restart |
| Isolated Linux compiler/readback | 66 | Includes 40 actual IPv4/IPv6 TCP/UDP packet probes |
| Signed Linux execution | 98 | Includes 43 actual packet probes, expiry and interrupted submission/recovery |

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

[Authority schema 3](../docs/authority-store.md) preserves original signatures,
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

The [independent review service](../docs/authority-review-service.md) has 23
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

The [authority UI](../docs/authority-review-ui.md) has a separate build and 35
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
Public CLI-handoff admission bounds and local recovery after loss of all owner
keys remain documented limitations. See the [implementation overview](../docs/implementation.md),
[platform status](../docs/platform-support.md) and [task ledger](task-ledger.json).

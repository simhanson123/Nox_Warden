# Durable signing coordination

Authority schema 9 retains the two-phase signing mechanics introduced in schema
7, the reservation guards added in schema 8, and original core-access cost
provenance. It also exposes a read-only readiness summary and trusted local quota
and provenance administration. The public preparation and worker paths remain
closed: protected bootstrap, independently verified build identity, qualified
native evidence and a protected signer are not implemented. No configuration
flag, browser approval, lab receipt or CLI option bypasses those requirements.

The controller still cannot issue or dispatch a policy grant. Successful
transaction tests use a private `cfg(test)` witness, actual WebAuthn approval
proofs and Ed25519 signatures. That witness is absent from normal builds and
does not constitute production qualification.

## Transaction boundaries

The implementation follows the signing transaction in F_03. All durable records
below share the independent authority SQLite database; the older standalone
`QuotaLedger` is not used to simulate a cross-database transaction.

1. Preparation rechecks the retained plan, semantic review, current distinct-human
   approval set, authority basis, target metadata and exact baseline observation.
   It derives cost from retained evidence and checks independently pinned root
   and project limits. Generation advancement, reservation, immutable intent,
   signer job and audit commit together under `BEGIN IMMEDIATE`.
2. A separately deployed signer would process the immutable job outside the
   database transaction. The job binds the exact canonical grant payload,
   reservation, generation, plan and approval hashes. This batch does not deploy
   that signer or provide an `AuthorityEvidence` adapter.
3. Finalization verifies the returned Ed25519 DSSE grant against the pinned
   purpose-specific key and exact prepared payload. It rechecks current evidence,
   approvals, quota pins and claim ownership. Signed bytes, first issuance cost,
   dispatch outbox and audit commit together. Revocation between the phases
   prevents completion; an audit failure rolls the transaction back.

An exact request retry resolves its original intent instead of allocating a new
generation. Stored signatures are verified when historical results are read.
With the retained trusted signer key unchanged, rewriting a projection and its
hash cannot create a valid signature. The historical key copy lives in the same
authority database: an attacker who can replace both that trust record and the
signed evidence is outside this check's guarantee. Protected storage and an
independent trust anchor remain deployment requirements. Retried dispatch uses
the same signed grant bytes. Historical results remain separate from permission
to perform a new operation.

The native observation must be a current **baseline** match for the exact
retained plan. A candidate match cannot substitute. The observation's generation
describes the reviewed plan's proposed generation; it is not a protected host
journal high-water mark. Signing has a separate target generation head, which
normal builds currently have no trusted bootstrap path to initialize.

## Quota and supported cost profile

Root and project limits are independently pinned with revision checks, validity
and revocation. A project's root binding cannot be switched to reset history.
The root belongs to its organization and may be administered from another project
in that same organization at the trusted local administrator boundary; it is not
owned exclusively by the project that first pinned it. Organization identity
still scopes every root lookup and revision change. Both buckets must admit a
reservation within the same transaction. Costs and totals are derived internally;
requests cannot supply a cheaper cost or a larger
limit. Administrative pinning is a trusted local operation, not an approval from
a controller session.

The implemented preparation profile is a reviewed, non-expanding
`policy_change`: zero new leases, destinations and lease seconds, and one
concurrent deployment. It currently requires both quota pins even for the
general-policy case in which F_03 permits a null root. Rootless preparation is
not implemented and requires a separate quota profile and storage upgrade.

Core access cost can now be derived from retained original provenance. The
trusted local importer binds a registered `add_access_lease` plan to the complete
original request, access envelope and delegation, plus an explicit lease ID.
The verifier checks their exact canonical hashes against the plan, request
identity/revision, tenant/target/principal/workload and asset/service membership,
scope exclusions, lifetimes and duration limits. Request revision is fixed at 1
for this core profile. The original request ID is distinct from the signing
coordinator's `SigningRequest.request_id`, which identifies a preparation retry.

The authority retains one immutable original record and an immutable binding for
each compatible plan. A request cannot change its bytes, root or lease; an
organization cannot reuse its lease identity, and a tenant cannot alias the
request's idempotency key under a new request ID. Exact retries add no audit
record. A later compatible plan may bind the same original record without
creating a second lease identity. Reads revalidate the canonical bytes, hashes
and stored projections rather than trusting a supplied cost summary.

Derived core cost uses the original request's full `lease_seconds`, its sorted
destination set and the retained lease ID. For example, an original 3,600-second
request still costs 3,600 seconds when the retained plan allows only a remaining
1,800-second window. The current independently pinned root and project quota
configuration must refer to the same root as the retained delegation. Each of
the five independently pinned root limits must also be no greater than its
original delegation ceiling: active leases, daily new leases, daily unique
destinations, daily cumulative seconds and concurrent deployments. Project
limits may be higher because every reservation must pass both buckets; the root
still enforces the delegation ceiling. Provenance does not create pins or permit
the caller to select another bucket.

Each plan's requested policy window must fit the original duration, but this
provenance record does not retain one absolute lease start/end across compatible
later plans. A later plan can propose a shifted window. The future core signing
profile must retain and enforce a single lease window before those plans can
authorize access; original cost retention alone does not supply that constraint.

This binding establishes cost inputs, not approval. Envelope/delegation approval
hashes and the workload reference do not prove signatures, authenticated identity
or current authority. A complete core semantic-review/native/signing profile is
still unavailable, so every core plan retains
`CORE_SIGNING_PROFILE_UNAVAILABLE`. Missing or no longer current provenance also
produces `CORE_REQUEST_BINDING_UNAVAILABLE`. No core grant can be prepared through
the public resolver.

The accounting engine also checks lease costs in private tests. It preserves
active and deployment slots, the rolling `(now - 86400, now]` issuance window,
distinct destinations and full approved lease seconds. Pending reservations
count before issuance; completed historical costs are not refunded on release.
UNKNOWN retains occupied slots even after intent or reservation expiry. Explicit
pre-issuance cancellation requires the absence of a signed result and outbox.
There is no timer that treats an unanswered dispatch as safely cancelled.

Schema 8 records ordered immutable quota transitions tied to retained work
events and, when applicable, issuance usage, the signed result, outbox and delivery
record. Reservation state and slot columns must match their latest transition.
SQL guards reject an unsupported ordinary UPDATE before its new state could
remove the row from an accounting index. A transition also requires its work head
to match the latest immutable work event, so an orphan cancellation event cannot
release slots. Read paths also compare the reservation with its evidence.
Creating the work evidence, quota transition, changed slots
and required audit occurs in the same transaction, so a failure rolls them back
together. A confirmed delivery returns the dispatch slot; it retains any active
lease slot and the original issuance charge.

Accounting queries use separate indexes for held obligations and released
issuance history on guarded heads derived from immutable quota transitions.
Changing only a reservation projection therefore cannot hide the obligation from
the accounting query. Exceeding 10,000 relevant rows or 200,000 destination visits
fails the transaction with a quota error; the implementation does not truncate
the history and undercount it. Retention and archival maintenance remain future
work.

## Claims and recovery

Signer and dispatch claims have distinct phases, opaque tokens, worker identity,
generation fences and bounded deadlines. Mutable work heads are checked against
retained immutable transition records. A stale worker cannot finish a newer
claim. Heartbeats cannot shorten the claim or extend the original intent deadline.
Repeating the same computed deadline adds no event or audit entry. A claim
generation permits at most 32 strict extensions, counted from retained immutable
events so reopening the store cannot reset the limit. Signer attempts are limited
to three and dispatch attempts to five, with bounded backoff.

Cancellation races finalization under the same database writer transaction:
either cancellation proves no issuance and releases the reservation, or a signed
result/outbox exists and cancellation is refused. Cancelling a claimed but
unissued job invalidates that worker claim and preserves the target generation
fence; a late completion cannot finalize the cancelled job. A lost delivery
response leaves UNKNOWN and retained quota. A successful acknowledgement needs independently
verified delivery evidence; there is no public constructor that turns a caller's
boolean into that evidence. Production dispatch and delivery verification are
still unimplemented. When retrieving an outbox grant, the store verifies its
actual Ed25519 signature and exact prepared job/payload binding under the retained
signer key, and checks issuance and outbox timestamps. This check does not supply
production delivery evidence. Retrieving historical signed bytes after expiry
does not renew their validity or authorize a new dispatch.

The authority's durable time fences continue to apply. A failed operation may
record a later observed time without committing an intent, reservation or job.
Do not lower those clocks or overwrite the database from an old backup to
recover capacity. See the [clock recovery limitations](target-metadata.md).

## Readiness and migration

`GET /authority/v1/plans/{plan_id}/signing-readiness` uses the existing live
reviewer, origin, proof and tenant checks. Its bounded, non-cacheable response
reports current blockers, approval hash, quota configuration, target generation
and an optional retained intent status. It does not reserve quota or start work.
`quota_configured` means current pins exist, not that capacity was reserved.
`signing_allowed` and `dispatch_allowed` remain false.
For core plans, request-binding availability is reported separately from the
unfinished core signing profile; importing original objects removes no production
bootstrap, build, native-qualification or signer requirement.

The eight-locale **Signing readiness** panel separates these blockers from
historical work and reservation state. It accounts for request latency and clock
rollback when expiring a view, and discards responses from an older plan. Refresh
does not approve, sign or dispatch. UNKNOWN continues to show held quota after a
view expires.

The [local CLI guide](signing-coordination-cli.md) covers quota pinning,
revocation, readiness, preparation requests, intent inspection and explicit
unissued-job cancellation. Preparation requests currently return a fixed rejection
and allocate no signing resources. An expired unissued job can be explicitly
cancelled once the transaction proves it has no result, outbox or issuance usage;
expiry alone releases nothing. Issued and UNKNOWN reservations remain held.
The [core provenance CLI guide](core-access-provenance-cli.md) covers bounded
original-object registration and historical lookup. Its summaries include hashes,
IDs and full cost inputs, without exposing request purpose, workflow or scope.
`current` describes the binding lifetime only; both permission fields stay false.

Existing schema 1–8 databases require the validated private-backup migration
described in [authority storage](authority-store.md). The schema 7 step creates
empty signing tables. The schema 8 step checks existing reservations against
retained immutable evidence before recording their proven transitions; it rejects
unsupported refunds and orphan reservations rather than legitimizing them. An
issued, UNKNOWN or active reservation requires matching usage, signed result and
outbox; active also requires retained delivery, and work heads must match their
latest immutable events. Migration imports no signer
key, generation, quota configuration or permission from earlier approvals,
controller registration or lab evidence. Earlier native proofs, receipts and
audit entries retain their original bytes. Current-version opens and repeated
migration calls check actual schema definitions as well as migration checksums.
The schema 9 step adds empty immutable original-request and plan-binding tables.
It preserves existing signing/evidence history and all deployed migrations
001–008; it never reconstructs a request, root or lease from a shorter policy
window, approval hash or old reservation.

Remaining dependencies are protected authority bootstrap and OS identities,
trusted target generation initialization, qualified compiler/baseline/observer
evidence, the complete core signing and rootless policy profiles, independently
authenticated workload/delegation authority, a separately deployed signer,
authenticated dispatch and delivery evidence, backup/restore epochs and
PostgreSQL transactions.

# Durable signing coordination

Authority schema 7 adds the storage and verification mechanics for a two-phase
signing transaction. It also exposes a read-only readiness summary and trusted
local quota administration. The public preparation and worker paths remain
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
generation. Stored signatures are verified when historical results are read;
rewriting a projection and its hash cannot create a valid signature. Retried
dispatch uses the same signed grant bytes. Historical results remain separate
from permission to perform a new operation.

The native observation must be a current **baseline** match for the exact
retained plan. A candidate match cannot substitute. The observation's generation
describes the reviewed plan's proposed generation; it is not a protected host
journal high-water mark. Signing has a separate target generation head, which
normal builds currently have no trusted bootstrap path to initialize.

## Quota and supported cost profile

Root and project limits are independently pinned with revision checks, validity
and revocation. A project's root binding cannot be switched to reset history.
Both buckets must admit a reservation within the same transaction. Costs and
totals are derived internally; requests cannot supply a cheaper cost or a larger
limit. Administrative pinning is a trusted local operation, not an approval from
a controller session.

The implemented preparation profile is a reviewed, non-expanding
`policy_change`: zero new leases, destinations and lease seconds, and one
concurrent deployment. It currently requires both quota pins even for the
general-policy case in which F_03 permits a null root. Rootless preparation is
not implemented. Core access grants remain blocked with
`CORE_REQUEST_BINDING_UNAVAILABLE` until original request, root, lease identity
and full approved duration can be independently resolved. A policy's shorter
remaining lifetime is never substituted for those missing inputs.

The accounting engine also checks lease costs in private tests. It preserves
active and deployment slots, the rolling `(now - 86400, now]` issuance window,
distinct destinations and full approved lease seconds. Pending reservations
count before issuance; completed historical costs are not refunded on release.
UNKNOWN retains occupied slots even after intent or reservation expiry. Explicit
pre-issuance cancellation requires the absence of a signed result and outbox.
There is no timer that treats an unanswered dispatch as safely cancelled.

Accounting queries use separate indexes for held reservations and released
issuance history. Exceeding 10,000 relevant rows or 200,000 destination visits
fails the transaction with a quota error; the implementation does not truncate
the history and undercount it. Retention and archival maintenance remain future
work.

## Claims and recovery

Signer and dispatch claims have distinct phases, opaque tokens, worker identity,
generation fences and bounded deadlines. Mutable work heads are checked against
retained immutable transition records. A stale worker cannot finish a newer
claim. Heartbeats cannot extend the original intent deadline. Signer attempts
are limited to three and dispatch attempts to five, with bounded backoff.

Cancellation races finalization under the same database writer transaction:
either cancellation proves no issuance and releases the reservation, or a signed
result/outbox exists and cancellation is refused. A lost delivery response leaves
UNKNOWN and retained quota. A successful acknowledgement needs independently
verified delivery evidence; there is no public constructor that turns a caller's
boolean into that evidence. Production dispatch and delivery verification are
still unimplemented.

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

The eight-locale **Signing readiness** panel separates these blockers from
historical work and reservation state. It accounts for request latency and clock
rollback when expiring a view, and discards responses from an older plan. Refresh
does not approve, sign or dispatch. UNKNOWN continues to show held quota after a
view expires.

The [local CLI guide](signing-coordination-cli.md) covers quota pinning,
revocation, readiness, preparation requests and intent inspection. Preparation
requests currently return a fixed rejection and allocate no signing resources.

Existing schema 1–6 databases require the validated private-backup migration
described in [authority storage](authority-store.md). Schema 7 starts its tables
empty. It imports no signer key, generation, quota configuration or permission
from earlier approvals, controller registration or lab evidence. Earlier native
proofs and receipts retain their original bytes.

Remaining dependencies are protected authority bootstrap and OS identities,
trusted target generation initialization, qualified compiler/baseline/observer
evidence, the core request resolver, a separately deployed signer, authenticated
dispatch and delivery evidence, backup/restore epochs and PostgreSQL transactions.

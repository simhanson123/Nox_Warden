# SQLite Lite persistence

This crate implements a bounded persistence slice of F-2.0 M02. It does not claim to complete M02 or the PostgreSQL Team profile.

Implemented: WAL/FULL connections with verified foreign keys; checksummed transactional migration; tenant-scoped principals, immutable request bodies, validation operations, 30-day response retention metadata; atomic request/idempotency/outbox/audit writes; exact original response replay; request state CAS; append-only, hash-linked audits with u64 big-endian counters; leased outbox generation fencing; online SQLite backups; draft-only policy revisions with lifetime validation, hash CAS and allow-shrink checks.

The service authenticates every tenant/principal before constructing `Tenant`. SQLite repository predicates and composite foreign keys are defense in depth; they are not PostgreSQL RLS. Production Lite uses one tenant. Draft policies and queued operations are never evidence of native firewall enforcement. Request submission still requires the caller to validate its exact wire schema, role and workload binding. The current store cannot mark a validation operation succeeded, because the complete immutable plan registry is not implemented here.

Unimplemented F-2.0 portions include normalized policy-scope projections and signed registry snapshots, PostgreSQL migrations/RLS, authority quotas, policy-approval WebAuthn proofs, worker queue proofs, signed PBOM storage, signed device receipts, application-managed WAL checkpoints. Outbox claims are an internal authenticated service boundary; they are not exposed as anonymous user operations. Backups capture only SQLite state and are not an authorization to restore executor generations or revive historical grants.

`cargo test -p fw_store --locked` exercises concurrency, replay conflicts, tenant isolation, failure injection, CAS, audit corruption detection, outbox expiry, migration checksums, backup/reopen, and policy restrictions. These tests do not establish power-loss behavior on other filesystems or native operating systems.

## Manual registry (migration 0002)

Assets and services now have immutable revision history, normalized address/asset/target/transport relations, tenant-qualified foreign keys, case-sensitive NFC name uniqueness, revision/hash compare-and-swap, and transactional idempotency/audit/outbox records. Asset UUIDs, revision metadata, creator identity and hashes are server-generated. Service IDs are caller-selected stable slugs required by `ServiceCreate`; retired IDs cannot be reused. Manual provenance is accepted only with `source_evidence=null`. Trusted provenance is rejected until its identity/evidence verifier exists. References must identify current objects in the authenticated tenant; an active service cannot newly reference a retired asset. Observe-only target inventory does not certify native capabilities.

`content_hash` is SHA-256 over canonical JSON of the complete revision with only the self-referential `content_hash` member omitted. The canonical bytes include tenant, immutable definition, creator/time, revision, previous hash and lifecycle state. Definitions normalize NFC text and sort sets before hashing. Reads recheck normalized projections against the canonical record. An idempotency replay returns the original immutable revision, even if the current head was later revised or retired. The controller uses `list_collection_page` for bounded snapshot pagination across catalogue, request, operation, target and enrollment views. Original creation-time/ID ordering, authenticated continuation, current eligibility and cache retention are described in the [collection contract](../../docs/catalogue-pagination.md). Legacy bounded list helpers still reject oversized whole-list reads; callers needing continuation must use the page API.

Migration startup verifies every historical checksum and compatible `PRAGMA user_version`. A legacy v1 database with `user_version=0` upgrades additively and transactionally through the current version; unknown future versions and modified migrations fail closed. Existing databases are not reset. Each catalog mutation increments the project security revision so future planners can detect stale registry snapshots; this does not claim the full plan/authority registry is implemented.


## Local passkeys (migration 0004)

A permanent local-owner enrollment marker closes bootstrap after the first
credential registration. New credentials start pending: a signed, user-verified
WebAuthn authentication must activate them before they can authorize sessions or
credential changes. Pending credentials cannot satisfy the last-working-key
check. Credential revocation retains its tombstone and invalidates subsequent
session authorization without treating ordinary counter updates as revocation.

Ceremony state is immutable, scoped to the current human/tenant, bound to a server
session or browser nonce, and expires after five minutes. A trusted bounded
WebAuthn callback verifies against current credentials inside the same immediate
transaction that consumes a challenge, updates the credential and appends audit.
Failures are audited with a durable ten-attempt limit and do not create a
credential. Creation is limited to sixteen ceremonies per principal in a
five-minute window, including completed and locked ceremonies. At most eight
unrevoked credentials may exist. Additional registration and revocation require
an active credential authenticated less than five minutes ago.

A successful retry returns the previous result with `replayed=true`; it is never
fresh authentication and cannot mint another session. Raw proofs and library
state stay in the private database; audit projections contain fixed reason codes
and public identifiers only. These are controller-local login records, not human
policy approvals or an independent signer's trusted credential/role registry.

## Audit pages and denial summaries (migration 0005)

`list_audit_page` captures the current append-only audit head on its first call.
Later pages retain that head, so newly appended events appear in a new scan and
cannot move the existing page boundaries. Pages contain at most 100 events and
96 KiB of event JSON, with an explicit continuation sequence whenever more of
the snapshot remains. The smaller byte budget leaves room for MCP's structured
and text copies. The HTTP/MCP layer authenticates the cursor and binds it to the
current principal, tenant, route, filters, snapshot and expiry. Store sequence
numbers alone are not authorization tokens. Page reads verify content hashes,
sequence/tenant projections and chain links without truncating an event.

Coalesced authentication denials use immutable canonical evidence separate from
the closed `f.audit-event/v1` object. The original event's `evidence_hashes` refer
to a `fw.authentication-denial-summary/v1` record containing a fixed reason,
decimal count and time window. Counts cover suppressed follow-up denials and
exclude the initial separately recorded sample. Summary evidence and its audit
reference commit together; duplicate summary content does not append another
event. Reads remain tenant-scoped and verify the content hash. Controller RAM
aggregation is bounded, and unflushed counts can be lost on a crash; this does
not claim a complete durable record of every unauthenticated request.

Migration 6 maintains verified list projections in the source mutation transaction, with atomic 128-ID backfill chunks. Cleanup retains the live 900-second snapshot window and each resource's last older version, and a persistent read clock prevents rollback into pruned history. It never deletes original audit, registry or capability evidence.

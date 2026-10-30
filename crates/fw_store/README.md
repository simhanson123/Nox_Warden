# SQLite Lite persistence

This crate implements a bounded persistence slice of F-2.0 M02. It does not claim to complete M02 or the PostgreSQL Team profile.

Implemented: WAL/FULL connections with verified foreign keys; checksummed transactional migration; tenant-scoped principals, immutable request bodies, validation operations, 30-day response retention metadata; atomic request/idempotency/outbox/audit writes; exact original response replay; request state CAS; append-only, hash-linked audits with u64 big-endian counters; leased outbox generation fencing; online SQLite backups; draft-only policy revisions with lifetime validation, hash CAS and allow-shrink checks.

The service authenticates every tenant/principal before constructing `Tenant`. SQLite repository predicates and composite foreign keys are defense in depth; they are not PostgreSQL RLS. Production Lite uses one tenant. Draft policies and queued operations are never evidence of native firewall enforcement. Request submission still requires the caller to validate its exact wire schema, role and workload binding. The current store cannot mark a validation operation succeeded, because the complete immutable plan registry is not implemented here.

Unimplemented F-2.0 portions include normalized registry/scope projections, PostgreSQL migrations/RLS, authority quotas, WebAuthn credentials/challenges, worker queue proofs, signed PBOM storage, signed device receipts, full snapshot-bound pagination and application-managed WAL checkpoints. Outbox claims are an internal authenticated service boundary; they are not exposed as anonymous user operations. Backups capture only SQLite state and are not an authorization to restore executor generations or revive historical grants.

`cargo test -p fw_store --locked` exercises concurrency, replay conflicts, tenant isolation, failure injection, CAS, audit corruption detection, outbox expiry, migration checksums, backup/reopen, and policy restrictions. These tests do not establish power-loss behavior on other filesystems or native operating systems.

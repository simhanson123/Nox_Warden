# Authority primitives

`verify_grant` validates the closed F core or policy-change payload, DSSE PAE,
Ed25519 signature, exact canonical payload bytes, key-purpose/tenant/time trust,
current epoch, and the independently resolved plan/artifact/baseline/candidate/
approval hashes. It returns an opaque `VerifiedGrant` for the executor journal.
The verified object retains the exact signed grant and typed rollback authority,
including its profile, scope, baseline, artifact and validity bounds. Native
adapters must resolve those immutable objects and verify actual observations;
a matching hash is not evidence of a kernel write. Generation consumption and
replay fencing are durable executor responsibilities.

`verify_recovery_grant` rechecks the signature, current trust and exact immutable
bindings against the signed rollback window. An expired dispatch window does not
become permission for a fresh apply: the native adapter still needs the persisted
operation, current generation, recovery scope/artifact and recovery CAS. The
ordinary acceptance/submission path retains its original dispatch deadline.

`verify_human_approval_set` binds immutable approval evidence to the exact plan
and requirement hashes, current epoch, expiry, role profile and independent human
count. The caller must implement `ProofVerifier` using actual WebAuthn verification
and current credential/role/revocation state. No production proof adapter or
permissive default is provided. `sign_grant` likewise requires an independent
`AuthorityEvidence` adapter. These library functions are not an isolated signer
service and are not reachable through an HTTP signing endpoint.

`QuotaLedger` uses SQLite `BEGIN IMMEDIATE`, WAL, and FULL synchronous writes.
Root and project limits are checked in the same transaction: active leases,
concurrent deployments, rolling 24-hour issuance counts, distinct destination
assets and full approved lease seconds. The window is `(as_of - 86400, as_of]`.
UNKNOWN retains capacity. Historical cost is not refunded on release. The same
immutable reservation can be replayed only while still reserved; consumed and
released reservations cannot authorize another issuance. A backwards authority
clock refuses fresh reservations. The supplied timestamp and limit values must
come from the authority, not a client.

Local-owner [WebAuthn login](../../docs/passkey-login.md) is implemented separately
and does not authorize a plan. Remaining M03 work includes plan-bound WebAuthn
approval/current-role proof adapters, durable independent
signer jobs/trust ceremonies, signed grant/quota reconciliation, complete
PostgreSQL authority transactions, and process/key isolation deployment. SQLite
unit/race/reopen tests do not certify production crash recovery or privileged OS
enforcement. The separate [signed Linux lab](../../docs/signed-linux-execution.md)
uses clearly marked synthetic plan/approval and signing fixtures to test native
integration. It does not supply a production `AuthorityEvidence` or WebAuthn
adapter, and the local controller cannot dispatch those fixture grants.

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
and current credential/role/revocation state. No complete production authority
adapter or permissive default is provided. `sign_grant` likewise requires an independent
`AuthorityEvidence` adapter. These library functions are not an isolated signer
service and are not reachable through an HTTP signing endpoint.

`ApprovalChallenge` creates a closed immutable context for a policy/access plan
or a distinct authority-bootstrap subject. Separate domain-prefixed SHA-256
digests bind the exact canonical payload and a fresh 32-byte random nonce.
`begin_approval_proof` and `finish_approval_proof` recheck context, origin and
validity and use the real WebAuthn verifier. Finish returns an opaque
`VerifiedBoundAssertion` with original proof fields and the updated credential.
It does not check role ownership, commit `HumanApproval` or consume the challenge.
See the [approval proof guide](../../docs/policy-approval-proofs.md).

`AuthorityStore` supplies the durable plan-decision transaction in a separate
SQLite schema. Its trusted provisioning APIs record principal identities,
pinned credentials and scoped roles. A pinned credential must complete a
persisted signed possession ceremony before activation. Stored immutable plans
and approval requirements use locally computed canonical hashes. Challenge
issuance commits private state before returning options; admission rechecks
current records and atomically verifies, consumes, updates the credential,
retains original evidence and appends the decision and audit event. With an
independently pinned epoch/role-policy basis and canonical human enrollment,
that same transaction verifies distinct eligible reviewers and records an
immutable approval set and members. Rejections veto the immutable plan; current
reads recheck retained proofs and current authority without creating new sets.
Exact retries return the original decision and aggregation receipt. Retained proof verification uses the saved
pre-authentication credential and admission time while separately checking
present key identity, role and revocation. See the
[authority store guide](../../docs/authority-store.md) for trust, transaction and
review boundaries.

The challenge and proof modules use the default-enabled `approval-proofs` Cargo
feature. Native executor and lab consumers disable default features, keeping
these approval APIs and their WebAuthn/OpenSSL dependencies out of those builds.
Grant, recovery and quota verification remain available without this feature.

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
and does not authorize a plan. Remaining M03 work includes approval HTTP/UI,
production out-of-band enrollment and authority bootstrap, trusted plan/artifact
admission, independent signer jobs/trust
ceremonies, signed grant/quota reconciliation, complete PostgreSQL authority
transactions, and process/key isolation deployment. The store accepts plan
decisions only; it does not issue grants or turn its provisioning API into an
authenticated production service. SQLite unit/race/reopen tests do not certify
production crash recovery or privileged OS enforcement. The separate
[signed Linux lab](../../docs/signed-linux-execution.md)
uses clearly marked synthetic plan/approval and signing fixtures to test native
integration. It does not supply production `AuthorityEvidence` or a human
approval workflow, and the local controller cannot dispatch those fixture grants.

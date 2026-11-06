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

`register_reviewed_plan` additionally commits independently recomposed full
before/after state evidence with the exact plan, requirements and audit in one
transaction. Since schema 4 it retains immutable canonical evidence and validates its
bindings on read. The review service uses checked challenge/admission APIs that
require this evidence for approval inside the corresponding transaction. Legacy
plan registration does not create review evidence. This semantic verification
does not certify the original target observations, compiler artifacts or native
gate results and does not create dispatch permission.

Schema 5 adds independently pinned target transport keys and nonce-bound signed
metadata. Admission atomically consumes the challenge and retains exact proof,
receipt, current head and audit. Current reads recheck original signatures,
current pin/revocation and effective expiry; exact retries acknowledge history.
Durable per-target time fences also survive refused or expired reads. The local
`fw_authority_admin` executable explicitly initializes project namespaces, pins,
challenges, admits, reads and revokes targets without creating human approval or
signing authority. See the [target metadata guide](../../docs/target-metadata.md).
Existing databases require an explicit validated private-backup migration.

Schema 6 extends this with independently pinned lab references and purpose-scoped
observers. Reviewed plans compile into exact retained baseline/candidate
artifacts; signed observations bind the compilation, current metadata, expected
installation and prior target head. The authority recomputes readback
correspondence and retains negative or unknown evidence without an observed
state hash. A protected read-only service/UI presents historical versus current
eligibility. No result qualifies a native backend or issues a grant. See the
[native evidence workflow](../../docs/native-evidence.md).

Schema 7 adds [durable signing coordination](../../docs/signing-coordination.md):
atomic intent/generation/quota preparation, exact signed-result verification,
current-evidence rechecks and outbox finalization, fenced retries and conservative
UNKNOWN accounting. Independent root/project quota administration and read-only
readiness are available. Production preparation and workers remain blocked until
protected bootstrap, native qualification, build identity and signer deployment
exist. Successful mechanics are exercised only through private test witnesses.
Core access cost resolution preserves the full original requested duration and
destination membership. Fresh cost/readiness eligibility requires a complete
review and a current retained fixed window. Compatible legacy policies must fit
that window; creating its first interval checks every existing request binding.
Legacy canonical bytes and retained quota accounting stay unchanged. These
structural checks never open production core signing or dispatch. See the
[fixed-window contract](../../docs/core-access-enforcement.md).

The challenge and proof modules use the default-enabled `approval-proofs` Cargo
feature. Minimal consumers can disable it and exclude the approval APIs and their
WebAuthn/OpenSSL dependencies; grant, recovery and quota verification remain
available. The Linux executor and testlab currently opt into approval contracts
and include those dependencies. That choice does not expose an approval ceremony
or policy signing endpoint in the native driver.

Schema15 adds signed workload bindings and exact original envelope/delegation
staging, independently pinned purpose-specific keys, actual owner-bound WebAuthn
bootstrap proofs and DSSE bootstrap authorizations. Its initial local/Lab profile
uses one current activated owner; existing Team plan quorum does not supply
complete Team bootstrap governance. Authorization stays
`authorized_pending_target_confirmation`, with policy signing and dispatch false.
Initial bootstrap refuses a target that already has a protected signing head,
preserving its epoch/generation and issued or UNKNOWN obligations. Signed workload
claims still need independently resolved asset revisions and packet-identity
attestation. See the [bootstrap contract](../../docs/protected-signing-authority.md).

The separate Linux [`fw_signer`](../fw_signer/README.md) process verifies distinct
OS identities, protected key/database paths and kernel Unix peer credentials.
Reference-only bootstrap requests resolve genuine retained owner proof before
issuing exact DSSE; policy jobs retain current-authority, quota, original-window
and claim fences. Production policy resolution remains closed pending target
confirmation, qualified build/native evidence and policy-signer trust. A private
test witness exercises core grant mechanics without opening that production gate.

The follow-up adds explicit schema16 project approval-origin pins. Trusted local
pin/CAS/read APIs do not import trust from a caller origin or retained challenge;
legacy15 challenges gain separate NULL-origin classification only and their
original proof bytes never become current through a matching late pin. New
challenges bind the current revision. New workload/bootstrap registry admissions
use one authoritative signature; published F multi-signature shapes and old
history/primary verification remain intact. Shared gate codes and versioned
readiness describe missing authority with every policy permission false.
The new [isolated target-confirmation contract](../../docs/target-authority-confirmation.md)
retains actual confirmed predecessors and signed receipts without qualifying
release or production dispatch. Readiness v3 exposes current versus historical state.

The [PR27 follow-up](../../docs/pr27-follow-up.md) records High S-1 in the signer
wrapper's file-check lifecycle. SQLite's process-owned POSIX locks must not be
released by independently opening/closing its database/WAL/SHM in the same process.
The signer source now uses metadata-only checks and pre-SQLite pinned input
descriptors. New focused external-reader/termination/restart regressions pass;
their exact source and runtime evidence are recorded separately in the follow-up.
The prior passing suites did not cover that lifecycle, and SIGTERM tests do not
qualify host power-loss recovery.

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
and does not authorize a plan. A separate approval HTTP service and UI are
implemented. Remaining M03 work includes the complete production approval flow,
out-of-band enrollment and authority bootstrap, trusted artifact/gate
admission, independent signer deployment/trust
ceremonies, authenticated grant delivery/reconciliation, complete PostgreSQL
authority transactions, and process/key isolation deployment. Public store paths
accept plan decisions and development evidence but do not issue production policy grants. The
provisioning API is not an authenticated production service. SQLite unit/race/reopen tests do not certify
production crash recovery or privileged OS enforcement. The separate
[signed Linux lab](../../docs/signed-linux-execution.md)
uses clearly marked synthetic plan/approval and signing fixtures to test native
integration. It does not supply production `AuthorityEvidence` or a human
approval workflow, and the local controller cannot dispatch those fixture grants.

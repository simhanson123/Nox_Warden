# Durable policy approval storage

`fw_authority::AuthorityStore` records a signed decision about an immutable plan
in a separate SQLite database. It persists the challenge, current credential and
role checks, original proof, credential update, decision and audit transaction.
The controller still refuses policy approval and deployment HTTP routes. This
library does not provide an approval screen, signing service or host protection.

## Trust boundary

Use an authority-owned database such as `authority.sqlite3`, separate from the
controller database. Its schema identity rejects a controller or unrelated
database instead of adding authority tables to it. SQLite foreign keys, WAL,
FULL synchronous writes and a bounded busy timeout support local transactions.
WAL initialization retries only SQLite busy/locked responses, with a five-second
monotonic deadline; normal connections retain the five-second SQLite timeout.
Canonical bytes preserve evidence; normalized columns, foreign keys and unique
constraints enforce tenant, credential, membership and challenge relationships.
On Unix, opening also requires a private regular single-link database file in a
directory without group/other write permission. These checks do not configure
Windows ACLs or establish protected directory ownership and IPC.

The embedding authority must authenticate its callers and supply trusted tenant,
principal and clock values. Provisioning a principal, pinning a public key,
granting a role or registering a plan is a privileged library operation. These
operations are not exposed through the controller, and controller login records
are not imported as trusted authority records. A role string or credential JSON
submitted by a browser cannot authorize provisioning.

The provisioning API is storage machinery for a future trusted enrollment
procedure. It is not the production initial-owner or authority-bootstrap
ceremony. A separately named database under the same writable OS account does
not establish an independent security boundary. Protected ownership and ACLs,
separate accounts/processes, authenticated IPC and a signer inaccessible to the
controller remain required. The library does not protect against an attacker
who can replace the authority database or execute privileged provisioning calls.
There is currently no authority daemon or operator CLI exposing these methods;
the reproducible entry point is the library integration suite.

## Credential, role and plan lifecycle

An explicitly pinned credential starts pending. A separate persisted WebAuthn
authentication ceremony proves possession before activation. The authority uses
its own credential snapshot; registration or a controller session alone does not
activate an authority credential. Revocation retains the credential record and
its public-key tombstone. Within the same authority tenant, the same public key
cannot be pinned again under a different credential ID or principal, including
after revocation. Scoped role grants carry validity bounds and a membership identity;
revocation retains the original record. Security changes advance a project
revision and append audit evidence.

The credential key fingerprint binds its principal, RP, credential ID, algorithm
and public key. It excludes mutable counter and backup-state information so a
later valid assertion does not change key identity. Counter and credential
snapshot checks remain separate from fingerprint comparison.
An additional `public_key_fingerprint()` hashes the domain
`fw.webauthn-public-key.v1\0` followed by canonical DER SubjectPublicKeyInfo.
It excludes identity labels. A separate append-only registry enforces its
tenant-scoped uniqueness across active, pending and revoked credentials;
critical reads recompute both fingerprints. Equivalent coordinate encodings
therefore cannot bypass a public-key tombstone.
Imported keys must satisfy the supported key policy: ES256 with P-256, or RS256
with a 2048-bit odd modulus and a valid odd exponent. Padding a weaker modulus
does not satisfy that check; an algorithm label cannot admit a different curve.

This store accepts `add_access_lease` and `policy_change` plans. It retains the
full plan and approval requirements in canonical form, checks their closed
contracts and bindings, and derives the hashes itself. The admitted original
contracts are `f.plan/v1`, `f.policy-change-plan/v1` and
`f.approval-requirements/v1`, with bounds of 256 KiB per plan and 8 KiB per
requirements object. Checks cover normalized policies, local patch hashes,
tenant/target/lifetime references, all eight required gate records and the
Lab/Team/high-risk role profiles. Plan retirement is retained separately from
immutable plan bytes. Changing a plan or its approval requirements requires a
new immutable plan and a new challenge.

Shape and hash admission do not independently execute the compiler, repeat a
gate, authenticate a referenced artifact or establish that a target can enforce
the plan. Trusted plan admission and a future signer must resolve and verify
those referenced objects and current authority independently. A plan containing
`PASS` gate strings is not sufficient authority for a firewall write.

Authority-bootstrap manifests are supported by the lower-level challenge
primitive, but this storage slice accepts plan decisions only. It does not
produce bootstrap approval proofs, aggregate an `ApprovalSet`, count a quorum,
reserve signing work, issue grants or dispatch policies.

## Schema upgrade and private backup

Fresh authority databases use schema version 2. The stable family identity
`fw.authority-store/v1` and SQLite application ID remain unchanged. Opening a
populated version 1 database returns `MigrationRequired` without adding tables
or treating its keys as newly enrolled. The explicit maintenance operation is:

```rust,ignore
AuthorityStore::migrate_v1("authority.sqlite3", "private-backups/before-v2.sqlite3")?;
let store = AuthorityStore::open("authority.sqlite3")?;
```

Use a protected existing backup directory and a new backup filename. The library
holds an IMMEDIATE transaction against concurrent writers, copies the committed
WAL-aware database through SQLite's online backup API, verifies the backup and
fsyncs its private file and digest manifest before changing the source schema.
Backup files and manifests contain restricted authority data and stay outside
public logs and source commits. Restoring an old backup over live revocations,
credential counters or executor authority requires a separate recovery procedure.

The migration validates the exact known version 1 schema and credential
projections, computes public-key fingerprints for all records including revoked
ones, and commits the new registry, migration checksums and version switch
atomically. Duplicate key material or invalid retained records aborts the
migration without choosing or deleting a credential. The private pre-migration
backup remains available. Existing decisions, assertions, consumption records,
counters and audit rows retain their original bytes. A repeated migration call
on a valid version 2 database makes no new backup or state change. Foreign and
future versions, changed migration checksums and pre-existing backup filenames
are rejected.

## Issuance and atomic decision admission

Challenge issuance resolves the stored plan and requirements, active credential,
current scoped role and authority revision. It persists the exact challenge,
private WebAuthn state and registry snapshots before returning browser options.
The challenge binds the decision as well as the plan: an assertion for `reject`
cannot be converted into `approve`.

Decision admission uses a SQLite `BEGIN IMMEDIATE` transaction. It rechecks the
issued challenge and current authority records, verifies the real WebAuthn
assertion, then commits the following together:

- Original signed assertion fields, private proof state and pre/post credential
  snapshots, with the applicable credential and role records.
- Updated credential state and one-use challenge consumption.
- Immutable `HumanApproval` decision, exact-request idempotency result and audit
  event.

Failed verification does not successfully consume a challenge. Failure attempts
are retained and capped at ten per challenge or credential-activation ceremony,
so restarting cannot reset an exhausted challenge. Exhaustion makes that
challenge unusable; it does not create a successful decision. At most sixteen
unexpired, unconsumed approval challenges per principal and sixteen activation
ceremonies per credential may be outstanding. These storage bounds do not
replace caller authentication or a future service's abuse controls. Database
write failure rolls back the transaction. No signer or network operation runs
inside the admission transaction.

A credential update makes previously issued challenges using that old snapshot
stale for new admission. A changed project security revision also conservatively
requires a fresh challenge. This does not invalidate an already admitted proof
solely because its counter subsequently advanced.

An exact successful retry with the same challenge, idempotency key and assertion
returns the original decision with `replayed = true`, including after later
expiry or revocation.
It does not create another approval, advance a counter, add another success
audit event or renew validity. Different assertion bytes or an idempotency key
that conflicts with an existing decision are rejected. Returning an old result
is an acknowledgement, not a new authorization; a future signer must still
check present validity, revocation and role membership. A `reject` remains a
reject and cannot satisfy an approval quorum.

## Retained proof verification

A retained proof is cryptographically checked using the original pre-assertion
credential, stored challenge state and trusted recorded admission time. Using
the latest counter for that historical signature would reject legitimate old
proofs; using the current time as the original ceremony time would incorrectly
expire them after the five-minute challenge window.

Current authorization is checked separately: the immutable plan and decision
must remain valid, and the current authority credential and role must still be
eligible with the same pinned key identity. A later legitimate credential
counter increase does not invalidate the stored signature. Key replacement,
revocation or a stale role cannot be hidden by retaining old verification data.
The store must verify the saved evidence and its projections rather than trust
an unchecked `approved` flag or a client-supplied evidence hash.

This read uses a consistent SQLite snapshot. Its returned value does not reserve
authorization against a later revocation. A future signing transaction must
repeat current authority checks when it commits; this library does not provide
an `AuthorityEvidence` or `ProofVerifier` adapter that can bypass that step.

## Reproduction and independent review

Run from the repository root with the documented build prerequisites:

```sh
umask 0022
source scripts/dev-env.sh
cargo test --locked -p fw_authority --test authority_store
cargo test --locked -p fw_authority -p fw_webauthn
cargo test --locked -p fw_authority --no-default-features
bash scripts/check.sh
```

Record the exact reviewed commit and comparison base. A useful review report
includes severity, path/line, reproduction, observed result, security impact and
tests not run. Software-authenticator tests verify cryptographic and storage
behavior; they do not establish human consent or platform qualification.

`DecisionResult::decision()` and `RetainedDecision::decision()` expose the signed
`Approve`/`Reject` enum. Inspect this value when consuming a successfully stored
or verified decision; a rejection can be stored and verified successfully.

For authorization and cryptography review, examine:

- Authority provisioning versus controller login trust; pending activation,
  current credential/role validity and permanent revocation.
- Exact tenant/principal/plan/requirements/decision/role/RP/origin/time binding;
  ordinary login and bootstrap challenge separation.
- Concurrent admission and revocation, one-use consumption with zero-counter
  authenticators, altered retries and cross-tenant requests.
- Original pre-authentication state in retained proof verification, combined
  with current stable key identity, revocation and membership checks.
- Rejection handling and the absence of an unchecked path to a quorum or grant.

For storage and failure review, examine:

- Schema identity, migration, foreign keys, uniqueness, immutable records and
  canonical-byte/normalized-column agreement.
- Commit-before-response issuance and atomic proof/counter/decision/audit
  writes, including rollback after each injected write failure.
- Restart and simultaneous-connection behavior for exact and conflicting
  retries, failures, exhausted challenges and retired plans.
- Strict JSON bounds, malformed/unknown/duplicate fields and time boundaries.
- Reduced-feature native builds and documentation boundaries. A same-account
  database test is not a test of protected IPC or operating-system isolation.

See the [verification summary](../reports/README.md) for executed results and
the [implementation overview](implementation.md) for the remaining product work.

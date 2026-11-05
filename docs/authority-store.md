# Durable policy approval storage

`fw_authority::AuthorityStore` records a signed decision about an immutable plan
in a separate SQLite database. It persists the challenge, current credential and
role checks, original proof, credential update, decision and audit transaction.
With independently provisioned authority and human identity records, that same
transaction can complete an immutable `ApprovalSet` for the plan.
The controller still refuses policy approval and deployment HTTP routes. This
library does not provide an approval screen, signing service or host protection.
The separate [local review service](authority-review-service.md) provides its own
authenticated HTTP boundary and immutable review content; production isolation
and signing remain separate deployment requirements.

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
The independent review daemon exposes possession proofs and decisions, never
these privileged provisioning methods. Its explicit isolated example provisioner
is test-only machinery, not a production initial-owner bootstrap ceremony.

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
produce bootstrap approval proofs, reserve signing work, issue grants or
dispatch policies.

## Durable policy review evidence

`register_reviewed_plan` is a trusted local importer for general policy changes,
not a browser endpoint. Core access uses the combined importer described below;
the general importer rejects `add_access_lease` plans.
It uses the shared `fw_planner::PolicyReviewEvidence` verifier to recompose the
exact policy change from normalized full before/after StateIR. Tenant, target,
source/capability references, candidate size/hash, patch hash and semantic effects
must match the immutable plan. Serialization of plan plus snapshots is bounded
at 128 KiB before canonical allocation. Its opaque `VerifiedPolicyReview` result
cannot be constructed by supplying a client boolean.

One IMMEDIATE transaction stores the full plan/requirements, immutable canonical
review bytes and hashes, project security revision and required audit. Failure at
either evidence or audit insertion rolls everything back. Exact repeat imports
revalidate stored projections without replacing bytes or appending another audit
record. `policy_review_evidence` returns and revalidates the stored content in one
snapshot; missing evidence is distinct from corruption. Stored admission time
must fall after plan registration and before expiry, and cannot be in the future.

The independent review service imports its explicitly configured private files
into already registered, uniquely resolved current plans. Subsequent display and
approve requests read authority storage; removing the import files and clearing
their configuration does not remove admitted review evidence. The service uses
`issue_reviewed_challenge` and `admit_reviewed_decision`, which require durable
review evidence for new approving decisions inside the same database transaction.
A rejection remains possible without available review evidence, and an exact
retry acknowledges its original decision without renewing authority.
For core plans, source configuration can confirm an exact already-retained
review, but cannot import review authority without its original provenance and
fixed window through this general-plan path.

The low-level `register_plan`, `issue_challenge` and `admit_decision` APIs still
serve trusted embeddings and preserved evidence tests. They do not certify that
semantic review happened. Legacy plans are never assigned review evidence during
migration, and retained decisions do not acquire dispatch authority by migration
or later import. Neither the reviewed nor low-level API authenticates a compiler
artifact, repeats every gate, validates current target observations, reserves
quota, signs grants or dispatches firewall changes. Those checks remain required
at the future signer boundary; semantic review is a separate prerequisite.

## Device-authenticated target metadata

Target metadata uses an independent trusted-local provisioning boundary. The
`provision_target_metadata_project` method creates only a tenant namespace and
its audit genesis; it creates no human, role, authority basis, approval or signing
key. Repeating that initialization does not append another event. It permits
metadata maintenance without inventing a reviewer identity.

`pin_target_transport` accepts an independently established Ed25519 public key,
certificate fingerprint, target, platform and validity interval. These are trust
pins supplied by the privileged administrator, not the outcome of an authority
X.509 chain or revocation-registry check. They must not be copied automatically
from a controller response or a submitted report. The reporting agent separately
checks its actual enrolled certificate identity, key, fingerprint and validity
before signing. Deployment must establish how administrators independently
verify these values and protect authority administration.

An immutable organization-wide key registry prevents moving a key to another
target or project. Pin changes use an explicit expected-revision comparison;
renewing the same active key requires a new certificate fingerprint. Rotation
and revocation leave permanent key tombstones, including across restarts and
later attempts to pin the key for another target. Exact pin retries return the
original revision without extending its lifetime. Pin revisions invalidate old
challenges and current metadata.

`issue_target_report_challenge` persists a fresh 32-byte nonce and the exact
tenant, target, pin revision and key/certificate fingerprints. At most four
unconsumed, unexpired challenges for the current target pin may be outstanding.
Challenge deadlines are exclusive and clipped to the pin's validity and five
minutes. `admit_target_report` verifies the exact canonical portable capability
report under the pinned key and platform. Its measurement must be at least as
recent as challenge issuance; a newly admitted report cannot replace a newer
measurement. One IMMEDIATE transaction commits the one-use consumption,
immutable proof and receipt, current head and required audit event.

An exact successful retry returns the original historical receipt, including
after expiry or revocation. It never advances the head or renews validity.
`current_target_metadata` revalidates the full signed proof and stored column
projections at the original admission time, then checks the current pin,
revocation and exclusive effective deadline. The current head must match the
latest immutable report sequence, and the pin head must match the latest pin
revision; partial pointer rollback or cross-target transplantation is rejected.
The effective deadline is the earliest of report expiry, challenge expiry and
pin expiry. Both receipts and snapshots explicitly retain
`authenticated_metadata_only` / `unverified`: a device signature authenticates
the source of a claim, not its accuracy, native protection, installed policy,
gate success, approval or permission to dispatch.

For a known target, every metadata operation first persists a nondecreasing
observation time in a separate short transaction. Even an expired read or later
failed admission retains this clock floor, so clock rollback cannot revive old
metadata or challenges after restart. The mutation transaction rechecks that
floor to cover concurrent operations. This deliberate security-state write is
the exception to otherwise atomic admission rollback: failed proof/audit work
does not consume a challenge or insert a receipt, head or success audit event.
The embedding administrator must supply trustworthy times.

Individual challenge, pin, proof and receipt rows are bounded; target/revision,
expiry and sequence indexes keep current reads and admission bounded. Immutable
successful evidence and trusted-local issuance history are retained rather than
silently deleted or capped by a lifetime issuance quota. Long-running deployments
still need an authorized retention/archival maintenance procedure; no public
issuance endpoint or maintenance deletion operation is supplied by this slice.

## Recomputed compilation and signed lab observations

Schema 6 introduced explicitly provisioned development native evidence. Its local
maintenance APIs do not create a production observer, authority bootstrap,
compiler qualification or signing permission. Every compilation/observation
receipt and status response retains `production_qualified:false` and
`dispatch_allowed:false`.

`pin_native_references` records the full isolated Linux scope, management
baseline, asset snapshot and unqualified capability bytes with a target-scoped
revision and lifetime. Reference updates use expected-revision CAS; withdrawal
is retained separately. The compiler accepts only its existing loopback lab
profile. Its `fw.isolated-lab-capability/v1` reference hash remains distinct from
the independently authenticated `f.target-capability/v1` metadata report.

`register_native_compilation` requires a current retained policy review, reference
pin and signed Linux/nftables metadata. It reconstructs both full baseline and
candidate artifacts, checks exact immutable plan bindings including its candidate
artifact hash, then rechecks input revisions, review and metadata inside the
committing transaction. Compilation bytes, historical receipt, current plan head
and mandatory audit commit together. Repeating the same current input tuple
returns its original receipt without renewed validity. The deadline is the
minimum of the plan, reference pin and metadata deadlines; metadata refresh
requires explicit revalidation and produces a new retained receipt.

`pin_native_observer` establishes a separate Ed25519 key purpose. Observer keys
have organization-wide target/project ownership and permanent revocation records.
Transport and observer key registries reject reuse in **both** directions,
including after rotation or revocation. Renewing a still-active observer pin is
an explicit CAS operation. A purpose label alone does not isolate a producer
process or establish that its signed capture came from the actual kernel.

An observation challenge binds the current compilation, separate metadata
receipt/report hashes, observer/reference revisions, immutable plan epoch and
generation, baseline state, artifact role, exact installation and expected
previous observation receipt hash. It carries a fresh random nonce, lasts at
most 300 seconds, and is clipped to compilation/observer validity. At most four
live challenges exist for the current observer pin. The actual collection command
and transfer channel are separate from these privileged storage APIs.

Admission revalidates current pins, compilation and target-global head, verifies
the real signature, reconstructs the installation and recomputes correspondence
with the signed raw nft capture. Challenge consumption, proof, receipt, next head
and audit commit atomically. A valid signed `mismatch` or `unknown` is retained
without an observed state hash; it does not fall back to an older matching
capture. The next challenge authenticates the predecessor receipt, which current
reads verify through one bounded predecessor lookup rather than recursively
loading all history. Epoch/generation and observation time cannot regress.

Exact retries acknowledge the original history even after expiry/revocation;
they do not restore present eligibility. `native_evidence_status` revalidates
retained compilation/proof/projections at the original admission time and
separately reports current validity. It exposes only bounded hashes, times,
comparison and provenance, never raw capture bytes. The selected plan's latest
retained observation remains visible after another plan advances the target head,
with `current:false` and `OBSERVATION_STALE`. A separate indexed lookup retrieves
that historical proof and revalidates it in full. `observation_head_hash` always
identifies the actual latest target-global receipt for CAS, and only that receipt
can be current. A plan with no observation returns `OBSERVATION_MISSING` even if
another plan owns the global head. Expired and retired plan evidence also remains
visible as historical, with `current:false`.

Native operations share the durable per-target observation clock. A failed or
expired request may advance that fence before the main transaction, preventing
rollback from reviving old evidence; proof/head/audit writes remain atomic.
References/receipts are bounded, compilation records are limited to 1 MiB,
challenges to 4 KiB, and signed proof envelopes to 3 MiB. Trusted-local history
retention has no silent truncation or permanent lifetime issuance cap. Authorized
archival maintenance and protected collector/IPC deployment remain future work.

## Original core-access cost provenance

Schema 9 introduced retention of the original `f.access-request/v1`,
`f.access-envelope/v1` and `f.delegation/v1` objects in a bounded
`fw.core-access-provenance/v1` record.
`register_core_access_provenance` is a trusted local operation against a previously
registered immutable core plan. Its verifier checks exact canonical hashes and
request, tenant, target, principal, workload, membership, scope and time bindings.
The explicit original request/revision and lease identity remain separate from
the signing coordinator's retry ID. Provenance v1 requires request revision 1.

`authority_core_access_requests` holds immutable original bytes and projections;
`authority_core_access_plan_bindings` attaches those same bytes to compatible
plans. The original request cannot change its root, lease or content. Lease IDs
are unique within an organization and request idempotency keys within a tenant,
preventing a new request ID from aliasing an already retained request. A new plan
attachment, security revision and audit entry commit atomically. Exact retries
return retained status, including after expiry or retirement, without appending
audit or renewing validity. New attachments require a current plan and inputs.
Update/delete guards preserve both tables. Separate `BEFORE INSERT` guards
reject collisions on every original request identity and on an existing plan
binding before SQLite applies `INSERT OR REPLACE`; replacement cannot silently
delete retained evidence when recursive delete triggers are disabled. Exact
application retries read the existing record instead of inserting a replacement.

`read_core_access_provenance` rechecks canonical bytes, hashes and every stored
projection; malformed evidence returns an error. Its bounded status omits the
original purpose, workflow and scope. Historical evidence remains readable with
`current:false` when the plan or inputs are no longer current. `current` is a
binding-lifetime observation, never approval or permission to sign or dispatch.
Both permission fields remain false. See the [local CLI guide](core-access-provenance-cli.md).

Cost derivation uses the full original requested duration, retained lease ID and
sorted destination set, and independently checks that the configured quota root
matches the delegation root. A shorter remaining plan window cannot lower that
cost. This existing provenance-v1 behavior also permits compatible shifted policy
windows within the original inputs' validity. Those records remain valid cost
history; they do not qualify for the stricter reviewed-core profile below.
Import does not authenticate envelope/delegation approval hashes or the
referenced workload, and does not create quota pins, native qualification,
approval sets or grants. Complete core signing and protected production authority
remain separate requirements.

## Reviewed core access and one absolute window

`register_reviewed_core_access_plan` atomically retains a closed original
`f.plan/v1` plan, requirements, full `PolicyReviewEvidence`, original provenance
and a `fw.core-access-lease-window/v1` sidecar. The shared review keeps its
existing `{before, after}` wire shape. Its core verifier recomposes normalized
requested policies against the complete baseline, preserving denies, unrelated
allows, associations and tombstones, and checks exact state, patch, policy and
semantic-effect hashes. Unknown or oversized semantic proofs are refused.
New associations must bind the request, one structural lease ID and the
recomputed `f.policy-authority-basis/v1` digest. The core plan itself has no
lease-ID field; retained original provenance supplies that identity binding.

The closed window is at most 4096 bytes and binds tenant, target, original
request ID/revision/hash, provenance hash, lease ID and canonical UTC
`not_before`/`expires_at`. Every requested policy shares this exact `[S,E)`;
`E-S` equals the full original request duration of 60–86400 seconds. The interval
must fit the envelope/delegation intersection and the plan's declared workload
lifetime. These checks establish structural correspondence, not an authenticated
workload issuer or delegated approval. Scope may be narrowed, but this profile
cannot shorten, shift or extend the original fixed interval.

Schema14 adds `authority_core_access_lease_windows`. Plan, requirements,
provenance, window, review, security revision and mandatory audits commit in one
admission transaction. Failure rolls that admission back. Exact retry validates
retained bytes without replacing evidence or adding audit events. Another
compatible plan can bind the same original lease only with that same window.
Immutable identity/rowid guards reject replacement; complete retained validation
also rejects missing references or altered projections. Migration infers no
window or review for legacy cost-only provenance. Existing accounting retains
one reservation per lease and unchanged issued/UNKNOWN/unsigned-delivered capacity.

Window reads and admission independently persist the existing durable project
quota-clock floor, including before a quota pin exists, and respect relevant
original-root and target floors. This clock observation can commit before a
later admission refusal; it creates no quota pin, capacity, reservation, job or
executor generation. Once expiry has been observed, backward samples cannot
make retained evidence current again, including after reopening. Historical
verification uses the durable floor, while `checked_at` reports the actual
sample. `read_core_access_lease_window` returns verified historical status after
plan expiry or retirement, or `None` if that plan has no retained reviewed
window. `current` concerns only structural window/plan/time state.

The [administration guide](core-access-provenance-cli.md) describes combined
registration and output-loss recovery. The authenticated
`GET /authority/v1/plans/{plan_id}/core-access-evidence` route exposes bounded
window summaries with no original proofs or credentials. Existing passkey review
and native compilation/observation paths consume the retained core evidence;
baseline and candidate artifacts remain independently rebuilt and observed.
Readiness v1/v2 contracts are unchanged. `CORE_SIGNING_PROFILE_UNAVAILABLE`,
`signing_allowed:false` and `dispatch_allowed:false` remain explicit. See
[core-access enforcement](core-access-enforcement.md) for the separate Linux
execution profile with synthetic trust and remaining production dependencies.

## Schema upgrade and private backup

Fresh authority databases use schema version 14. The stable family identity
`fw.authority-store/v1` and SQLite application ID remain unchanged. Opening a
populated version 1–13 database returns `MigrationRequired` without adding tables
or treating its keys as newly enrolled. The explicit maintenance operation is:

Stop the authority service and its workers before migration, then restart them
with the new binary. Do not mix older running binaries with a migrated database;
schema11 strengthens retained history, audit and reference validation; schema12
adds nullable project-only quota roots. Schema13 makes full retained validation
mandatory at open and adds atomic audit/work bindings and independent accounting
membership checks. Schema14 adds immutable reviewed-core lease windows without
changing the published SQL001–013 or legacy provenance bytes.

```rust,ignore
AuthorityStore::migrate("authority.sqlite3", "private-backups/before-v14.sqlite3")?;
let store = AuthorityStore::open("authority.sqlite3")?;
```

Use a protected existing backup directory and a new backup filename. The library
checks that source, backup, manifest and SQLite `-journal`/`-wal`/`-shm` paths
do not overlap before opening the source. Every destination name, including its
manifest and sidecars, must be unused; existing files or final symlinks are
rejected without modifying them or creating an orphan backup. This path preflight
also runs for an already current schema: its backup directory must exist and all
destination names must remain unused even when no copy is needed.
Maintenance source/backup/manifest basenames must be ASCII; Unicode parent
directories remain supported. ASCII names compare without case within the same
Unix directory identity, including directory aliases. Without a native directory
identity adapter, non-Unix platforms conservatively reject matching basenames
across directories as well. Migration qualification here is Linux only.

The library holds an IMMEDIATE transaction against concurrent writers, copies the committed
WAL-aware database through SQLite's online backup API, verifies the backup and
fsyncs its private file and digest manifest before changing the source schema.
Backup files and manifests contain restricted authority data and stay outside
public logs and source commits. Restoring an old backup over live revocations,
credential counters or executor authority requires a separate recovery procedure.

An abrupt exit during backup creation can leave a private backup file with an
empty or incomplete manifest. Such a pair is not a verified recovery backup.
Keep the original database and incomplete pair for inspection and retry migration
with a different, unused backup basename. Destination preflight deliberately
refuses to overwrite that pair; the program does not silently delete it or reuse
an incomplete manifest. Only a successfully completed, validated backup/manifest
pair establishes backup completion. Do not restore the incomplete copy over the
source or remove source WAL/journal files to force a retry.

The migration validates the exact known starting schema and credential
projections, computes public-key fingerprints when upgrading version 1 records
including revoked ones, and commits the new registries, migration checksums and version switch
atomically. Duplicate key material or invalid retained records aborts the
migration without choosing or deleting a credential. The private pre-migration
backup remains available. Existing decisions, assertions, consumption records,
counters and audit rows retain their original bytes. A repeated migration call
on a valid version14 database makes no new backup or state change. Version13
requires an explicit backed-up upgrade. Opening version14 and current-version
maintenance compare checksums and the exact known object inventory, including
autoindexes; optional sqlite_stat1/stat4 tables require exact structural metadata.
Neither sqlite_-prefixed objects nor lookalikes such as sqliteX_hidden are exempt.
Removing or replacing a guard, or adding an unexpected object, causes rejection
even if the stored version and checksum rows remain unchanged. Foreign and
future versions, changed migration checksums and pre-existing backup filenames
are rejected. The version 3 step never invents a current epoch, role policy, human mapping
or approval set from historical plans and decisions. Original pre-aggregation
retries return `NotEvaluated`. `migrate_v1` remains a compatibility alias for the
explicit maintenance operation. The version 4 step adds an empty immutable
review-evidence table; it never synthesizes semantic proof from historical plans
or approvals. Version 5 adds empty target key, pin, revocation, challenge,
observation-clock and metadata evidence tables. It never imports controller
trust, invents target reports or grants existing approvals dispatch authority.
Version 6 adds empty native reference/observer registries, compilation records,
challenges and observation history. It preserves prior target metadata without
inferring observer trust or qualified baseline evidence. Version 7 adds empty
signing intents, jobs, results, target generation heads, independent quota
registries, reservations, work transitions and dispatch outbox records. It
preserves prior evidence without inferring signer authority, a generation, quota
configuration or dispatch permission.

Version 8 preserves the deployed version 7 migration and checksum. It validates
existing quota reservations against retained immutable work, issuance and delivery
evidence before seeding the new transition history and installing projection
guards. A released reservation without matching cancellation evidence is rejected;
elapsed time never supplies that evidence. A known-schema database with
inconsistent retained state is backed up first, then the migration fails and rolls
back, leaving the original source state and the validated private backup available
for investigation. An unrecognized schema or physically corrupt SQLite database
is refused before creating a backup; physical validation precedes any rebuild so
maintenance cannot silently repair a corrupt accounting index during upgrade.
Migration does not rewrite original proofs, receipts, audit bytes or signer trust.
Version 9 preserves migrations 001–008 and adds empty immutable core-access
request and plan-binding tables. Existing version 8 evidence and signing history
remain unchanged. Migration cannot invent the original request, root, lease or
full duration from old plan windows or approvals. Registration must subsequently
supply the original objects through the separate trusted local boundary.
The new tables reject updates, deletes and insertion conflicts on every retained
identity, including SQLite row IDs. These insertion guards also block `REPLACE`
when recursive triggers are disabled; replacement cannot silently remove an
original request or plan binding. Exact library retries compare retained bytes
before insertion and do not append another audit event.

Version 10 preserves migrations 001–009 and validates bounded legacy work
histories before installing work-event/head/delivery guards and accounting
indexes that include every `active` reservation. Revisions, allowed transitions,
claim identity and latest-head agreement must be consistent. Delivery insertion
requires a claimed dispatch head. Any prior UNKNOWN dispatch event prevents
accepting a reservation relabeled `issued`, including when the latest dispatch
head has been re-claimed. Invalid known-schema history aborts the upgrade and
leaves the source and validated private backup intact.
Validation permits at most 192 work events per job phase. Older histories from
before the heartbeat cap may exceed this bound and cannot automatically upgrade;
the same source/backup preservation applies. Migration never trims historical
events, rewrites their state or invents claims to fit the current state machine.

The upgrade preserves original proofs, receipts, canonical BLOBs and physical
`dispatch_slots` projections, including legacy zero values on `active` rows.
Effective accounting and held-status reads retain one dispatch slot for every
issued reservation. An unsigned `delivered` record cannot return capacity or
resolve execution uncertainty. Migration invents no authenticated delivery
receipt; such verification and release remain future work. The live accounting
path also checks the full defined quota/work guard set against cached canonical
SQL. These integrity checks do not protect against coherent replacement of the
entire authority database and its trust records.
See [durable signing coordination](signing-coordination.md).

Version 14 preserves migrations 001–013 and adds an empty immutable window table.
Existing cost provenance, plans, approvals, quota reservations and native history
retain their original bytes; no historical activation/expiry, semantic review,
completion or signing authority is manufactured. Legacy provenance without a
reviewed window remains readable through its original API. Current open and
maintenance validation also replays retained reviewed-core/window bindings.
Populated schema13 migration regressions reconstruct the released schema around
genuine old-API rows; they are not newly executed old-binary fixtures.

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
- A completed immutable `ApprovalSet`, its exact members and current head when
  eligible reviewers satisfy the independently configured authority policy.

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
reject and cannot satisfy an approval quorum. The original typed `aggregation`
receipt is returned unchanged, even if the current set is no longer valid.

## Audit chronology and verification

Every new audit append checks the indexed latest event against the tenant's
stored head, canonical bytes and column projections. Its timestamp must be at
least the previous event's timestamp; equal timestamps are permitted. A backward
timestamp returns `AuthorityError::Time` and rolls back the enclosing mutation,
including credential/activation changes, security revisions and audit state.
Exact retries that return existing results do not append or advance audit time.

`AuthorityStore::verify_audit_chain(&mut self, &AuthorityTenant)` returns
`Result<Option<AuthorityAuditVerification>>`. The summary contains `event_count`,
`head_hash` and optional `last_recorded_at`. `None` means the tenant has no project,
head or events. A known empty project requires the zero-sequence, zero-hash
genesis head; a missing head, orphan event or nonempty missing history is an
error. The caller must authenticate the tenant before invoking this local API.

Verification streams bounded rows in one consistent read transaction, checking
exact canonical event bytes, all stored projections, tenant identity, hashes,
contiguous unsigned sequences, previous links, nondecreasing timestamps and the
final head. It retains constant-size chain state rather than collecting history;
oversized values are rejected before copying them into Rust-owned buffers.
The returned chain and its timestamp ordering remain tenant scoped. The live
connection gate first revalidates the database globally after an external commit;
corruption in another tenant can therefore refuse this diagnostic read before a
summary is produced. Valid tenants never share an audit clock. Unchanged local
writes retain their indexed-tail checks, while a changed database also requires
the complete validation described below. Legacy backward history then refuses
new appends rather than allowing a later event to conceal an older error.
Neither this verifier nor the connection gate rewrites or repairs history.
No schema migration is needed.

This summary verifies a local snapshot, not an external trust anchor. A writer
able to replace the entire database and recompute every chain value can produce
another internally consistent history. External checkpoints, trusted time and
protected OS deployment are separate requirements; this API does not fabricate
those guarantees or create signing authority.

## Independent reviewer aggregation

`provision_authority_basis` pins an authority-owned current epoch, role-policy
hash and validity interval. Neither is copied from a plan. An exact repeated pin
is idempotent; a changed pin requires a strictly greater unsigned 64-bit epoch.
`bind_human_identity` binds each verified principal to an independently established
canonical human ID. Known identity aliases must share that ID. These trusted
local APIs are not a signed bootstrap-manifest verification ceremony, and WebAuthn
user verification alone cannot establish that two accounts belong to two people.

Aggregation requires the plan's epoch and role-policy hash to match the current
basis. Its author and participating reviewers must have explicit human bindings;
missing enrollment produces `AuthorityUnavailable`, never a fabricated quorum.
For Team profiles, author aliases are excluded and each required role must be
filled by a distinct canonical human. Lab owner and high-risk profiles retain
their exact required roles. Candidate lookup first excludes expired, withdrawn
or currently ineligible decisions and known author aliases. It then selects the
smallest approval ID for each canonical human/required-role pair. Duplicate votes
and identity aliases therefore consume one meaningful candidate slot per role;
revoked keys and memberships consume none. Every selected representative still
undergoes original-proof and current-registry verification. Matching admits up
to 64 such candidates and three roles, including non-greedy role assignments.
An indexed SQLite query has a separate budget of approximately one million VM
instructions to bound work over retained history. Exceeding either bound rolls
back the new admission without truncating candidates or changing earlier votes.
The scoped query handler is removed on success, failure and unwinding.

The T4 `BEGIN IMMEDIATE` transaction rechecks every selected member's original
WebAuthn proof and current key, role, revocation and validity, then runs the closed
`f.approval-set/v1` verifier before storing canonical bytes and normalized members.
Selection, membership insertion, the set head, decision receipt and audits commit
with challenge consumption and the credential update. There is no authorization
snapshot passed from a separate read transaction. Foreign keys bind exact tenant,
plan, decision, credential, role and human identity; uniqueness prevents counting
one person or role twice. Set validity is bounded by every member, plan and basis.

A recorded rejection is a terminal veto for that immutable plan, including after
the rejecting credential or decision expires or is revoked. Further progress
requires a new plan. Late dissent, decision withdrawal, key/role revocation,
authority changes and expiry can invalidate a stored set without changing its
bytes. Fresh valid signed decisions can append a new immutable set after a prior
set becomes stale; they never rewrite it or renew an identical selection. The
current head advances without falling back to an older set.

The privileged local `revoke_approval_set` API withdraws the named immutable set
and atomically retains its tombstone, security revision and audit event. Repeating
the withdrawal does not rewrite its actor/time or add another audit event. It does
not withdraw another current set, the plan, or its member decisions; use the
separate decision-withdrawal and plan-retirement operations for those scopes.
Withdrawing an older historical set therefore leaves a different eligible
current head valid. This API has no HTTP route and does not establish that an
already applied network policy was removed.

Set withdrawal does not automatically produce replacement authority. While the
same deterministic eligible representatives remain selected, that already-used
selection stays `Stale`, even if another person submits a fresh vote. A different
selection requires relevant old decisions to expire or be withdrawn, or a new
eligible representative to be selected, followed by a fresh signed admission.
Original set bytes and historical admission receipts remain unchanged.

`approval_review_status` returns typed current status and an optional verified
set in one read snapshot. It never creates a set on GET, including after trusted
enrollment completes. `current_approval_set` returns only the current verified
set or `None`. A still-valid plan and authority basis returns `Pending` after old
member approvals expire, are withdrawn, or lose a current key/role, allowing
fresh signed reviews to create a new immutable set. An invalid plan or basis,
or an explicitly revoked current set, remains `Stale`. These results are review snapshots, not signing capabilities. The
signing transaction repeats current checks before granting authority; its public
production resolver currently remains closed.

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
authorization against a later revocation. The signing transaction must
repeat current authority checks when it commits; this library does not provide
an `AuthorityEvidence` or `ProofVerifier` adapter that can bypass that step.

## Reproduction and independent review

Run from the repository root with the documented build prerequisites:

```sh
umask 0022
source scripts/dev-env.sh
cargo test --locked -p fw_authority --test authority_store
cargo test --locked -p fw_authority --test authority_quorum
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
- Terminal dissent, distinct canonical humans, author aliases, exact current
  authority basis and absence of an unchecked path to a quorum or grant.

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

## Retained history and project-only quota

Schema11 rejects hidden-rowid, primary-key and alternate-key collisions before
SQLite replacement conflict handling, including FK OFF / recursive triggers OFF
writers. Audit heads can advance only to the exact next retained event using
unsigned64 sequence checks. Work events consume unique tenant/job/phase/revision/
kind/time audit bindings and project the head atomically. UUID syntax and retained
dispatch-created/delivery/preceding-claim times agree in SQL and Rust.

Migration links existing work events only to uniquely matching original audit
records. Matching requires a complete monotonic bijection within each tenant,
job and phase: equal counts, contiguous work revisions, strictly increasing audit
sequences, exact kind/time and valid canonical audit bytes. Two legitimate renewals
in the same second have one complete ordered assignment and can migrate. Missing,
surplus or unjustifiably ordered records are rejected with source and backup
preserved. It does not manufacture an old event, job, completion receipt or
refund. Current schema inventory compares exact known object metadata, including
autoindexes; optional ANALYZE tables have explicit structural checks. A reserved
SQLite-looking name never exempts an unknown trigger, table, index or view.

Since schema13, open and current-version maintenance run physical SQLite integrity,
reference graph, complete audit chain, quota transition/projection and retained
work/lifecycle validation within one consistent read snapshot. Existing-database
validation does not reserve the writer for that complete replay. Empty database
initialization and actual legacy upgrades remain serialized, with identity and
version rechecked after acquiring their write lock. Legacy migration is not an
online rewrite. Validation rejects hidden held heads, reservations without
intents and stale index contents even when all schema SQL has been restored
exactly. It never repairs corrupt indexes or rewrites history.

Each opened authority connection retains the `data_version` read inside its
successfully validated SQLite snapshot. Before a new transaction, a different
version requires full physical and retained validation again. A healthy write
from another connection also invalidates that cache; peer commits are not
implicitly trusted. Sensitive writer transactions first validate in a deferred
read snapshot, release it, then acquire their write lock and compare that
snapshot's version. On a change in that interval it drops the writer transaction,
clears the cached token and repeats deferred validation, for at most three total
acquisition attempts. It has not yet executed the requested operation's body.
Repeated changes exhaust the budget with the existing typed `Conflict`; the
caller may retry. Local taint, failed integrity and storage errors exit without
this retry. The bound limits attempts, not elapsed time: a contended call can
replay complete history three times. No new token is sampled after COMMIT and treated
as already checked. Failed validation leaves no reusable token.

Unchanged transactions on the same connection keep bounded reservation/head
accounting and scoped evidence checks, without a complete lifetime replay on
every admission. Nonpartial reservation state indexes include unsigned active
policy deliveries. Closed work-mutation audit kinds must have matching retained
events/bindings; unrelated intent/result/quota audit kinds remain independent.
Complete validation also checks work audits whose resource has no job. Normal
audit-first/event-second transaction prefixes are validated only when complete.

Retained signing-clock selection also occurs inside a validated read snapshot.
The request/intent/latest-job binding is compared again in the final validated
transaction; a concurrent selection change returns `Conflict` rather than using
an unobserved job. The private connection wrapper exposes no unchecked row-read
method. Clock observation still resolves the job's immutable reservation and
original root, and independently committed clock floors survive later diagnostic
or protected-authority refusal. Current project scope and historical job scope
remain distinct after configuration cutover.

Preparing an unsafe local schema/PRAGMA operation permanently invalidates that
connection's cached evidence; an independently validated reopen is required.
Production code exposes neither a raw connection nor hook replacement through
this private wrapper. This is a restriction on the authority's reachable API,
not protection against malicious code executing inside the process. SQLite's
change counter is a connection-local change detector, not a cryptographic anchor
or protection against arbitrary offline file replacement. An attacker able to
replace the entire DB can also replace its local audit chain; external anchors
and protected OS deployment remain outstanding.

Complete integrity verification still costs work proportional to retained
history. Cached prepared statements and reuse of already verified records remove
redundant work, but do not establish constant-time opening or a supported history
size. Read snapshots may keep WAL pages alive until verification ends. Measured
fixture sizes, runtime conditions and current limits belong in the verification
summary; no lifetime job ceiling or silent pruning is introduced.

Schema12 rebuilds quota pins, reservations and transition heads for nullable roots.
Only its dedicated maintenance connection disables FKs, before the transaction;
rollback/commit precedes restoration and readback of FK ON. Original rowids and
typed values, including canonical v1 bytes, are checked before commit. The full
expected guard set is derived independently, with null-safe identity comparisons.
Source version/checksums, private backup, graph, integrity and schema checks remain
mandatory; populated databases require explicit maintenance and retired old handles.
See [project quota](project-policy-quota-design.md) for cutover and shared-capacity
semantics. Rootless quota grants no OS privilege and opens no signer/dispatch gate.

The schema13 audit INSERT guard requires the exact unsigned successor and matching
previous hash, and atomically advances its head. A work-event INSERT consumes the
current unclaimed audit event and atomically inserts its unique binding and projects its
work head. Standalone bindings cannot be staged for later consumption, including
with foreign keys disabled. Migration013 installed these guards and indexes while
preserving SQL001–012; schema14 retains all published SQL001–013 unchanged.

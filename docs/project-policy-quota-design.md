# Rootless project quota: implementation preparation

Status: design preparation only; no rootless implementation or authenticated lifecycle qualification is claimed. Here **rootless** means general-policy quota without a delegation root, not running a firewall without OS privileges. Production signing and dispatch remain closed.

The inspected baseline is PR20 head `9e021b31171ae19ff8c9e7eba400d8dd4630a001`, schema10. The later user-supplied review reports Low findings N1–N7; this preparation does not claim to have independently reproduced or fixed them. Address that hardening before relying on its guards for rootless changes. It may consume the next migration and expand the guard set: assign the rootless migration number from the actual implementation baseline, and recalculate its complete schema/guard reference and dependency graph. Do not freeze future code to schema11 or 45 guards.

## Recommended storage and migration approach

Prefer nullable roots in the existing accounting graph over parallel rootless reservation tables. `authority_signing_intents.reservation_id` is mandatory and references the existing reservations table; a second table or union view cannot satisfy that FK. Parallel storage therefore requires further FK or signing-history redesign, while fake rooted placeholders violate the intended contract.

At schema10, the necessary table replacements are `authority_signing_quota_pins`, `authority_signing_quota_reservations`, and `authority_signing_quota_transition_heads`. Only project pins may have a null root. Null-root reservations must have no lease, zero lease seconds and zero active slots; their heads cannot carry a lease. Preserve all existing keys, uniqueness, FK, state, issuance and immutable-input constraints. Copy explicit columns **including hidden rowid** with `INSERT SELECT`; never deserialize/reserialize existing canonical pin, cost, snapshot or signing evidence bytes.

Schema10 has 45 signing guards, 15 triggers attached to or referencing these three tables, and a 16-table transitive incoming-FK closure. Those are historical observations, not future acceptance constants. N1/N2/N3/N7 hardening may add guards or dependencies. Inspect the actual post-hardening schema and recreate every affected object from compiled expected definitions, preserving strengthened audit, transition and replacement protections.

The known nullable changes are:

- `authority_signing_quota_transition_heads_insert`: use `r.root_id IS NEW.root_id` instead of `=`.
- The latest `authority_signing_quota_transition_heads_update`: use `NEW.root_id IS NOT OLD.root_id` instead of `!=`, retaining its hidden-rowid and immutable-identity checks.
- The latest-head predicate in `signing_quota::read_record`: use `h.root_id IS ?` instead of `=`.
- Audit all newly added predicates for SQL NULL behavior. Compare Rust optional roots as `Option` values and represent accounting scope explicitly as `Root(id)` or `Project`; never invent a sentinel root.

Preserve the current accounting-head `no_replace` guard and **UPDATE followed by conditional INSERT** membership advancement. Restoring the older UPSERT conflicts with replacement protection. Preserve the held-index predicate containing every `reserved`, `issued`, `unknown` and `active` row; do not restore the old lease-filtered `active` predicate.

Keep published migration SQL and historical schema digests unchanged. Construct an independent reference for the new current schema, including **all** expected live signing guards, and retain bounded SQL checks and full schema validation on open and migration fast paths. Adopt N6's eventual strengthened internal-object policy; do not reintroduce blanket trust for names beginning `sqlite_`.

## FK-safe maintenance procedure

Disposable probes started from a product-initialized schema10 database. On the product dependency's bundled SQLite3.50.2 (`rusqlite0.37.0`/`libsqlite3-sys0.35.0`), deferring FKs during parent replacement produced equal rows and an empty `foreign_key_check` but failed `COMMIT` with extended error787. Setting `foreign_keys=OFF` inside the transaction was ineffective. Disabling FKs **before** the transaction succeeded, preserving rowids/BLOBs, with FK enforcement restored afterward. Python SQLite3.53.1 reproduced this. These structural probes used representative BLOBs, not authentic signing histories; real fixture validation remains required.

1. Retain private-directory/path checks, durable private online backup plus manifest, FULL synchronous mode, known source migration checksums and exact source schema validation. Use a dedicated maintenance connection that is never returned as an `AuthorityStore`.
2. Outside any transaction set `foreign_keys=OFF`, read back zero, then begin IMMEDIATE and validate the source under the writer lock. Create the private backup before source mutation. Close/reopen long-lived authority handles for maintenance; a SQLite writer lock does not retire older application processes after commit.
3. Run required historical migrations and their strengthened work-history, quota, audit and lifecycle validation in the same transaction. Preserve proven legacy backfill rules and use retained event times, not migration wall time or unsigned delivery timestamps. Do not commit an intermediate schema during the requested upgrade or synthesize historical audit/provenance/completion authority.
4. Drop the affected guards, create replacement tables, copy rowid and explicit columns, drop old tables, rename replacements to the original names, and recreate expected indexes/guards. Do not rename the old parent first, because SQLite can retarget child FK definitions to the temporary name.
5. Before commit verify unchanged retained rows/BLOBs/rowids, global FK consistency, integrity, strengthened lifecycle/audit/transition consistency and the complete expected new schema. Record the new migration checksum and version atomically. No refund, clock advancement, approval or grant is invented.
6. On error roll back before restoring FKs; after success restore them after commit. Read back `foreign_keys=1` on every exit, keep the private backup after failure, and never expose a connection or report success with enforcement disabled. Do not clear deferred enforcement debt by toggling `defer_foreign_keys` off before commit.

Empty-schema bootstrap worked with FKs enabled in the probe; explicitly test that path against the final implementation. Reject populated replacement under FKs enabled. Legacy test reconstruction needs a reverse table rebuild, not just dropping additive objects: preserve genuine historical SQL and rowids, and refuse to downgrade fixtures containing null-root/v2 records to a schema that cannot represent them.

## API scope and unresolved cutover choice

Keep root quota pins mandatory-root; split project quota input from the current root-pin alias. Preserve old unversioned `PinRecord` and reservation/v1 codecs and bytes. Introduce explicit versioned records for project-only pins/snapshots, with strict version selection and all root metadata present together or absent together. Reject unknown versions/fields, v1 null roots, partial root references and rootless lease costs. Project-only policy cost is no lease, zero seconds, no destinations, zero active slots and one initial dispatch slot.

Project-only configuration, readiness, deadlines and lifecycle checks use the project pin and clock. Retained rooted records continue to use their stored root and project clocks. Core requests still require retained provenance, the matching root, both pins, original delegation ceilings and every existing signing/profile gate. A missing root must never select a generic core fallback.

**Resolve cutover semantics before implementation.** Current project root binding is permanent; merely making the input optional while forbidding `Some↔None` only supports new unrooted projects. It cannot produce legitimate mixed rooted/rootless obligations in one project. Recommended option: an explicit administrator-authorized, CAS-controlled project-pin revision can change `Some(A)→None`, while retaining A as a permanent historical anchor and preserving every pin, clock and obligation. Decide whether restoration is initially forbidden or allowed only to A; never permit a later B by looking only at the current null head. Alternative: new policy reservations select project-only scope independently of an existing rooted pin, which changes that pin's previous semantics and needs explicit design. Migration itself performs no cutover.

## Capacity and history invariants

`dispatch_slots` is the historical projection; `effective_dispatch_slots()` returns one whenever `issued_at` exists. Preserve this rule and `held()` for both record versions. Without an authenticated completion adapter, unsigned delivered/active records retain issued capacity, including policy rows with no lease and stored dispatch slots zero. Expiry, reopening and rolling daily windows do not release concurrent dispatch capacity.

One project scan must include all rooted and rootless obligations, with shared row/destination bounds; root scans include only their exact non-null root. Keep UNKNOWN sticky across later claims, preserve its history/projection check and keep the temporary `mark_unknown` intermediate bypass narrow. Cancellation releases only genuinely unissued work with the required retained evidence and audit linkage.

An isolated SQL probe retained protected head rowids and UPDATE/INSERT membership for rooted active, rooted UNKNOWN and rootless active rows: project effective slots were three and original-root slots two while raw dispatch slots summed to one. Replacement, rowid relocation, null-root identity mutation and old-form UPSERT were refused. Witness guards were temporarily bypassed only to isolate membership mechanics and then restored; those synthetic rows are **not** authenticated evidence or migration-valid lifecycle fixtures.

## Required acceptance coverage

- Real guarded rootless policy lifecycles: reserved→issued→unsigned active and issued→UNKNOWN→claimed→unsigned active; effective capacity remains held and second admission is refused before/after expiry, reopen and beyond 24 hours. Cancellation, timeout, unsigned delivery and root absence cannot refund issued capacity.
- Legitimate same-project rooted v1 and rootless v2 obligations share one quota and combined row/destination bounds, including old active policy records. Verify organization/project isolation, exact-root accounting and no budget reset on the chosen cutover path.
- Real historical upgrades, including schema7/8/9/10 and later supported hardening versions: renewed claims, UNKNOWN with later claims, unsigned active policies, expired unissued jobs, canonical snapshots and core provenance. Preserve every old byte and rowid; retain conservative capacity after reopen. Include prior-release binaries producing original databases where feasible, not only reconstructed head fixtures.
- Preserve and exercise N1–N7 fixes: transition continuity and replacement protection; audit-chain/head and transition-audit coupling; SQL/Rust identifier validation; retained timing rules; unexpected internal-named objects; FK-disabled rowid/alternate-unique replacement attacks. Never satisfy new guards by inventing old audit or signing authority.
- Remove/replace every current live signing guard and attempt rootless reserve/finalize. Include restored-guard history attacks, logical/hidden-rowid replacement, `UPDATE OR REPLACE`, null↔nonnull identity changes and intact work-sequence/delivery-claim enforcement.
- Force failures after copy, drop, rename, guard recreation, FK verification, version recording and commit; verify original source schema/version/rows and private backup. Cover crashes/reopen and multiple-process migration races. Verify FK enforcement and orphan refusal on normal post-migration connections.
- Fresh initialization, verified current-version no-op migration, exact historical/current digests and guard cache, genuine legacy-fixture reconstruction and failure before backup for unknown source schemas.
- Exact v1 reads/retries/hashes; strict new codecs; null-root project without a root pin; CAS races; missing/revoked/expired pins; monotonic clocks including refused operations; core rejection under project-only configuration; production signing/dispatch still closed.

Implementation touchpoints: `store/signing_quota.rs`, `store/signing_intents.rs`, current/new migration definitions and `store/migrations.rs`, admin project-pin input/output, legacy fixture reconstruction, quota integrity/history/work-guard/migration/readiness/CLI tests. Re-read these against the post-hardening baseline before coding. This note is self-contained; disposable probe files are not required to resume the design.

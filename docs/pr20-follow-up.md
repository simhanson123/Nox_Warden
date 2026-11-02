# PR20 review follow-up: open correction and acceptance matrix

Implementation baseline: PR20 head `9e021b31171ae19ff8c9e7eba400d8dd4630a001`,
merged as `6eb68a9251b76ac164f8efb0fa5ad5ded1336564`, authority schema10.
The [original external report](reviews/pr20-claude-review.md) is retained verbatim.
All N1–N7 are **open and unfixed**. Their Low severity is attributed to that report.
This handoff contains source assessment and one new public-API N2 reproduction;
it does not rerun the external reviewer's unavailable private probes.
Paths beginning `store/` below are under `crates/fw_authority/src/`.
Line numbers describe the fixed baseline and will move during implementation.

| Finding | External execution attribution | This handoff session |
| --- | --- | --- |
| N1 transition-history replacement | Claude directly reproduced | Source inspected; full lifecycle reproduction pending |
| N2 audit-tail removal | Claude migration subagent only | Independently reproduced with real public APIs; still unfixed |
| N3 mutation without audit | Claude and work-state reviewer | Source inspected; reproduction pending |
| N4 SQL/Rust worker UUID and partial event/head | Reported confirmed in combined review | Source inspected; reproduction pending |
| N5 legacy time-binding omissions | Claude migration subagent only | Source inspected; reproduction pending |
| N6 unexpected reserved-name schema objects | Claude binary reproduction; subagent effect probe | Source inspected; reproduction pending |
| N7 job/history disappearance with FK OFF | Claude migration subagent only | Source inspected; reproduction pending |

First reproduce the reported cases using real guarded fixtures and keep opposite
regressions. Implement coherent new schema/runtime protections, preserving old
migration001–010 bytes. Do not mark a finding fixed from documentation or a source
inspection alone. Missing original evidence must be rejected rather than invented.

## N1: retained quota transition replacement

Locations: `store/migration_008.sql:2–23,28–86`; `store/signing_quota.rs:694–700,747–760`; schema10's `migration_010.sql` protects transition **heads**, not the transition history table.

`authority_signing_quota_transitions` has a composite PK `(org_id,project_id,reservation_id,revision)` and hidden rowid. It has UPDATE/DELETE guards plus insertion-order/evidence guards, but no BEFORE INSERT collision guard. The order guard evaluates a valid predecessor before REPLACE deletes the conflicting old row. Current reads compare only the maximum revision and its current head; they do not prove a contiguous retained history beginning at revision0. This matches external N1's claimed sequence: genuine unissued job; signer cancellation event/head; insert a valid released revision1 at the revision0 rowid via INSERT OR REPLACE; update reservation projection; revision0 is lost.

Implement in a new migration, preserving 001–010: BEFORE INSERT reject both explicit hidden-rowid and logical PK collisions, regardless of conflict algorithm/recursive_triggers. Add bounded retained-history validation for gaps, missing genesis, projection/witness disagreement, ordering, and valid imported revision0 history. Do not invent removed rows on migration. Existing schema7 migration legitimately seeds `kind='imported'` at revision0 for already advanced states; preserve that supported case. Keep current immutable UPDATE trigger and schema10 protected-head UPDATE-then-conditional-INSERT path.

Acceptance: real cfg(test) guarded signing fixture, intact guards/FK ON/recursive OFF; show original replacement accepted before correction, refused after; compare all original transition rows, rowids, head, quota, audit, and reopen state. Cover PK, explicit rowid, INSERT OR REPLACE and UPDATE OR REPLACE; ensure normal reserve/issue/cancel/UNKNOWN/delivered transitions and migrated imported genesis still work. Missing historical rows in a legacy source must fail before committing the upgrade and retain valid private backup.


## N2: audit tail removal — independently reproduced here

Locations: `store/schema.sql:137–153`; generic audit UPDATE/DELETE guards in `store/migrations.rs:107–123`; `store/audit_log.rs:97–125,128–191`; audit writer `store/mod.rs:368–410`; genesis callers `store/provision.rs:36` and `store/target_metadata.rs:235`.

Fresh execution: `source scripts/dev-env.sh; cargo build --locked -p fw_authority` exited0; a standalone Rust probe linked the newly built library and used the public AuthorityStore APIs. It opened a private disposable schema10 DB, provisioned two distinct genuine principals at timestamps1700000000/1700000001, and verified two genuine audit events. A separate SQLite connection set FK ON and recursive_triggers OFF, kept every guard unchanged, then ran this tail rewrite on the disposable fixture:

```sql
-- Save the first row's sequence/event_hash as two BLOB parameters before mutation.
INSERT OR REPLACE INTO authority_audit
 (rowid,org_id,project_id,sequence,event_hash,previous_hash,kind,resource_id,recorded_at,canonical_bytes)
 SELECT (SELECT MAX(rowid) FROM authority_audit),org_id,project_id,sequence,
        event_hash,previous_hash,kind,resource_id,recorded_at,canonical_bytes
 FROM authority_audit ORDER BY sequence LIMIT 1;
UPDATE authority_audit_heads SET sequence=?,event_hash=?;
```

Observed: audit2→1, both principals retained, guard definitions identical, foreign_key_check empty, verify_audit_chain reports success with event_count1 on the existing store and after close/reopen. No fabricated hash/canonical bytes were used. The full probe exited0. The complete portable [probe source and commands](reviews/pr20-local-audit-repro.md) are retained in Git; no temporary log is needed to reconstruct this case. To reproduce permanently, add this public-API scenario to `tests/authority_audit.rs`, which already has private-directory and provision helpers.

Fix audit collision protection over hidden rowid, `(org_id,project_id,sequence)` PK and `(org_id,project_id,event_hash)` unique key. Protect audit-head hidden/logical identity and deletion; permit only valid genesis and an exact next event with its predecessor matching the retained head. Check BLOB u64 sequences without truncating them to SQLite's signed INTEGER. Keep canonical hash verification and monotonic event time in Rust; local guards cannot replace an external anchor against whole-database rollback.

Important integration: `provision.rs` currently uses INSERT OR IGNORE for an existing audit head. A strict BEFORE INSERT collision guard fires before IGNORE and would break retries. Change it to a checked existing-row path or INSERT WHERE NOT EXISTS while preserving concurrency/atomicity. The central audit writer already uses plain INSERT event then UPDATE head, so it need not use UPSERT. New audit guards do not match the current `authority_signing_` prefix; add the necessary audit guard dependencies to live protected-operation checks deliberately, rather than assuming current signing guard enumeration covers them.

Acceptance: unchanged-prefix tail replacement and head rewind must be refused; head DELETE, logical/rowid REPLACE, arbitrary UPDATE, cross-tenant transplantation, skipped/rewound sequence and mismatched hash rejected. Test empty genesis, real provision/activation/decision/signing append, same-time timestamps, exact retries, all write-failure rollback points, reopened chain verification and supported legacy migration. Keep external audit anchoring explicitly outstanding.


## N3: mutation-to-audit binding

`crates/fw_authority/src/store/signing_jobs.rs::write_head` (around 332–394) inserts the work event, inserts/updates its head, then calls `audit(...)` in the same application transaction. `store/mod.rs::audit` (around 368–405) computes canonical audit bytes, appends the event and updates its head. Existing application tests such as `audit_failure_rolls_back_claim_and_cancellation_with_quota` already cover transaction rollback on audit failure. The missing boundary is direct SQL: SQL guards do not require the corresponding audit event.

Design a non-reusable binding between each mutating work event (tenant/job/phase/revision/kind/time) and its exact audit record, including claim, renew, retry, cancel, finalized, dispatch-created, unknown and delivered paths. Merely finding any historical audit with the same job/kind is insufficient. Existing order writes audit last; adding a BEFORE trigger that expects audit first would break legitimate writes. Reorder or redesign mutation/audit projection atomically and check exact-retry/no-op behavior. Preserve all current issuance/UNKNOWN/capacity guards and application audit rollback behavior. Determine how legitimate legacy histories are validated without fabricating audit events or rewriting canonical bytes. Missing or ambiguous historical bindings need an explicit fail-closed migration policy.

An audit hash chain inside the same writable DB is not an authentication mechanism against a DB writer: the writer can also construct a syntactically valid audit entry. The attainable near-term property is that direct state mutation cannot occur without retained, uniquely linked audit evidence and cannot erase old history. External anchoring/protected storage and authenticated completion remain separate requirements. Do not promote a locally consistent delivered+audit pair into quota-release authority. The UI currently exposes current dispatch state; if the product must retain visible past UNKNOWN after a recorded delivery, add an explicit bounded history flag and API/UI tests rather than erasing the uncertainty history.

Acceptance: direct cancel/delivered mutations without audit rejected; wrong tenant/job/revision/kind/time audit and reused audit rejected; application success produces exactly one required audit per actual mutation; exact retry adds none; audit insertion/head failure rolls back work, quota, outbox and head together; issued effective dispatch slot remains 1 after all mutations/reopen/expiry.


## N4: canonical UUID and partial event/head writes

SQL `migration_010.sql` around line 22 checks only `length(worker_id)=36`. Rust `signing_jobs.rs::valid_head` calls `identifier`, which ultimately requires `Uuid::parse_str(s)` and `u.to_string()==s` (`src/lib.rs::uuid_ok`): lowercase canonical 8-4-4-4-12 hex shape. A 36-character invalid value can therefore enter via SQL but will fail subsequent Rust history reads.

Add the same canonical syntax restriction in the next migration's replacement trigger, preserving NULL rules for inactive states and all existing claim counters/deadlines/length limits. Do not invent version/variant restrictions that Rust does not impose. Test every hyphen position, non-hex, uppercase, 36-byte versus 36-character strings, embedded NUL and valid canonical edge UUIDs against both SQL and Rust.

The event-without-head half is separate. `write_head` intentionally inserts event before updating head, and `work_history` rejects `current != previous` around 283. An immediate BEFORE-event check requiring the new head already exists is incompatible with the normal protocol. Consider an AFTER-event authoritative head projection, or a rigorously enforceable transaction protocol, while preserving previous-head validation and no-replace guards. Do not claim the UUID check alone fixes incomplete event/head transactions; at minimum maintain fail-closed reads and explicitly document the DB-writer DoS boundary. Test legitimate multi-statement writes and a committed event-only transaction independently.


## N5: migration/runtime parity for retained time bindings

`migrations.rs::apply_v10` runs `validate_work_histories`, `validate_legacy_reservations` and `validate_retained_signing_lifecycles`; the latter uses retained MAX(work.updated_at), not wall time. That is the correct time source and must remain so.

Missing checks visible in source:
- `signing_jobs.rs::work_history` first-event branch (around 264–275) binds signer-created to job.created_at, but dispatch-created is not bound to outbox.created_at. SQL 010 enforces that equality.
- The delivered branch (around 246–254) checks the previous claim window against the event.updated_at but does not bind that time to delivery.recorded_at. SQL 010 requires equality.
- `lifecycle_status` (around 777–789) checks delivery hash/bytes and recorded time between issuance and the supplied observation time, but does not bind recorded_at to the actual immediately preceding claimed event's `[updated_at,claim_until)` window. SQL `authority_signing_deliveries_claim`, lines 94–102, does.

Create one consistent retained-history validator covering these correlations, used by ordinary reads and maintenance, with bounded historical queries. Prefer validating against the actual previous claim in the ordered history; do not select an unrelated later claim or refresh timestamps during migration. Preserve imported records byte-for-byte or reject them with the existing private backup.

Acceptance: genuine valid v8/v9/v10 states remain readable/migratable, including renewals, later claims, UNKNOWN and expiry; mutate each binding independently and reject migration with original version/rows retained plus valid backup; test inclusive claim start and exclusive claim deadline; add actual legacy-binary-created DB coverage where feasible (external reviewer used head-generated downgraded fixtures and explicitly did not run this stronger case). Keep migrations001–010 unchanged; introduce later schema SQL for changed guards rather than rewriting released migrations.


## N6: reserved internal SQLite object filtering

`migrations.rs::schema_digest` (around 140–153) excludes every row whose name begins with literal `sqlite_`. The normal SQLite CREATE restriction does not make that a trustworthy inventory rule after writable_schema/file manipulation. `signing_quota.rs::account` (around 868–881) verifies all expected named signing triggers individually, but does not reject additional trigger objects. Thus fixing only ordinary open/migrate inventory does not by itself establish the same check for an already-open connection.

Build expected object metadata from the independently initialized known schema and compare actual object inventory. Automatically generated indexes should be validated by exact expected name/type/table/NULL-SQL relationship, not accepted through an arbitrary `sqlite_autoindex_*` name prefix. If optional engine-created `sqlite_sequence` or statistics tables are permitted, enumerate the supported actual names and exact structural metadata needed for the configured bundled SQLite version; never allow `sqlite_stat*` as an unrestricted wildcard or allow a trigger merely because it adopts an internal name. Consider whether to include known autoindexes directly in the digest and handle optional statistics separately. Ensure oversized injected SQL remains bounded and every existing source-version validator and same-version migrate path applies the stricter policy. Add live unexpected-trigger detection where the claimed live integrity boundary requires it, without trusting definitions read from the attacked DB.

Acceptance: disposable DB writable_schema injection under reserved names is rejected on open, same-version migrate and legacy migration; include trigger, table, view, index and fake internal-name/type combinations. Test altered existing connection plus schema refresh for the live accounting path. Valid fresh DBs, expected autoindexes and explicitly supported ANALYZE/engine-generated objects continue to work. Preserve ordinary sqliteX/SQLITE9x rejection from F3. No host or user database should be used for these probes.


## N7: missing job with FK disabled

Locations: `store/migration_007.sql:11–50,76–140,179–201`; `store/mod.rs:127–185`; `store/signing_intents.rs:287`; `store/signing_quota.rs:694–700`; `store/migrations.rs:314–330,355–361`.

The affected durable tables lack BEFORE INSERT collision guards:

| Table | Identities in addition to hidden rowid |
|---|---|
| authority_signing_intents | PK `(org,project,intent)`; unique `(org,project,request)`; unique `(org,project,target,epoch,generation)` |
| authority_signing_jobs | PK `(org,project,job)`; unique `(org,project,intent)` |
| authority_signing_results | PK `(org,project,intent)` |
| authority_signing_quota_reservations | PK `(org,project,reservation)`; unique `(org,reservation)`; partial unique `(org,lease)` for nonnull lease |
| authority_signing_quota_usage | PK `(org,project,reservation)` |
| authority_signing_outbox | PK `(org,project,job)`; unique `(org,project,intent)` |

Include transitions/audit above in the same identity audit. Review adjacent pins, revocations, destinations, target/quota heads and clocks for the same retained-identity pattern; do not silently claim all durable tables are covered by fixing only the eight named report targets.

`AuthorityStore::open` enables and reads back FK ON, but current schema validation checks definitions/migration records without a foreign_key_check of already stored rows. Enabling FKs does not retroactively reject orphans written earlier with FK OFF. Quota reads validate reservation/cost/usage/head, while complete lifecycle migration iterates jobs; neither alone proves the global graph contains all jobs referenced by intents/work/outbox. This source structure supports the external disappearance finding; the full delivered/held attack has not been re-executed in this handoff session.

Fix all listed identity collisions before insertion, independent of FK/recursive_triggers settings; preserve immutable update/no-delete rules. Add deliberate detection of already damaged reference graphs at current open/maintenance and sensitive reads, including bidirectional intent↔job linkage and orphan work/outbox/delivery/membership. Bound work rather than adding an unbounded whole-database scan to each quota admission. Define upgrade refusal for pre-existing missing evidence, preserving source and backup; never create a replacement job or refund a held reservation.

Acceptance: reproduce with actual delivered/held fixture, FK OFF writer/recursive OFF, then open with normal FK ON; all rowid/PK/alternate-key collisions refused after fix, and previously orphaned source rejected. Compare canonical bytes, every original row, effective dispatch capacity, job visibility, audit and reopened lifecycle. Repeat FK ON/OFF × recursive ON/OFF matrix and normal exact-retry/issuance/cancellation flows.


## Reported flaky test and CLI diagnostic wording

External observations only: first full check exited101 in `fw_control::cli_auth::tests::delegated_cli_access_ends_on_logout_expiry_or_credential_revocation`, isolated test passed5/5, full rerun passed800+1+32 Rust and180 UI. Do not label the initial failure fixed or claim its cause has been proved.

Source gives another concrete timing hypothesis besides the report's 300-second freshness window: the test registers/authenticates `second-key` with `credential(..., now())`, then later issues its browser session using a new `now()` (`cli_auth.rs` around585–590). The store requires `authenticated_at <= credential.last_used_at` (`fw_store/src/passkeys.rs` around735–738). Crossing a one-second boundary can therefore make the fabricated test session inconsistent with the retained authentication time. Investigate a deterministic test clock or use the exact completed-authentication timestamp; do not weaken the production five-minute freshness or retained-proof checks. Reproduce the boundary deliberately, retain actual failure response code, then run isolated and full appropriate tests.

`docs/core-access-provenance-cli.md` around94–96 previously said tenant failures retain existing diagnostics. In `fw_authority_admin.rs`, malformed tenant identifiers fail at line274 with TENANT_REJECTED; syntactically valid but unavailable/unprovisioned tenant failures reached through the provenance operation are mapped at lines367/379 to CORE_ACCESS_PROVENANCE_REJECTED. The handoff corrects this documentation distinction; product behavior is unchanged. Preserve cross-tenant non-disclosure; no general error-detail expansion is warranted.


## Integration order and qualification

Reproduce N1/N7 fully and preserve N2's public-API test first; implement the new guarded schema plus current/legacy integrity checks with the other PR20 findings. Keep old migration hashes unchanged. Then rebase the prepared rootless project-quota design onto the resulting schema: the next version may be security schema11 with rootless schema12, so no new session should assume rootless must use11. All existing issued/UNKNOWN/unqualified-delivery effective capacity remains held. Public signing/dispatch remain closed; this is local persistence hardening, not protection from a hostile OS administrator or full-file replacement.

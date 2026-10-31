# Catalogue and request pagination

The controller exposes bounded snapshot pages for `/api/v1/assets`, `/services`,
`/access-requests`, `/operations`, `/targets` and `/enrollments`. Responses retain
`data` as an array and use the existing read envelope's `next_cursor`. The default
limit is 50 and the maximum is 100; explicit values outside 1–100 return HTTP 400.
Rows are ordered by original resource creation time, then stable resource ID.

Start with, for example, `/api/v1/assets?limit=25`. Continue with the returned
opaque cursor until `next_cursor` is null. Subsequent requests may omit the limit
and filter, or repeat their original values. Changing either requires a new
first-page request. A new snapshot includes later additions and revisions;
continuing an old snapshot retains its original membership and object revisions.
The list revision stays fixed throughout that snapshot.

Each HMAC-SHA256 cursor binds the current tenant, authenticated principal and
session, route, eligibility filter, page size, snapshot revision, fixed sort and
last key. Its original 900-second deadline does not slide when another page is
read. Expiry returns HTTP 410 `CURSOR_EXPIRED`. Invalid or mismatched cursors
return HTTP 400 `INVALID_INPUT` with a stable detail reason. Authentication and
credential revocation checks run again on every page. The process-local key
invalidates old cursors on controller restart; a new authenticated read is then
required. Audit pagination retains its separate cursor schema and semantics.

Pages reserve at most 192 KiB for their data array, leaving room inside the
256 KiB response boundary for the envelope and cursor. If the next row would
exceed that budget, the response contains fewer rows and a continuation. A single
oversized row fails with HTTP 413. A partial page never implies end of collection;
only a null `next_cursor` does.

The CLI returns one bounded envelope per invocation. Its list commands accept
`--limit` and `--cursor`; the cursor is passed through the URL query encoder and
cannot alter the route or add parameters. Options are validated before opening
the session file or contacting the controller. For example:

```sh
fw_cli assets --limit 25
fw_cli assets --limit 25 --cursor '<next_cursor from the previous response>'
```

The same options work for services, requests, operations, targets, enrollments
and audit. They are rejected on health, status, capabilities and login commands.
The next invocation must use the same authenticated session; a cursor alone is
not an authentication credential.

## Current selection eligibility

The implementation query extension `eligible=true` is available on assets,
services and targets for form selectors. Asset and service records must still be
active. Target selection and active service writes share the same server checks:
a real enrollment, an unrevoked currently valid certificate, and a current
capability report whose `checked_at <= now < valid_until`. A bare local target
placeholder or registration without a report cannot become a service target.
There is no invented heartbeat threshold. The shipped agent emits reports with
five-minute validity; the signed-in operator can request another report.

Current retirement, revocation and expiry can remove a member from a previously
issued selector snapshot. The cursor still advances, including when a page is
empty. Clients must continue when a non-null cursor exists. An updated report
cannot revive an expired report inside an old target snapshot; start a new
snapshot to see it. Ordinary target/enrollment lists preserve the snapshot and
conservatively display an invalid current credential or expired selected report
as `quarantined`. Stored immutable asset/service hashes are never rewritten to
represent current eligibility.

These checks describe catalogue suitability. A device's authenticated capability
report is not independent qualification or installed firewall evidence. Target
views expose the actual `enforcement_backend` and nullable `observed_at`; they do
not invent qualification fields. Report refresh commits a distinct monotonic
outbox revision with its immutable capability, audit and projection. Exact
current-report retries create no additional report or outbox event.

## Storage and validation

SQLite migration 6 creates a discardable projection cache. Every source mutation
and its content-hashed projection commit together. Existing rows are verified
and backfilled in chunks of 128 IDs inside one migration transaction; an invalid
source aborts the entire migration. Original catalogue revisions, capability
reports and audit evidence remain immutable.

Cache cleanup retains all versions within the 900-second cursor window plus the
last older version of each resource. That predecessor is required by live
snapshots predating a change. Cleanup runs on collection reads and changes;
inactive tenants do not accumulate new cache history. A persistent per-tenant
clock highwater rejects clock regression after pruning. The store independently
rejects expired snapshots, so direct callers cannot read incomplete pruned
history by bypassing HTTP cursor validation. This is bounded historical cache
retention, not a retention policy for original evidence or current resources.

Regression suites cover more than 100 rows in every collection, same-second
changes, byte-bound continuation, cursor tampering/scope, expiry/pruning, clock
rollback, migration rollback, current target suitability, and concurrent report
refresh with exact retry behavior:

```sh
cargo test --locked -p fw_store -p fw_control -p fw_cli
python scripts/smoke_cli.py
```


The real browser check (`scripts/smoke_catalogue_navigation.py`) writes bounded
`stage`/`failure_stage` and category codes when a check fails. It does not retain
Playwright assertion text, page input values, private paths or raw controller
logs in its report or console summary. Locator assertions have an explicit
15-second timeout; asset mutation waits for the actual successful POST response
and the loaded detail heading before returning to the registry. These waits
express readiness, not evidence that a timeout caused any previous failure.
The disposable controller is health-checked and its process/browser are closed
on failure. Use a separate `--port` for concurrent smoke runs. Diagnostic unit
regressions run through `scripts/check.sh` and can be invoked separately with
`python -m unittest discover -s scripts -p test_catalogue_smoke_diagnostics.py`.

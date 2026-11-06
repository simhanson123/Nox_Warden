# Retain core-access reviews, original cost and fixed windows

`fw_authority_admin` can atomically register a reviewed `f.plan/v1`
`add_access_lease` plan with its original request, envelope, delegation and one
absolute lease window. The existing provenance-only commands can still bind
original cost evidence to an already registered plan. Both are trusted local
imports into the protected authority database. The administrator must obtain
those original objects independently
and protect the database and input files from the controller OS user.
Controller enrollment, a browser session and possession of an object hash do
not authorize this command.

The retained evidence identifies the original request and revision, delegation
root, lease and full requested duration. A plan that permits only the remaining
part of a lease still carries the original duration as its cost. For example, a
3,600-second original request costs 3,600 seconds even when the plan's policies
cover only the final 1,800 seconds. Destination IDs are retained as a sorted,
unique set. Callers cannot supply a reduced duration or independent quota total.
That existing provenance-v1 behavior permits compatible shorter or shifted
policy windows while no fixed window has been retained. Once there is a window,
provenance-only policy intervals must stay inside it. First-window admission also
checks every existing binding; an out-of-window legacy binding rejects the whole
admission and preserves the old rows. The combined reviewed profile below
requires every requested policy to use the same full-duration fixed interval.
New live cost/readiness requires the plan's retained full review and window;
legacy full-duration cost history and existing reservation accounting remain
readable and unchanged. Issued, UNKNOWN and unsigned-delivered work still holds
capacity. A legacy plan can gain the reviewed profile through the full combined
validation; provenance import alone does not qualify it.

This checks immutable object binding and bounded scope and time consistency.
It does not verify the envelope or delegation's approval signatures, authenticate
the referenced workload, prove human approval, qualify a production backend, or
create a grant. Approval hashes are references, not cryptographic evidence of
authority. Both `signing_allowed` and `dispatch_allowed` remain false.

## Register a reviewed core plan and its fixed window

Use `register-reviewed-core-access-plan` for full-state core review. The older
general `register-reviewed-plan` command rejects core access plans. Supply one
closed JSON object of at most 512 KiB:

```json
{
  "schema_version": "fw.reviewed-core-access-plan/v1",
  "plan": {},
  "requirements": {},
  "evidence": {"before": {}, "after": {}},
  "provenance": {},
  "window": {}
}
```

The empty objects above are placeholders for the complete closed core plan,
approval requirements, full before/after StateIR, original
`fw.core-access-provenance/v1` and window. They are not a valid fixture. The
provenance contains the unchanged original `f.access-request/v1`,
`f.access-envelope/v1` and `f.delegation/v1` objects described below. Unlike the
provenance-only command, combined registration retains the plan and requirements
in the same transaction as its evidence.

The closed window object contains these fields:

```json
{
  "schema_version": "fw.core-access-lease-window/v1",
  "org_id": "ORG_UUID",
  "project_id": "PROJECT_UUID",
  "target_id": "TARGET_UUID",
  "request_id": "REQUEST_UUID",
  "request_revision": 1,
  "request_hash": "sha256:ORIGINAL_REQUEST_DIGEST",
  "provenance_hash": "sha256:ORIGINAL_PROVENANCE_DIGEST",
  "lease_id": "LEASE_UUID",
  "not_before": "2026-11-05T12:00:00Z",
  "expires_at": "2026-11-05T13:00:00Z"
}
```

Replace the symbolic IDs and digests with independently prepared values. The
window is bounded to 4096 bytes and uses canonical UTC timestamps. Its interval
`[S,E)` must equal every requested policy lifetime, have the full original
requested duration of 60–86400 seconds, fit the envelope/delegation intersection
and end within the plan's declared workload lifetime. New associations bind the
same request and lease and the recomputed `f.policy-authority-basis/v1` hash.
The original core plan has no lease-ID field; the retained provenance/window
supplies that binding. The review independently recomposes the complete baseline
and candidate, including existing denies, unrelated allows and retained state.
See [core-access enforcement](core-access-enforcement.md) for exact semantics.

```sh
umask 077
target/debug/fw_authority_admin register-reviewed-core-access-plan \
  --database authority/authority.sqlite3 \
  --org-id ORG_UUID --project-id PROJECT_UUID < reviewed-core-access-plan.json
```

Registration returns a bounded `fw.core-access-lease-window-status/v1` with plan,
request, provenance and window hashes, lease identity and original duration,
fixed start/end, admission/sample times and `current`. It returns no original
proof or credential. `current` describes structural window/plan/time validity,
never production eligibility. Plan, requirements, original provenance, window,
review, security revision and mandatory audits commit atomically. Exact retry
preserves bytes and audit history. Another compatible plan may bind the same
original lease only with that same window; approval, retry and reopening cannot
move or refresh it.

## Read the retained window

```sh
target/debug/fw_authority_admin read-core-access-lease-window \
  --database authority/authority.sqlite3 \
  --org-id ORG_UUID --project-id PROJECT_UUID < plan-reference.json
```

`plan-reference.json` contains only `{"plan_id":"PLAN_UUID"}`. The response is
`fw.core-access-lease-window-query/v1` with a `window` status or `null` when the
tenant's plan has no retained reviewed window. Existing cost-only provenance
does not imply a window. Both permission fields remain false. Expired or retired
plan history remains readable and exact registration retries recover the
original evidence without renewing it.

Window observation durably advances the project's existing quota-clock floor,
even before a quota pin exists, and respects relevant original-root and target
floors. It creates no quota pin, reservation, job or generation. A clock
observation follows closed structural plan and requirements validation, so a
malformed plan or requirements object does not advance it. A well-formed attempt
may commit observation before later current-time, conflict or admission refusal.
Within the protected-database boundary, after observed expiry,
backward wall-clock samples cannot make the window current again, including
after reopening; `checked_at` still reports the actual sample.
Provenance registration/read and window read also compare the window selected
for observation with the final transaction. A concurrent first-window admission
can cause a conflict refusal; retry the same operation to observe the retained
window. This never renews its original interval.

This guarantee assumes the authority database and privileged importer remain
protected. A schema-capable writer can remove guards, rewind local clock state
and restore them; a local SQL or hash-chain check cannot prove external
monotonicity against that writer. F_01 excludes administrator/root and trust-root
compromise. Protected authority deployment and independent external anchoring
remain unfinished; no database-rewrite protection is claimed here.
These commands do not establish OS-account/ACL separation. Protected authority
storage remains a precondition; it is not satisfied when the controller can
rewrite the authority schema. The root-compromise exclusion alone does not
resolve that deployment's SQL-writer exposure.

These two commands take no `--approval-origin`. Input is bounded and the outer
request is closed before the clock is sampled. Full nested plan/requirements
validation completes before durable clock observation. Malformed input or rejected bindings use status 1
and `AUTHORITY_ADMIN code=CORE_ACCESS_LEASE_WINDOW_REJECTED`; malformed tenant
identifiers retain `TENANT_REJECTED`. Output failures use `OUTPUT_FAILED` and
can follow a successful commit. Recover by reading the same plan or retrying
the exact combined registration; output loss does not establish rollback.

The authenticated reviewer route
`GET /authority/v1/plans/{plan_id}/core-access-evidence` returns the bounded
`fw.core-access-evidence/v1` envelope, tied to tenant, target, plan hash and sample
time. It requires a current reviewer/session proof and normal Origin/CSRF checks,
uses no-store responses and exposes no raw original proofs. Verified historical
windows remain readable after plan expiry. Its explicit gate remains
`CORE_SIGNING_PROFILE_UNAVAILABLE`; readiness v1/v2 contracts are unchanged.

## Register original cost evidence only

The command reads one closed JSON object from stdin:

```json
{
  "plan_id": "44444444-4444-4444-8444-444444444444",
  "provenance": {
    "schema_version": "fw.core-access-provenance/v1",
    "request_id": "66666666-6666-4666-8666-666666666666",
    "request_revision": 1,
    "lease_id": "77777777-7777-4777-8777-777777777777",
    "request": {},
    "envelope": {},
    "delegation": {}
  }
}
```

The empty nested objects above are placeholders. Supply the complete, unchanged
`f.access-request/v1`, `f.access-envelope/v1` and `f.delegation/v1` objects. Version
1 requires request revision `1`. The plan must already exist in the specified
authority tenant; the command does not import a plan or approval requirements.
The original core request ID is distinct from the signing coordinator's
`request-signing.request_id`, which identifies a signing preparation retry.

```sh
umask 077
target/debug/fw_authority_admin register-core-access-provenance \
  --database authority/authority.sqlite3 \
  --org-id ORG_UUID --project-id PROJECT_UUID < core-provenance.json
```

There is no `--approval-origin` option for provenance import or lookup. The
input cannot contain a private key, signing grant, production qualification
override or caller-computed cost. The 128 KiB stdin limit applies to the complete
request. Unknown properties, duplicate JSON keys, malformed values and excess
input are rejected without truncation.

Successful registration returns a bounded status with plan, request and
provenance hashes, request ID and revision, root and lease IDs, original
`lease_seconds`, destination IDs, admission time, validity and current blocking
gates. It returns no original purpose, workflow, scope or raw source object.

An exact retry preserves the original registration and adds no audit event.
The original request/revision, request idempotency key and organization lease
identity cannot be rebound to changed provenance. A later compatible plan may
refer to the same retained original evidence without creating another lease
identity. Each plan binding and its audit record are committed atomically.

## Read retained cost status and recover from output loss

```sh
target/debug/fw_authority_admin read-core-access-provenance \
  --database authority/authority.sqlite3 \
  --org-id ORG_UUID --project-id PROJECT_UUID < plan-reference.json
```

`plan-reference.json` contains only `{"plan_id":"PLAN_UUID"}`. The response
uses `schema_version: "fw.core-access-provenance-query/v1"`, with a
`provenance` status or `null` when that tenant's registered plan has no retained binding, and
`signing_allowed: false` and `dispatch_allowed: false`. An expired plan's
historical evidence remains readable; its currentness and blocking gates
describe whether the binding is usable now. A historical record does not renew
a plan or recover signing authority.

A missing plan or a plan belonging to another tenant is rejected without
disclosing whether another tenant has registered it.

Invalid provenance requests and rejected bindings exit with status 1 and the
fixed diagnostic `AUTHORITY_ADMIN code=CORE_ACCESS_PROVENANCE_REJECTED`.
Malformed tenant identifiers use `TENANT_REJECTED`. A syntactically valid but
unavailable or unprovisioned tenant reached through a provenance operation uses
`CORE_ACCESS_PROVENANCE_REJECTED`, preserving cross-tenant non-disclosure.
Argument, database and output failures retain the administration tool's
existing fixed diagnostics. Errors do not echo supplied object contents,
identifiers or database paths. Successful stdout is canonical JSON without a
trailing newline.

Registration can commit before stdout fails. A full output destination, a
read-only output descriptor or a broken pipe returns status 1 and
`AUTHORITY_ADMIN code=OUTPUT_FAILED` when stderr remains writable. Read the
same plan's retained provenance or retry the exact registration to recover the
result. Output failure does not establish rollback. Read and retry do not erase
or replace committed evidence. A writable `/dev/null` is a valid destination.

Schema 9 introduced the provenance records. Current authority databases use
schema15; schema14 added the reviewed-core window sidecar and schema15 adds the
signed authority/bootstrap registry, preserving published SQL001–014 and legacy
provenance bytes. Opening a populated schema1–14 database
requires explicit backed-up migration. Migration preserves existing state and
does not manufacture original requests, windows, reviews or approval. See
[authority storage](authority-store.md) for the migration procedure and
[signing coordination](signing-coordination.md) for remaining signing gates.

## Verification scope

```sh
source scripts/dev-env.sh
cargo test --locked -p fw_authority --test core_access_admin
cargo test --locked -p fw_authority --test core_access_window --test core_access_store --test core_access_provenance
```

The administration tests run the actual local executable against private SQLite
databases; the store tests directly exercise retained evidence. They cover strict
input, retained cost and tenant binding,
idempotent retries, fixed-window/full-state binding, lookup and output failure
recovery. These commands describe the verification scope; executed results
belong in the [verification summary](../reports/README.md). They establish local
import and persistence behavior; production signing and native enforcement
remain unavailable through these commands.

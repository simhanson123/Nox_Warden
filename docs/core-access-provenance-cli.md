# Retain original core-access cost evidence

`fw_authority_admin` can bind a previously registered `f.plan/v1`
`add_access_lease` plan to its original access request, access envelope and
delegation. This is a trusted local import into the protected authority
database. The administrator must obtain those original objects independently
and protect the database and input files from the controller OS user.
Controller enrollment, a browser session and possession of an object hash do
not authorize this command.

The retained evidence identifies the original request and revision, delegation
root, lease and full requested duration. A plan that permits only the remaining
part of a lease still carries the original duration as its cost. For example, a
3,600-second original request costs 3,600 seconds even when the plan's policies
cover only the final 1,800 seconds. Destination IDs are retained as a sorted,
unique set. Callers cannot supply a reduced duration or independent quota total.

This checks immutable object binding and bounded scope and time consistency.
It does not verify the envelope or delegation's approval signatures, authenticate
the referenced workload, prove human approval, qualify a production backend, or
create a grant. Approval hashes are references, not cryptographic evidence of
authority. Both `signing_allowed` and `dispatch_allowed` remain false.

## Register the original objects

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

## Read retained status and recover from output loss

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
Argument, database, tenant and output failures retain the administration tool's
existing fixed diagnostics. Errors do not echo supplied object contents,
identifiers or database paths. Successful stdout is canonical JSON without a
trailing newline.

Registration can commit before stdout fails. A full output destination, a
read-only output descriptor or a broken pipe returns status 1 and
`AUTHORITY_ADMIN code=OUTPUT_FAILED` when stderr remains writable. Read the
same plan's retained provenance or retry the exact registration to recover the
result. Output failure does not establish rollback. Read and retry do not erase
or replace committed evidence. A writable `/dev/null` is a valid destination.

Schema 9 adds the provenance records to the authority database. Existing schema
8 databases require explicit backed-up migration; migration preserves existing
state and does not manufacture original request evidence. See
[authority storage](authority-store.md) for the migration procedure and
[signing coordination](signing-coordination.md) for remaining signing gates.

## Verification scope

```sh
source scripts/dev-env.sh
cargo test --locked -p fw_authority --test core_access_admin
```

These tests run the actual local administration executable against private
SQLite databases. They cover strict input, retained cost and tenant binding,
idempotent retries, lookup and output failure recovery. They establish local
import and persistence behavior; production signing and native enforcement
remain unavailable through these commands.

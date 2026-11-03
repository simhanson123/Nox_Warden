# Inspect signing readiness and maintain independent quota

`fw_authority_admin` operates on the protected authority database as a trusted
local administrator. Controller sessions, enrollment and browser approvals do
not authorize these maintenance commands. Protect the database directory and
redirected output from the controller OS user; a separate filename alone does
not provide that separation.

The commands expose readiness, independent root/project quota pins, retained
intent status and explicit cancellation before issuance. They accept no private
policy key, raw grant payload, supplied quota total or production-qualification
switch. Current lab evidence cannot
create a signing intent or dispatch grant, including when it has a matching
signed observation and a current human approval set.

## Pin root and project quota separately

The root bucket belongs to an organization. A rooted project pin independently
binds that project's limits to a root; both limits apply. A project-only pin
limits general policy without a delegation root. Both scopes share one project
budget and preserve previously held obligations. Creating another root cannot
reset project history.
The trusted local administrator can manage that organization's root through any
provisioned project in the same organization. The first project to pin a root
does not own it exclusively. An identifier from another organization does not
grant access to its root pin, revision or revocation.

Each pin reads the following closed JSON shape from stdin. Choose the UUID and
whole-second UTC validity interval through the trusted local configuration
process. The sample times are illustrative and must be replaced with an
appropriate current interval. Active leases and concurrent deployments range
from 1 to 10,000; daily new leases and destinations from 1 to 100,000; cumulative
seconds from 60 to 2,147,483,647. Zero does not mean unlimited and is rejected.

```json
{
  "pin": {
    "root_id": "88888888-8888-4888-8888-888888888888",
    "limits": {
      "active_leases": 2,
      "new_leases_per_day": 4,
      "unique_destinations_per_day": 8,
      "cumulative_seconds_per_day": 3600,
      "concurrent_deployments": 1
    },
    "not_before": 1793491200,
    "not_after": 1793494800
  },
  "expected_revision": null
}
```

```sh
umask 077
target/debug/fw_authority_admin pin-signing-root-quota \
  --database authority/authority.sqlite3 \
  --org-id ORG_UUID --project-id PROJECT_UUID < root-quota.json
target/debug/fw_authority_admin pin-signing-project-quota \
  --database authority/authority.sqlite3 \
  --org-id ORG_UUID --project-id PROJECT_UUID < project-quota.json
```

Initial pins use `expected_revision: null`. Updates supply the current positive
decimal revision string, for example `"1"`; JSON numbers, leading zeros and
overflow are rejected. Root and project revisions advance independently. An exact
retry with the current revision returns that revision; changed limits or validity
create a new revision. Omitting the expected revision after creation is a conflict.
Successful pinning returns its revision and does not enable signing or dispatch.

## Configure project-only general policy

Only `pin-signing-project-quota` accepts this explicit versioned input. Omit
`pin.root_id` entirely; a null root, partial root metadata, unknown version or
unknown field is rejected. Legacy unversioned input still requires a root UUID.
The root-pin command always requires its root and never accepts v2 project input.

```json
{
  "schema_version": "fw.signing-project-quota-pin/v2",
  "pin": {
    "limits": {
      "active_leases": 2,
      "new_leases_per_day": 4,
      "unique_destinations_per_day": 8,
      "cumulative_seconds_per_day": 3600,
      "concurrent_deployments": 1
    },
    "not_before": 1793491200,
    "not_after": 1793494800
  },
  "expected_revision": null
}
```

Run the same `pin-signing-project-quota` command shown above. For a newly
configured project, use null expected revision. To cut an existing rooted project
over to project-only scope, supply its current project revision string. The
response contains `schema_version: "fw.signing-project-quota-pin/v2"`,
`quota_scope: "project"`, the revision and both false permission fields; it
contains no root field.

A project first configured with root A may move A→project-only→A using explicit
CAS revisions. Restoration uses the original unversioned mandatory-root input
with A and the current project revision. Root B is always refused, including
while the current pin has no root. A project first configured project-only must
remain project-only. Exact retries with the current revision add no pin or audit
entry. Cutover neither releases old obligations nor resets the project budget.

General policy costs no lease, seconds, destinations or active-lease slots and
reserves one dispatch slot. The other positive pin limit fields remain required;
project-only scope cannot authorize access leases. This is an accounting choice,
not an OS privilege mode. Production signing and dispatch remain closed.

`revoke-signing-root-quota` reads
`{"root_id":"ROOT_UUID","expected_revision":"1"}`.
`revoke-signing-project-quota` reads `{"expected_revision":"1"}`.
They use the same database and tenant arguments. Revocation prevents new use of
that pin; it does not erase history or prove that an earlier dispatch ended.

## Inspect readiness and request preparation

`read-signing-readiness-v2` reads `{"plan_id":"PLAN_UUID"}`. Both readiness and
`request-signing` require a trusted `--approval-origin` argument matching the
authority review deployment. There is no default origin and the JSON request
cannot override it. The verifier rechecks retained WebAuthn evidence; origin
configuration does not manufacture human approval.

```sh
target/debug/fw_authority_admin read-signing-readiness-v2 \
  --database authority/authority.sqlite3 \
  --org-id ORG_UUID --project-id PROJECT_UUID \
  --approval-origin http://localhost:8790 < plan-reference.json
```

This example uses the authority review service's default origin. Supply that
service's actual configured origin when it differs; the controller login origin
is a separate trust context.

The response reports current blocking conditions separately from stored evidence.
Pinning quota may resolve a quota-configuration blocker while production
qualification and protected signer deployment remain incomplete. A retained
matching observation is evidence, not a signing capability.

The v2 response includes `quota_scope` (`root`, `project` or null),
`quota_root_id` (a UUID only for root scope), and
`latest_dispatch_unknown_seen` (a boolean, or null when no latest intent exists).
Scope describes current valid configuration independently of any latest
historical reservation. Expired/revoked pins have null scope and a missing quota
blocker. Core requests with project-only configuration or missing original
provenance report `quota_configured: false`. A past UNKNOWN stays visible after
later recorded delivery and does not establish enforcement or return quota.

The original `read-signing-readiness` command retains the v1 15-field shape for
rooted or unavailable configuration. It rejects current project-only
configuration with `SIGNING_READINESS_REJECTED`; select the explicit v2 command.
The matching authenticated read-only HTTP route is
`GET /authority/v2/plans/{plan_id}/signing-readiness`; v1 does not downgrade a
project-only response. The authority UI uses v2 explicitly. Both versions now
report missing core provenance as missing applicable quota; retained v1 pin and
reservation bytes are preserved.

`request-signing` accepts only this reference shape:

```json
{
  "request_id": "66666666-6666-4666-8666-666666666666",
  "plan_id": "44444444-4444-4444-8444-444444444444",
  "expected_plan_hash": "sha256:EXACT_PLAN_HASH",
  "expected_approval_set_hash": "sha256:EXACT_APPROVAL_SET_HASH"
}
```

Use the same database, tenant and approval-origin arguments as the readiness
command. The authority resolves the immutable objects itself. Unqualified
requests return exit 1 with `AUTHORITY_ADMIN code=SIGNING_REQUEST_REJECTED`; they
consume no quota reservation or target generation and create no signer job or
dispatch outbox entry. Repeating that request does not grant authority.

## Cancel retained work before issuance

`cancel-signing-job` reads the closed request `{"job_id":"JOB_UUID"}`. It uses
the database, organization and project arguments, with no approval-origin option:

```sh
target/debug/fw_authority_admin cancel-signing-job \
  --database authority/authority.sqlite3 \
  --org-id ORG_UUID --project-id PROJECT_UUID < job-reference.json
```

The command is an explicit trusted local maintenance action, including for an
expired intent. In one transaction it verifies that the job belongs to the
specified tenant, has no issued result, usage or dispatch outbox, and has an
unissued reservation. It records cancellation, invalidates any signer claim and
releases the unused reservation. It preserves the intent, work history and
target generation fence. An issued or UNKNOWN reservation cannot be cancelled
or refunded; expiration alone never establishes safe release.

Success returns canonical JSON with `job_id`, `status: "cancelled"`,
`signing_allowed: false` and `dispatch_allowed: false`. Repeating the same
successful cancellation is idempotent. Missing jobs, another tenant's jobs and
ineligible states return exit 1 with
`AUTHORITY_ADMIN code=SIGNING_CANCELLATION_REJECTED`. Unknown request fields,
duplicate keys or invalid JSON return the existing `INPUT_REJECTED` diagnostic.

## Read an intent and handle command failures

`read-signing-intent` reads `{"intent_id":"INTENT_UUID"}` with database and
tenant arguments. It returns a bounded status object or `"intent": null` when
that tenant has no such intent. An absent intent is not fabricated from the
request ID. The response contains no private key or raw signed payload, and its
`signing_allowed` and `dispatch_allowed` fields remain false. This command does
not enumerate other tenants or expose a grant-delivery endpoint.
Historical intent reads and job retries use the project clock plus the retained
reservation's root clock, if any. Restoring a rooted configuration does not add
that root's clock to an older project-only job. Readiness also checks the current
configuration's clock because it reports current pin eligibility.

Signing requests have the existing 128 KiB stdin limit. Unknown fields,
duplicate JSON keys, invalid identifiers, unexpected options and noncanonical
revisions fail with fixed diagnostics without echoing private values or paths.
Successful stdout is canonical JSON without a trailing newline.

Output errors can occur after a quota pin or cancellation commits. A full
destination, a read-only output handle or a pipe without a reader returns exit 1 and
`AUTHORITY_ADMIN code=OUTPUT_FAILED` when stderr is writable. Preserve the
reported/current revision and inspect retained state before updating again;
an output error does not establish rollback. After lost cancellation output,
inspect the retained intent or retry that exact job cancellation. A writable
`/dev/null` remains a valid output destination. See [target metadata recovery](target-metadata.md#command-output-and-retained-state)
for the shared output contract and
[authority storage](authority-store.md) for backed-up schema migration.

## Verification scope

```sh
source scripts/dev-env.sh
cargo test --locked -p fw_authority --test signing_admin --test signing_readiness_versions
cargo build --locked -p fw_authority --bin fw_authority_admin
NOX_TEST_AUTHORITY_ADMIN="$PWD/target/debug/fw_authority_admin" \
  cargo test --locked -p fw_authority --lib \
  cancellation_cli_preserves_commits_retries_tenants_and_issued_unknown -- --ignored
```

These regressions run the actual administration executable against private
SQLite databases, including signed lab observation and WebAuthn fixtures.
The explicitly ignored cancellation test uses private `cfg(test)` preparation to give the real executable
retained unissued and issued work. It covers expired claimed work, tenant
refusal, output loss after cancellation, exact retry without extra events,
unchanged generation and issued/UNKNOWN refusal. `scripts/check.sh` builds the
executable and runs this explicitly required process test; it is ignored by
standalone library tests because those do not build the executable.
They establish refusal, persistence and recovery behavior. They do not qualify
production signing, protected OS identities, authenticated dispatch, PostgreSQL
or native host enforcement.

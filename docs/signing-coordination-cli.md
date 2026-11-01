# Inspect signing readiness and maintain independent quota

`fw_authority_admin` operates on the protected authority database as a trusted
local administrator. Controller sessions, enrollment and browser approvals do
not authorize these maintenance commands. Protect the database directory and
redirected output from the controller OS user; a separate filename alone does
not provide that separation.

The commands expose readiness, independent root/project quota pins and retained
intent status. They accept no private policy key, raw grant payload, supplied
quota total or production-qualification switch. Current lab evidence cannot
create a signing intent or dispatch grant, including when it has a matching
signed observation and a current human approval set.

## Pin root and project quota separately

The root bucket belongs to an organization. The project pin independently binds
that project's limits to a root. Both limits apply; creating another root does
not allow a bound project to reset its quota history by switching roots.

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

`revoke-signing-root-quota` reads
`{"root_id":"ROOT_UUID","expected_revision":"1"}`.
`revoke-signing-project-quota` reads `{"expected_revision":"1"}`.
They use the same database and tenant arguments. Revocation prevents new use of
that pin; it does not erase history or prove that an earlier dispatch ended.

## Inspect readiness and request preparation

`read-signing-readiness` reads `{"plan_id":"PLAN_UUID"}`. Both readiness and
`request-signing` require a trusted `--approval-origin` argument matching the
authority review deployment. There is no default origin and the JSON request
cannot override it. The verifier rechecks retained WebAuthn evidence; origin
configuration does not manufacture human approval.

```sh
target/debug/fw_authority_admin read-signing-readiness \
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

## Read an intent and handle command failures

`read-signing-intent` reads `{"intent_id":"INTENT_UUID"}` with database and
tenant arguments. It returns a bounded status object or `"intent": null` when
that tenant has no such intent. An absent intent is not fabricated from the
request ID. The response contains no private key or raw signed payload, and its
`signing_allowed` and `dispatch_allowed` fields remain false. This command does
not enumerate other tenants or expose a grant-delivery endpoint.

Signing requests have the existing 128 KiB stdin limit. Unknown fields,
duplicate JSON keys, invalid identifiers, unexpected options and noncanonical
revisions fail with fixed diagnostics without echoing private values or paths.
Successful stdout is canonical JSON without a trailing newline.

Output errors can occur after a quota pin commits. A full destination, a
read-only output handle or a pipe without a reader returns exit 1 and
`AUTHORITY_ADMIN code=OUTPUT_FAILED` when stderr is writable. Preserve the
reported/current revision and inspect retained state before updating again;
an output error does not establish rollback. A writable `/dev/null` remains a
valid output destination. See [target metadata recovery](target-metadata.md#command-output-and-retained-state)
for the shared output contract and
[authority storage](authority-store.md) for backed-up schema migration.

## Verification scope

```sh
source scripts/dev-env.sh
cargo test --locked -p fw_authority --test signing_admin
```

These regressions run the actual administration executable against private
SQLite databases, including signed lab observation and WebAuthn fixtures.
They establish refusal, persistence and recovery behavior. They do not qualify
production signing, protected OS identities, authenticated dispatch, PostgreSQL
or native host enforcement.

# Core access review, fixed lease windows and isolated execution

This M03/M04L/M05/M06 batch starts at PR25 merge
`a624a1e684a8fc0065ac4f4609101410f56c50bb`. It connects original core
`f.plan/v1` access requests to full-state review, an immutable absolute window,
independent native recompilation and explicit development-only Linux execution.
Current verification belongs in [reports](../reports/README.md); source presence
and lab evidence do not establish production qualification.
The [PR26 follow-up](pr26-follow-up.md) qualifies the received review, legacy
binding rules, conservative-clock boundary and additional lab checks.

## Exact semantic review

`PolicyReviewEvidence` retains its existing canonical `{before, after}` shape.
The policy-change branch and `SemanticDiff` serialized fields remain unchanged.
The additive core branch independently recomposes normalized requested policies
with `compose_access_patch`, preserving the complete baseline: existing denies,
unrelated allows, associations and tombstones. It checks exact baseline/candidate,
patch and sorted requested-policy hashes, tenant/target/reference context and
complete bounded TCP/UDP semantics. Unknown or oversized proofs are refused.

New policy associations must share the plan's request, one structural lease ID
and the recomputed `f.policy-authority-basis/v1` hash. Core plans do not themselves
carry a lease ID; the authority store separately binds that structural ID to
the retained original provenance. Semantic verification alone grants nothing.

Core's existing closed effect summary has counts and one hash. The implementation
defines the digest of this canonical object:

```text
schema_version: fw.core-access-effect/v1
newly_allowed_flow_count
removed_flow_count
newly_allowed_region_hash
removed_region_hash
```

Counts are the lengths of the deterministic exact region-cell sets. They are
normalized flow regions, not individual packets or an unbounded address count.
The golden empty-to-one-TCP-region example hashes to
`sha256:d39479437e196371fb3d64e3b525e0114e3e31341922f8ae139c8a87c43e0637`.
All requested policy lifetimes share exactly `[S,E)`, with original requested
duration `E-S` between 60 and 86400 seconds. Scope may be narrower; this reviewed
profile cannot shift, shorten or extend the original fixed time interval.

## Retained original window

`fw.core-access-lease-window/v1` is closed and bounded to 4096 bytes. It binds
organization/project/target, original request ID/revision/hash, provenance hash,
lease ID and canonical UTC `not_before`/`expires_at`. Its duration must equal the
full original request, fit the envelope/delegation intersection and the plan's
declared workload lifetime, and match every requested policy and review binding.
Those lifetime/hash checks are structural; they do not authenticate the workload
issuer or delegated approval.

Schema14 adds an immutable window sidecar. Combined registration atomically
retains plan, requirements, original provenance, fixed window, review and mandatory
audits/security revision. Exact retry preserves bytes and audit history. Another
compatible plan may bind the same original lease only with the same window;
replacement, rowid collision, another lease, missing reference or altered retained
projection is refused. Existing one-reservation-per-lease behavior and issued/
UNKNOWN/unsigned-delivered capacity are unchanged.

Published SQL001–013 and schema9 provenance bytes are preserved. Existing v1
provenance may describe shorter or shifted compatible policy windows for historical
cost accounting. Once a request has a retained window, provenance-only bindings
must stay inside it. Creating the first window checks every existing binding and
atomically refuses an out-of-window legacy history without changing old rows.
A shorter compatible legacy binding can remain cost history; new live cost and
readiness require that plan's full retained review and exact fixed window.
Legacy full-duration costs, reservation snapshots and
issued/UNKNOWN/unsigned-delivered capacity remain intact. A legacy plan may gain
the strict profile by passing the complete combined registration checks;
provenance import alone does
not supply a review or window.
Migration adds no inferred legacy window, approval or completion evidence.
The populated legacy migration tests reconstruct released schema13 around genuine
old-API rows; they are not newly executed old-binary fixtures.

Window observation uses the existing durable project quota-clock floor, even
before a quota pin is configured, and respects relevant original-root/target
floors. It creates no quota pin, capacity, reservation, job or generation.
Clock observation can commit independently of later admission refusal. After
closed structural plan/requirements validation, a well-formed attempt can persist
time even when later current-time or database checks refuse admission. Malformed
plan/requirements cannot advance that floor. Within the protected-database
boundary, after observed expiry and backward wall-clock samples, reads and exact
retries remain verified history with `current=false`, including samples before
admission and after reopening. Historical bytes are checked at the durable floor;
`checked_at` still reports the actual sample. `current` describes the structural
window/plan/time state, never production eligibility.

Provenance registration/read and window read recheck the selected window after
clock observation. A concurrent first-window registration changes that selection
and returns `Conflict` for retry, so a new window cannot be consumed without its
required clock observation. Retry retains the original absolute interval.

The floor is local durable state, not an external monotonic anchor. A writer able
to remove SQL guards, rewind the floor and restore the schema can create a
coherent earlier database that local checks accept. A local hash chain cannot
prove otherwise against that writer. F_01 excludes administrator/root and
trust-root compromise from the boundary; protected authority deployment and an
independently protected external anchor remain unfinished. This follow-up does
not claim to prevent privileged database rewrites or whole-database rollback.
Protected authority storage is a precondition. OS-account/ACL separation remains
unfinished; a deployment giving the controller permission to rewrite the
authority schema does not satisfy it. The root-compromise exclusion alone does
not resolve SQL-writer attacks.

## Administration, API and browser

The trusted-local `register-reviewed-core-access-plan` command accepts the closed
`fw.reviewed-core-access-plan/v1` object, at most 512 KiB:

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

The empty objects above indicate required typed content; they are not valid
fixtures. `read-core-access-lease-window` takes closed `{ "plan_id": "…" }`
input and returns a bounded `fw.core-access-lease-window-query/v1` with a window
or null. Input is bounded and the outer request is closed before the command
samples time; full nested plan/requirements validation precedes durable clock
observation. Output
failure does not undo an already committed registration; exact retry/read recovers
the original result. Existing provenance commands and bytes remain compatible.

`GET /authority/v1/plans/{id}/core-access-evidence` returns the closed
`fw.core-access-evidence/v1` envelope, pinned to tenant, target, plan ID/hash and
sample time. It requires a current authenticated reviewer, session proof and
normal origin/CSRF checks, uses no-store responses and exposes no original proof
or credential material. Verified historical windows remain readable after plan
expiry. Startup source configuration may confirm an exact already-retained core
review; it cannot import core authority through the old general-plan path.

Existing passkey review and native-evidence routes support the retained core
review. The browser displays complete before/after state, fixed window and
current/future/expired/historical/missing evidence in all eight locales. English
default and saved language choice remain unchanged. A memory-only time high-water
for the authenticated client prevents local expiry from reversing across refresh
or remount; a newly authenticated client starts its own observation state.
Neither UI state nor the new endpoint changes readiness v1/v2 wire shapes.
`CORE_SIGNING_PROFILE_UNAVAILABLE`, `signing_allowed=false` and
`dispatch_allowed=false` remain explicit.

## Native development profile

Core native compilation independently rebuilds both complete states against the
pinned reference. Lab capability and authenticated target metadata stay distinct;
a baseline observation cannot be replaced by a candidate observation.

For isolated core observations, a separate closed `reference-pin.json` uses
`fw.core-lab-reference-pin/v1`, a canonical positive `reference_revision`,
`production_authorized=false` and the pinned `LabReferences`. The fixture writes
this trusted lab input before constructing the bundle. Both observation paths
rebuild the complete baseline and candidate against it and compare exact bundle
artifacts and recovery references. Observation metadata records the pin/reference
hashes, revision and `reference_source=separate-trusted-lab-input`, plus expected
and submitted artifact hashes. The external pin constrains observation evidence
compilation. Driver initialization, apply and replay retain their existing
artifact, grant and trust-scope validation paths; this adds no production trust
or independently provisioned authority boundary.

The additive `fw.isolated-core-access-execution-bundle/v1` carries the actual
closed core plan, review, provenance and fixed window together with a core grant,
artifacts, prior installation and explicitly synthetic lab approval. A separate
`fw.isolated-lab-trust/v1` file pins grant/confirmation keys and must set
`production_authorized=false`. The internal runtime projection preserves the
exact core objects through journal replay
and separately authorized restrictive recovery. Existing legacy bundle bytes
remain unchanged. Fresh normal submission uses current validity; historical
accepted material and recovery retain their own original signed deadlines.
Reopen/retry cannot call a new relative lifetime binding or refresh `[S,E)`.
Within one apply or recovery call, a scoped callback can reuse a private proof
of the exact immutably borrowed material. It cannot serialize or export that
proof. Initial and final authority checks still read current trust and verify
keys, DSSE bindings and normal/recovery time; the watcher, initialization and
standalone verifier each perform their own complete material validation.
The five-second installation budget, including a two-second native-process
reserve, stays unchanged. Reusing immutable calculations does not reuse an old
authorization result or rebind accepted installation material.

The separate isolated command is:

```sh
python scripts/core-access-linux-lab.py --skip-image-build --report reports/core-access-linux-lab.json
```

Run after the existing signed lab has built its pinned image. The core scenario
uses one valid IPv4 INPUT TCP request/envelope and the original minimum 60-second
window. Existing denies and unrelated TCP/UDP leases live in its baseline.
Its required evidence includes actual signed baseline/candidate captures,
new and established connection expiry at the original `E`, tamper refusal before
native mutation/generation, replay without refresh and core-specific restrictive
recovery after normal-plan expiry while original recovery authority remains valid.
The expiry and recovery scenarios create separate fixture operations. Both use
an original 60-second lease. At creation, the expiry case selects dispatch and
plan/confirmation caps of `S+45`/`S+50`; the unconfirmed recovery case selects
`S+18`/`S+20` and the original recovery deadline `S+180`. No accepted grant is
extended. The initial baseline installation is bound immediately before its
native submission, within the existing five-second budget, retaining its old
absolute expiries. Current signature checks before and after the tamper cases
ensure those refusals cannot pass merely because the original grant expired.
The forged signature is exactly 64 bytes and must produce
`CORE_BUNDLE_GRANT_SIGNATURE`; every mutation requires its own exact bounded
refusal and unchanged generation, operation/material state and owned table.
`production_authorized=true` instead produces `LAB_TRUST_BINDING` during trust
loading, and is reported as that separate condition.

Expiry evidence includes an independent lower bound on remaining kernel token
lifetime derived from original `E` and the installation clock bracket. A positive
new/established TCP sample targets
`E − (clock uncertainty + elapsed time + commit budget) − 2 seconds`, followed by
negative samples at `E+1`. The fixture's one-second uncertainty, zero elapsed
binding time and unchanged five-second commit budget put that target at `E−8`.
This preserves the explicit early-cutoff model in
[F_04 section 8](specs/F_04_정책컴파일러_집행_복구_명세.md).
The two-second packet-sampling margin is separate from the native-process reserve;
it does not enlarge any installation or security deadline. The lower bound allows
one second for nftables integer-second representation. Checking only the expired
state at `E+1`, or deriving the minimum from the observed timeout itself, cannot
prove that a short token retained its intended conservative lifetime.
Counts from the three older labs stay separate. CI retains the new report and
allows 60 minutes for the expanded serial suite; product/test security deadlines
are unchanged.

One native limitation was exposed by this scenario: the pinned nftables 1.0.6
prints an anonymous multiport `ct.proto-dst` set as strings such as
`0x46a0 [invalid type]`. The conservative readback verifier rejects that shape.
The core lab expresses its companion OUTPUT allowance as three scalar policies
with the same port union, old lease/request/basis and lifetime; denies and old
TCP/UDP coverage remain intact. This does not qualify multiport native readback.
Compiler/readback support for that case remains a Linux qualification requirement;
accepting ambiguous strings is not a substitute.

Production workload/delegation bootstrap, protected signing-generation
initialization, independent signer/dispatch deployment, authenticated completion,
external audit anchoring and installed-host lifecycle remain unfinished. The
Linux lab is not Windows WFP/callout or macOS Network Extension qualification.

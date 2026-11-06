# Compilation and native observation evidence

The independent authority can reconstruct a reviewed plan's Linux compilation,
retain the resulting artifacts, and verify signed observations against those
exact artifacts. A protected read-only API and the authority review screen expose
the retained evidence and its current eligibility. This development workflow
connects plan review, target metadata, compilation, collection and durable history.
It accepts retained general policy-change reviews and original core-access
reviews registered with their provenance and fixed window through the
[combined core-access importer](core-access-provenance-cli.md).

Three claims remain distinct:

- An explicit reference pin identifies the approved lab scope, baseline, source
  snapshot and capability bytes. It comes from local authority administration.
- Recompilation proves that the retained plan and full before/after state produce
  the recorded artifacts under this implementation. It does not independently
  attest the plan's declared compiler/validator build digests.
- An observation signature authenticates a purpose-scoped lab producer's bytes.
  Readback verification recomputes correspondence with the expected installation.
  The signature alone does not establish that the producer measured a real kernel.

The shipped collector reads actual `nft` output under the disposable Linux lab
guard. Its process tests exercise that acquisition path. Production observer
isolation, management baseline qualification and native support remain separate
requirements. Every result retains `production_qualified:false` and
`dispatch_allowed:false`; no operation issues a policy grant.

## Inputs and trust

Start with an authority database and project namespace, a separately pinned
transport identity, and a current signed report as described in
[target metadata](target-metadata.md). Then provision the following through the
trusted local administration boundary:

| Input | Meaning |
| --- | --- |
| Reviewed plan, requirements and full before/after state | Existing immutable semantic review; importing it does not record human approval. |
| Native reference pin | Exact `LabReferences`, target and validity interval, with revision CAS. |
| Lab-observer pin | Separate Ed25519 public key, target and validity interval; its permitted purpose is lab observations. |
| Expected installation | Deterministically validated runtime binding of a compiled artifact, including boot/namespace/clock and original deadlines. |

The `fw.isolated-lab-capability/v1` reference used by the compiler differs from
the device's `f.target-capability/v1` metadata. Receipts bind both independently;
neither hash can substitute for the other. References support the existing
isolated loopback profile, with empty management paths and no production
qualification. Unsupported host references fail rather than becoming a lab PASS.

Observer trust is not imported from controller enrollment. The administrator
must independently maintain reference and observer validity, ownership and
revocation. Private observer seed files belong only to the lab collection
process; the authority maintenance command accepts public pins and proofs.
An expected installation describes what to compare. It does not prove a
previous approved journal operation or who installed the rules.

## Local workflow

Build with the pinned toolchain:

```sh
source scripts/dev-env.sh
cargo build --locked -p fw_authority -p fw_linux_executor --bins
```

All authority commands below use these options and read one closed JSON object
from stdin:

```text
fw_authority_admin COMMAND --database PATH --org-id UUID --project-id UUID
```

Use the private directory/file rules in [target metadata](target-metadata.md).
Prepare inputs from independently verified material; substituting invented
identities or synthetic test pins does not provision production authority.

| Command | Input |
| --- | --- |
| `register-reviewed-plan` | `{"plan":…, "requirements":…, "evidence":{"before":…,"after":…}}` |
| `register-reviewed-core-access-plan` | `{"schema_version":"fw.reviewed-core-access-plan/v1","plan":…, "requirements":…, "evidence":{"before":…,"after":…},"provenance":…,"window":…}` |
| `read-core-access-lease-window` | `{"plan_id":…}` |
| `pin-native-references` | `{"pin":{"target_id":…,"references":…,"not_before":…,"not_after":…},"expected_revision":null}` |
| `pin-native-observer` | `{"pin":{"target_id":…,"public_key":[32 byte values],"not_before":…,"not_after":…},"expected_revision":null}` |
| `compile-native` | `{"plan_id":…,"expected_reference_revision":"1"}` |
| `challenge-native` | `{"plan_id":…,"artifact_role":"baseline","installation":…,"expected_head":null,"authority_epoch":"0","generation":"0"}` |
| `admit-native` | The exact `SignedNativeObservation` proof envelope. |
| `read-native` | `{"plan_id":…}` |
| `revoke-native-references` / `revoke-native-observer` | `{"target_id":…,"expected_revision":"1"}` |

Ellipses denote required prepared values, not literal valid input. Revisions,
epoch and generation are canonical decimal strings. Pin times are Unix seconds.
`public_key` contains the 32 raw Ed25519 bytes. Updating a pin supplies its current
revision; exact successful retries preserve their original revision and lifetime.
The expected observation head comes from current authority state, with `null`
only for the first observation. These development epoch/generation bindings do
not establish production bootstrap or consume an executor generation.

Compilation reads the retained reviewed plan and pinned references, rebuilds
both artifacts, and checks the candidate's exact `artifact_hash`. It binds the
current metadata receipt separately. Changed references or current metadata
require a new current compilation receipt; prior evidence remains historical.
The general review importer rejects core access plans. Their combined import
also retains the original request, envelope/delegation and one absolute window;
later core compilation/observation reads recheck that retained binding. Each
requested policy uses the full original `[S,E)`, so review, native collection or
retry cannot start a new relative lease. Baseline and candidate remain distinct
artifact roles: a baseline capture cannot satisfy a candidate observation.

Transfer the public challenge and exact expected artifact/installation through
an authenticated protected channel to the isolated collector. In the disposable
lab only:

```sh
fw_linux_executor collect-evidence \
  --artifact /lab/private/artifact.json \
  --installation /lab/private/installation.json \
  --observer-key /lab/private/observer-key.json \
  --challenge /lab/private/challenge.json \
  --output /lab/private/observation-proof.json
```

The collector validates the expected scope before reading the private observer
key, reads the actual owned table, records boot/namespace and bounded clock
samples, then writes a new private proof file. It accepts no supplied raw dump
or shell command. It changes neither firewall rules nor the execution journal.
The [executor README](../crates/fw_linux_executor/README.md) defines the lab guard
and protected purpose-key format. Admit the proof with `admit-native`, then use
`read-native` to inspect current eligibility separately from the returned receipt.

## Persistence and status

Schema **6** introduced this native evidence. Current authority storage uses
schema **14**; upgrading populated known schemas 1–13 requires an explicit
validated private backup. Schema14 preserves published SQL001–013 and existing
native/provenance bytes, and infers no legacy core window, review, observer trust
or completion evidence. Opening an older database does not silently import
trust or evidence. The existing `fw_authority_admin migrate` command and
[authority backup rules](authority-store.md) apply.

Challenge consumption, original proof, immutable receipt, current observation
head and mandatory audit commit together. Exact retries acknowledge the same
history without extending freshness. Current reads recompute original signatures
and readback correspondence and recheck present pins, metadata, plan, head and
deadlines. Retained clock observations prevent expired evidence from returning
after clock rollback. A lost output can follow a successful commit; retry the
exact proof or re-read state rather than assuming rollback.

Native evidence shares the target time floor. Incorrect future time therefore
has the same durable availability impact and unresolved immediate-recovery limit
described in the [forward-clock runbook](target-metadata.md#incorrect-forward-clock-and-recovery).

Challenge, payload and proof bounds are defined in
[fw_native_evidence](../crates/fw_native_evidence/README.md). They are local
development contracts; they are not a replacement for the original F internal
transport envelope. There is no destructive automatic history cleanup.

The authenticated endpoint is:

```text
GET /authority/v1/plans/{plan_id}/native-evidence
```

It returns bounded summaries and closed reason codes, never raw captures,
private keys or proof bodies. The UI distinguishes retained history from current
evidence and clears its current label when evidence expires. Refresh performs
an authenticated read without a passkey decision or approval action.

`match` means the signed capture corresponds to the specified artifact and
installation under the verifier. `mismatch` and `unknown` retain no observed
state hash. None of these labels qualifies a host, completes a human quorum or
authorizes dispatch. Human approval and native evidence remain separate panels
and separate checks.

For reviewed core plans, the authenticated
`GET /authority/v1/plans/{plan_id}/core-access-evidence` route separately returns
a bounded `fw.core-access-evidence/v1` summary of the fixed window, plan bindings
and sample time. It uses the same current reviewer/session proof and Origin/CSRF
boundary and no-store responses. Retained historical windows remain readable
after plan expiry; neither this read nor a current native receipt changes
`CORE_SIGNING_PROFILE_UNAVAILABLE`, `signing_allowed:false` or
`dispatch_allowed:false`. The browser presents full before/after state and
current/future/expired/historical/missing window evidence in all eight locales.
These additive reads do not change readiness v1/v2 wire contracts.

## Isolated core-access execution

The separate `fw.isolated-core-access-execution-bundle/v1` carries the actual
closed core plan, full review, original provenance and immutable lease window,
together with signed core grant, artifacts, previous installation and explicitly
synthetic lab approval. A separate `fw.isolated-lab-trust/v1` file pins the grant
and confirmation keys and must set `production_authorized=false`.
Runtime projection and journal replay preserve
those exact objects. Legacy lab bundle bytes remain unchanged. Fresh normal
submission checks current plan and window validity; accepted historical material
and separately authorized restrictive recovery retain their original signed
deadlines. Retry, reopen and recovery cannot shift `[S,E)`.

The observation fixture separately loads a closed `reference-pin.json` prepared
from its administrative reference inputs before bundle creation. Both baseline
and candidate observation compilation use that pin and compare the submitted
bundle/recovery references and artifacts against it. Capture records retain the
pin hash, reference hash/revision and expected/submitted bindings. This corrects
the fixture's previous self-reference; it does not add an external-reference gate
to driver init/apply/replay or authenticate a production reference issuer. The
driver retains its existing signed-material and lab-trust checks. The separate
pin remains a synthetic trusted lab input, not an OS-protected deployment service.

After the signed Linux lab builds its pinned image, run the separate profile:

```sh
python scripts/core-access-linux-lab.py --skip-image-build --report reports/core-access-linux-lab.json
```

The scenario uses a valid IPv4 INPUT TCP core request/envelope and the original
minimum 60-second lease. Its full baseline retains existing denies and unrelated
TCP/UDP leases. The required evidence includes signed actual baseline/candidate
captures, new and established connection expiry at the original deadline,
tamper refusal before native mutation/generation, replay without refresh, and
core-specific restrictive recovery after normal-plan expiry while original
recovery authority remains valid. This profile's results are reported separately
from the existing packet, signed-execution and native-evidence suites.

The follow-up also requires a positive new/established TCP observation before
the documented conservative cutoff, an independently computed token-lifetime
lower bound, and negative traffic after original `E`. Its positive target is
`E−8`: the unchanged one-second uncertainty and five-second commit budget, plus
a separate two-second packet-sampling margin. This margin does not increase the
driver's five-second installation budget or its two-second process reserve.
A correctly sized 64-byte forged signature must reach the exact signature
refusal; each negative case checks its intended bounded reason and unchanged
generation, journal material and owned native table. Trust-load refusal remains
distinct from cryptographic verification. See [the review follow-up](pr26-follow-up.md)
for the actual verification status and the known multiport readback limit.

This is explicit synthetic trust in a disposable lab. It does not provision
production workload/delegation bootstrap, protected signing generation,
independent signer/dispatch deployment or authenticated completion. See
[core-access enforcement](core-access-enforcement.md) for the complete profile
and remaining dependencies. Linux lab evidence does not qualify installed-host
lifecycle, Windows WFP/callout or macOS Network Extension enforcement.

## Reproduction

```sh
source scripts/dev-env.sh
bash scripts/check.sh
python scripts/smoke_authority_review.py \
  --service-binary target/debug/fw_authority_service \
  --fixture-binary target/debug/examples/review_fixture
python scripts/smoke_native_evidence.py --report reports/native-evidence-smoke.json
```

The native evidence smoke uses explicit synthetic trust and a disposable Docker
namespace with NET_ADMIN. It collects actual kernel state, then exercises
independent admission, retained/current reads, tampering, replay and revocation.
Its result does not qualify installed-host protection. The current verification
summary records exact executed commands, counts and limitations.

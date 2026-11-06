# Isolated Linux execution driver

This executable verifies signed fixture grants and connects the durable executor
journal to actual nftables apply/readback, packet probes, confirmation and
restrictive recovery. Its original signed-policy commands refuse execution outside
the guarded, loopback-only disposable lab. It is not a host installer or the
controller's production executor.

Use the supported runner from the repository root:

```sh
source scripts/dev-env.sh
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
```

The runner supplies a private fixture bundle and a separately pinned public-key
registry. Policy signing keys stay with the test-only fixture generator; the
driver has no policy-signing or human-approval command. Its separate read-only
collector can sign captured bytes with an explicitly provisioned lab observer
key. `LabApproval` is synthetic and cannot be treated as a WebAuthn proof.

The internal fixture CLI consists of `init` and `apply` with `--state-dir`,
`--bundle` and `--trust`; `observe`, `recover` and `status` use `--state-dir`,
`--operation-id` and `--trust`. `probe` also takes `--output`; `confirm` takes
`--confirmation`. All state and evidence paths are private lab files. The runner
owns their lifecycle; do not copy fixture keys or bundles into production state.

The complete [signed execution guide](../../docs/signed-linux-execution.md)
describes immutable artifacts, runtime expiry binding, journal/CAS behavior,
actual probe evidence and the limits of the separate recovery process. Unknown
state, expired recovery authority and unsupported bootstrap/clock cases do not
acquire new write authority. The product remains observe-only.

The core-access lab additionally pins compilation inputs in a separate closed
`reference-pin.json` (`fw.core-lab-reference-pin/v1`), carrying a positive decimal
revision, `production_authorized:false` and exact `LabReferences`. The synthetic
fixture administrator creates it before artifact construction. Both observation
challenge creation and proof verification read that file independently of bundle
references, rebuild both artifacts and compare their complete bytes. Capture
provenance records the pin and reference hashes plus expected/submitted artifact
hashes. The file belongs to the isolated evidence workflow, not the executor's
production trust registry. It is synthetic fixture input and does not establish
an OS-protected deployment authority. Driver initialization, apply and replay
retain their existing signed-material and trust-scope checks; this pin qualifies
neither those paths nor production execution.

## Read-only native evidence collector

Inside the same guarded disposable namespace, a separate purpose-scoped observer
key can sign an actual `nft -j list table` capture:

```sh
/lab/fw_linux_executor collect-evidence \
  --artifact /lab/evidence/artifact.json \
  --installation /lab/evidence/installation.json \
  --observer-key /lab/evidence/observer-key.json \
  --challenge /lab/evidence/challenge.json \
  --output /lab/evidence/proof.json
```

All directories and files must be private (`0700`/`0600`), owned by the executing
user and beneath `/lab`. Aliases, shared files and existing proof outputs are
refused. The command accepts no readback input: it always executes the fixed,
bounded native read inside the guarded loopback namespace. It writes only the new
private proof file; it does not install rules or mutate an executor journal.

The closed observer-key JSON object has `schema_version:"fw.lab-observer-key/v1"`,
`org_id`, `project_id`, `target_id`, positive decimal-string `observer_revision`,
integer Unix `not_before_unix`/`not_after_unix`, and `seed` as an array of 32 raw
Ed25519 seed bytes. This is a development observation key, never a policy signing
key. Provision its public key independently in the authority's lab-observer
registry. Keep its private seed out of logs, source control and command arguments.

The authority challenge must arrive through an authenticated protected transfer.
Before reading the key, the collector checks the challenge's exact scope,
artifact/installation hashes, current time and the actual boot/network namespace.
It then checks key identity/revision and samples clocks around the native capture.
Boot/namespace changes, time rollback, an excessive capture interval, expired
challenge/key and invalid installation bindings fail without publishing a proof.
The authority independently verifies the signature and recomputes correspondence;
UNKNOWN/MISMATCH captures remain useful negative evidence and never gain an
observed-state hash merely because their signature is valid.

The installation input declares the expected native bytes. Matching those bytes
does not prove their original installation provenance, journal approval or
historical policy authorization. A signature proves possession of the observer
key, not protected collector deployment. Every result remains development-only,
`production_qualified:false` and `dispatch_allowed:false`.

## Target bootstrap integration

The separate [target-confirmation profile](../../docs/target-authority-confirmation.md)
implements a bounded non-loopback management baseline, exact
owner-authorized bootstrap material, durable generation0 epoch/predecessor state,
native readback and fresh probes. It uses a dedicated development confirmation
receipt, not a policy grant or a reinterpretation of `f.receipt/v1`. The target
path supplies no arbitrary signed-payload or caller-PASS input. Inside its guarded
isolated profile, invoke `bootstrap-target --config FILE --bundle FILE`; only those
options are accepted. Private config fixes tenant/target/state, independent root
and target pin plus seed path. Fresh state must be absent; partial loss/legacy
grant journals refuse initialization. Same-config/boot/netns/journal generation0
rotation requires the exact confirmed predecessor and atomic full verified B
replacement. Key/boot recovery remains unsupported.

Historical exact retries return their original confirmation, with separate
`accepted_epoch`, `current_epoch`, `current_journal_state` and time-only
`challenge_unexpired`. PENDING/UNKNOWN cannot be hidden by an older receipt.
Every production permission stays false. Fresh target kernel/full-batch evidence
is recorded separately in the verification summary; existing loopback tests
cannot qualify this path or installed host support. Negative UDP distinguishes
a successful send followed by timeout from EPERM1 with zero sent bytes.

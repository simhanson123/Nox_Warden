# Fixed-window legacy bindings and precise core lab evidence

This follow-up starts at reviewed PR26 head
`3866ceaa2b86da3ea3653da338d433a23a02b283`, compared with PR25 merge
`a624a1e684a8fc0065ac4f4609101410f56c50bb`. The reviewed target tree is
`7f349ae2b22d1c19464454bcec8eb079d15614ef`. Historical review results below
do not validate the changed follow-up tree.

## Received evidence

The [complete supplied PR26 review](reviews/pr26-claude-review.md) is preserved
as 15,748 bytes, including 162 CRLF endings and opening progress notes, SHA256
`7f82e555c1c734c9592b7ec3ddf96a4c65891b18815a02e00b45c0c6a1cba37d`.
It reports no Medium-or-higher defect or blocker to continued development, two
Low findings, one informational finding, an existing design limitation and four
lab coverage gaps. It identifies F1 as required before opening core signing.

The external lead reviewer directly reproduced F1. Its parallel reviewers
reported additional planner counterexamples, schema14 fault/migration checks and
executor/API/UI tests. In particular, the external schema reviewer used an actual
older binary to create a schema13 database; the repository's populated migration
tests reconstruct the old schema around old-API rows. Those are distinct kinds
of evidence. The supplied private probes and temporary logs are not repository
regressions and are not claimed to have been rerun here.

The review reports local canonical checks, a 530-test shared-umask suite,
workspace binaries/examples, focused checks and browser/service smokes. Remote
PR CI42036443828 failed before execution because of a billing lock. The reviewer
had no managed Docker and marked Linux, signed Linux, core-access Linux and
native-evidence runtime checks NOT_RUN. Its static lab assessment is not a fresh
packet or kernel result. Earlier project lab passes are separate historical
evidence and do not verify this follow-up.

The review's `--lib window_migration` filter matched zero tests. The real module
filter is `--lib window_tests` (two tests at the reviewed baseline). Exit status
zero with zero executed tests is not a PASS. Fresh focused results must include
a nonzero executed count.

## Source assessment and correction contract

| Item | Assessment and resulting behavior |
| --- | --- |
| F1, Low | Baseline provenance-only registration did not consult an already retained request window; a shifted plan could be marked current beyond `E`. Provenance-only intervals now must fit any retained `[S,E)`. Before creating the first window, combined admission checks every existing binding of that request and atomically refuses an out-of-window legacy history. A full reviewed plan still requires the exact original interval, not merely containment. |
| F1, live use and history | New live cost/readiness requires that plan's complete retained core review and window. Window-less legacy original bytes, full-duration cost history, reservation snapshots and capacity accounting remain intact. Issued, UNKNOWN and unsigned-delivered work keeps its capacity. Reads, reopen and complete retained validation must preserve this distinction in both registration orders. No history is rewritten or given an inferred window. |
| F2, Low/informational | Baseline combined registration observed time before full closed plan/requirements validation. Structural validation now precedes the independent clock commit. Malformed plan or requirements objects cannot advance it. Well-formed attempts may still observe conservative time before later time, conflict or admission refusal; historical exact retries do not receive a new admission time. |
| F3, informational | Existing legacy evidence can intentionally gain the strict reviewed profile through complete combined validation. That path rechecks plan, requirements, full-state review, provenance and exact original window. It is useful migration behavior and is retained. The earlier categorical documentation that legacy evidence cannot qualify was too broad. Provenance import or schema migration alone still creates no reviewed qualification. |
| F4, existing trust boundary | Removing SQL guards, rewinding a clock and restoring the exact schema can produce a coherent older state that local validation accepts. This is not fixed by this batch. Local durable expiry protects against backward wall-clock samples while protected retained state is intact; it does not prove external monotonicity against a privileged database writer or whole-database rollback. |

The relevant baseline paths are
[`access_provenance.rs`](../crates/fw_authority/src/store/access_provenance.rs),
[`access_window.rs`](../crates/fw_authority/src/store/access_window.rs) and
[`signing_quota.rs`](../crates/fw_authority/src/store/signing_quota.rs).
No published migration001–014 or original schema/specification is rewritten.
No new migration is needed for these validation changes.

An additional internal review of the follow-up found a concurrent selection gap:
a provenance/window operation could initially select no window, skip observation,
then read a peer's newly registered first window in its final transaction. An
expired response in that interleaving would not itself persist the expiry floor.
Provenance registration/read and window read now compare initial and final
window selections and return `Conflict` for retry on a change. This is a new
internal finding and regression case, separate from Claude's private probes or
the received report's F1 reproduction.

F4 retains the existing deployment and trust boundary. A writer controlling both
a database and its local chain can rewind both. Such a writer need not be root.
Protected authority storage is a precondition; a deployment giving the controller
permission to rewrite the authority schema does not satisfy it. OS-account/ACL
separation remains unfinished, and this batch does not establish that deployment
boundary. Independently protected external anchoring and protected
authority deployment remain future work; extra local observation records alone
cannot establish that external monotonicity. [F_00](specs/F_00_시작안내.md)
points to the governing F_01 trust model:
[F_01 section 3](specs/F_01_제품_구현_기준.md) excludes administrator/root
and trust-root compromise. [F_09 section 3](specs/F_09_멀티플랫폼_설치_집행_명세.md)
also excludes VM snapshot rollback and privileged trust-base tampering and
requires re-enrollment/new epoch after restore. These exclusions do not relax
ordinary expiry, restart or conservative-clock requirements, and the root
exclusion alone does not resolve all SQL-writer attacks.

## Lab coverage corrections

The four gaps are supported by baseline source; the external reviewer could not
execute them in Docker. The follow-up must prove each check reaches its intended
condition and retains the original security deadlines:

| Gap | Required evidence |
| --- | --- |
| Early expiry could pass | Assert an independently derived lower bound on kernel token remaining lifetime, then positive new and established TCP samples near the original expiry and negative samples after `E`. Preserve the compiler's documented conservative early cutoff and the existing five-second installation budget. An `E−3` example cannot override that cutoff. |
| Signature case failed length validation | Use an exactly 64-byte forged Ed25519 signature and require the specific signature-verification refusal. A malformed-size signature is a codec test. |
| Refusal could fail for another reason | Require the exact bounded refusal code for each mutation, separately confirm the unchanged generation, operation/material state and owned table, and check a currently valid control. `production_authorized=true` is a trust-load refusal, reported separately from bundle cryptographic validation. |
| Bundle supplied its own reference | Supply a separate closed trusted lab reference input before constructing the bundle, then rebuild both complete baseline and candidate against it and compare exact artifacts/recovery references. Retain its hash/revision in observation metadata. A self-consistent mutated bundle reference must not become the observation comparison authority. |

The separate file is `reference-pin.json`, with schema
`fw.core-lab-reference-pin/v1`, a positive canonical revision,
`production_authorized=false` and `LabReferences`. Its scope is lab observation
evidence compilation. It does not introduce a new external-pin check in driver
initialization/apply/replay; those retain the existing artifact and grant/trust
validation paths. Observation metadata labels its source as
`separate-trusted-lab-input` and records pin/reference hashes, revision and
expected/submitted artifact hashes. This remains synthetic local trust.

The near-expiry positive target is
`E − (uncertainty + elapsed time + commit budget) − 2 seconds`: `E−8` for this
fixture's one-second uncertainty, zero elapsed binding time and unchanged
five-second budget. This retains
[F_04 section 8](specs/F_04_정책컴파일러_집행_복구_명세.md)'s explicit early-cutoff
model. The extra two seconds are a bounded packet-sampling margin,
separate from the native-process reserve. Token lifetime bounds use the original
expiry, binding and observation clocks, with one second of nftables integer
representation tolerance. An earlier expiry outside that allowed conservative
bound must fail even if all post-expiry probes are blocked.

All lab approval, trust and compilation evidence remains explicitly synthetic
and `production_authorized=false`. Test keys, virtual authenticators and packet
success cannot open production signing or dispatch. Anonymous multiport
`ct.proto-dst` readback on pinned nftables1.0.6 remains unqualified; the scalar
companion fixture does not establish support for that native shape.

## Reproduction and verification

The permanent [window regressions](../crates/fw_authority/tests/core_access_window.rs)
include the three independently reproduced baseline cases:

| Exact test name | Reviewed production source | Corrected focused run |
| --- | --- | --- |
| `legacy_import_cannot_escape_an_existing_fixed_request_window` | Failed assertion: outside binding accepted | Passed |
| `first_window_refuses_preexisting_outside_legacy_history_atomically` | Failed assertion: inconsistent first window accepted | Passed |
| `malformed_closed_plan_never_commits_a_clock_observation` | Failed assertion: clock advanced | Passed |

Each baseline invocation ran one newly authored regression against an isolated
copy of `3866ceaa2b86da3ea3653da338d433a23a02b283` production source and exited
101 at its expected assertion, with no compilation failure. These are new public
API reproductions, not the external reviewer's unavailable private probes. The
corrected file also covers contained legacy history, strict explicit upgrade,
request/lease aliases and guard-restored inconsistent history. Run an exact case
with `cargo test --locked -p fw_authority --test core_access_window TEST_NAME -- --exact`.

Run from the repository root with the pinned environment:

```sh
source scripts/dev-env.sh
cargo test --locked -p fw_authority --test core_access_window --test core_access_admin
cargo test --locked -p fw_authority --test core_access_store --test core_access_provenance
cargo test --locked -p fw_authority --lib core_access_cost_tests
cargo test --locked -p fw_authority --lib window_tests
cargo test --locked -p fw_linux_executor
cargo test --locked -p fw_testlab --bin fw_signed_lab_fixture reference_pin_tests
python native/linux/test_core_snapshot_runner.py
```

Use the managed disposable runner for native checks, after building the signed
lab's pinned image:

```sh
python scripts/core-access-linux-lab.py --skip-image-build --report reports/core-access-linux-lab.json
```

These are reproducible commands, not a record that this document's author ran
them. New exact commands/counts, independent internal review, canonical checks
and runtime outcomes belong in [reports](../reports/README.md) and the
[ledger](../reports/task-ledger.json). A skipped runtime remains NOT_RUN. Remote
CI status and each exact head/merge must be recorded separately from local
results; the earlier billing failure is not a new CI pass.

## Remaining product path

Production authority and the three-OS release remain unfinished.
The next dependency is protected workload/delegation and bootstrap authority,
then protected target epoch/generation initialization, independently deployed
signer/dispatch and authenticated completion. External audit anchoring and
restore/re-enrollment must retain the same trust boundary. Linux still needs
installed-host management connectivity, watchdog/reboot/physical-NIC/coexistence
and common-host qualification. Windows WFP with the required callout and macOS
Network Extension still need native implementations, signed platform runners
and kernel qualification. Signed install/update/uninstall, recovery, complete
operator flows and release acceptance remain required by M03, M04L/W/M and
M05–M10. These dependencies have different costs; neither a percentage nor a
completion date is justified by the current test totals.

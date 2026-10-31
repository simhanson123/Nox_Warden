# Signed execution in the isolated Linux lab

This development profile connects signature verification and the durable executor
journal to actual nftables application, semantic readback, packet probes and
restrictive recovery. It runs only in a disposable loopback network namespace.
The management application remains observe-only and cannot dispatch this driver.

The lab checks real Ed25519 signatures against a separately configured trust
registry. Its plans, approvals and signing authority are **synthetic test
fixtures**. They do not represent a human WebAuthn approval, authority bootstrap,
qualified target capability, workload identity or production management probe.
The original supplied contracts remain unchanged.

## Run the suite

From the repository root with the pinned toolchain active and the managed local
Docker daemon available:

```sh
source scripts/dev-env.sh
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
```

The runner builds `fw_linux_executor` and the test-only `fw_signed_lab_fixture`,
then transfers them into the same pinned Debian lab image used by the existing
[packet suite](../native/linux/README.md). Runtime networking is `none`; only
`CAP_NET_ADMIN` is added after dropping all capabilities. There are no host
mounts, published ports, devices or privileged-container flags. The root
filesystem is read-only and `/lab` is a private, disposable tmpfs. The exact
container is removed on success and failure.

The native driver independently checks the lab marker, the caller's different
network namespace, loopback-only topology and its persisted boot/scope bindings.
It uses a fixed nft executable with bounded I/O and execution time. A marker file
is an accident-prevention guard, not a security boundary against a compromised
root user. Use the runner to create the complete isolated fixture; the driver is
not an installer or a command for changing the active host firewall.

`--skip-image-build` reuses a previously built local lab image. The report still
records its exact image ID. Source and binary hashes, namespace isolation,
executed assertions, packet counts and cleanup status are recorded without
private signing keys. Startup failures are `NOT_RUN` with exit code 2; executed
assertion or cleanup failures are nonzero. Only a completed suite reports `PASS`.
Generated reports are ignored by Git. CI retains selected reports for seven days.

## Immutable objects and runtime binding

The closed Rust types in
[`fw_backend_linux::portable`](../crates/fw_backend_linux/src/portable.rs) and
[`fw_linux_executor`](../crates/fw_linux_executor/src/lib.rs) define this
experimental profile. A client cannot add arbitrary native commands to an
artifact: binding rebuilds the compiler output and checks exact correspondence.

| Object | Binding and purpose |
| --- | --- |
| Portable artifact | Normalized full `StateIr`, resolved lab baseline/source/capability/scope references, deterministic native template and absolute token deadlines. Runtime timeouts are absent from this object. |
| Installation | Portable artifact hash, native artifact hash, operation/grant identity and the sampled boot, UTC, `CLOCK_BOOTTIME` and namespace context. Relative token lifetimes are derived from original deadlines with uncertainty, elapsed-time and commit-budget deductions. |
| Execution bundle | Exact signed grant, lab plan and synthetic approval, previous/candidate/recovery artifacts and the previous installation. Plan hashing excludes the final approval to avoid a circular dependency. |
| Trust registry | Locally pinned public keys with tenant, target, purpose, epoch and validity. It is separate from the submitted execution bundle; a grant cannot introduce the key that authorizes itself. |
| Journal material | Signed grant, complete state/artifact/recovery objects, installation and scope bindings stored before a native submission. Recovery is fenced by this persisted material and the generation high-water mark. |
| Probe report | Actual bounded TCP/UDP nonce outcomes selected by the signed lab plan, operation/grant/generation/state bindings and an actual readback hash. Confirmation resolves the locally collected report, not a submitted success flag. |

The isolated baseline has no network management paths and defaults to business
traffic drop. Assets resolve only to the loopback scope. These are explicit lab
objects, not fabricated production baseline or capability attestations. The
initial portable profile rejects nonempty tombstone sets and conflicting deny
revisions rather than guessing recovery authority.

The policy hash is the canonical full normalized `StateIr` hash, including
associations and reference hashes. The signed portable artifact remains stable
while time passes. Relative timeouts are derived only for a newly authorized
submission; retries and observations use the saved installation. Readback checks
native rules and remaining token bounds against the original boot/monotonic
context. A single snapshot cannot prove that no shorter-lived token refresh
occurred in the past.

## Apply, confirm and recover

The fixture first installs a known default-deny baseline and the driver reads
that actual kernel state during initialization. An empty ruleset is not accepted
as proof of default deny.

For a new operation, the driver checks trusted signature purpose and validity,
exact tenant/target/epoch/generation and object bindings, then re-reads the
baseline. It persists complete material and a separate recovery child's readiness
acknowledgement before marking submission `UNKNOWN`. It replaces only the owned
table in one nft transaction. A command exit alone cannot make the operation
active: actual semantic readback is required to reach `VERIFYING`.

The grant's `not_after` bounds the start of native execution; policy absolute
expiry is a separate deadline. The driver rechecks authority immediately before
starting the nft command and bounds that process to two seconds. This does not
guarantee that a kernel transaction completes before every authority deadline.

The probe command collects real packet outcomes and stores its report privately.
A separate fixture signer signs a confirmation bound to that report and the
exact operation. Confirmation requires fresh matching readback, the exact local
report, a valid signature and the durable deadline/CAS. `CONFIRMED` records that
this lab operation passed those checks; it does not promote a product target to
supported or establish that a temporary lease lasts beyond its original expiry.

The separate recovery process can take the journal lock after normal command
completion or a command crash. Acquisition waits at most five seconds for actual
OS lock contention; other journal errors fail immediately. The driver reloads
and pins current trust after obtaining ownership. After the confirmation deadline it rechecks the
operation, generation, actual state, signed recovery scope/artifact and validity,
then claims recovery through the same durable state machine as confirmation.
Recovery authority is checked again before native command submission.
The initial recovery projection removes all business allows and preserves the
previous/candidate deny restrictions and the approved lab baseline. It never
restores a raw historical ruleset or reduces the generation high-water mark.
Actual matching readback is required before recording `ROLLED_BACK`. A later
signed generation resolves its previous installation from the confirmed or
recovered journal state and re-reads that baseline before changing anything.
An older recovery process cannot overwrite it. If a process is killed after the
recovery write but before recording completion, the next recovery attempt checks
the actual restored state and completes its journal entry without reinstalling
rules. Entries created by the earlier journal-only primitive cannot be upgraded
into native execution by attaching material after acceptance.

Recovery authority is bounded. When it is missing or expired, this profile has
no unsigned quarantine fallback and makes no guessed write. Unknown or drifted
state blocks new widening changes. Existing kernel expiry remains in force.
The process-lifetime writer lock can block the recovery child if its owner is
permanently paused or hung, so this is **timeout/crash recovery for bounded
commands**, not a qualified independent watchdog for all executor failures.
Boot restoration and an independently authorized production quarantine path are
still required.

## Remaining product work

The controller's approval and deployment endpoints remain unsupported. Completing
the product still requires plan-bound WebAuthn approval and current-role
verification, immutable approval storage, independent signer jobs and quota revalidation, authority
bootstrap, workload bindings and authenticated policy transport. No registered
`unverified` device is silently promoted to a dispatchable target. Local-owner
[passkey login](passkey-login.md) identifies the operator but does not create
policy approval or signer authority.

The lab does not qualify physical NICs, management-path survival, ICMP/fragments,
PMTU, arbitrary clock failures, reboot/install/upgrade behavior, or coexistence
with other firewall managers. Windows WFP/callout and macOS Network Extension
implementations and signed installers remain separate work. See the
[platform status](platform-support.md) and [verification summary](../reports/README.md).

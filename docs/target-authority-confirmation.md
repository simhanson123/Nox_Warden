# Isolated target authority confirmation

This M03/M04L/M05 work follows the focused S-1 durability correction on
`feat/target-authority-confirmation`, based on PR27 head
`5fc576f672c2e0671164b73a667e3452b99ea82a`. It implements the contracts below;
source implementation and actual validation are separate. Executed evidence is in
[reports](../reports/README.md), and review corrections are in the
[PR27 follow-up](pr27-follow-up.md).

The original F12 contracts have no bootstrap-specific target receipt shape.
This implementation defines an explicit `fw.*` development profile instead of
reinterpreting the grant-specific `f.receipt/v1`. Original specifications,
published SQL001–015 and old signed/history bytes remain unchanged.

Schema16 separates target confirmation, registry, transport and observer keys by
their actual public-key bytes within an organization. Their existing fingerprint
encodings remain role-specific and unchanged. A schema15 database with conflicting
key-role assignments can therefore require recovery before migration: the upgrade
refuses that state and preserves the original database and its private backup.
This blocks the whole database, including unaffected tenants, from schema16
operation. Retired/revoked assignments remain in the conflict check. There is no
automatic deletion, relabeling or authority-preserving repair of that history.

## Exact development contracts

| Object | Contract |
| --- | --- |
| Management baseline | `fw.isolated-bootstrap-management-baseline/v1`; tenant/target, namespace, interface name/index, private/documentation IPv4 point-to-point `/30`, peer, management TCP and positive/negative UDP ports, independently configured probe-peer public key |
| Capability | `fw.isolated-bootstrap-capability/v1`; Linux/nftables, `isolated-linux-bootstrap-v1`, kernel/architecture/nft version; not production qualification |
| Compiled program | `fw.isolated-bootstrap-nft-program/v1`; independently recomputed management-baseline/capability hashes and exact owned-table nft JSON |
| Target key pin | `fw.target-bootstrap-key-pin/v1`; tenant/target/key/profile, canonical uint64 revision, public key and exclusive validity interval |
| Challenge | `fw.target-bootstrap-challenge/v1`; exact manifest/authorization/B/capability/program hashes, old/new epoch, generation0 and previous confirmation, key pin identity/revision/fingerprint, fresh nonce and exclusive deadline |
| Target bundle | `fw.target-bootstrap-bundle/v1`; exact manifest/authorization/proofs/challenge/baseline/capability; independently configured root and private keys are outside the bundle |
| Confirmation payload | `fw.target-bootstrap-confirmation/v1`; exact challenge, durable journal/boot/namespace identity, accepted epoch, generation0, wall/monotonic observation bracket, raw readback and three probe observations |
| Confirmation envelope | `fw.target-bootstrap-confirmation-envelope/v1`; canonical DSSE payload type `application/vnd.fw.target-bootstrap-confirmation.v1+json`, exactly one authoritative target signature |

The management-baseline hash is a separate reference from full StateIR. An old
loopback `PortableArtifact`/`LabBaseline` with empty management paths cannot be
relabeled as this non-loopback baseline. The bounded compiler emits default-drop
input/output/forward chains in one tenant/target-owned table, allowing only the
specified outbound management TCP/positive UDP path and exact conntrack replies.
There are no business allows, arbitrary nft input or broad established-flow
exception. The target must check its actual namespace/interface/address context;
validating a supplied hash alone does not measure that context.

Readback is compared to a fresh compilation. Only known nft runtime metadata and
equivalent TCP/UDP spelling are normalized. Exact IPv4/typed transport selectors
also establish the redundant family/protocol guards omitted by nftables1.0.6.
Connection protocol is direction-independent; original IPv4 connection addresses
retain that meaning when nft omits their family. Other direction/family/tuple
changes remain distinct. Extra objects, fields,
expressions, changed rules or ordering within a chain refuse correspondence.
The management profile is deliberately narrower than complete `common-host-v1`
and does not qualify installed Linux support.

The challenge parser is bounded to 8 KiB and at most 300 seconds. Confirmation
types are bounded to 256 KiB, compiled programs/readback to 128 KiB. Nonces are canonical
32-byte base64, Ed25519 signatures are 64 bytes, and epoch/revision/monotonic
counters are canonical uint64 strings. Required nullable fields must be present.
Independent source review identified a preallocation-budget issue in these new
typed APIs. The source correction checks depth/float constraints and a nonallocating
writer budget before canonical allocation, with exact encoded length checks before
base64 decoding. Boundary/depth/equivalence regressions cover typed admission;
their executed results are recorded separately. Bounded wire parsing alone does
not establish that typed-object allocation contract.

## What a receipt proves

The target independently verifies the exact owner-authorized bootstrap material
against its configured root and recompiles the approved baseline. Actual WebAuthn
possession/current-owner verification belongs to the authority signer; a supplied
proof object or proof hash alone does not establish consent.

The target journal must durably accept the exact epoch/predecessor before
reporting confirmation. The signed payload binds the entire retained challenge,
including the management baseline/capability/program hashes and target key pin.
Observation times must follow acceptance, fit the challenge/key intervals and
agree with bounded monotonic elapsed time. Output loss and retries must converge
on the retained exact operation instead of creating a new epoch or refreshing
authority.

Probe requests use `fw.bootstrap-probe-request/v1`, the challenge hash and a
distinct fresh nonce. Management TCP and positive UDP replies are signed under
the baseline's probe-peer key with the `fw.bootstrap-probe-peer/ed25519/v1`
domain. Their exact request hashes and byte counts are checked. Negative UDP is
a signed observation, not cryptographic proof of firewall blocking. Required
nullable `os_error` distinguishes an actual successful send followed by timeout
(null error) from `local_send_denied` (Linux EPERM1, zero bytes sent/received,
no response). Other send errors fail; positive replies require null error. The lab separately proves the negative listener is
live before initial baseline and checks the peer side across rotation. That lab
acceptance control is not a product payload field or a caller-supplied PASS.

The profile supports generation0 rotation when the actual confirmed predecessor
and latest pending authority agree and atomic baseline replacement can be
verified. It does not derive a durable predecessor from a local pending head or
an unconfirmed legacy chain. Existing signing heads, generation fences and
issued/UNKNOWN obligations cannot be reset or refunded to create a new genesis.

## Runtime and operator interfaces

The isolated target command is:

```sh
fw_linux_executor bootstrap-target --config FILE --bundle FILE
```

Only those two options are accepted. The private
`fw.isolated-target-bootstrap-config/v1` contains `org_id`, `project_id`,
`target_id`, `state_dir`, independently configured `bootstrap_trust`,
`target_key_pin` and `seed_file` (exactly 32 private seed bytes). There is no
caller-PASS, raw readback/probe input or crash-control option. The bundle carries
the public exact approved material; the runtime collects observations itself.

Fresh `state_dir` must be absent. It creates a private anchor and separate
`bootstrap.sqlite3`; an existing legacy grant journal/`initial.json`, a missing
database in existing state, or incompatible anchor refuses initialization.
Marker/config/bundle/seed/anchor descriptors are opened before SQLite and retained
for bounded reads; later path checks are metadata-only. The separate journal
preserves accepted epochs, receipt bytes and clock floors. Interrupted pending
work becomes UNKNOWN and is not silently reapplied. Original grant journals stay
unchanged.

The anchor fixes protected config and boot identity. Supported generation0 epoch
rotation uses the same config/boot/netns/journal and a new approved baseline;
changing a target/bootstrap root key or boot in existing state is explicitly
unsupported recovery. The authority's key-pin rotation/revocation APIs do not
complete native key/boot recovery or installed key lifecycle.

The result `fw.target-bootstrap-result/v1` contains the full confirmation/hash,
`replayed`, `accepted_epoch`, `current_epoch`, `current_journal_state`,
`highest_generation` and time-only `challenge_unexpired`. A historical exact
receipt can be returned after a later epoch or UNKNOWN operation; the separate
current fields prevent that receipt from concealing current uncertainty. Result
state is `target_confirmed_pending_qualification`, with production signing and
dispatch false. Preserve private output and retry exact material after output
loss; returning history never authorizes another native write.
The native command checks stdout writes and flushes after closing its journal.
An output failure returns `OUTPUT_FAILED` with exit1; it does not undo a committed
receipt. The same exact input retrieves the retained receipt on retry.

Trusted `fw_authority_admin` commands below take database/org/project, strict
stdin bounded to 256 KiB, and no private key:

| Command | Input / output |
| --- | --- |
| `pin-target-bootstrap-key` | `{pin,expected_revision}` for the independently verified typed target key pin and its CAS |
| `revoke-target-bootstrap-key` | `{target_id,revision}`; retain revocation/history |
| `challenge-target-bootstrap` | `{manifest_id,expected_target_revision,baseline,capability}` → exact `TargetBootstrapBundle` |
| `import-target-bootstrap-confirmation` | Direct `SignedTargetBootstrapConfirmation` envelope; no extra wrapper |
| `read-target-bootstrap-status` | `{target_id}` → `fw.target-bootstrap-query/v1`, status or null and false policy flags |

Key-pin revision and `expected_target_revision` (the confirmation-head CAS) are
different counters. Actual baseline/capability hashes must enter the immutable
manifest before the owner ceremony. The fixture's `--target-evidence PATH` hook
accepts only `{baseline,capability}` for that purpose; adding new hashes after
approval is not a valid workflow. These interfaces share retained authority
checks with direct API admission; CLI presence alone does not prove execution.

The reproducible isolated runner is:

```sh
python scripts/target-bootstrap-linux-lab.py --report reports/target-bootstrap-linux-lab.json
```

It uses the pinned Linux lab image, a disposable container with no external network or
host mounts, and private network namespaces connected only to one another. The
container's initial network namespace receives the fixed Docker sysctl
`net.netfilter.nf_conntrack_tcp_loose=0` and is retained as the target. Separate
coordinator and peer namespaces are created and checked independently at value 1.
The fixture explicitly enters the coordinator namespace; target execution enters
the retained target namespace and reduces its capabilities to `CAP_NET_ADMIN`.
No private mount or inner sysctl write is needed. Default security profiles and
the seven setup capabilities remain unchanged; peer and signer processes use
separate identities. Native packet
observations and two accepted target confirmations are required for a passing
report. The required CI step retains the report for seven days. A configured CI
step is not an executed check; current results remain in the verification summary.

## Current evidence and versioned readiness

`fw.target-bootstrap-status/v1` retains accepted receipt/epoch/revision/hash/times
even after expiry/revocation. `current_confirmation_eligibility` separately
rechecks present trust/head/freshness; the state label alone supplies no current
authority. Every signing/dispatch flag remains false.

Use explicit `read-signing-readiness-v3` with its existing approval-origin review
verifier, or HTTP `/authority/v3/plans/:id/signing-readiness`. V3 extends the v2
fields with the exact current bootstrap authorization hash and bounded
`target_bootstrap` evidence, including `current_for_plan`. Published v1/v2 wire
shapes remain unchanged before accepted target history. Once that history exists,
even if expired, legacy projection refuses with HTTP409/CLI1
`SIGNING_READINESS_V3_REQUIRED`. The UI requests/parses v3 explicitly, with no
legacy fallback. A current target receipt and `current_for_plan` still do not
qualify the build/native backend or grant policy permission.

## Authority and qualification boundary

The authority must recheck its durable floor, target/key trust, exact challenge,
current owner/bootstrap material and predecessor in the final admission
transaction. Target receipt retention, current head and audit must commit
atomically. Exact retry acknowledges the retained result; it does not renew the
original lease or grant any dispatch permission.

Production build/compiler identity, native observer/baseline qualification,
policy-signer key trust and actual workload-source attestation remain independent
requirements. Shared canonical gates and readiness v3 expose contextual reasons;
published readiness v1/v2 remain exact legacy projections. A successful
development target confirmation still returns policy signing/dispatch false.

Actual target integration and full-batch results are recorded separately in
[verification](../reports/README.md). See [remaining acceptance](remaining-work.md)
for authenticated dispatch/completion, installed Linux lifecycle, Windows WFP,
macOS Network Extension and release work.

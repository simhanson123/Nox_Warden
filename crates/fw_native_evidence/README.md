# Development compilation and native observation evidence

This crate independently rebuilds the isolated Linux compiler artifacts from a
retained semantic policy review and explicitly pinned reference bytes, then
verifies purpose-bound Ed25519 signatures over bounded raw observations. It runs
no operating-system command, consumes no challenge, and grants no policy signing
or dispatch authority. An authorized producer signature authenticates bytes;
it does not prove that those bytes were captured from a kernel.

## Compilation

`compile_evidence(plan, review, references)` verifies `PolicyReviewEvidence`,
resolves complete before/after `StateIr` references and calls the deterministic
portable compiler for each state. Organization/project/target bindings and
`plan.artifact_hash` must match the exact rebuilt candidate artifact. The plan's
`candidate_state_ref` identifies StateIR bytes, a different object from the
portable compiler artifact. The resulting opaque `VerifiedCompilation` retains
canonical plan/review/reference hashes and both complete artifacts.

The embedding authority must first admit the complete closed plan contract,
authenticate reference provisioning and recheck current revisions before storing
the result. This crate's semantic review does not supply the full plan-admission
or human/quorum boundary. It does not independently attest the plan's declared
`compiler_hash` or `validator_hash` as build digests. Rebuilding with the local
compiler establishes deterministic correspondence, not binary provenance.

The supported references are explicitly unqualified isolated-loopback laboratory
objects: `lo`, conntrack zone zero, no management paths, and
`production_qualified:false`. Their `fw.isolated-lab-capability/v1` hash remains
distinct from the authenticated device report's `f.target-capability/v1` hash.
Neither can be substituted for the other or promoted into a production PASS
gate. Canonical compilation evidence is bounded at 1 MiB.

## Observation protocol

The closed schemas are:

- `fw.lab-native-observation-challenge/v1`
- `fw.lab-native-observation-payload/v1`
- `fw.lab-native-observation-proof/v1`

The authority challenge binds its ID, tenant/target, explicitly scoped observer
key fingerprint/revision, reference revision, compilation hash, separate metadata
receipt/report hashes, baseline state, expected prior observation head, epoch,
generation, baseline/candidate artifact role and exact artifact/installation
hashes. It contains a 32-byte random nonce and canonical UTC times with an
exclusive maximum 300-second lifetime. Counters use canonical decimal strings.
Challenge issuance and current-state CAS are authority-store responsibilities.

The payload contains the exact `Installation`, runtime `ObservationContext`, raw
nft JSON and mandatory `production_qualified:false`. Canonical payload bytes are
encoded with unpadded base64url. The Ed25519 signature covers the NUL-terminated
domain `fw.lab-native-observation/ed25519/v1`, then canonical JSON containing the
proof schema, complete challenge, challenge hash, payload hash and byte length.
Key fingerprints are canonical Ed25519 SPKI SHA-256, shared with metadata, but
observer-purpose authorization is independently provisioned.

`sign_observation` checks time, observer key and expected installation bindings.
Its caller must authenticate the challenge transfer and collect the claimed
capture. It deliberately permits signing a capture that later compares as
UNKNOWN/MISMATCH, so negative evidence need not disappear. Merely signing JSON
does not make its content true.

`verify_observation` resolves the expected challenge/key/artifact from trusted
caller context, verifies the strict signature and original bytes, reconstructs
the exact installation, and independently executes the bounded semantic readback
verifier. Boot, namespace and wall/monotonic correspondence remain checked by the
existing native verifier. Only MATCH carries an observed state hash;
UNKNOWN/MISMATCH always carry none. Even MATCH remains lab-only correspondence,
not proof of producer isolation, absence of other tables, historical token
refreshes, or qualified host protection.

Sizes are bounded at 4 KiB per challenge, 2 MiB per payload and 3 MiB per proof.
New wire objects reject duplicate/unknown fields, unsafe integers, floats,
noncanonical signed payloads, overdeep values and alternate base64 encodings.
Observation time must be at or after challenge issuance and no later than
admission. Effective validity ends at the earlier challenge or observer-trust
deadline; the store must additionally clip to current metadata/reference/plan
validity and atomically consume with proof, head and mandatory audit. Exact
historical verification uses original admission time and never renews authority.

Run `cargo test --locked -p fw_native_evidence` for actual signature, deterministic
compilation, binding substitutions, negative correspondence and bounds tests.
These pure tests use synthetic captures; actual kernel collection belongs to the
separate disposable Linux process suite.

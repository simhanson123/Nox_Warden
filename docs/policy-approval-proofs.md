# Policy approval proof primitives

The authority library can bind a WebAuthn assertion to one immutable policy plan
or authority-bootstrap subject. This is a cryptographic building block: the
controller still refuses approval HTTP routes, and the application remains in
observe mode. Local-owner login and CLI authorization do not approve a policy.
The separate [authority store](authority-store.md) adds durable one-use admission
and retained verification for plan decisions, using explicitly provisioned
authority credentials and roles. It does not expose the human review workflow.

## Immutable challenge

`ApprovalChallenge` uses the closed `fw.approval-challenge-payload/v1` payload.
The authority supplies the resolved context; a caller-provided role or hash is
not evidence that the caller is authorized. The payload binds:

- Organization, project and principal IDs, plus a server-generated challenge ID
  and 32-byte cryptographically random nonce.
- Either a `plan` subject with exact `plan_kind`, `plan_id` and `plan_hash`, or an
  `authority_bootstrap` subject with `manifest_id` and `subject_hash`. Bootstrap
  is a separate subject type and permits only the `owner` role.
- The immutable requirements hash, `approve` or `reject` decision, and one of
  `owner`, `network_reviewer`, `service_reviewer` or `security_reviewer`.
- The configured RP ID and exact origin, issuance, expiry and subject validity.

Plans are limited to `add_access_lease` and `policy_change`. Challenges expire at
the earlier of issuance plus 300 seconds and subject expiry; the expiry instant
is excluded. The current verifier supports the development `localhost` RP and
exact configured HTTP origin, including its port.

Canonicalization uses the repository's closed ASCII-property/integer profile.
Retained payload admission rejects unknown or duplicate fields, invalid typed
references and noncanonical nonce encoding, with an 8 KiB input bound. Parsing
recomputes cached canonical bytes and hashes; it does not establish provenance.

The WebAuthn challenge is the following 32-byte digest. Each domain includes its
trailing zero byte:

| Subject | Digest input |
| --- | --- |
| Plan | `fw.approval.plan-challenge.v1\0` followed by canonical payload bytes |
| Authority bootstrap | `fw.approval.authority-bootstrap-challenge.v1\0` followed by canonical payload bytes |

The digest algorithm is SHA-256. The existing plan response exposes the hash of
only the canonical payload as `challenge_payload_hash`.
Bootstrap has no fabricated `PlanRef` or plan-challenge response. Before proof
verification, `validate_context` compares all bound context, RP and origin fields
against the supplied current authority inputs and checks the validity interval.

## Bound WebAuthn verification

`fw_webauthn` creates a separate bound authentication ceremony with the derived
challenge. Browser options and the library's retained verification state use the
same challenge at creation. The adapter verifies the authenticator signature,
exact challenge and origin, RP hash, user presence/verification and current
credential snapshot. Original signed `clientDataJSON` bytes are preserved.
The bound ceremony has its own closed state schema and checks the caller's
expected digest as well as the response challenge; ordinary login state cannot
be substituted for it. The supplied credential must come from trusted current
authority storage, not the browser.

This uses pinned `webauthn-rs` 0.5.4 with a narrow local patch exposing
application-derived authentication challenges. The upstream verifier remains
responsible for WebAuthn cryptography. Ordinary login keeps its random-challenge
path. See the [dependency and source review](passkey-dependencies.md) for the
patched packages, upstream provenance, licenses and reproduction details.

The authority bridge exposes `begin_approval_proof` and `finish_approval_proof`.
Both receive the issued challenge and freshly resolved context. Begin returns
browser options and private server state. Finish rechecks context and time,
verifies the bound assertion and returns an opaque `VerifiedBoundAssertion`
containing the challenge, original assertion fields, updated credential and
verification time. This result has no public constructor and does not implement
a permissive production `ProofVerifier`.

These authority APIs use the default-enabled `approval-proofs` Cargo feature.
The native executor and lab consumers disable it, so approval ceremony code and
its WebAuthn/OpenSSL dependencies are not added to their grant-verification builds.

## Durable plan admission and remaining integration

A valid assertion proves a credential signed the supplied challenge. It does not
by itself prove informed human consent, current role membership or permission to
sign a firewall grant. `AuthorityStore` resolves its own stored plan,
requirements, active credential and scoped role. It atomically verifies and
consumes a plan challenge, updates the credential, retains original proof
evidence and records an immutable decision and audit event. Exact successful
retries return the same result without renewing it. Retained proof verification
uses original pre-authentication state and admission time, together with current
key identity, revocation, role and plan checks.

Credential pinning, principal provisioning, role grants and plan registration
remain privileged inputs from a trusted embedding authority. There is no
automatic trust transfer from the controller's login database. The following
remain unimplemented:

- Approval HTTP endpoints and a human-facing immutable plan review ceremony.
- Production out-of-band identity and credential enrollment, authenticated
  authority IPC and independent verification of referenced plan artifacts/gates.
- Durable authority-bootstrap admission, quorum/`ApprovalSet` aggregation and
  signing jobs linked to current authority and quota.
- A separate authority/signer daemon, protected keys and authenticated IPC.
- Production authority bootstrap, authenticated host dispatch and the complete
  approval → application → expiry/recovery workflow.

The local login database is not an independently protected signer credential
registry. `finish_approval_proof` remains only a cryptographic primitive; callers
must use the authority admission transaction for a durable decision. A separate
SQLite file does not establish OS-process isolation, and a recorded decision
does not grant signing or execution authority. Repeated verification of a
retained proof does not issue another decision or consume another challenge.

## Verification scope

Run the focused suites from the repository root:

```sh
cargo test -p fw_authority -p fw_webauthn --locked
```

The tests exercise real WebAuthn signature verification with software-generated
authenticator responses and immutable-context counterexamples. Software and CDP
virtual authenticators do not establish human consent, physical-key support or
hardware attestation. Existing browser login checks exercise a separate local
authentication workflow; isolated Linux packet checks use synthetic authority
fixtures. Neither completes the production approval path.

See the [verification summary](../reports/README.md) for confirmed results and
the [implementation overview](implementation.md) for the broader release boundary.

# Portable target metadata evidence

This crate authenticates a bounded `f.target-capability/v1` report using the
device's Ed25519 transport key and an independently issued authority challenge.
It does not grant policy authority, prove native enforcement, attest the machine,
verify an X.509 chain or consume a challenge. Protected authority storage supplies
the pinned key, tenant, target, certificate binding, revision and revocation state.

The development challenge (`fw.target-metadata-challenge/v1`) binds a unique
challenge ID, organization/project/target IDs, positive decimal key revision,
SPKI and certificate SHA-256 fingerprints, 32-byte random nonce and canonical UTC
issue/expiry times. Its lifetime is at most 300 seconds. An unsigned challenge
file must reach the agent through an explicitly authenticated, protected local
transfer; neither JSON parsing nor its claimed identity authenticates its issuer.
The agent must compare all enrollment bindings before signing.

The proof (`fw.target-metadata-proof/v1`) contains the challenge, base64url encoded
exact canonical report bytes, and a base64url Ed25519 signature. Both encodings
are unpadded and canonical. The signature covers the fixed NUL-terminated domain
`fw.target-metadata-proof/ed25519/v1`, followed by canonical JSON containing the
proof schema, entire challenge, its hash, the report hash and byte length. Public
key fingerprints use Ed25519 SubjectPublicKeyInfo DER, matching enrollment.

Admission rejects malformed/duplicate/unknown fields, floating-point or unsafe
integers, noncanonical reports, weak/noncanonical public keys, altered signatures,
identity/purpose substitutions and out-of-window timestamps. Reports must be
measured at or after challenge issuance and no later than admission. They last
at most 300 seconds and may claim only unverified or unsupported enforcement
features with no qualified profiles. The retained current-evidence deadline is
the minimum of report expiry, challenge expiry and the trusted key/certificate
deadline. Every bound is exclusive at expiry. Challenges are limited to 4 KiB,
reports to 64 KiB and proof envelopes to 128 KiB.

`verify_report` returns opaque authenticated metadata. The authority must verify
the original challenge from its own storage, recheck current pin/certificate
validity and revocation, and atomically consume the challenge with the immutable
proof, current report and mandatory audit. Retained historical cryptographic
verification uses the original admission time; it does not renew the current
deadline or restore a revoked key. Identical retries must acknowledge the same
history without issuing new authority. No result from this crate is a verified
policy grant or an enforcement qualification result.

Run `cargo test --locked -p fw_target_evidence` for real Ed25519 signature,
OpenSSL SPKI parity, strict parsing, substitution and time-bound regressions.

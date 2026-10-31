# Passkey dependency review

The passkey adapter pins `webauthn-rs` **0.5.4** and uses its
registration/authentication verifier. Its matching protocol, core,
attestation-CA and base64 support packages are also 0.5.4. Two packages,
`webauthn-rs` and `webauthn-rs-core`, are now copied from those exact published
archives under `vendor/` and selected by Cargo path patches. Their original
registry checksums remain in the
[vendor provenance](../vendor/webauthn-challenge-provenance.json); unmodified
registry dependencies retain their checksums in `Cargo.lock`.

The local patch allows a caller-derived 32-byte authentication challenge so
approval proofs bind an immutable, domain-separated payload and fresh random
nonce. It adds an optional core-builder challenge and an explicit high-level
method, preserving the ordinary random-challenge path and upstream verification.
A feature gate also limits unused attestation imports when those features are
disabled. No signature-verification algorithm is reimplemented. The
[vendor guide](../vendor/README.md) records the exact patch and source/license
checks. This change adds or replaces no external dependency versions.

The adapter requires user verification and enables only the library's
`danger-allow-state-serialisation` feature. That feature permits protected
server-side ceremony persistence. It does not make browser-provided state
trustworthy: the API stores state itself and never accepts replacement ceremony
state from a client. The separate bound-authentication state cannot be replaced
with ordinary login state. Hardware attestation and a complete production policy
approval service are not claimed by these library primitives.

Compared with `82bf8dc`, the lockfile adds **34 external package versions** and
replaces none. Their upstream license declarations comprise 22 MIT/Apache-2.0
dual-license packages, five MIT packages, five MPL-2.0 packages and two packages
offering BSD-2-Clause, Apache-2.0 or MIT. The five MPL packages are
`webauthn-rs`, `webauthn-rs-core`, `webauthn-rs-proto`,
`webauthn-attestation-ca` and `base64urlsafedata`.

The registry package records upstream Git revision
`282d95f20648090bc131cdd33cdced336c33c3d1`. Its
[license text](https://github.com/kanidm/webauthn-rs/blob/282d95f20648090bc131cdd33cdced336c33c3d1/LICENSE.md)
was checked against the MPL-2.0 declaration. Exact license copies are included
with both vendored packages because the published crate archives omitted them.
The vendored and modified upstream files remain MPL-2.0; original project code
remains Apache-2.0. Dependency licenses and source availability notices must accompany
binary distribution; this metadata review is not legal clearance. The adapter
reuses the existing locked OpenSSL bindings (`openssl` 0.10.81 and `openssl-sys`
0.9.117); the host supplies OpenSSL rather than a newly vendored copy.

The current resolved lockfile, including the two path-patched packages, was
checked with **cargo-audit 0.22.2**, including registry yanks and without advisory
exclusions. The official RustSec
database was refreshed to revision
`2295466c4e9df26647fd67d8fa1c705ac2fc7f81` (updated 30 October 2026).
The scan reported **zero known vulnerabilities and no warnings** across 266
locked packages. The executed command was:

```sh
/workspace/toolchains/cargo-audit/bin/cargo-audit audit --file Cargo.lock \
  --db /workspace/toolchains/rustsec-advisory-db --json
```

With cargo-audit installed elsewhere, `cargo audit --file Cargo.lock` performs
the equivalent current-advisory check using its default database location.
Generated inventories and audit JSON stay in ignored local reports. These
checks cover published RustSec advisories and registry status at that snapshot.
An advisory scan does not review the local vendor patch or establish upstream
endorsement of it. These checks do not prove absence of undisclosed defects or
assess the separately installed OpenSSL library, browser or authenticator firmware.

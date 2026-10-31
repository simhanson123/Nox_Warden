# Local owner passkeys

This adapter uses pinned `webauthn-rs` 0.5.4 for real WebAuthn registration and
authentication. Both ceremonies require user presence and user verification.
The initial relying party is exactly `localhost`; the configured HTTP origin,
including its port, must match. IP addresses, subdomains and remote deployment
are outside this local profile.

Credential public keys and library ceremony states can be serialized only for
protected server-side storage. Private authenticator keys stay in the user's
authenticator. Browser responses are bounded and closed; original encoded
`clientDataJSON` bytes are retained for signature verification. Unsigned browser
extension outputs do not establish trust.

The caller must atomically check current credential revocation and account state,
enforce the five-minute challenge lifetime, consume a challenge once, update the
credential and create the authenticated session. If a credential changed after
a challenge was issued, the adapter rejects that stale challenge. Concurrent
authentication must retry with fresh state rather than roll back a counter.

Passkeys may be synchronized or hardware backed. This module does not claim
hardware attestation, independent human policy approval, authority bootstrap,
signing service isolation or native firewall deployment. Future policy approval
needs its own domain-separated immutable subject challenge and current-role
verification; a successful login alone never constitutes policy approval.

`webauthn-rs` is MPL-2.0; its cryptographic implementation uses system OpenSSL.
Its state-serialization feature is enabled for the server database, never for
untrusted browser-supplied ceremony state.

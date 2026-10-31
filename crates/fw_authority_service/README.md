# fw_authority_service

Independent bounded loopback authority review process with pinned-credential
WebAuthn login and exact-plan approval/rejection ceremonies. Explicit private
configuration, existing authority trust and a separate UI origin are required.
It exposes typed historical admission results and separately revalidated current
approval sets. Missing independent quorum trust stays explicitly unavailable.
No controller credential import, anonymous provisioning, signer or host writes.

See [startup, trust boundaries, HTTP contract and reproduction](../../docs/authority-review-service.md).

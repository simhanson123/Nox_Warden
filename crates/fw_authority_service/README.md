# fw_authority_service

Independent bounded loopback authority review process with pinned-credential
WebAuthn login and exact-plan approval/rejection ceremonies. Explicit private
configuration, existing authority trust and a separate UI origin are required.
It exposes typed historical admission results and separately revalidated current
approval sets. Missing independent quorum trust stays explicitly unavailable.
No controller credential import, anonymous provisioning, signer or host writes.

Explicit `/authority/v3/plans/:id/signing-readiness` adds bounded current bootstrap
authorization/target-confirmation evidence with `current_for_plan` and false policy
permissions. V1/v2 keep their exact old shapes before accepted target history;
after that history exists, even when expired, they refuse with
`SIGNING_READINESS_V3_REQUIRED` instead of dropping unsupported state. The authority
UI selects/parses v3 explicitly. This read-only evidence does not qualify a native
backend or turn target receipt freshness into signing/dispatch permission.

See [startup, trust boundaries, HTTP contract and reproduction](../../docs/authority-review-service.md).

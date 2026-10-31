# Independent authority review screen

The authority has a separate React entry and build. The controller's observation
console cannot provide the approval screen or its plan evidence. This local
screen is served by `fw_authority_service` at `http://localhost:8790`; its API
client refuses to run from another origin. The service must independently
configure a different controller origin, protect its files and database, and
pin the authority credential outside the controller.

Build from `web/` with the pinned dependencies installed:

```sh
npm run check
npm test -- --run
npm run build:authority
```

Install the complete `web/dist-authority` directory with the authority, and set
its `ui_directory` to that directory. The directory contains `index.html` and
hashed `assets/` files; it is separate from the controller's `web/dist`. No Node
server or external CDN is required. Serve this bundle only through the authority
service, which provides the response security headers and exact request-origin,
session and CSRF checks. Do not proxy the controller's review HTML into it.

The operator supplies a locally configured authority profile alias. The screen
obtains a fresh native WebAuthn assertion for the independently pinned key;
controller registration and login cannot supply that authority credential.
Cookie state alone does not restore an authenticated screen after reload. The
separate authority session proof, plan content and assertions remain in memory;
only the supported, explicitly selected language is saved in localStorage.
First visits default to English even in browsers set to another language.

A review shows the full immutable plan and requirements, complete plan and
requirements hashes, target, UTC plan validity, current eligible roles, required
gates, and authority-verified full before and after policy states. Missing review
evidence disables approval. Failed or unknown required gates, incomplete
analysis and expiration also disable approval. Role selection starts empty and
consent starts unchecked. The UI re-fetches the immutable plan and current
context immediately before requesting a decision-bound challenge. Approval and
rejection each invoke fresh browser WebAuthn and submit its original signed
assertion to the authority. The server repeats all authorization checks.

The API contract uses plain JSON under `/authority/v1` and
`X-Authority-CSRF` on all authenticated reads and writes. It includes `/session`,
`/auth/options`, `/auth/verify`, `/plans`, `/plans/{id}`,
`/approvals/challenges`, `/approvals/assertions`, and `/logout`. A detail response
contains the exact `plan`, `requirements`, `plan_hash`, `requirements_hash`,
`roles`, `review:{available:true,before,after}` (or `available:false`), and
`current_principal_decisions:[{approval,current_valid}]`, `aggregation:{state}`
and `current_approval_set:null|{content,hash,valid_until}`. An approved current
aggregate must match its non-null set ID, hash, tenant, plan reference,
requirements, authority epoch, role policy and validity. Contradictory responses
are errors, with no current-authority claim. The challenge binds
its nested `subject.plan_ref`, tenant, principal, requirements, decision, role,
RP, origin and expiry. Browser request options remain under
`options.publicKey`; the existing WebAuthn bridge converts only its base64url
browser fields. The UI does not interpret a role string or a checked box
as authorization.

A lost assertion response leaves the exact signed request and its idempotency
key in memory for an explicit retry. A terminal denial clears that request and
consent; it does not create a recorded decision. Existing verified decisions
remain visible on a later review, with their server-reported current validity.
The screen reads current aggregation and the verified set from the authority's
single-snapshot detail response. It distinguishes pending, authority unavailable,
terminal signed dissent, stale, not evaluated and approved. The only displayed
member count comes from the verified current set's included signed approvals.
It does not infer independent people or completed quorum from its own decision.

Decision responses, including exact retries, acknowledge the original admission.
Their aggregation is labeled historical. After a decision, the UI removes the
previous current status and separately refreshes the detail; a failed read
retains the historical decision but displays current authority as unavailable.
Refresh can recheck authority explicitly without resubmitting an assertion.
The set's own deadline is included in the display timer, so its verified badge
and current-set content disappear when that deadline passes, even before the
plan or session expires. A current own approval blocks duplicate approval, but the reviewer can submit a
fresh explicit rejection of that same plan with a new role selection, unchecked
consent and another WebAuthn verification. A historical receipt does not block
new approval when the earlier proof is no longer valid and the current read
requires new reviews. An uncertain pending signed request continues to block
new decisions until its result is resolved. A snapshot does not reserve
permission for a signer.
The backend uses independently pinned local epoch and human-identity mappings;
this does not implement production signed-manifest bootstrap. Recorded approval
and a current set do not issue a grant, deploy a policy, or prove that any host
firewall is active.

Run the real browser integration after building the service and its explicitly
test-only fixture provisioner:

```sh
python scripts/smoke_authority_review.py \
  --service-binary /path/to/target/debug/fw_authority_service \
  --fixture-binary /path/to/target/debug/examples/review_fixture
```

The provisioner creates a new disposable private authority database, real
planner before/after evidence, and a synthetic pinned key for Chromium's CDP
virtual CTAP2 authenticator. The script uses the shipped UI and real service to
sign in, record a separately signed decision, reload, and inspect the verified
retained decision. Fixtures with separate rejection and missing-evidence plans
also cover those routes. It never writes a host firewall. This automated
protocol check is not physical-key compatibility, human consent, protected
operating-system deployment or native network enforcement qualification.

English, Korean, Japanese, Spanish, German, French, Simplified Chinese and
Traditional Chinese have independent authority catalogues with automated key
and placeholder parity. Human language and assistive-technology review remain
unverified.

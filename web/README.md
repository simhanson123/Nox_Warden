# Control interface

A static React/TypeScript client for the local controller. It uses same-origin
`/api/v1` requests, HttpOnly sessions and session-bound CSRF. Passkey-authenticated
reads also require the CSRF proof, which is kept only in memory. A reload or new
tab asks for passkey login again; its cookie alone cannot restore the proof.
No credentials, policy data or API responses are written to browser storage;
only the selected locale is persisted. No external fonts, analytics, scripts or CDN resources are
loaded.

```sh
npm ci --prefix web
npm run check --prefix web
npm test --prefix web -- --run
npm run build --prefix web
```

The controller serves `web/dist` at `http://localhost:8787` by default. Use that
exact configured origin for real WebAuthn and session flows. During frontend
development, Vite proxies `/api` to `127.0.0.1:8787`, but its separate development
origin is not accepted by the controller's fixed Origin policy. Build and serve
the client through the controller for authentication integration checks.
The installed controller has no runtime dependency on Node.

Implemented views are overview, access request create/list/detail, policies,
targets, audit events, immutable asset/service registry management, and passkey
security settings. Request details have reloadable `/requests/:id` links;
`/cli-login/:id` retains its request across passkey sign-in and requires an
explicit matching terminal-code confirmation.
Server action hints gate request creation; the API independently authorizes all
operations. Requests use a stable idempotency key across retries, refreshed when
form contents change. Creation is displayed as acceptance, never activation.

The login screen distinguishes initial console-token setup from an enrolled
owner's passkey login. Security settings use actual `navigator.credentials.create`
and `get` calls, show pending/verified/revoked credentials, and require recent
passkey authentication for additions and revocations. Registration alone returns
to sign-in; it does not establish a signed authentication. Cancellation produces
no successful login. The last verified key is protected, including when an
unverified spare exists. See the [passkey lifecycle](../docs/passkey-login.md).

The UI shows only API data. An empty collection, failed request, unverified
platform and observation-only mode have distinct presentations. Raw record
fields render as escaped text, and known credential fields are redacted from the
record dialog as defense in depth. The server must still sanitize and authorize
all evidence responses.

English is the default on a first visit, regardless of browser language. Users
can choose Korean, Japanese, Spanish, German, French, Simplified Chinese or
Traditional Chinese; an explicitly selected language is remembered locally.
An invalid or inaccessible stored preference falls back to English. Eight locale
catalogs have automated key and placeholder parity.
Security translation review by native speakers remains incomplete. The UI does
not yet implement the full F-2.0 plan approval, topology graph, enrollment management,
telemetry consent management or complete route set. Native enforcement and
platform qualification cannot be inferred from this client or component tests.

The component suite exercises no-enforcement status, failed reads, malicious
labels, cookie/CSRF exchange, locale selection, idempotent retries and preserved
API denial errors. Detailed browser integration output stays in ignored local
reports or CI artifacts rather than source commits.

The live browser check requires Python Playwright and Chromium. From the
repository root, start a fresh development controller and run:

```sh
FW_PUBLIC_ORIGIN=http://127.0.0.1:8787 cargo run -p fw_control --locked
# In another terminal, before enrolling an owner in this disposable state:
python scripts/smoke_browser.py --token-file state/bootstrap-token --output reports/browser
```

The token must be fresh and is never copied into logs or screenshots. The test
creates a manual asset and a second immutable revision, verifies the missing-target
service prerequisite, and submits an explicitly untrusted request fixture through
the authenticated API; the request must remain `needs_info`. Reports include Chromium version, viewport sizes,
checks, limitations and screenshots. Automated checks are not full WCAG or native
language certification.

Asset writes use the exact `AssetWrite` DTO with `manual` provenance and null
source evidence. Registry revisions require the precise ETag from the current
resource; stale responses block resubmission until a fresh review. Service forms
use registered destinations and targets and cannot invent an enrollment. In a
fresh controller, service creation remains blocked until the device workflow
provides a registered target and its first authenticated capability report.
Follow the [device enrollment guide](../docs/device-enrollment.md) to initialize
the Linux client, issue an invitation and report over mTLS. The Targets page then
shows the actual target, and service forms can select it alongside a stored
destination asset. Stale reports and revoked or expired credentials cannot
establish an available target. The CLI handles invitations and revocation; a
dedicated enrollment-management screen is not implemented.

The agent report lasts five minutes; run `fw_agent report` again when needed.
Registration and a real capability hash do not mean enforcement is qualified.
Desired/observed policy hashes remain null and all enforcement capabilities are
unverified. Access requests select only registry assets and services; neither
manual registration nor a selected target attests workload identity or activates
network access.

A separate integration check starts real controller, CLI and agent processes,
enrolls a device over pinned TLS, reports over mTLS, and verifies live browser
target selection and persisted service creation:

```sh
python scripts/smoke_enrollment.py --browser
```

This check uses temporary private state and does not alter the host firewall.
Browser and component tests remain distinct from native platform qualification.

The passkey integration suite creates its own disposable controller state and
uses actual browser WebAuthn with a Chromium CDP virtual CTAP2 authenticator:

```sh
python -m pip install -r scripts/requirements-browser.txt
python -m playwright install --with-deps chromium
python scripts/smoke_passkeys.py
```

Use `--browser-executable /usr/bin/chromium` to select an installed test browser.
The suite covers signed login, durable enrollment after restart, bootstrap
shutdown, credential management and browser-authorized CLI login/revocation.
Virtual authenticator evidence does not establish physical-key compatibility,
a human approval decision or a production signer trust boundary.

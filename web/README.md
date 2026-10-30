# Control interface

A static React/TypeScript client for the local controller. It uses same-origin
`/api/v1` requests, HttpOnly sessions and session-bound CSRF. No credentials,
policy data or API responses are written to browser storage; only the selected
locale is persisted. No external fonts, analytics, scripts or CDN resources are
loaded.

```sh
npm ci --prefix web
npm run check --prefix web
npm test --prefix web -- --run
npm run build --prefix web
```

The controller serves `web/dist`. During frontend development, `npm run dev
--prefix web` starts a loopback Vite server that proxies `/api` to the controller
on `127.0.0.1:8787`. The controller's Origin allowlist must permit the explicitly
selected development origin; production has no dependency on Node.

Implemented views are overview, access request create/list/detail, policies,
targets and audit events. Request details have reloadable `/requests/:id` links.
Server action hints gate request creation; the API independently authorizes all
operations. Requests use a stable idempotency key across retries, refreshed when
form contents change. Creation is displayed as acceptance, never activation.

The UI shows only API data. An empty collection, failed request, unverified
platform and observation-only mode have distinct presentations. Raw record
fields render as escaped text, and known credential fields are redacted from the
record dialog as defense in depth. The server must still sanitize and authorize
all evidence responses.

Six locale catalogs contain 119 keys with automated key and placeholder parity.
Security translation review by native speakers remains incomplete. The UI does
not yet implement the full F-2.0 plan approval, topology graph, enrollment,
telemetry consent management or complete route set. Native enforcement and
platform qualification cannot be inferred from this client or component tests.

The component suite exercises no-enforcement status, failed reads, malicious
labels, cookie/CSRF exchange, locale selection, idempotent retries and preserved
API denial errors. Browser integration evidence is recorded separately in the
repository reports.

The live browser check requires Python Playwright and Chromium. From the
repository root, start a fresh development controller and run:

```sh
python scripts/smoke_browser.py --token-file state/live/bootstrap-token --output reports/browser
```

The token must be fresh and is never copied into logs or screenshots. The test
creates one synthetic request against the local controller; it requires the
result to remain `needs_info`. Reports include Chromium version, viewport sizes,
checks, limitations and screenshots. Automated checks are not full WCAG or native
language certification.

# Verification and implementation status

This directory tracks the concise status summary, [task ledger](task-ledger.json)
and [specification provenance](spec-import.json). Generated reports, logs and
screenshots are ignored by Git. CI retains selected HTTP, CLI, enrollment, Linux
packet, signed-execution, passkey and audit reports as downloadable artifacts for
seven days; logs and check status remain attached to [GitHub Actions runs](https://github.com/simhanson123/Nox_Warden/actions/workflows/ci.yml).
Keep tests and reproduction commands in source control. The supplied specification
and its bundled fixtures remain unchanged under `docs/specs`.

## Reproduce the checks

Run from the repository root after installing the [build prerequisites](../README.md#run-locally):

```sh
source scripts/dev-env.sh
bash scripts/check.sh
# Focused immutable approval challenge and bound WebAuthn verification suites:
cargo test -p fw_authority -p fw_webauthn --locked
python scripts/check_vendor.py
cargo build -p fw_control -p fw_cli -p fw_agent --locked
python scripts/smoke_control.py
python scripts/smoke_cli.py
python crates/fw_cli/tests/smoke_login.py
# Browser prerequisites: docs/passkey-login.md
python scripts/smoke_passkeys.py
python scripts/smoke_login_admission.py
python scripts/smoke_audit.py
python scripts/smoke_enrollment.py
python scripts/linux-lab.py --report reports/linux-lab.json
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
```

The full repository check passes: **414 Rust tests, 43 UI tests, 27 specification
checks, 52 core and 28 extended contract fixtures, and nine Linux runner
regressions**. Formatting, Clippy, frontend types, the production build and parity
across eight locale catalogues with 213 keys also pass.

The real-controller HTTP and CLI smokes pass **24 and 11 checks**, respectively;
the separate CLI protocol fixture passes **five checks**. The TLS enrollment
smoke with Chromium passes **25 checks**, including original contract validation,
live target selection and persisted service creation. Its nonbrowser CI subset
contains 23 checks. The suite uses real Ed25519 certificates, pinned TLS, mutual
authentication, durable retries, conservative capability reports and credential
revocation. Reports do not record private keys or credential values.

Controller/store verification includes
15 login-admission regressions for encrypted tickets, tampering, bounded decompression,
maximum credential/assertion sizes, current revocation/counter checks, zero-counter
replay, separate database connections and four injected write failures. Its
real-controller Chromium suite passes **14 checks**: 1,005 anonymous options
requests create no pending database rows, an earlier legitimate proof still
authenticates, protected registration remains available, replay fails and restart
rotates the ticket key. The flood regression was observed failing before the fix.
Run `cargo test --locked -p fw_control -p fw_store` and
`python scripts/smoke_login_admission.py`; both require localhost socket access.
The new browser report is an ignored local output or a seven-day CI artifact.
This is bounded admission testing, not a sustained network/CPU saturation claim.

The isolated compiler/readback suite passes **66 checks, including 40 actual
packet probes**.
It covers IPv4/IPv6 TCP/UDP allow/deny and expiry, plus 13 bounded semantic readback
checks including actual kernel rule mutation and restore. Docker with an isolated
network namespace and NET_ADMIN is required; see the [Linux lab guide](../native/linux/README.md).
These results cover the experimental compiler profile, not full native release
qualification or an application-driven firewall deployment.

The separate [signed execution suite](../docs/signed-linux-execution.md) passes
**55 checks, including 35 actual packet probes**. It covers verified grants,
durable native material, real apply/readback and probe confirmation, replay
without timeout refresh, established/new IPv4/IPv6 TCP/UDP expiry, automatic
recovery after an applying process is killed, recovery completion after its
writer is killed, and a later generation fencing stale recovery. Both the
original and signed suites remove their disposable containers successfully.
Signing and approval inputs are clearly marked synthetic fixtures, and the
recovery process is not a qualified watchdog against a permanently hung lock
owner. Expired rollback authority causes no unsigned fallback write.

The [passkey browser suite](../docs/passkey-login.md) passes **56 checks** with
actual Chromium WebAuthn backed by a CDP virtual CTAP2 authenticator and real
controller/CLI processes. It covers durable owner enrollment across restart,
signed login, credential management, bootstrap closure and browser-authorized CLI
login. The browser request view withholds the expected terminal code and polling
secret; missing or incorrect codes and unauthenticated authorization fail.
Initial bootstrap sessions also reject cookie-only proof recovery and owner
registration. Both browser and CLI sessions work before credential revocation and are
rejected afterward. Browser/controller cleanup succeeds. This verifies the
protocol and cryptographic path with an automated authenticator; it does not
establish physical-key compatibility or a human policy-approval decision.

The [audit integration suite](../docs/audit-log.md) passes **21 checks** using
real HTTP/MCP and browser pagination after 100 anonymous and 100 invalid-cookie
requests. It checks bounded denial evidence, stable snapshot traversal, a fresh
read including later events, the browser's Next page and successful cleanup.
Its report is `reports/audit-smoke.json`; credentials are excluded. These results
do not establish complete per-request audit retention across crashes.

The [approval proof suites](../docs/policy-approval-proofs.md) add **27 passing
Rust tests** within that total: six bound-authentication tests, nine typed
challenge tests and twelve authority-bridge tests. They cover domain-separated
plan/bootstrap challenges and real signature verification against their
immutable context. Their software authenticator responses are
cryptographic test inputs, not evidence of a human approval decision. The
controller exposes no approval service. These bridge tests alone do not establish
durable one-use consumption or independent role and credential trust.
The [vendored-source check](../vendor/README.md) verifies the recorded source and
license inventory; its archive mode also checks the original registry checksums
and reconstructs the complete local patch. RustSec advisory scanning does not
review those source changes.

The [durable authority store](../docs/authority-store.md) adds **56 passing Rust
tests** within the total: eight key-fingerprint/import-policy tests, eight full
plan/requirements admission tests, six provisioning tests and 34 transaction
tests. They exercise real P-256 signatures, zero-counter replay protection,
simultaneous connections, restart, exact retries, current revocation, retained
proofs after counter advancement, immutable SQL transitions, bounded failures,
six injected decision-write failures and activation audit rollback. Concurrent
first-open coverage uses sixteen fresh databases; a separate 100-repeat stress
run passed all 1,600 fresh-database races after bounded WAL lock retries.
Schema 2 adds permanent public-key tombstones independent of credential aliases.
Migration tests cover private verified backups, duplicate-key rollback, schema
checksums, and preservation of original signatures and exact retry results. Imported weak RSA and
mislabeled-curve tests were observed failing before the validation fix.
The emitted HumanApproval and both complete plan fixtures also validate against
the preserved original schemas. An additional **23 tests** pass with
`fw_authority --no-default-features`; native executor/lab dependency trees exclude
WebAuthn and OpenSSL. These are transaction and cryptographic checks, not
process-kill/power-loss, protected IPC, human-consent or installed-host qualification.

Live Chromium checks cover English-first startup and saved locale selection,
asset revisions, deep links and service prerequisites. The enrollment browser
check additionally verifies selecting an actual registered target, creating a
service and seeing the saved service after reload:

```sh
python scripts/smoke_enrollment.py --browser
```

This variant requires Python Playwright and local Chromium; see the
[web guide](../web/README.md). Human translation review and full accessibility
acceptance remain incomplete. Detailed results stay in local output or CI
artifacts, rather than a continuing development diary.

## Release boundary

The controller remains **observe-only**. Local-owner passkey login identifies the
operator. Durable plan-decision admission now exists as an authority library;
the human approval interface, quorum aggregation and independent signer
integration remain incomplete.
Transport registration and measured
capability metadata now support real target/service inventory; they do not
bootstrap policy authority, attest workloads or activate access requests.
Certificate renewal and remote enrollment, full Linux qualification, Windows
WFP/callout and macOS Network Extension implementations, independent
signer/watchdog integration, signed installers and release acceptance remain
incomplete. See the [implementation overview](../docs/implementation.md),
[device workflow](../docs/device-enrollment.md) and
[platform status](../docs/platform-support.md).

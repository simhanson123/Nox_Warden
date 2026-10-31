# Verification and implementation status

This directory tracks the concise status summary, [task ledger](task-ledger.json)
and [specification provenance](spec-import.json). Generated reports, logs and
screenshots are ignored by Git. CI retains selected HTTP, CLI, enrollment and
Linux packet, signed-execution and passkey reports as downloadable artifacts for seven days; logs and check status
remain attached to [GitHub Actions runs](https://github.com/simhanson123/Nox_Warden/actions/workflows/ci.yml).
Keep tests and reproduction commands in source control. The supplied specification
and its bundled fixtures remain unchanged under `docs/specs`.

## Reproduce the checks

Run from the repository root after installing the [build prerequisites](../README.md#run-locally):

```sh
source scripts/dev-env.sh
bash scripts/check.sh
cargo build -p fw_control -p fw_cli -p fw_agent --locked
python scripts/smoke_control.py
python scripts/smoke_cli.py
python crates/fw_cli/tests/smoke_login.py
# Browser prerequisites: docs/passkey-login.md
python scripts/smoke_passkeys.py
python scripts/smoke_enrollment.py
python scripts/linux-lab.py --report reports/linux-lab.json
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
```

The full repository check passes: **280 Rust tests, 43 UI tests, 27 specification
checks, 52 core and 28 extended contract fixtures, and nine Linux runner
regressions**. Formatting, Clippy, frontend types, the production build and parity
across eight locale catalogues with 214 keys also pass.

The real-controller HTTP and CLI smokes pass **24 and 11 checks**, respectively;
the separate CLI protocol fixture passes **five checks**. The TLS enrollment
smoke with Chromium passes **25 checks**, including original contract validation,
live target selection and persisted service creation. Its nonbrowser CI subset
contains 23 checks. The suite uses real Ed25519 certificates, pinned TLS, mutual
authentication, durable retries, conservative capability reports and credential
revocation. Reports do not record private keys or credential values.

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

The [passkey browser suite](../docs/passkey-login.md) passes **48 checks** with
actual Chromium WebAuthn backed by a CDP virtual CTAP2 authenticator and real
controller/CLI processes. It covers durable owner enrollment across restart,
signed login, credential management, bootstrap closure and browser-authorized CLI
login. Both browser and CLI sessions work before credential revocation and are
rejected afterward. Browser/controller cleanup succeeds. This verifies the
protocol and cryptographic path with an automated authenticator; it does not
establish physical-key compatibility or a human policy-approval decision.

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
operator; plan-bound approval and independent signer authority remain separate
unimplemented integrations. Transport registration and measured
capability metadata now support real target/service inventory; they do not
bootstrap policy authority, attest workloads or activate access requests.
Certificate renewal and remote enrollment, full Linux qualification, Windows
WFP/callout and macOS Network Extension implementations, independent
signer/watchdog integration, signed installers and release acceptance remain
incomplete. See the [implementation overview](../docs/implementation.md),
[device workflow](../docs/device-enrollment.md) and
[platform status](../docs/platform-support.md).

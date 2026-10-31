# Nox Warden

An Apache-2.0 host firewall project with a Rust policy core, local control API,
SQLite storage, CLI and React interface. **The current application is a development
build in observe mode. It does not protect host traffic or provide a qualified
firewall release.**

English is the default interface language. Users can select Korean, Japanese,
Spanish, German, French, Simplified Chinese or Traditional Chinese; their explicit
selection is remembered. The original [F-2.0 specifications](docs/specs/F_00_시작안내.md)
are preserved, with current user decisions recorded in [AGENTS.md](AGENTS.md).

## Current functionality

- Local-owner passkey registration and signed login, durable enrollment, protected
  credential addition/revocation and browser-authorized CLI sessions. Registration
  alone does not create an authenticated passkey session.
- Linux device registration with a fingerprint-bound invitation, pinned TLS trust,
  Ed25519 client certificates and authenticated capability reports. A real target
  appears after its first report; every enforcement capability remains unverified.
- Authenticated local asset and service catalogues with immutable revisions,
  ETags, tenant isolation and transactional audit records. Services can reference
  registered targets with current credentials and reports. Authenticated audit
  reads use bounded snapshot pages; repeated denials retain bounded samples and
  linked count summaries. See the [audit guide](docs/audit-log.md).
- Access requests with strict JSON validation, normalization, idempotent storage
  and operation/audit queries. Requests without workload binding and authority
  remain `needs_info`; they are not presented as active network permissions.
- Policy and security libraries for deny precedence, current allow union, bounded
  leases, policy comparison, approval requirements, Ed25519 DSSE, atomic quotas,
  durable executor journals, audit verification and opt-in telemetry state.
- Typed plan/bootstrap challenges and real WebAuthn verification of assertions
  bound to their immutable context. A separate [authority store](docs/authority-store.md)
  atomically records decisions, current credential/role checks, original proofs
  and immutable approval sets requiring independent human reviewers.
- A separate [policy review service and screen](docs/authority-review-ui.md)
  authenticate pinned authority passkeys, show verified before/after policy
  evidence and collect fresh signed approval or rejection. Historical receipts
  remain separate from current quorum, revocation and expiry checks. Production
  authority bootstrap, protected OS deployment and signer integration remain
  incomplete; controller login does not approve a policy.
- A multilingual management UI, secure local CLI login and authenticated read-only
  MCP tools. The controller does not dispatch native firewall writes.
- Isolated Linux nftables suites for packet semantics and signed execution. The
  experimental driver verifies pinned signatures, journals complete policy and
  recovery material, applies an atomic batch, reads actual rules and collects
  packet probes before confirmation or authorized restrictive recovery.

See [implementation boundaries](docs/implementation.md), [platform status](docs/platform-support.md)
and the concise [task ledger](reports/task-ledger.json) for remaining work.

## Run locally

Required tools: Rust **1.99.1**, Node **24.19.0**, npm **11.9.0**, and Python 3 with
`scripts/requirements.txt`, plus OpenSSL development headers and `pkg-config`
(on Debian/Ubuntu: `libssl-dev pkg-config`). Cargo and npm dependencies use
committed lockfiles.
For the managed Linux x86_64 workspace, `bash scripts/install-rust.sh` installs
the pinned toolchain when needed. Other hosts can use rustup with
`rust-toolchain.toml`.

```sh
source scripts/dev-env.sh
python -m pip install -r scripts/requirements.txt
cargo build --workspace --locked
npm ci --prefix web
npm run build --prefix web
cargo run -p fw_control --locked
```

Open `http://localhost:8787`. Before owner enrollment, the server creates a private
`state/bootstrap-token` file valid for ten minutes and one login, removed when
consumed. Use it to open
**Security**, register the first passkey, then sign in with that passkey. Adding
another passkey or revoking one requires a recent passkey authentication. A newly
registered key becomes active only after its first signed login, and the last
active key cannot be revoked. See the [passkey guide](docs/passkey-login.md).

Owner enrollment and credentials survive restart; browser and CLI sessions do
not. After passkey login, the browser keeps its session proof only in memory, so
a reload or new tab requires passkey sign-in again. Once enrolled, the owner cannot be replaced
through bootstrap, including after restart. The browser persists only the
selected language, never credentials or API data.

This local development profile uses loopback HTTP, HttpOnly/SameSite cookies,
exact Origin checks and CSRF protection. The separate device enrollment listener
uses TLS 1.3 on loopback when explicitly configured. Remote operator management
and OIDC remain unavailable. Configure `FW_STATE_DIR`, `FW_PORT` and `FW_WEB_DIR`
for state, HTTP port and static assets. `FW_PUBLIC_ORIGIN` accepts only the exact
bound `localhost` or `127.0.0.1` origin; the IP form disables WebAuthn and never
reopens bootstrap for an enrolled owner.

```sh
cargo run -p fw_cli -- health
# Before enrollment: console token. After enrollment: approve in the browser.
cargo run -p fw_cli -- login
cargo run -p fw_cli -- status
cargo run -p fw_cli -- assets
```

CLI login uses `FW_BOOTSTRAP_FILE` (default `state/bootstrap-token`) only before
owner enrollment. Afterward it prints a controller URL and eight-character code
for explicit approval in the browser with a recent passkey login. It atomically
writes `FW_SESSION_FILE` (default `state/cli-session.json`) with mode `0600`.
Polling secrets, tokens and cookies are not command-line arguments or log output.
Protected credential-file handling currently supports Unix; Windows ACL support
remains incomplete. See the [CLI guide](crates/fw_cli/README.md).

To register a Linux device, follow the [device enrollment guide](docs/device-enrollment.md):
create the controller PKI once, initialize the device identity, issue a protected
invitation, enroll with a verified CA pin, and submit a capability report. This
unlocks real target selection in the service catalogue. Registration remains
observe-only; it does not approve a policy or install firewall rules.

## Validation and release status

```sh
bash scripts/check.sh
cargo build -p fw_control -p fw_cli -p fw_agent --locked
python scripts/smoke_control.py
python scripts/smoke_cli.py
python scripts/smoke_enrollment.py
# Requires the browser test prerequisites in docs/passkey-login.md.
python scripts/smoke_passkeys.py
python scripts/smoke_audit.py
# Requires the isolated Docker lab; these commands do not enable host protection.
python scripts/linux-lab.py --report reports/linux-lab.json
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
```

The [verification summary](reports/README.md) records scope, reproducible commands
and CI links. Detailed logs, screenshots and generated reports are local outputs
or short-lived CI artifacts, rather than recurring source commits.

The [Linux lab](native/linux/README.md) exercises actual IPv4/IPv6 TCP/UDP allow,
deny, connection expiry and actual rule-tamper detection in an isolated network
namespace. The [signed execution lab](docs/signed-linux-execution.md) additionally
connects signature verification, durable preparation, native apply/readback,
probe confirmation and restrictive timeout/crash recovery. Its authority and
approval inputs are explicitly synthetic fixtures. Full Linux qualification,
Windows WFP/callout and macOS Network Extension implementations,
independent authority/watchdog integration, signed installers and production
identity lifecycle, certificate renewal and remote enrollment remain unfinished.
Unit, HTTP and browser tests do not replace native platform qualification.

Telemetry and donations are not enabled. No package release, paid cloud resource
or production firewall deployment has been performed.

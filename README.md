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

- Authenticated local asset and service catalogues with immutable revisions,
  ETags, tenant isolation and transactional audit records. Service creation
  requires an existing target; manual records do not establish trusted identity.
- Access requests with strict JSON validation, normalization, idempotent storage
  and operation/audit queries. Requests without enrollment and authority remain
  `needs_info`; they are not presented as active network permissions.
- Policy and security libraries for deny precedence, current allow union, bounded
  leases, policy comparison, approval requirements, Ed25519 DSSE, atomic quotas,
  durable executor journals, audit verification and opt-in telemetry state.
- A multilingual management UI, secure local CLI login and authenticated read-only
  MCP tools. The controller does not dispatch native firewall writes.
- A real isolated Linux nftables packet smoke suite, separate from the application
  and from full platform qualification.

See [implementation boundaries](docs/implementation.md), [platform status](docs/platform-support.md)
and the concise [task ledger](reports/task-ledger.json) for remaining work.

## Run locally

Required tools: Rust **1.99.1**, Node **24.19.0**, npm **11.9.0**, and Python 3 with
`scripts/requirements.txt`. Cargo and npm dependencies use committed lockfiles.
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

Open `http://127.0.0.1:8787`. The server creates a private
`state/bootstrap-token` file containing a token valid for ten minutes and one
login. Enter it in the local login screen, or use it through the CLI below.
Sessions end when the server restarts. The browser stores only the selected
language, never credentials or API data.

This local development profile uses loopback HTTP, HttpOnly/SameSite cookies,
Origin checks and CSRF protection. Remote TLS, OIDC and WebAuthn integration are
not available. Configure the state directory with `FW_STATE_DIR`, port with
`FW_PORT`, and static asset directory with `FW_WEB_DIR`; remote binding is not
supported.

```sh
cargo run -p fw_cli -- health
# The bootstrap token can be consumed once, by either the browser or CLI.
cargo run -p fw_cli -- login
cargo run -p fw_cli -- status
cargo run -p fw_cli -- assets
```

CLI login reads `FW_BOOTSTRAP_FILE` (default `state/bootstrap-token`) and atomically
writes `FW_SESSION_FILE` (default `state/cli-session.json`) with mode `0600`.
Tokens and cookies are not command-line arguments or log output. Secure credential
file handling currently supports Unix; Windows ACL support remains incomplete.
See the [CLI guide](crates/fw_cli/README.md).

## Validation and release status

```sh
bash scripts/check.sh
cargo build -p fw_control -p fw_cli --locked
python scripts/smoke_control.py
python scripts/smoke_cli.py
```

The [verification summary](reports/README.md) records scope, reproducible commands
and CI links. Detailed logs, screenshots and generated reports are local outputs
or short-lived CI artifacts, rather than recurring source commits.

The [Linux lab](native/linux/README.md) exercises actual IPv4/IPv6 TCP/UDP allow,
deny and connection expiry in an isolated network namespace. Full Linux
qualification, Windows WFP/callout and macOS Network Extension implementations,
independent authority/watchdog integration, signed installers and production
identity/enrollment remain unfinished. Unit, HTTP and browser tests do not replace
native platform qualification.

Telemetry and donations are not enabled. No package release, paid cloud resource
or production firewall deployment has been performed.

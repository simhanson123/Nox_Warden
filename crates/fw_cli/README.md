# fw_cli

Local operator login, device invitations, credential revocation and controller
queries. The CLI does not approve network access or run firewall commands.

From the repository root, start the controller and then run:

```sh
cargo run -p fw_cli -- login
cargo run -p fw_cli -- status
cargo run -p fw_cli -- assets
cargo run -p fw_cli -- services
cargo run -p fw_cli -- enrollments
cargo run -p fw_cli -- targets
```

`FW_API_URL` selects the controller origin (default `http://127.0.0.1:8787`).
`FW_BOOTSTRAP_FILE` selects the protected one-use token file (default
`state/bootstrap-token`). `FW_SESSION_FILE` selects the saved session (default
`state/cli-session.json`). Token and cookie values are never accepted as command
arguments or printed by login.

The CLI uses the controller's Origin/CSRF-capable local session protocol. Login
stores the cookie and CSRF token in a private, atomically replaced file bound to
the exact API origin. It consumes the same one-use bootstrap credential as the
browser. A token already consumed by either cannot be reused; restart the
controller with the same state to issue a new token. Sessions expire with the
server's policy and are invalidated on restart.

## Register and revoke devices

Initialize the controller PKI and device key using the
[device enrollment guide](../../docs/device-enrollment.md). With the device's
public key fingerprint, issue a protected invitation:

```sh
cargo run -p fw_cli -- enroll-token \
  --name 'Local Linux device' \
  --platform linux \
  --fingerprint 'sha256:REPLACE_WITH_DEVICE_PUBLIC_KEY_FINGERPRINT' \
  --output state/invitations/device.json
```

The CLI generates a cryptographically random token and idempotency key, saves them
in a private invitation file before the API call, and sends only the token hash
to the operator API. The invitation is bound to the API origin, target name,
platform and public key fingerprint. The output contains the invitation path,
target ID and expiry; it does not contain the token.

If a response is lost, rerun the same command with the same output file. The CLI
preserves the original token and idempotency key, so the target and ten-minute
expiry remain unchanged. Different arguments or an API origin mismatch are
rejected. Preserve the invitation privately and supply its file path to
`fw_agent enroll`; do not copy its contents into command arguments or logs.

`enrollments` lists actual certificate registrations, including those waiting for
an authenticated capability report. `targets` lists complete target views after
such a report exists. Current credentials and a fresh report permit target
selection in the service catalogue; all enforcement features remain unverified.

To revoke the registered credential:

```sh
cargo run -p fw_cli -- revoke-target REPLACE_WITH_TARGET_UUID
```

Revocation blocks subsequent device authentication and new service references.
It does not change host firewall rules or terminate traffic. The controller stays
observe-only, and access requests cannot become active through registration.

## Credential and transport boundaries

Operator transport permits HTTPS or loopback IPv4 HTTP, disables redirects,
bounds response bytes and uses a ten-second timeout. HTTPS login requires a
Secure cookie. This does not add a remote operator listener to the controller.
Device enrollment uses the separate pinned TLS endpoint described in its guide.

Credential files and their parent directory must be owned by the current Unix
user with no group/other access. Symbolic-link paths, hard-linked input
credentials, public permissions and oversized files are rejected. Atomic
replacement does not modify another hard-link target. Native protected
credential-file handling on non-Unix platforms is not implemented; sensitive
operations refuse rather than claiming Windows ACL guarantees. Unauthenticated
health checks remain portable. OIDC, WebAuthn, policy authority bootstrap and
certificate renewal remain unavailable.

## Validation

```sh
cargo test -p fw_cli --locked
cargo clippy -p fw_cli --all-targets --locked -- -D warnings
cargo build -p fw_control -p fw_cli -p fw_agent --locked
python crates/fw_cli/tests/smoke_login.py
python scripts/smoke_cli.py
python scripts/smoke_enrollment.py
```

The first Python check uses a temporary protocol server; the remaining checks use
real controller processes. Reports and protected state remain ignored local files.

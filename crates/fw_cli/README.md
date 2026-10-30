# fw_cli

Read-only CLI with an explicit local development login. It never runs firewall commands or grants network access.

From the repository root, start the controller and then run:

```sh
cargo run -p fw_cli -- login
cargo run -p fw_cli -- status
cargo run -p fw_cli -- assets
cargo run -p fw_cli -- services
```

`FW_API_URL` selects the controller origin (default `http://127.0.0.1:8787`). `FW_BOOTSTRAP_FILE` selects the protected one-use token file (default `state/bootstrap-token`). `FW_SESSION_FILE` selects the saved session (default `state/cli-session.json`). Token and cookie values are never accepted as command-line arguments or printed by login.

The CLI uses the controller's actual Origin/CSRF-capable local session protocol. A successful login stores the cookie and CSRF token in a private, atomically replaced file, bound to the exact API origin. Login consumes the same one-use bootstrap credential as the browser. A token already consumed by the browser or another CLI cannot be reused; restart the development controller to issue a new token. Sessions expire with the server's policy and are lost on server restart.

Transport permits HTTPS or loopback IPv4 HTTP, disables redirects, bounds response bytes and sets a ten-second timeout. HTTPS login requires a Secure cookie. Credential files and their parent directory must be owned by the current Unix user with no group/other access. Symbolic-link paths, hard-linked input credentials, public file permissions and oversized files are rejected. Atomic replacement does not modify another hard-link target.

Native protected credential-file handling on non-Unix platforms is not implemented; login and session reads refuse rather than claiming Windows ACL guarantees. Unauthenticated health checks remain portable. This is a local development workflow, not OIDC, WebAuthn, production enrollment or a privileged login.

Validation:

```sh
cargo test -p fw_cli --locked
cargo clippy -p fw_cli --all-targets --locked -- -D warnings
cargo build -p fw_cli --locked
python crates/fw_cli/tests/smoke_login.py
```

The Python smoke uses a temporary loopback protocol server and synthetic credentials, separately from the real-controller integration smoke.

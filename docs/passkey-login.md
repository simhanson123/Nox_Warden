# Local-owner passkey login

The local controller supports real WebAuthn passkey registration, signed login,
credential addition/revocation and browser-authorized CLI login. These operations
identify the local owner; they do not approve a firewall policy or enable host
enforcement. The management application remains in observe mode.

## Set up and sign in

Build the controller and static client as described in the [repository guide](../README.md#run-locally),
then start `fw_control` and open **`http://localhost:8787`**.

1. Before owner enrollment, enter the private `state/bootstrap-token` into the
   initial login screen. It is valid for ten minutes and one login.
2. Open **Security**, name the first passkey and register it through the browser's
   authenticator prompt. User verification is required.
3. Registration ends the setup session. Choose **Sign in with a passkey** and
   complete a signed authentication with the newly registered passkey.
4. Add and authenticate a spare passkey from Security when needed. A registered
   key stays pending until it completes its first signed login.

Registration requests `attestation: none`. It does not certify an authenticator's
hardware, and a registration response alone is not treated as signed login.
Passkeys may be synchronized or hardware backed; the controller receives public
credential material and proof, not the authenticator's private key.

Enrollment and credential state persist in the controller database. Once the
owner is enrolled, bootstrap is blocked even after restart, and existing
bootstrap sessions cannot operate as the enrolled owner. Startup does not issue
a replacement bootstrap token. Sessions themselves are memory-only: after
restart, sign in with a passkey again. There is no implemented lost-all-passkeys
recovery ceremony or bootstrap bypass. Keep a verified spare for continued access.

Credential additions and revocations require a passkey authentication less than
five minutes old. The server checks freshness and current credential state;
a displayed UI action is not authorization. A pending spare cannot authorize
credential changes or permit revocation of the last verified credential.
Revocation retains its record and invalidates sessions bound to that credential
on subsequent requests, including CLI sessions. The last verified credential
cannot be revoked.

## CLI login

Run `cargo run -p fw_cli -- login`. Before owner enrollment it uses the protected
console-token file. After enrollment:

1. The terminal prints the exact local controller URL and an eight-character
   uppercase code.
2. Open that URL, sign in or reauthenticate with a passkey, and type the code from
   the terminal. Approve CLI login explicitly.
3. The CLI exchanges a separate one-use polling secret for its own session and
   writes the existing private session file. The browser never receives this
   polling secret, and it is not placed in a URL or printed.

The request expires after five minutes. Logging out or replacing the authorizing
browser session before exchange cancels its authorization. A restart or lost
exchange response requires a new CLI login request. Exchanging a CLI session
preserves the original passkey authentication time; it cannot renew permission
to add or revoke a key.
The [CLI guide](../crates/fw_cli/README.md) describes file permissions and settings.

## Origin and runtime boundaries

The listener binds to `127.0.0.1`; the default browser and CLI origin is
`http://localhost:8787`. `FW_PORT` changes the port. WebAuthn binds the RP ID to
exactly `localhost` and verifies the exact configured origin, including its port.
It does not derive trusted configuration from request headers.

`FW_PUBLIC_ORIGIN` may select the exact bound `localhost` or `127.0.0.1` HTTP
origin. The IP form keeps existing development clients usable before enrollment,
but explicitly disables WebAuthn. Switching to that form cannot reopen bootstrap
for an enrolled owner. Other origins, remote HTTPS management and OIDC are not
implemented by this profile. Use the built client served by the controller for
real authentication; a separate Vite development origin is not allowlisted.

Passkey-authenticated requests require both the HttpOnly/SameSite=Strict cookie
and the session's `X-CSRF-Token`, including reads such as `/session`. The browser
holds that second proof only in memory. Reloading or opening a new tab therefore
requires passkey login again; a cookie alone cannot restore the session or fetch
its proof. This prevents a different localhost-port service receiving the shared
hostname's cookie from using that cookie alone to recover the session token.
The CLI stores both values in its existing private session file.

Before owner enrollment, initial bootstrap setup retains the legacy cookie-only
read behavior and requires trusted local services/processes. The additional
proof requirement protects enrolled passkey sessions; it does not make initial
bootstrap or a compromised host an independent security boundary.

Mutations additionally check the exact configured Origin. Loopback HTTP does not
set the Secure cookie attribute. This remains a development profile and does not
establish isolation from software or administrators controlling the same host.

The controller stores local-owner credentials and proof in its own database.
That database is not an independently protected signer's source of authority.
Plan-bound human approval still requires an immutable subject challenge, current
roles and original proof verification in the separate authority. A successful
login does not satisfy those requirements. See the [implementation boundaries](implementation.md)
and [WebAuthn dependency review](passkey-dependencies.md).

## Authentication API extension

These routes extend the development API; the preserved original specifications
are unchanged. All paths below are under `/api/v1` and use the existing response
envelope and bounded JSON handling.

| Method and path | Purpose and authorization |
| --- | --- |
| `GET /auth/status` | Public local origin support, owner-enrollment and bootstrap availability; no credential keys or proof. |
| `GET /auth/passkeys` | Authenticated credential metadata, including pending/verified/revoked status and current key. |
| `POST /auth/passkeys/registration/options` | `{name}`; initial bootstrap session or recent verified passkey session. |
| `POST /auth/passkeys/registration/complete` | `{ceremony_id, credential}`; exact browser registration response and bound authenticated session. Returns registration status and ends that session, not a signed login. |
| `POST /auth/passkeys/login/options` | `{}` or an optional `credential_id`; creates a browser-bound authentication challenge. |
| `POST /auth/passkeys/login/complete` | `{ceremony_id, credential}`; actual signed browser assertion, current credential, challenge and browser binding. |
| `POST /auth/passkeys/{id}/revocations` | `{}`; recent verified passkey session, with last-verified-key protection. |
| `POST /auth/logout` | `{}`; authenticated session and CSRF. |
| `POST /auth/cli/requests` | `{}`; bounded, expiring CLI request. Returns the polling secret only to the requesting CLI. |
| `GET /auth/cli/requests/{id}` | Authenticated view of the request and display code; never the polling secret. |
| `POST /auth/cli/requests/{id}/authorize` | `{user_code}`; explicit matching code, recent verified passkey session and CSRF. |
| `POST /auth/cli/requests/{id}/exchange` | `{poll_token}`; pending response or one-use credential-bound session transfer. |

Mutations require a UUID `Idempotency-Key`, exact Origin and JSON content type;
passkey-authenticated reads and all authenticated mutations also require the
session CSRF token. Challenge options
return `{ceremony_id, public_key, expires_at}`. Browser credential responses use
base64url-encoded binary fields, and the signed `clientDataJSON` bytes are
preserved exactly.

Ceremonies expire after five minutes. Verification runs against current stored
credentials inside the same bounded transaction that consumes a successful
challenge, updates credential state and records proof/audit. Failed assertions
cannot become successful consumption, and attempt/creation limits bound retries.
Concurrent stale credential snapshots require a fresh ceremony.

Authentication completion and CLI exchange are intentionally one-use, unlike
idempotent catalogue writes: replaying successful proof does not return or mint
another session. An exact repeated completed login returns a conflict; a lost
response requires fresh authentication. A controller restart does not resurrect
old sessions or authentication results.

## Reproduce the browser check

From the repository root, after building `fw_control`, `fw_cli` and `web/dist`:

```sh
python -m pip install -r scripts/requirements-browser.txt
python -m playwright install --with-deps chromium
python scripts/smoke_passkeys.py
```

Use `--browser-executable /usr/bin/chromium` to select an installed browser.
The suite starts real controller and CLI processes with private temporary state.
Chromium executes actual `navigator.credentials.create/get` against a CDP virtual
CTAP2 authenticator; the controller verifies the resulting cryptographic proof.
Tests cover restart, bootstrap closure, credentials and CLI transfer/revocation.
Generated reports identify this virtual-authenticator scope and omit credentials,
private keys and proof bytes. They remain ignored local output or bounded CI
artifacts. This does not verify a physical security key, a human consent decision,
OS firewall installation or native packet enforcement.

Confirmed totals and remaining release work are recorded in the
[verification summary](../reports/README.md).

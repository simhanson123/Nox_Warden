# Local-owner passkey login

The local controller supports real WebAuthn passkey registration, signed login,
credential addition/revocation and browser-authorized CLI login. These operations
identify the local owner; they do not approve a firewall policy or enable host
enforcement. The management application remains in observe mode.

## Set up and sign in

Build the controller and static client as described in the [repository guide](../README.md#run-locally),
then start `fw_control` and open **`http://localhost:8787`**.

1. Before owner enrollment, enter the private `state/bootstrap-token` into the
   initial login screen. It is valid for ten minutes and one login; successful
   consumption removes the configured private token file before returning a
   session.
2. Open **Security**, name the first passkey and register it through the browser's
   authenticator prompt. User verification is required.
3. Registration ends the setup session. Choose **Sign in with a passkey** and
   complete a signed authentication with the newly registered passkey.
4. Add and authenticate a spare passkey from Security when needed. A registered
   key stays pending until it completes its first signed login.

Wrong bootstrap tokens are limited to ten failed attempts per 60-second window;
further wrong attempts receive HTTP 429 with `Retry-After: 60`. A correct, unused,
unexpired console token remains usable during that cooldown, so anonymous
failures cannot permanently lock out initial setup. This never bypasses token
consumption, expiry or the durable owner-enrollment marker.

The launcher pins the token file and its private parent. On Unix, consumption
checks their identity, ownership, permissions and link state before removal and
parent synchronization. A replaced or unsafe file is not deleted; cleanup failure
returns no session and the consumed token remains invalid. These checks do not
claim Windows ACL qualification or isolation from a compromised same-UID process.

Registration requests `attestation: none`. It does not certify an authenticator's
hardware, and a registration response alone is not treated as signed login.
Passkeys may be synchronized or hardware backed; the controller receives public
credential material and proof, not the authenticator's private key.

Enrollment and credential state persist in the controller database. Once the
owner is enrolled, bootstrap is blocked even after restart, and existing
bootstrap sessions cannot operate as the enrolled owner. Startup does not issue
a replacement bootstrap token. Sessions themselves are memory-only: after
restart, sign in with a passkey again. There is no implemented lost-all-passkeys
recovery ceremony or bootstrap bypass. This also applies if the first registered
key is lost or cannot authenticate before its first signed login: the durable
owner marker already closes bootstrap, and no verified spare exists yet. That
state has no supported recovery workflow. Keep a verified spare once enrollment
and the first login succeed.

Credential additions and revocations require a direct browser passkey session
authenticated less than five minutes ago. The server checks its own session
provenance, freshness and current credential state;
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
   your own terminal. The browser request view does not return or display the
   expected code; the server checks the value you enter. Approve CLI login
   explicitly, and do not enter a code sent by someone else.
3. The CLI exchanges a separate one-use polling secret for its own session and
   writes the existing private session file. The browser never receives this
   polling secret, and it is not placed in a URL or printed.

The request expires after five minutes. Logging out or replacing the authorizing
browser session before exchange cancels its authorization. A restart or lost
exchange response requires a new CLI login request. Exchanging a CLI session
preserves the original passkey authentication time and creates a delegated
session. It retains ordinary controller API reads and writes, but cannot add or
revoke owner credentials or authorize another CLI, even within the browser's
five-minute authentication window. The server selects this session type; client
headers and stored session-file fields cannot change it. The initial bootstrap
enrollment path remains as described above.

Public passkey login still requires a new, bound, one-use WebAuthn assertion. A
valid fresh assertion may replace a CLI session with a direct browser session;
requesting options, replaying an old proof or submitting an invalid assertion
does not promote it. Logout ends the selected session, expiry ends access, and
credential revocation invalidates all sessions bound to that credential.

Possession of a request URL does not supply its confirmation code or authorize
the request. Someone who creates a request still knows that request's code and
could try to persuade an owner to enter it. Manual terminal confirmation is not
a complete defense against social engineering or a compromised local host.

The controller retains at most 16 CLI login requests until their five-minute
expiry, including requests already exchanged. Creation does not require an
existing session. A local client can fill these slots and temporarily prevent
legitimate CLI login with `CLI_LOGIN_LIMIT` (HTTP 429); expiry clears old entries
when another creation is attempted. This bound limits memory, but does not
provide availability against a local requester repeatedly filling the queue.
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

All authenticated requests, including initial bootstrap setup, require both the
HttpOnly/SameSite=Strict cookie and the session's `X-CSRF-Token`, even for reads
such as `/session`. The successful bootstrap or passkey login response supplies
that second proof. The browser holds it only in memory; the CLI stores both
values in its existing private session file. A cookie alone cannot restore the
session or retrieve its proof, even when a local client supplies the configured
Origin header. This prevents another localhost-port service receiving the shared
hostname's cookie from using it to take over initial owner registration.

Reloading or opening a new tab requires passkey login again once an owner is
enrolled. Before enrollment, keep the initial setup tab open until registration
and the first signed login finish. If its memory proof is lost before any owner
registration, restart the local controller to obtain a fresh console token.
Registration reserves the durable owner immediately; afterward restart never
reopens bootstrap, including while the first credential is still pending.

Mutations additionally check the exact configured Origin. Loopback HTTP does not
set the Secure cookie attribute. This remains a development profile and does not
establish isolation from software or administrators controlling the same host.

The controller stores local-owner credentials and proof in its own database.
That database is not an independently protected signer's source of authority.
The [approval proof library](policy-approval-proofs.md) separately implements
immutable subject challenges and bound WebAuthn verification. The separate
[authority store](authority-store.md) implements explicit credential pinning and
activation, current scoped roles and durable one-use decision storage. Protected
service deployment, production authority enrollment, quorum and signing still
remain incomplete. Controller login never supplies those approvals. See the [implementation boundaries](implementation.md)
and [WebAuthn dependency review](passkey-dependencies.md).

## Authentication API extension

These routes extend the development API; the preserved original specifications
are unchanged. All paths below are under `/api/v1` and use the existing response
envelope and bounded JSON handling.

| Method and path | Purpose and authorization |
| --- | --- |
| `GET /auth/status` | Public local origin support, owner-enrollment and bootstrap availability; no credential keys or proof. |
| `GET /auth/passkeys` | Authenticated credential metadata, including pending/verified/revoked status and current key. |
| `POST /auth/passkeys/registration/options` | `{name}`; initial bootstrap session or recent direct browser passkey session. |
| `POST /auth/passkeys/registration/complete` | `{ceremony_id, credential}`; exact browser registration response and bound bootstrap or recent direct browser session. Returns registration status and ends that session, not a signed login. |
| `POST /auth/passkeys/login/options` | `{}` or an optional `credential_id`; creates a browser-bound authentication challenge. |
| `POST /auth/passkeys/login/complete` | `{ceremony_id, credential}`; actual signed browser assertion, current credential, challenge and browser binding. |
| `POST /auth/passkeys/{id}/revocations` | `{}`; recent direct browser passkey session, with last-verified-key protection. |
| `POST /auth/logout` | `{}`; authenticated session and CSRF. |
| `POST /auth/cli/requests` | `{}`; bounded, expiring CLI request. Returns the confirmation code and polling secret only to the initiating client. |
| `GET /auth/cli/requests/{id}` | Authenticated request ID, controller origin, expiry and state; neither the confirmation code nor polling secret. |
| `POST /auth/cli/requests/{id}/authorize` | `{user_code}`; explicit matching code, recent direct browser passkey session and CSRF. |
| `POST /auth/cli/requests/{id}/exchange` | `{poll_token}`; pending response or one-use credential-bound session transfer. |

Mutations require a UUID `Idempotency-Key`, exact Origin and JSON content type;
passkey-authenticated reads and all authenticated mutations also require the
session CSRF token. Challenge options
return `{ceremony_id, public_key, expires_at}`. Browser credential responses use
base64url-encoded binary fields, and the signed `clientDataJSON` bytes are
preserved exactly.

Ceremonies expire after five minutes. Protected registration ceremonies remain
in the database with their existing creation and failure budgets. Anonymous login
options allocate no pending database row or global admission slot, so unrelated
requests cannot exhaust a five-minute login quota or the registration budget.
Each options request returns a fresh challenge, including repeated idempotency
keys; issuance has no persistent side effect.

For login only, `ceremony_id` is an opaque encrypted ticket, not a UUID. The
server serializes its private verification state into an AES-256-GCM envelope
using a random 32-byte process master, a unique 12-byte nonce and 16-byte tag. The
authenticated context binds the configured origin, login purpose/version,
server-selected owner and tenant, browser cookie hash, random challenge ID and
issuance/expiry times. The browser holds this encrypted ticket only in memory;
plaintext verification state is never accepted from clients. Tickets must not
be put in URLs, logs or browser storage. Restart rotates the key and rejects
pending tickets; it does not reopen bootstrap.

Each process has one checked 64-bit nonce sequence. HMAC-SHA256 derives a
separate AES key for each block of 65,536 issuances; ciphertext and authenticated
context bounds keep each key below 2^27 GHASH input blocks. Earlier keys remain
derivable until process exit, so issuance floods do not evict unexpired tickets.
Sequence exhaustion refuses new issuance without disabling existing tickets.
These encryption-use bounds do not bound attacker-controlled failed verification
attempts or promise availability under sustained request saturation.

Verification runs against current stored credentials inside an IMMEDIATE SQLite
transaction. A successful signature atomically updates the credential, records
one-use challenge consumption and retains original verification state, assertion
and audit evidence. Current owner/principal, key revocation and counter state are
rechecked. Zero-counter authenticators still receive durable replay protection.
Failed assertions create no per-attempt challenge/proof rows; denial samples and
counts use the existing bounded audit aggregation. Concurrent stale credential
snapshots require a fresh ceremony.

All public requests retain the 64 KiB limit. Tickets are bounded to 26,000
encoded bytes before decoding. The server compresses bounded state before AEAD
encryption, then authenticates before decompression; a fixed 64 KiB + 1 KiB
output buffer rejects oversized output, incomplete streams and trailing data.
Plaintext verification state contains public credential material and challenges,
never authenticator private keys. Stored state and assertions each retain their
64 KiB bounds and individual assertion field limits are unchanged. A regression
uses eight independent RSA keys and random maximum-size credential IDs together
with maximum permitted assertion field sizes to check the whole request bound.
Bounded parsing and cryptographic work do not guarantee availability under
sustained CPU or network saturation; there is no shared anonymous history quota
that can lock out successful completion.

This development login extension explicitly departs from F_02's ordinary POST
idempotency contract: public issuance has no persistent result to replay. Only
authenticated encrypted server state travels through the browser, which also
differs from the upstream library's recommendation to keep all serialized
ceremony state server-side. Registration and policy approval retain that
recommendation, and F_01's 64 KiB public request bound remains enforced.
The exception prevents public
requests from reserving every owner's authentication slot; it does not establish
full specification compliance or independent policy authority.

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
python scripts/smoke_login_admission.py
```

Use `--browser-executable /usr/bin/chromium` to select an installed browser.
The suite starts real controller and CLI processes with private temporary state.
Chromium executes actual `navigator.credentials.create/get` against a CDP virtual
CTAP2 authenticator; the controller verifies the resulting cryptographic proof.
Tests cover restart, bootstrap closure, credentials and CLI transfer/revocation.
They also exercise delegated CLI management denials, borrowed registration proof,
normal catalogue reads/writes, and replacement only after a new signed login.
The login-admission suite sends 1,005 anonymous options requests, checks that no
pending database rows accumulate, completes an earlier genuine browser proof,
checks replay and registration availability, and verifies restart key rotation.
Generated reports identify this virtual-authenticator scope and omit credentials,
private keys and proof bytes. They remain ignored local output or bounded CI
artifacts. This does not verify a physical security key, a human consent decision,
OS firewall installation or native packet enforcement.

Confirmed totals and remaining release work are recorded in the
[verification summary](../reports/README.md).

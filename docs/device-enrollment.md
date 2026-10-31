# Register a Linux device for observation

This workflow registers a real transport identity and makes its current capability
report available to the target and service catalogues. The controller and device
client run on the same Linux host in this development profile: the device listener
binds only to loopback. Registration does not approve access requests or change
firewall rules.

## Prepare the controller

Install the [build prerequisites](../README.md#run-locally), including the OpenSSL
development headers, then run from the repository root:

```sh
source scripts/dev-env.sh
cargo build -p fw_control -p fw_cli -p fw_agent --locked
npm ci --prefix web
npm run build --prefix web
export FW_STATE_DIR=state
unset FW_ENROLLMENT_DIR
cargo run -p fw_control --locked -- init-enrollment-ca
export FW_ENROLLMENT_DIR=state/enrollment
cargo run -p fw_control --locked
```

Initialization creates a private `state/enrollment` directory with `ca.pem`,
`ca-key.pem`, `server.pem` and `server-key.pem`. Existing PKI is never overwritten;
for a subsequent start, use the same state and PKI directories and skip
initialization. The command prints the public CA path and `trust_bundle_hash`.
Record that hash through a trusted channel. CA and server private keys stay with
the controller; only the public CA file is shared with a device.

The operator API defaults to `http://localhost:8787`. The separate device endpoint is
`https://127.0.0.1:8791`; `FW_ENROLLMENT_PORT` changes its port, not its bind address.
Omitting `FW_ENROLLMENT_DIR` disables registration. Invalid configured PKI causes
startup to fail rather than creating a new trust root.

The root CA lasts 365 days and the server certificate 30 days. Renewal and rotation
are not automated. Preserve the private state across restarts; do not replace a
root to work around a trust failure.

## Create the device identity and invitation

In a second terminal, from the same repository:

```sh
source scripts/dev-env.sh
cargo run -p fw_agent --locked -- init --state-dir state/device
cargo run -p fw_cli --locked -- login
cargo run -p fw_cli --locked -- enroll-token \
  --name 'Local Linux device' \
  --platform linux \
  --fingerprint 'sha256:REPLACE_WITH_DEVICE_PUBLIC_KEY_FINGERPRINT' \
  --output state/invitations/device.json
```

Replace the fingerprint with the public `key_fingerprint` printed by `fw_agent
init`. The device creates its own Ed25519 key and CSR. Initialization refuses to
replace an existing identity. Before owner enrollment, the operator authenticates
with the controller's one-use bootstrap file. After passkey enrollment, CLI login
prints a browser URL and code: sign in with a passkey and explicitly approve the
matching code. The [passkey guide](passkey-login.md) describes that flow.
Restarting invalidates operator sessions but preserves passkeys and device
registrations; it never reopens bootstrap for an enrolled owner.

The CLI writes the invitation to a protected file **before** requesting issuance.
The API receives a token hash; the raw token stays in the invitation file. A retry
with the same command and output file retains its target and expiry. It does not
create a second invitation or extend the ten-minute deadline. Keep invitations
in private directories and transfer them only through a protected channel; do not
paste their contents into a terminal command, issue, screenshot or log.

## Enroll with pinned trust

Replace the public bundle hash below with the value verified during controller
initialization. The CA file and its hash must come from a trusted channel; do not
accept a new root merely because an endpoint supplies it.

```sh
cargo run -p fw_agent --locked -- enroll \
  --state-dir state/device \
  --controller https://127.0.0.1:8791 \
  --ca-file state/enrollment/ca.pem \
  --trust-bundle-hash 'sha256:REPLACE_WITH_VERIFIED_CA_BUNDLE_HASH' \
  --invitation-file state/invitations/device.json
```

TLS uses the explicit root, normal hostname verification and TLS 1.3. Redirects
are disabled. The controller checks the invitation's public key binding and the
CSR signature, and supplies the tenant, target and SAN itself. The certificate
has client-authentication usage and no policy-signing authority.

The agent saves its pending request ID and nonce before sending the first request.
Retry the same command after a lost response: the server's persisted issuance
reservation fixes the CSR and issuance time, so a retry returns the same identity
without refreshing its validity. A different invitation, key, controller or CA
pin cannot reuse pending state silently. Exact retry recovery is bounded by the
original invitation's expiry.

A device certificate lasts at most 24 hours. The response's eight-hour renewal
hint does not mean renewal is implemented. Expired credentials fail closed;
automatic renewal and replacement of an existing device identity remain future
work.

## Report and inspect the target

```sh
cargo run -p fw_agent --locked -- report \
  --state-dir state/device \
  --controller https://127.0.0.1:8791 \
  --ca-file state/enrollment/ca.pem \
  --trust-bundle-hash 'sha256:REPLACE_WITH_VERIFIED_CA_BUNDLE_HASH'

cargo run -p fw_agent --locked -- status \
  --state-dir state/device \
  --controller https://127.0.0.1:8791 \
  --ca-file state/enrollment/ca.pem \
  --trust-bundle-hash 'sha256:REPLACE_WITH_VERIFIED_CA_BUNDLE_HASH'

cargo run -p fw_cli --locked -- enrollments
cargo run -p fw_cli --locked -- targets
```

`enrollments` shows certificate registration even before a report exists.
`targets` returns a complete target only after an authenticated capability report.
The report contains the actual Linux kernel version, agent executable hash and
nftables version when available. It makes no claim of qualified enforcement:
features remain `unverified`, and supported profiles, protocols and qualification
profiles are empty. Desired and observed policy hashes remain null; authority
epoch and generation remain `0`.

The agent reports once per command. Its capability report lasts **five minutes**;
run `report` again when it becomes stale. Each new immutable report receives a
monotonic outbox revision; an exact retry creates no duplicate event. Missing or stale reports, revoked
credentials and expired certificates cannot establish a usable service target.
This is device-supplied metadata authenticated by a transport identity, not an
independent assessment of the machine or proof of installed firewall rules.

To use the browser after CLI setup, restart the controller with the same state
and PKI, then enter its new bootstrap token in the local login screen. Run a fresh
agent `report` if needed. The Targets page shows the registered device. Create a
manual destination asset, then create a service selecting that destination and
the registered target. The saved service remains visible after reload. Access
requests still remain `needs_info`: workload binding, policy approval and native
dispatch are not connected.

## Revoke a device credential

With a valid operator CLI session:

```sh
cargo run -p fw_cli --locked -- revoke-target REPLACE_WITH_TARGET_UUID
```

Revocation is persistent. Subsequent device status and capability requests fail
authentication, and new service references are rejected. It does not remove kernel
rules or terminate traffic; this application has not installed a policy.
The existing browser session and CLI cannot both consume the same bootstrap
credential; restart and log in through the CLI if the browser consumed it.

## Reproduce the integration check

The smoke script launches real controller, CLI and agent processes using temporary
private state, actual certificates, pinned TLS and mutual authentication:

```sh
python scripts/smoke_enrollment.py
python scripts/smoke_enrollment.py --browser
```

The browser variant additionally needs Python Playwright and local Chromium. It
checks registration-backed target selection and persisted service creation.
Reports omit credential values and stay in ignored local output. These checks do
not qualify native firewall enforcement. See the [agent guide](../crates/fw_agent/README.md),
[CLI guide](../crates/fw_cli/README.md) and [platform status](platform-support.md).

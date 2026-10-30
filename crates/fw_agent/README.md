# Device enrollment client

`fw_agent` creates a Linux device's transport identity, enrolls it with an
explicitly trusted controller, and reports measured metadata over mutual TLS.
It does not apply firewall rules, sign policies, or claim that registration
qualifies a device for enforcement.

Build from the repository root:

```sh
source scripts/dev-env.sh
cargo build -p fw_agent --locked
cargo run -p fw_agent -- init --state-dir state/device
```

`init` creates an Ed25519 private key and CSR in a private directory. It prints
only the public key fingerprint and metadata. Give that fingerprint to the
controller's authenticated operator, who creates a registration invitation with
`fw_cli enroll-token`. Copy the invitation through a protected channel into a
private directory on the device. Obtain the controller's `ca.pem` and its exact
SHA-256 bundle hash through a separately trusted channel; the client never learns
its trust root from an unauthenticated network connection.

```sh
cargo run -p fw_agent -- enroll \
  --state-dir state/device \
  --controller https://127.0.0.1:8791 \
  --ca-file state/controller-pki/ca.pem \
  --trust-bundle-hash sha256:REPLACE_WITH_VERIFIED_CA_BUNDLE_HASH \
  --invitation-file state/invitations/device.json

cargo run -p fw_agent -- report \
  --state-dir state/device \
  --controller https://127.0.0.1:8791 \
  --ca-file state/controller-pki/ca.pem \
  --trust-bundle-hash sha256:REPLACE_WITH_VERIFIED_CA_BUNDLE_HASH
```

Use `status` with the same options as `report` to read the registered device's
current status. The controller checks current certificate registration and
revocation as well as the TLS certificate chain. The client pins the exact CA
bundle and uses normal TLS hostname verification, only the explicitly configured
roots, and TLS 1.3 cipher suites. Redirects are disabled. Enrollment tokens and
private keys never appear in command arguments or output.

The client retains a private request ID and nonce before its first enrollment
attempt, so retrying uses the same reserved issuance. A different invitation,
key, controller origin, or trust pin cannot silently reuse that pending state.
The verified certificate chain is saved as `certificate.pem`; `enrollment.json`
is the authoritative atomic registration record. A process lock prevents
concurrent updates. Credential reads reject symlinks, multiple hard links,
non-regular files, unsafe shared ancestors, and public permissions. Existing
identities are never silently overwritten.

Capability reports contain the actual kernel version, the agent executable's
SHA-256 hash, and the installed nftables version when available. Every security
feature remains `unverified`; the report claims no qualified profiles or
supported protocols. Reporting metadata is not an independent attestation of the
machine or an authorization to change its firewall.

Certificates expire after at most 24 hours. Automatic renewal and certificate
rotation are not implemented in this slice; expired credentials fail closed.
OS-protected Windows credential storage and macOS enrollment tooling remain
unimplemented. Generated identities and report output belong in ignored local
state, not source control.

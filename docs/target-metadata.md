# Independently pinned target metadata

The authority can retain a fresh capability report signed by a separately pinned
device transport key. Controller enrollment and its mTLS report do not establish
this authority trust: a trusted local operator must verify and provision the
target, public key, certificate fingerprint, platform and validity bounds through
an independent channel. The portable proof authenticates the reporting key and
exact bytes; it does not attest the machine or qualify a firewall feature.

This M03/M05 development slice uses `fw.target-metadata-challenge/v1` and
`fw.target-metadata-proof/v1`, described in the
[shared verifier](../crates/fw_target_evidence/README.md). These are development
contracts, separate from the preserved F dispatch protocol. Every admitted report
remains `unverified`; no command produces a policy signature or dispatch grant.

## Local maintenance and device flow

Build the binaries with the pinned toolchain:

```sh
source scripts/dev-env.sh
cargo build --locked -p fw_agent -p fw_authority --bins
```

`fw_authority_admin` is a Unix local maintenance executable. Access to the
protected authority database is its caller authorization boundary. It accepts
public keys/proofs, never policy signing keys. It is not a remotely authenticated
provisioning service or the production authority-bootstrap ceremony. Separate OS
accounts, protected IPC and Windows ACL support remain deployment work.

Use an authority-owned directory with mode `0700` and a private database. On a
fresh installation, `init` refuses to overwrite an existing file. `init-project`
accepts only `{}` and establishes the organization/project namespace and audit;
it creates no person, role, authority basis or trusted target. `$ORG` and `$PROJECT`
below must be the independently verified UUIDs, matching device enrollment.

```sh
umask 077
mkdir -m 0700 authority exchange
target/debug/fw_authority_admin init --database authority/authority.sqlite3
printf '{}' | target/debug/fw_authority_admin init-project \
  --database authority/authority.sqlite3 --org-id "$ORG" --project-id "$PROJECT"
target/debug/fw_authority_admin pin-target \
  --database authority/authority.sqlite3 --org-id "$ORG" --project-id "$PROJECT" < pin.json
target/debug/fw_authority_admin challenge-target \
  --database authority/authority.sqlite3 --org-id "$ORG" --project-id "$PROJECT" \
  < target.json > exchange/challenge.json
```

Prepare `pin.json` from independently checked public enrollment material. Its
closed shape is `{"pin":{...},"expected_revision":null}` for the first pin.
The `pin` fields are `target_id` (UUID), `public_key` (JSON array of 32 raw Ed25519
byte values), `certificate_fingerprint` (`sha256:` plus 64 lowercase hex digits), `platform` (`linux`, `windows`
or `macos`), and `not_before`/`not_after` (integer Unix seconds). Validity must be
the intersection of the approved key and certificate trust windows. The store
does not parse the certificate or validate its chain on behalf of the operator.
`target.json` is the closed object `{"target_id":"<verified target UUID>"}`.

For rotation or certificate renewal, supply the current positive revision as a
canonical decimal string, for example `"expected_revision":"1"`. A stale
revision fails unless it exactly retries the current pin with its original CAS
predecessor; that retry returns the same revision without renewing validity.
Keys retain organization-wide target/project ownership, including
after rotation or revocation; an old key cannot be reassigned or revived.
Renewing the same key with a new certificate requires an explicit new revision
and a new challenge/proof. It cannot relabel an old signature as new evidence.
The store supports this explicit pin update; device certificate renewal itself
remains unimplemented.

Transfer the unsigned challenge through an explicitly authenticated, protected
local channel to the enrolled device. JSON parsing does not authenticate its
issuer. The device checks its tenant, target, SPKI, certificate and time bindings,
validates its enrolled key/certificate against the configured CA, measures a new
report, and signs it without making a network request. This command is currently
Linux-only; its input and output parent directories must be private:

```sh
target/debug/fw_agent sign-metadata --state-dir device-state \
  --controller https://localhost:9443 --ca-file device-ca.pem \
  --trust-bundle-hash "$CA_HASH" --challenge-file exchange/challenge.json --output-file exchange/proof.json
```

Use the actual enrolled origin and explicitly trusted CA/hash. The new proof file
is private (`0600`); an existing path or unsafe alias is refused. Return it to the
authority over the protected channel and admit it:

```sh
target/debug/fw_authority_admin admit-target \
  --database authority/authority.sqlite3 --org-id "$ORG" --project-id "$PROJECT" < exchange/proof.json
target/debug/fw_authority_admin read-target \
  --database authority/authority.sqlite3 --org-id "$ORG" --project-id "$PROJECT" < target.json
```

`revoke-target` takes `{"target_id":"<UUID>","expected_revision":"1"}` on
stdin. Revocation is durable and removes current eligibility; it does not contact
the device or modify its firewall. Controller certificate revocation is a separate
trust domain and must be reflected in independent authority maintenance.
Offline signing cannot query controller revocation; its local certificate checks
do not replace this authority-side maintenance.

## Freshness, transactions and failure handling

Challenges contain a random 32-byte nonce and last at most 300 seconds, clipped
to pin validity. At most four live unconsumed challenges exist per current target
pin. Challenge/report/proof sizes are bounded at 4/64/128 KiB. Admission verifies
strict canonical bytes and the real Ed25519 signature. Reports must be measured
at or after challenge issuance; their effective deadline is the minimum of report,
challenge and pin deadlines, all exclusive at expiry.

Challenge consumption, immutable proof/receipt, current head and mandatory audit
commit in one SQLite transaction. Concurrent exact retries return the original
receipt without consuming again; altered retries fail. Historical receipts can
still acknowledge an accepted report after expiry/revocation, but only a current
read rechecks the latest immutable head, pin, signature, projections and deadline.
It never falls back to an older report or reserves permission for later signing.

Per-target observed time is retained separately before time-sensitive operations,
including a read or refused admission. A later clock rollback cannot revive an
expired pin/report. That clock fence may advance when proof admission fails;
challenge/proof/head/audit changes still roll back together. The CLI samples time
after reading stdin so waiting for input cannot preserve expired authority.

The executable emits fixed error codes without input values or private paths.
An output-write failure can occur after a durable commit: it does not establish
rollback. Re-read current state or retry the exact proof as appropriate. A lost
challenge response occupies its slot until expiry; issuing another challenge
does not recover the lost one. Retained history has no destructive automatic
cleanup; bounded retention/maintenance remains future work.

Authority schema **5** requires an explicit validated private backup to migrate
known schemas 1–4. It imports no target trust from legacy controller records:

```sh
target/debug/fw_authority_admin migrate \
  --database authority/authority.sqlite3 --backup authority/authority-before-v5.sqlite3
```

See [authority storage](authority-store.md) for backup/path/collision rules.

## Verification and next dependency

```sh
cargo test --locked -p fw_target_evidence -p fw_agent -p fw_authority
cargo build --locked -p fw_control -p fw_cli -p fw_agent -p fw_authority --bins
python scripts/smoke_enrollment.py --authority-metadata --report reports/target-metadata-smoke.json
```

The optional smoke uses actual enrollment, certificates and separate processes
with a clearly synthetic fixture pin. It tests tampering, tenant substitution,
reopen, exact replay and revocation; it never changes a host firewall. Unit tests
also cover migration, atomic failures, races, expiry/clock rollback and corrupted
retained bindings. Native measurements and gate evidence, independently trusted
baseline/artifacts, durable signing intents with quota, protected signer/dispatch
deployment and three-OS qualification remain separate requirements.

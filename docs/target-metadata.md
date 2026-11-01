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

### Incorrect forward clock and recovery

An incorrect future system-clock sample can persist a floor beyond real time.
Restarting the process, reopening the database or correcting the OS clock does
not lower that floor. Pin, challenge, admission (including exact historical
retry), current read and revocation refuse earlier time. A read or refused
operation can advance the target floor without changing evidence. A successful
audited future mutation also advances the project's audit timestamp: earlier
audited writes to other targets in that project can then fail, even when their
unaudited current reads remain available.

1. Suspend new authority work while checking the host's trusted UTC/NTP source;
   preserve the database and evidence using the documented consistent-backup
   procedure. Do not keep an incorrect future clock merely to make commands pass.
2. Correct the time source. Existing records and clock floors remain intact.
   Resume only once trusted time reaches all relevant target and audit floors;
   reaching a floor is allowed, but expired pins/proofs still fail normally.
3. Recheck independent trust, renew eligible pins where needed, obtain a fresh
   challenge/report and read the current result. A retained historical receipt
   does not restore expired authority.

There is no immediate operator clock-reset API or qualified new-epoch recovery
workflow yet. If waiting is unacceptable, this is an unresolved availability
limitation, not permission to lower SQL clock values, delete the database,
restore an older snapshot or reuse past grants. Such changes could revive expired
authority and erase the anti-replay history. The reopened-store regression proves
catch-up with fresh evidence and no fence reset; it does not qualify production
disaster recovery.

### Command output and retained state

The executable emits fixed error codes without input values or private paths.
Successful exit requires the complete response to be written and explicitly
flushed, including `--help`. A full destination, a read-only output handle,
or a pipe without a reader returns exit 1
with `AUTHORITY_ADMIN code=OUTPUT_FAILED` when stderr is writable. A broken stderr
does not turn that failure into a panic. Success confirms delivery to the output
stream, not that a downstream reader processed or durably saved the response.
A writable discard sink such as `/dev/null` remains a valid successful destination.
The Rust runtime may restore descriptors closed before program startup to that
sink; after startup this is indistinguishable from intentional redirection.

An output failure can occur after a durable database commit: it does not
establish rollback. Re-read current state or retry the exact proof as appropriate;
the original receipt is retained without renewing authority. A lost challenge
response still occupies its original quota slot until expiry or successful
consumption; issuing another challenge neither recovers nor deletes the lost
one. Retained history has no destructive automatic cleanup; bounded
retention/maintenance remains future work.

For `fw_agent sign-metadata`, a failed stdout summary returns exit 1
with the fixed JSON error code `COMMAND_OUTPUT_FAILED` when stderr is writable.
The signed proof file may already be durable. Preserve and validate that file
before deciding how to recover; do not delete it or repeat collection blindly.
An existing output path is refused, so a retry cannot silently replace the proof.

### Schema migration

Target metadata was introduced in schema 5. The current authority schema **7**
requires an explicit validated private backup to migrate known schemas 1–6.
It imports no target trust from legacy controller records:

```sh
target/debug/fw_authority_admin migrate \
  --database authority/authority.sqlite3 --backup authority/authority-before-v7.sqlite3
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
baseline/artifacts, protected signer/dispatch deployment and three-OS
qualification remain separate requirements. [Durable signing coordination](signing-coordination.md)
now retains transactional intent and quota mechanics; its production resolver
remains closed.

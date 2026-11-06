# Independent local signer boundary

`fw_signer --config /absolute/path/signer.json` runs a separate Linux process
under an explicitly configured non-root signer UID. The controller UID must be
different and non-root. The process verifies its real/effective identity, disables
core dumps, sets no-new-privileges and creates private files under umask `077`.
It does not create OS accounts, install a service or configure platform ACLs.

The closed `fw.signer-config/v1` object contains `signer_uid`, `controller_uid`,
`org_id`, `project_id`, `database_path`, `key_file`, `key_id`, `socket_path` and
`webauthn_origin`. Configuration is loaded from a protected file, never from IPC.
Paths must be absolute and are walked without following symlinks. Config, key,
database and existing SQLite sidecars must be regular, single-link,
signer-owned private files; their final directories must be signer-owned and
not writable by group/other. The Ed25519 key file contains exactly 32 raw seed
bytes and is never returned or logged. Deployment must provision those paths
and ensure the controller cannot rewrite authority storage or read signer keys.
Configuration is limited to 16 KiB; the database and each checked sidecar to
512 MiB. Exceeding these bounds is a refusal, not a retention/archival procedure.

Database/WAL/SHM checks use metadata-only `fstatat` through a protected parent
directory with `AT_SYMLINK_NOFOLLOW`. They must never independently open and close
those inodes after SQLite opens them: POSIX `fcntl` locks belong to the process,
and closing another descriptor can release SQLite's locks. Config/key descriptors
are opened before SQLite and retained for bounded `pread`; later checks compare
path/device/inode/ownership/permissions before and after reading. Startup refuses
input aliases with SQLite files, and the store drops before those descriptors.
Config/key replacement requires restart even with identical bytes; restoring
permissions on the same safe inode can recover normal checks.

The [PR27 review](../../docs/reviews/pr27-claude-review.md) found High S-1 in the
previous file-check lifecycle. Metadata-only source checks alone are not runtime
durability evidence: the [follow-up](../../docs/pr27-follow-up.md) records the new
passing external-reader/DMS and termination/restart exact-retry regressions.
Current integrated validation belongs in [reports](../../reports/README.md);
SIGTERM/restart in tmpfs does not qualify host power-loss recovery.

The Unix socket checks kernel `SO_PEERCRED` against the configured controller
UID. Its parent may allow directory traversal while remaining protected from
controller writes. Socket mode alone is not authentication. Existing socket
paths are refused and never automatically removed. Windows named-pipe and macOS
XPC implementations are not supplied by this crate.

Each connection carries one 4-byte big-endian length followed by strict closed
JSON, then the client closes its write half. Requests are limited to 4,096 bytes;
responses to 524,288 bytes. Trailing bytes/frames, duplicate fields, actor strings,
paths, grant payloads and caller qualification flags are refused. Read/write
deadlines are three seconds across each complete read/write operation, measured
with the monotonic clock. The `fw.signer-request/v1` operations are:

```json
{"schema_version":"fw.signer-request/v1","request_id":"00000000-0000-4000-8000-000000000001","operation":"status"}
```

```json
{"schema_version":"fw.signer-request/v1","request_id":"00000000-0000-4000-8000-000000000001","operation":"status_v2"}
```

```json
{"schema_version":"fw.signer-request/v1","request_id":"00000000-0000-4000-8000-000000000001","operation":"sign_job","job_id":"00000000-0000-4000-8000-000000000002","expected_claim_generation":"0"}
```

```json
{"schema_version":"fw.signer-request/v1","request_id":"00000000-0000-4000-8000-000000000001","operation":"authorize_bootstrap","manifest_id":"00000000-0000-4000-8000-000000000003"}
```

Request/job UUIDs and decimal claim generations must be canonical. A `sign_job`
request references retained immutable work; it cannot choose new signed bytes.
The authority store owns claim fencing, current evidence verification, exact
payload signing and atomic finalization. Config/key/database protections are
rechecked before each operation. Output failure never refunds a committed
issuance or changes its exact retry identity.
The database device/inode is pinned across open and requests; replacing the
path with another database is refused.

`authorize_bootstrap` resolves a retained immutable manifest and actual owner
WebAuthn proof from the configured tenant. It rechecks current credential/owner
role, independently pinned bootstrap-purpose key and exact trust-root binding,
creates the bounded DSSE authorization and retains it before returning its exact
bytes and status. The request supplies no signing bytes or approval hashes.
The result remains `authorized_pending_target_confirmation`, with policy
signing/dispatch false. This initial local/Lab single-owner profile does not
complete Team multi-party bootstrap governance.

`status` returns the exact legacy `fw.signer-status/v1` process/key/peer summary
with `signing_allowed:false`, `dispatch_allowed:false` and the original
`BUILD_IDENTITY_UNVERIFIED`/`NATIVE_QUALIFICATION_UNAVAILABLE` labels.
Clients that need shared canonical gate codes explicitly request `status_v2` and
receive `fw.signer-status/v2`, with `BUILD_IDENTITY_REQUIRED` and
`NATIVE_QUALIFICATION_REQUIRED`. Its verified peer/key fields and false policy
permissions have the same meaning. Both operations use the closed v1 request
envelope and the same bounds/deadlines. Process status does not infer target
confirmation or current target-specific authority.
Production authority resolution remains closed. This is not a generic signing
endpoint or evidence that a target accepted its epoch/baseline, a native backend
is qualified, or production policy signing/dispatch is available. See the
[bootstrap and signer contract](../../docs/protected-signing-authority.md) and
[verification status](../../reports/README.md).

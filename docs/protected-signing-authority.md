# Protected bootstrap and independent signer boundary

This M03/M05 batch starts at
`dded7e94e84ef0e59a0552e961c5c57eaaabdd81` on
`feat/protected-signing-authority`. Its dependency PR26 remains open/unmerged
with remote CI blocked before execution by billing. The
[received follow-up review](reviews/pr26-follow-up-claude-review.md) confirms
F1–F3 and reports no development blocker; its Low D6 timing findings and
whole-store recovery documentation are included in this batch. Current actual
validation belongs in [reports](../reports/README.md).

## Authority contract

The implementation connects the existing WebAuthn owner challenge, independently
provisioned authority records, DSSE, immutable original core provenance/window and durable
signing/quota machinery. It does not replace those mechanisms with caller-provided
approval or qualification flags.

| Object | Exact contract and authority |
| --- | --- |
| Workload binding | `f.workload-binding/v1` payload with DSSE type `application/vnd.f.workload-binding.v1+json`; separate purpose-scoped issuer key |
| Envelope/delegation | Original `f.access-envelope/v1` and `f.delegation/v1` bytes; staging alone authorizes nothing |
| Bootstrap manifest | `f.authority-bootstrap-manifest/v1`; exact immutable subject with no circular approval-set reference |
| Owner proof | `f.bootstrap-approval-proof/v1`; retained actual WebAuthn assertion and current owner-role binding |
| Bootstrap authorization | `f.bootstrap-authorization-envelope/v1` wrapping `f.bootstrap-authorization/v1` and its purpose-bound DSSE |
| Registry status | `fw.authority-registry-status/v1`; retained state, current eligibility and explicit gates, always policy signing/dispatch false |

The signed workload registry retains a cryptographically authenticated issuer
binding. Its signature does not independently establish that the claimed workload
is isolated or that its attestation source is qualified. Original
access-envelope and delegation objects remain their existing unsigned immutable
contracts. They are staged as exact bytes and hashes, then authorized through
their exact references in the owner-approved bootstrap manifest. No new generic
signed-envelope format supplies a second approval path.

`AuthorityBootstrapManifest` binds its organization/project/target, old and new
epoch, trust root, management baseline, capability and exact envelope/delegation
hashes. The manifest contains no final approval-set hash that would make its hash
depend on its own approval. A separate owner WebAuthn proof binds the immutable
manifest subject and current authority. The bootstrap authorization is DSSE with
payload type `application/vnd.f.authority-bootstrap.v1+json`. Import independently
checks those bindings and retains the authorization with its evidence atomically.
The management-baseline `B` hash is a distinct reference from the full StateIR
baseline hash. A matching full-state hash cannot substitute for independently
trusted management-baseline evidence.

The initial bootstrap profile requires one current, independently provisioned
owner and an activated pinned credential with an actual bound WebAuthn assertion.
It covers local/Lab initial authority. Existing Team plan approvals continue to
enforce their distinct-human quorum independently; they do not make this
single-owner bootstrap flow complete Team root-creation or dynamic governance.
Team multi-party bootstrap/authority-change governance remains a later profile.
Controller login, an AI proposal or an unactivated credential cannot supply this
owner proof or silently enroll the trust root.

The bootstrap stages are `staged`, `owner_approved`, then
`authorized_pending_target_confirmation`. Local authorization does not establish
that a target durably accepted its epoch/generation, installed the baseline or
passed management/positive/negative probes. The final pending stage is neither
current execution authority nor permission to sign or dispatch a policy.

Initial bootstrap refuses a target that already has a protected signing head.
It cannot overwrite an existing target epoch/generation or erase issued/UNKNOWN
obligations to create a new genesis. A pending local manifest head is separate
from the executor's durable target confirmation and cannot reset it.

Registry operations share a durable project clock floor and recheck it in their
final transaction. A peer's later expiry observation cannot be bypassed between
initial selection and commit. Historical proof/signature validation remains
separate from current key, owner, input and pending-head eligibility; exact retries
retain original bytes and validity. These local floors require protected retained
storage and do not establish external rollback protection against a coherent
database/backup rewind.

Migration015 is additive. Published SQL001–014, original schema bytes and review
and specification sources remain unchanged. Valid older databases require the
explicit protected backup migration; it does not infer signed workload authority,
owner proof, target confirmation or an initial generation from historical plans.
After publication, migration015 and its schema/guard contract are likewise
immutable history; later schema changes require a new migration.
A database with conflicting schema14 window history still fails complete retained
validation during its required explicit upgrade. See the
[recovery boundary](authority-store.md#conflicting-legacy-core-windows-and-recovery).

## Trusted local administration

Run `fw_authority_admin` only with independently authorized access to the
protected authority database. Every command below takes `--database PATH`,
`--org-id UUID` and `--project-id UUID` and reads one strict JSON object from
stdin, bounded to 128 KiB. Credential possession and bootstrap ceremonies also
take trusted `--approval-origin ORIGIN`. Private assertions/authorization files
belong under `umask 077`; put their contents in stdin, never command arguments
or logs. These commands do not accept a private signing key.

| Step | Commands and input |
| --- | --- |
| Independent authority enrollment | `provision-authority-principal` takes `principal_id`, `issuer`, `subject`; `bind-authority-human` takes `principal_id`, `human_id`. These labels must come from the protected OOB identity procedure. |
| Pending public credential | `pin-authority-credential` takes `credential`, `not_before`, `not_after`; the public credential must have been independently enrolled. |
| Actual possession | `challenge-authority-credential` takes `credential_id`; `activate-authority-credential` takes `activation_id`, `assertion`. Use a real origin-bound WebAuthn assertion. |
| Owner role | `grant-authority-role` takes `principal_id`, `role`, `not_before`, `not_after`; role grant alone does not approve a manifest. |
| Purpose-specific registry trust | `pin-registry-trust-key` takes `{"pin":RegistryTrustKey}`. Independently establish scope/key/purpose; use the canonical bootstrap pin hash as the manifest trust-root reference. Workload and bootstrap keys remain distinct. |
| Exact signed workload | `import-workload-binding` takes the original complete signed binding; its current status authenticates its issuer and retained freshness, not observed workload isolation. |
| Original bootstrap inputs | `import-access-envelope`, `import-delegation`, then `import-bootstrap-manifest` take the original contract objects directly. They remain staged. |
| Owner manifest consent | `challenge-bootstrap` takes `principal_id`, `credential_id`, `manifest_id`; `admit-bootstrap-proof` takes `principal_id`, `challenge_id`, `assertion`. A proof hash or controller session is insufficient. |
| Bootstrap authorization | The signer IPC `authorize_bootstrap` references only `manifest_id` and creates/imports the exact DSSE after resolving current retained owner proof. `import-bootstrap-authorization` alternatively takes `manifest_id`, `authorization` and verifies an already signed authorization. |
| Read or recover lost output | `read-authority-registry` takes `object_kind`, `object_id`; envelope/delegation IDs are `UUID:revision`, and bootstrap authorization uses the manifest UUID. |
| Retained revocation | `revoke-registry-trust-key` takes `key_id`; `revoke-authority-registry-object` takes `content_hash`; credential/role revocations take `credential_id`/`membership_id`. Revocation preserves history. |

The CLI exposes challenge/response plumbing; it does not implement a complete
bootstrap browser enrollment screen or authenticate an administrator's OOB human
identity. The operator must establish those facts independently. A lost import
response can be recovered by the read command and exact retry. Reads and retries
retain the original authority window; they cannot renew an approval, issue a
replacement request or reset an epoch/generation/quota obligation.

## Independent signer process

The signer is a separate Linux process configured with distinct non-root signer
and controller OS identities. Its private key and authority database belong to
the signer identity; protected filesystem paths and Unix peer credentials are
checked independently of request actor strings. The controller receives no raw
key and cannot submit arbitrary payload bytes for signing. Requests reference
retained jobs and their claim generation; current authority, exact original
payload, quota and fenced completion remain authority-owned checks.

The process boundary is useful only with the configured ownership, directory/file
permissions and authenticated IPC. A separate process under the same writable
account does not establish that boundary. This batch does not install system
accounts, configure every platform's ACLs or claim resistance to host
administrator/trust-root compromise or coherent whole-storage rollback.

## Production gates and remaining acceptance

`BUILD_IDENTITY_REQUIRED`, `NATIVE_QUALIFICATION_REQUIRED` and
`TARGET_EPOCH_CONFIRMATION_REQUIRED` remain explicit prerequisites alongside
`POLICY_SIGNER_KEY_REQUIRED`, protected signer deployment and its current authority
context. A bootstrap-purpose key does not become a policy-signing key. The production
resolver stays closed wherever any prerequisite is missing. A successful owner
ceremony, signed registry import, process status response or lab observation does
not qualify a native backend or open production policy signing/dispatch.

`WORKLOAD_SOURCE_ATTESTATION_REQUIRED` also remains explicit: signed workload
claims do not independently resolve asset IDs to revision snapshots or bind a
claimed source identity to actual packet enforcement. The
`read_core_authority_status` library summary can link the signed binding,
exact original provenance/window and matching
local bootstrap material while still returning every policy permission false.
Expired/revoked or superseded authorization remains verified history; its pending
label does not survive a failed current trust/owner/input/head check as usable
authority.

Subsequent work includes target durable epoch/generation confirmation with actual
baseline and management probes, qualified compiler/validator build identity and
observer/baseline/native evidence, authenticated delivery/completion/reconciliation,
and installed Linux lifecycle/watchdog/reboot/coexistence acceptance. Windows WFP
with its required callout and macOS Network Extension need native implementation,
signed platform runners and real kernel tests. Signed install/update/uninstall,
recovery, complete operator workflows, locale/accessibility acceptance and release
operations remain required. Test totals do not determine a completion percentage
or release date.

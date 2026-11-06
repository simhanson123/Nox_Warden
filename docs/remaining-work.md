# Remaining product work and acceptance

The project remains a partial implementation, with a substantial amount of
release work. The policy/approval/storage core and disposable Linux execution
have executable coverage. Installed production authority is incomplete, and the
Windows WFP/callout and macOS Network Extension backends still require native
implementation. Test totals cannot establish a defensible completion percentage
or calendar estimate.

The following sequence maps deliverables to the original
[F08 task DAG](specs/F_08_Codex_Cloud_작업계획.md). Windows and macOS can proceed
in parallel once their shared contracts are stable; each needs its own supported
native runner and evidence. Current review/implementation status is in the
[ledger](../reports/task-ledger.json), not inferred from this plan.

| Order / tasks | Deliverable | Acceptance needed before claiming completion |
| --- | --- | --- |
| Implemented correction, M03/M05 | PR27 signer durability and registry diagnostics/trust binding | Lock-preserving checks, real external-reader/DMS tests and exact authorization/floor after termination/restart are implemented and freshly exercised. The original defect was independently reproduced; current results are in reports/README.md. Revoked re-pin, project-bound origin and consistent closed gates have regression coverage. |
| M03/M04L/M05 | Qualify production inputs on the isolated target-confirmation path | Exact durable epoch/generation predecessor, signed retained target receipt and fresh management-baseline/probe evidence; wrong tenant/key/replay/expiry fail closed. Independently qualify build/compiler/observer/capability and resolve real workload asset revisions/source identity. Local pending bootstrap never substitutes for target confirmation. |
| M03/M04L/M05/M07 | Authenticated exact dispatch and completion | Bind mTLS/IPC delivery to the exact grant, artifact, revocation and durable inbox replay; verify completion and reconcile restart/disconnection. Preserve original lease windows and fencing; UNKNOWN/unsigned delivery never refunds issued capacity. |
| M04L/M08 | Installed Linux lifecycle | Protected service accounts/ACLs/key provisioning and rotation, complete common-host profile including ICMP/fragments/PMTU, real-host baseline and packet acceptance, independent hung-writer watchdog, expiry/crash/reboot/update/coexistence, interrupted install and safe uninstall/recovery on supported versions. Disposable namespace success is insufficient. |
| M04W/M08 | Native Windows/Windows Server | Service, WFP persistent/boot filters and required packet-time callout, protected IPC, signed driver/installer and actual Windows packet/expiry/crash/reboot/update/uninstall acceptance. Common Rust logic or cross-compilation is insufficient. |
| M04M/M08 | Native macOS | App and Network Extension/system extension, authenticated XPC and packet callbacks, entitlements/signing/notarization, and actual supported-device deadline/crash/boot/update/uninstall acceptance. No PF fallback. |
| M01/M02/M03/M05/M06/M07 | Operational authority, evidence and user workflows | Complete extended serializers/registry cross-references and co-signature identity, Team bootstrap/change governance, OIDC/PostgreSQL/RLS, certificate/key lifecycle, backup/approved epoch restore/external audit anchors, bounded retention/redaction/export, notifications and opt-in telemetry/deletion. Complete request/approval/enrollment/evidence/topology UX, keyboard/accessibility and human acceptance of all eight locales; retain English default and saved selection. |
| M08/M09/M10 | Distribution and full release acceptance | Signed provenance/SBOM/notices, three-OS end-to-end/install matrix, supported-version evidence, provider/channel/F11 profiles, documentation and supply-chain/security review. Telemetry defaults OFF; optional donation never gates security. Run required PR CI and separate main CI after merge. |

High S-1 from the [received PR27 review](reviews/pr27-claude-review.md) was the
first dependency. The correction and isolated target-confirmation path are
implemented; current executed results belong in the verification summary.
The next deliverable is qualified inputs and authenticated policy dispatch/
completion. Target confirmation does not complete installed-lifecycle or
three-OS acceptance. PR26/PR27 billing-blocked CI is a
separate unresolved integration dependency. No remote PASS, merge, release date
or production readiness follows from local development alone.

The pinned nftables1.0.6 anonymous multiport `ct.proto-dst` readback remains
unsupported and conservatively refused. Existing scalar companion fixtures do
not qualify that native form. Likewise virtual authenticators, experimental UIDs,
a browser or a cross-compile cannot replace installed supported-OS acceptance.

---
name: firewall-install
description: Install, upgrade, or diagnose this firewall using its verified native releases on Windows, macOS, Linux, and supported cloud VMs. Distinguish host installation from restricted hosting or WordPress integration.
---

# Firewall installation

Use this skill for this project's installation and deployment diagnosis. It does not grant cloud-account privileges or approve policy expansion.

## Find the real product first

Read the repository's `docs/specs/F_09_멀티플랫폼_설치_집행_명세.md` for OS packaging and `docs/specs/F_11_클라우드_호스팅_설치채널_명세.md` for the selected hosting environment. Resolve those paths from the repository root. If the skill was installed separately, obtain the matching version of those documents from the user's selected, verified project repository; do not guess a download host or npm package name.

This supplied skill belongs to a design package. It is usable for diagnosis and preparation now, but there is no released firewall binary in this package. Before installation, verify that the repository actually has a matching release, signed manifest, installer, CLI help, and supported OS entry. If no release exists, state that precisely and prepare the implementation or installation plan; never run an invented install command.

## Choose the correct scope

Determine the target machine, OS/architecture, version, administrator/root availability, provider/hosting class, current firewall manager, and recovery access. Existing user authorization persists; ask only for missing scope or an unapproved consequential action. Read-only diagnosis and local preparation may proceed.

On an administrator-controlled VM or physical machine, use the signed native package. On shared/managed WordPress hosting without host privileges, explain the limitation and use only a supported integration or external control plane. A WordPress plugin, npm wrapper, Docker container, or skill does not gain host-firewall authority by itself.

## Install within the authorized task

Use the release-pinned installer and CLI interface documented for that version. Verify checksum and signature/provenance before elevation. Detect conflicts, preserve the current manager's configuration, establish recovery, install in observe-only mode, enroll the target, and show native capability/health. Move to enforced mode only within the user's approved target and policy scope, after required checks succeed. Never disable all existing security groups or OS firewall rules to make installation pass.

For cloud VMs, prefer instance identity/workload federation and least privilege. Keep provider security groups and host policy distinct. Do not create billable resources, publish credentials, or change production network rules merely to run an installation demonstration. Stop repeated mutation on a persistent permission/signature/connectivity failure and report the evidence.

## Verify and report

Run the real version's status/capability, readback, management-connectivity, allowed/blocked traffic, and expiry checks in the approved test scope. Report installed artifact/version, target OS, active versus observe-only state, privilege/signing/approval status, and failures or unavailable guarantees. Never convert skipped Windows/macOS/Linux native tests into success. Offer the concrete next action needed for any incomplete installation while continuing independent authorized preparation.

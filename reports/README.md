# Verification and implementation status

Keep source, regression tests, reproducible commands, this summary, the
[task ledger](task-ledger.json) and [specification provenance](spec-import.json)
in Git. Raw reports, logs and screenshots are ignored. Selected smoke reports
remain downloadable for seven days from [GitHub Actions](https://github.com/simhanson123/Nox_Warden/actions/workflows/ci.yml).
The supplied specification and fixtures under `docs/specs` remain unchanged.

## Current signer durability and target-confirmation follow-up

`feat/target-authority-confirmation` starts at
`5fc576f672c2e0671164b73a667e3452b99ea82a`, tree
`719b80f88255921711ede7b4f4da81876568f7e3`.
The [received PR27 review](../docs/reviews/pr27-claude-review.md) is preserved as
17,066 bytes, 207 CRLF endings and SHA256
`8b4fa4e6d84ec7c755b3489309bb72a2e31e8fed1bc0634408c010348fd19357`.
Its private probes were not supplied or rerun. Its author directly reproduced
SQLite lock release; its parallel reviewer reported signer commit loss,
differing duplicate authorization and SIGBUS. The earlier PR27 20-stage PASS
missed that descriptor/external-reader lifecycle and remains historical evidence.

The integrated change repairs signer SQLite lock preservation, revoked-key
re-pin diagnostics, independently pinned project origins, gate consistency and
registry profile boundaries. Schema16 and a separate target journal connect
actual isolated non-loopback Linux management rules, signed peer responses,
full kernel readback and retained target confirmations. Explicit CLI/readiness v3
and eight-locale UI distinguish accepted history from current eligibility.
Production policy signing and dispatch remain closed. See the
[correction contract](../docs/pr27-follow-up.md),
[target profile](../docs/target-authority-confirmation.md) and
[remaining acceptance](../docs/remaining-work.md).

Fresh independent baseline reproduction verified all 488 exact PR27 Git blobs,
then reproduced lock loss, lost authorization/floor, differing valid DSSE and
SIGBUS with a freshly built old signer. Its report SHA256 is
`a7c32a4463624a7b5ead271211698292324565823e2c7fa20b904061be244d9c`.
The earlier corrected focused run passed 7 library and 2 startup cases plus
55 normal process checks/17 actual operator CLI calls. Its 432-input digest is
`d0b164d2061934f8fafafbe245339aa2a1754c5cdb000c0cb722b83eb9189f5c`
and report SHA256 is
`c3a1311f4bc91e83007ed73c41c5f71cd105d2be9265a48a756aeafd66fc9661`.
Those focused results are separate checkpoints, not final integrated totals.

The first final-validation snapshot has 462 frozen inputs, SHA256
`08d8709eafdc2b7ab4120831873acecf68f19b8d374b3bc982c041a227c34f8e`.
The fresh canonical invocation passed 1,074 workspace Rust tests, one separate
explicit cancellation CLI test, 33 reduced-feature tests, Python 46/6/20/3,
UI 215 in 11 files and both UI builds, including contracts, fmt and Clippy.
Four ignored workspace declarations include helpers invoked by parent tests
and the separately executed CLI case. Two nested worker summaries were excluded.
The separate shared-umask0002 authority/service invocation passed 637 tests,
with three ignored declarations and two nested worker summaries excluded.
The two invocations overlap and must not be added into a unique-test total.
Fresh npm restore, preflight and workspace binaries/examples build passed.
Canonical count receipt SHA256:
`a8671be90fdbf89f0b65d97f3470849028ab2251f85155867f4895c7903a4c6b`;
shared-umask count receipt SHA256:
`b7d98e4e769de80e9d84f95a0dddc24ccbe552f6596eb9302b3c21d07ee560b5`.

| Fresh runtime suite | Passing checks | Actual execution |
| --- | ---: | --- |
| HTTP / CLI / separate CLI protocol | 24 / 13 / 5 | Real services; separate synthetic CLI protocol fixture |
| Enrollment API / browser / metadata | 23 / 25 / 41 | TLS services and retained evidence |
| Catalogue / passkeys / login admission | 11 / 76 / 14 | Browser and virtual CTAP2 |
| Audit / authority browser | 21 / 44 | Authenticated v3, closed gates, absent-target panel and browser review |
| Isolated Linux | 66 | 40 actual packet-test cases |
| Signed Linux | 98 | 43 actual packet-test cases |
| Core access Linux | 85 | 26 actual packet-test cases and two signed captures |
| Native evidence | 33 | Five actual captures; zero packet probes |
| Protected signer | 57 | Distinct-UID processes, 18 actual operator CLI calls and lock/restart durability |
| Target bootstrap | 53 | 35 actual operator CLI calls; two accepted epochs; six sent request cases/eight attempts |
| Current14→16 compatibility | 15 | Typed rows/rowids/bytes and private backups preserved; incompatible source refused |

All 21 selected final stages passed: 18 bind the original snapshot; protected
signer, target bootstrap and current 14→16 compatibility bind the corrected
snapshot below. The original failed attempt is preserved separately.
Independent final source/evidence/binary/report and selected-artifact audits
passed with no mismatch or pending item. Their receipt SHA256 values are
`75a60ed736aa95e7f2e2f57f2e15bec2b0acf4db38e0998cfc114ed4e164b30f`
and `eb69eacfa019bc4ba4b97796e942739a3ad90813ee6b1aac12687c2d03608625`.
They verify21 selected stages, the separate original failure/control,23-stage
binary continuity and15 selected CI report structures, including the local
`enrollment-api.json` to CI `enrollment-smoke.json` naming correspondence.
This evidence audit does not claim independent source review of code written
by that auditor or a remote CI execution.
The combined summary was written once after those audits, SHA256
`c2fca63998858021d3c4650d22cc5be54d0c248ba9237d0ec894b0d4f518a485`.

The first final protected-signer attempt failed before any product check. Its
18-command setup exceeded the helper's 15-second bound; Python's attempted
cross-UID timeout cleanup lacked CAP_KILL and masked TimeoutExpired as EPERM.
The failure report is preserved unchanged, SHA256
`3b2fbb00cf5eab954488401cee807eaa2526b2b9067683ccc0d8c66a0e6fc3a2`.
The sole source correction uses bounded cleanup under the child's actual UID
and gives only that setup command 90 seconds. Ordinary commands retain 15 seconds;
product code, Docker capabilities and authentication conditions are unchanged.
The corrected 462-input snapshot is
`a0e05b559055508656af4ded010832c1fc785853056ac166c52064e8912092aa`.
Exactly one file changed; the other 461 inputs, all Rust/UI source, stayed identical.
The source-transition receipt SHA256 is
`be014e32ff8d74855f6841ed0ca5993692a0cff65966281490c09b502cbbe517`.
Python 46/6/20/3 and pycompile passed again. An actual four-capability timeout
control verified both child UIDs, termination and reap with the fixed diagnostic
(case 1, product scenarios 0); SHA256
`c5f9325b89ee1ce8a9e0d9729f11335bf9e59ea36bece3cb5d70763366ce8fc1`.
The corrected protected-signer run passed on that new snapshot in 30.64s,
report SHA256
`83b325145cdbe79b1eb9f043868f4a12e405b30e465b087cf462413cc3f46c2d`.
The target run passed in 122.65s, including a real 77.461s wait for signed expiry.
Report SHA256:
`b3cd8ba3ffcba94274dce19bcb3ae945afa5908ad844c6d3d8ba0b028c18e572`.
It verifies actual B1/B2 UDP role exchange, signed positive TCP/UDP responses,
output-loss recovery, changed-nonce refusal, accepted1/current2 historical retry
and retained epoch2 after expiry with eligibility false. Two negative EPERM
attempts sent zero bytes and are excluded from the six transmitted cases.
Earlier successful stages retain their original 08d source binding; these results
are not presented as one unchanged whole-source run.

Current14→16 compatibility freshly executes only the current admin binary
against retained provenance-verified old 3866 fixtures; no new old-binary build
or fixture-generation run is claimed. All old rowids/SQLite cell types/values
and the private backup are preserved, all 18 new tables are empty, and inherited
incompatible history is refused unchanged without a backup/manifest/sidecar.
The genuine released15 fixtures below were separately produced for this batch.

The browser fixture exercises the v3 API/parser/common gates with an absent
target summary. Accepted-target history/current presentation has separate Rust
and UI tests; it is not claimed as native-target browser evidence. Native
results use disposable namespaces, experimental identities and development keys.
SIGTERM/restart in tmpfs does not certify host power-loss recovery or installed
Linux, Windows or macOS. Negative UDP records actual EPERM1 denial with zero
transmitted bytes, separately from successfully sent timeout observations.

Cleanup found no remaining lab container or active service/browser and no scan
errors. 129 exited browser/crashpad zombies owned by PID1 were separately observed;
this is not a claim that the process table is empty.

Current tools were rechecked: Rust/Cargo1.99.1, Node24.19.0/npm11.9.0,
Python3.12.14, Chromium154 and Docker28.4/vfs. Browser runs use the formal
`--browser-executable /usr/bin/chromium` override. No host firewall, host network,
account billing, managed security profile or production deployment was changed.

Published SQL001–015, original specifications and earlier reviews are unchanged.
The lead compared 82 immutable files (including 53 specifications) and 247 external
Cargo identity/checksum tuples; all matched. Preservation receipt SHA256:
`cc6157a92a082439cc6d09b9645449c8334df23c605224934e87ea42d2794602`.
Two public synthetic v15 fixtures come from normal released 5fc flows, not
fabricated authority or whole-database dumps. The healthy fixture preserves all
original typed rows/rowids through16; the released15 cross-role key fixture
verifies whole-database refusal with original/private backup preserved.
Three migration regressions and the nine-table guard matrix ran in canonical
and shared-umask suites. The matrix covers 256 refusals and 60 rollback-only
structural controls, which are not independently authenticated authority.

PR26 and PR27 remain open/unmerged. Rechecked CI42150829408 and CI42216796210
failed before execution with: “The job was not started because your account is
locked due to a billing issue.” Local PASS is not remote PASS, merge or main CI.
Resolve this feature's actual head/tree/PR/run from its retained completion record.
The next Claude Opus5.5 prompt is preparation, not an executed external review.

Reproduce the principal current checks with:

```sh
source scripts/dev-env.sh
npm ci --prefix web
bash scripts/check.sh
(umask 0002; cargo test --locked -p fw_authority -p fw_authority_service)
cargo build --locked --workspace --bins --examples
python scripts/smoke_protected_signer.py --report reports/protected-signer-smoke.json
python scripts/target-bootstrap-linux-lab.py --report reports/target-bootstrap-linux-lab.json
```

The other runtime commands are the smoke/lab steps in
[CI](../.github/workflows/ci.yml), with the browser override recorded above.
The [complete review prompt](../docs/target-authority-review-prompt-ko.txt)
includes focused migration/guard/backend/journal commands. Raw local reports
remain outside Git; selected CI JSON reports have seven-day retention.

## PR27 protected authority and signer checkpoint (historical)

`feat/protected-signing-authority` starts at
`dded7e94e84ef0e59a0552e961c5c57eaaabdd81`. PR26 remains an open,
unmerged dependency on that head; `main` remains at
`a624a1e684a8fc0065ac4f4609101410f56c50bb`. The lead rechecked the PR's
billing-lock annotation. Neither local validation nor this new branch establishes
a remote CI PASS, merge or successful main CI.

The [received follow-up review](../docs/reviews/pr26-follow-up-claude-review.md)
confirms F1–F3 and reports no development blocker. Its 15,477 original bytes,
193 CRLF endings and SHA256
`5fdd4046a0cde498d3e91b1589db8a2613e07883307782a75113ae1ad8deafaa`
are preserved. Its private probes were not supplied; its Docker/native suites
were NOT_RUN. D6a/D6b concern conservative lab timing validation and availability.
The [whole-database conflict recovery boundary](../docs/authority-store.md#conflicting-legacy-core-windows-and-recovery)
now records the affected tenants, evidence preservation, trustworthy compatible
restore context and strict genuine-request registration requirements. There is
no automatic database repair or implemented production restore procedure.

The current substantial batch implements signed authority/bootstrap admission and
an independent signer process while retaining explicit pending target confirmation
and unavailable production qualification. All 20 fresh final local stages and
the independent source/report/binary/artifact audit passed. `bash scripts/check.sh`
passed 1,016 workspace Rust tests (3 ignored; 2 nested worker summaries excluded),
1 explicit cancellation CLI test, 32 reduced-feature tests, Python diagnostic
suites 36/6/14/3 and 211 UI tests in 11 files, both UI builds, contracts, fmt and
Clippy. Fresh shared-umask authority/service tests passed 593 tests (3 ignored;
2 nested worker summaries excluded), and the workspace binaries/examples build
passed. All 20 stages retained the same 427-input source digest:
`f55ec761434508c86be4365f1d2afd98e1c22fc9bb5d6b429ffbdf9e004fc11b`.
The following PR26 sections retain historical counts and source digests; they
are not reused as validation of the changed source.

The complete [Korean review prompt](../docs/protected-signing-review-prompt-ko.txt)
fixes the comparison base and resolves the exact resulting feature head/tree from
the branch's stacked-PR completion record. That record and the user handoff carry
the complete actual-SHA prompt; preparation is not a Claude review execution.

| Fresh runtime suite | Passing checks | Actual execution |
| --- | ---: | --- |
| HTTP / CLI / separate CLI protocol | 24 / 13 / 5 | Real processes; separate synthetic CLI protocol fixture |
| Enrollment API / browser / metadata | 23 / 25 / 41 | TLS services and retained evidence |
| Catalogue / passkeys / login admission | 11 / 76 / 14 | Browser and virtual CTAP2 |
| Audit / authority browser | 21 / 43 | Services and retained review |
| Isolated Linux | 66 | 40 actual packet probes |
| Signed Linux | 98 | 43 actual packet probes |
| Core access Linux | 85 | 26 actual packet probes and two signed captures |
| Native evidence | 33 | Five actual captures; zero packet probes |
| Protected signer | 47 | Distinct-UID processes and exactly 17 operator CLI invocations; zero packet probes |

The core run checks typed `U=1/e=0/C=5`, deduction6 and exact original `E−8`.
The independently recomputed minimum was 2 seconds and both actual tokens retained
5 seconds in a 6.291 ms observation bracket. At `E+2.059`, core tokens were absent
and new/established TCP was blocked. Owner activation/assertion and bootstrap DSSE issuance run through the
actual protected signer; independent verification, lost initial response/exact
durable retry, key loss, database replacement and restart are exercised without
issuing a policy result or opening dispatch. These are local test identities,
not production enrollment or native qualification.

The actual legacy compatibility/migration probe passed 15 checks, separately
covering genuine old-binary initialization/migration and the inherited conflicting
schema14 candidate. The separately built old `3866cea` admin executable has SHA256
`e87b4e5aa08ba27c756b5faad33c5f29c3097afd306c2b7f0fb9511dae5a8118`.
It was freshly built in an isolated target from 169 verified old production
inputs; the separate old private regression test is not compiled into that binary.
The healthy CLI-seeded control preserves rows, hidden rowids, SQLite types and
BLOB bytes across all 66 old tables; nine registry tables start empty and its
backup matches the manifest digest. This small control does not exercise rich
issued/UNKNOWN histories. The inherited conflicting candidate remains unchanged
and produces the exact open/migrate refusals before backup creation.
Cleanup found zero containers, active test services or active
browsers; 111 browser/crashpad zombies were recorded separately and not reaped.
The independent audit confirms 20/20 stages and source/report/binary correspondence,
SHA256 `fbba22cd7496ed40263c599a21fee8a0c7af2656550e3c8c8b42b863b833c7a8`.
Targeted structure inspection of all 14 selected CI artifacts passed, SHA256
`121638baa6724f9572a6e39d4b88a76fb471dec90993004debf1e8df95ae8334`.
That inspection is not a general secret scan or an external Claude review.
The frozen final local summary has SHA256
`b91472b08488522940bed35e2f555e69ec9e2dd792ddb52af6706c24903ae179`.
The preservation audit confirms 80 immutable original files and separately
classifies the one legitimately changed migration regression fixture.

Four preliminary canonical attempts failed on Clippy findings, a test-only
recursive-hook borrow and a stale schema9 migration table-count expectation.
Those failures and earlier protected-fixture setup failures remain private and
are excluded from the final passing totals. Corrections preceded the fresh final
freeze and checks; no production qualification is inferred from their success.

Reproduce the main checks from the repository root with the pinned environment:

```sh
source scripts/dev-env.sh
bash scripts/check.sh
(umask 0002; cargo test --locked -p fw_authority -p fw_authority_service)
cargo build --locked --workspace --bins --examples
cargo test --locked -p fw_authority --test authority_registry_contracts --test authority_registry_store --test authority_registry_integrity --test authority_registry_admin --test authority_registry_matrix
cargo test --locked -p fw_authority --lib schema15_
cargo test --locked -p fw_signer
python native/linux/test_core_snapshot_runner.py
python native/linux/test_signed_runner.py
python scripts/smoke_protected_signer.py --report reports/protected-signer-smoke.json
python scripts/linux-lab.py --report reports/linux-lab.json
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
python scripts/core-access-linux-lab.py --report reports/core-access-linux-lab.json
python scripts/smoke_native_evidence.py --report reports/native-evidence-smoke.json
```

The last five commands require managed disposable Docker. Preserve its configured
socket, proxy/CA and authentication; use `--skip-image-build` only after building
the pinned lab image. No command targets a host's active firewall. Registry matrix
tests live in [authority_registry_matrix.rs](../crates/fw_authority/tests/authority_registry_matrix.rs):
two tests contain 144 refusal attempts and 52 rollback-only SQL controls; these
are assertions within tests, not additional workspace test totals. Rich retained
issued/UNKNOWN/active migration histories and hidden-rowid checks are in
[migration_rebuild_tests.rs](../crates/fw_authority/src/store/migration_rebuild_tests.rs).
The individual CLI migration test compares typed rows and original evidence;
do not describe each CLI fixture as independently checking hidden rowids.

D6's new regressions can be replayed against the exact old production Python
modules without a private harness or Docker:

```sh
nox_d6_probe=$(mktemp -d /tmp/nox-d6-repro.XXXXXX)
mkdir -p "$nox_d6_probe/native/linux" "$nox_d6_probe/scripts"
cp native/linux/test_core_snapshot_runner.py native/linux/test_signed_runner.py "$nox_d6_probe/native/linux/"
git show dded7e94e84ef0e59a0552e961c5c57eaaabdd81:native/linux/core_access_lifecycle.py > "$nox_d6_probe/native/linux/core_access_lifecycle.py"
git show dded7e94e84ef0e59a0552e961c5c57eaaabdd81:native/linux/signed_lifecycle.py > "$nox_d6_probe/native/linux/signed_lifecycle.py"
git show dded7e94e84ef0e59a0552e961c5c57eaaabdd81:scripts/signed-linux-lab.py > "$nox_d6_probe/scripts/signed-linux-lab.py"
python -m unittest discover -s "$nox_d6_probe/native/linux" -p test_core_snapshot_runner.py
python -m unittest discover -s "$nox_d6_probe/native/linux" -p test_signed_runner.py
```

Both old-module runs are expected to fail at the constants/shape/rounding
assertions, including old missing-field errors; import/setup failures do not
reproduce D6. Run both commands even when the first exits nonzero. The same
committed tests against current modules must pass. These are new independent
regressions, not the supplied reviewer's unavailable probes.

For the genuine old CLI migration control, build the reviewed `3866cea` production
source in a separate tree/target rather than reconstructing old SQL:

```sh
nox_old14_tree=$(mktemp -d /tmp/nox-old14-repro.XXXXXX)
git archive 3866ceaa2b86da3ea3653da338d433a23a02b283 | tar -x -C "$nox_old14_tree"
CARGO_TARGET_DIR="$nox_old14_tree/target" cargo build --locked --manifest-path "$nox_old14_tree/Cargo.toml" -p fw_authority --bin fw_authority_admin
```

Use that exact binary's `init`, `init-project` and `pin-target` commands with a
private database and a synthetic public pin shaped as documented in the
[metadata administration guide](../docs/target-metadata.md#local-maintenance-and-device-flow).
They create a genuine schema14 namespace, target pin and two audit events. Stop
all writers, preserve the original and migrate a consistent separate copy with
the current `fw_authority_admin migrate --database COPY --backup UNUSED_PATH`.
Compare original/copy/backup SQLite types and evidence bytes; this small control
does not supply signed jobs or rich quota history.

The incompatible schema14 candidate is separate preserved evidence created by
the old `3866cea` public API in the earlier follow-up, not recreated by those three
CLI seed commands. Its construction paths are the old full-core registration and
legacy provenance APIs exercised by
[core_access_window.rs](../crates/fw_authority/tests/core_access_window.rs) and the
[F1 reproduction](../docs/pr26-follow-up.md#reproduction-and-verification).
The current ordinary open may stop at `MigrationRequired`/`DATABASE_REJECTED`;
explicit migration reaches strict window validation and refuses with
`Binding`/`MIGRATION_REJECTED` before creating a new backup/manifest. The final
report must distinguish that inherited byte-preserved candidate, the freshly
built/CLI-seeded control and reconstructed permanent migration fixtures.

<a id="current-pr26-review-follow-up"></a>

## PR26 review follow-up checkpoint (historical)

The [received PR26 review](../docs/reviews/pr26-claude-review.md) targets
`3866ceaa2b86da3ea3653da338d433a23a02b283`.
[The follow-up](../docs/pr26-follow-up.md) addresses legacy fixed-window binding,
malformed-input clock observations, strict legacy upgrades and stronger native
expiry/signature/refusal/reference verification. The raw report is preserved;
its private probes were not supplied and its Docker suites were NOT_RUN.

New tests against an isolated copy of that exact production source independently
reproduced F1 in both registration orders and F2: three matching regression tests
failed at the expected assertions, without compilation errors. Those failures
prove the baseline defects; the corrected-code results are recorded below.
Implementation, focused checks and independent source review are complete.
Fresh canonical `bash scripts/check.sh` passed **957 workspace Rust tests**
(3 ignored; two nested worker summaries excluded), **1 explicit CLI test**,
**32 reduced-feature tests**, **211 UI tests in 11 files**, both UI builds and
static/Python checks. Python diagnostic suites passed 27/6/14/3 tests.
The final 406-input digest is
`c533bbc57909184dc29fe3a1bbed2574a5c230f0e7be006644806a2409015302`.
Fresh shared-umask authority/service tests passed **541** tests, with 3 ignored
and two nested worker summaries excluded. The workspace binaries/examples build
and all runtime verification also passed on unchanged inputs.

The new actual core Linux run passed **85 checks, 26 actual packet probes and
two signed captures**, with unchanged inputs and container cleanup. Original
`E−8` new and established TCP observations succeeded within a 6.7 ms clock
bracket; the independently computed minimum token lifetime was 1 second and
both actual tokens retained 4 seconds. Post-`E` traffic was blocked and core
tokens expired. All six exact refusal cases preserved journal/generation/native
state, including a 64-byte forged signature reaching signature verification.
Both captures bind the separate observation reference pin and independently
recompiled artifacts. Driver init/apply/replay gained no new external-pin gate.

Focused authority window19, live-cost7, primitive v1 accounting1, first-window
concurrency1 (three real-peer paths), reference-pin3 and final Python runner27
passed. These commands overlap and are not summed as a workspace total. The
v1 regression covers retained full-duration charge and primitive occupancy,
not a newly exercised complete legacy core signing lifecycle. An earlier
native-package focused execution preceded the final Python diagnostic change
and had a documentation-only source-map change; final canonical/core evidence
above binds the final source instead.

The first new core attempt failed its diagnostic assertion after 21 checks,
6 packets and one capture; cleanup succeeded. Its child raw stderr was not
retained. A separate same-binary/pinned-image help probe confirmed the existing
exact leading GLIBC2.39 loader warning. The corrected parser classifies only
that one known leading warning separately and requires an exact application
primary/wrapper chain, rejecting other output. The subsequent actual core run
passed every intended refusal. The failed attempt is preserved privately and
excluded from passing totals. Prior checkpoint counts below are historical.

| Fresh runtime suite | Passing checks | Actual execution |
| --- | ---: | --- |
| HTTP / CLI / separate CLI protocol | 24 / 13 / 5 | Real processes; separate synthetic CLI protocol fixture |
| Enrollment API / browser / metadata | 23 / 25 / 41 | TLS services and retained evidence |
| Catalogue / passkeys / login admission | 11 / 76 / 14 | Browser and virtual CTAP2 |
| Audit / authority browser | 21 / 43 | Services, restart and retained review |
| Isolated Linux | 66 | 40 actual packet probes |
| Signed Linux | 98 | 43 actual packet probes |
| Core access Linux | 85 | 26 actual packet probes and two signed captures |
| Native evidence | 33 | Five actual captures; zero packet probes |

An additional old-implementation compatibility probe passed four checks: a real
`3866cea` public-API-created incompatible schema14 database is rejected by the
new admin executable with exact `DATABASE_REJECTED`, no successful output and
unchanged database bytes. Expected admin exit1 is the successful refusal result.
This is distinct from the external review's schema13 migration experiment.

Fourteen fresh runtime JSON reports, the separate CLI protocol and old-database
probe were verified; thirteen reports are selected for CI. The independently
checked final local summary has SHA256
`771c38ffef7123e348fb18bb6d6b7dc73d746f9f00e8bf0a13603105f36b260c`.
Reported source hashes and each executable's own execution-stage hash match;
binary reproducibility across hosts is not claimed. All four lab containers
were removed, with zero containers and zero live test services/browsers. The
93 remaining Chromium/crashpad entries were confirmed PID1-owned zombies.

The first unsigned Linux attempt was NOT_RUN before packets because buildx's
metadata directory was read-only. A private writable `BUILDX_CONFIG` corrected
that environment issue while retaining Docker/auth/proxy settings; the same
product command then passed. The catalogue command and all 11 assertions passed
on first execution; the private collector was corrected to understand its
existing `passed:true` report schema, preserving the original report/metadata.
Neither adjustment changed product source or reused previous passing reports.
No production qualification, external rollback protection or multiport readback
qualification is claimed. Independent source/evidence review found no remaining
finding within this correction scope; it is not a new Claude execution.

The PR's original CI42036443828 attempt1 never started a runner/test step because
GitHub reported a billing lock; it produced no artifacts. No remote CI PASS or
merge is inferred from local validation. The retained PR completion record holds
subsequent exact-head remote status.

## Reviewed PR26 core-access checkpoint

This integrated batch starts at PR25 merge
`a624a1e684a8fc0065ac4f4609101410f56c50bb` on
`feat/core-access-enforcement`. The [received PR25 review](../docs/reviews/pr25-claude-review.md)
reports no security defect or development blocker; [source-qualified corrections](../docs/pr25-review-assessment.md)
fix the prompt filter and describe the actual fault matrix and hook/snapshot scope.
Fresh exact baseline-filter verification passed one test. Schema14 and the
[connected core profile](../docs/core-access-enforcement.md) are implemented.
Focused planner, window/migration, CLI/API/UI and native-codec tests passed.
Consolidated source review and the actual new core Linux lab are complete: the
lab passed **72 checks, 24 actual packet probes and two signed native captures**,
including the original 60-second expiry and autonomous restrictive recovery after
normal-plan expiry under the original recovery deadline. The shipped authority
browser passed **43** checks, including a fresh virtual-passkey core approval,
unchanged fixed times and closed signing/dispatch. Fresh `bash scripts/check.sh`
passed **943 workspace Rust tests**, 3 intentionally ignored declarations,
**1 explicitly executed CLI test**, **32 reduced-feature tests** and **211 UI
tests in 11 files**, both production UI builds and all static/Python checks.
The Rust workspace total excludes two nested migration-worker summaries. Shared
`(umask 0002; cargo test --locked -p fw_authority -p fw_authority_service)` also
passed **530** tests with 3 ignored and two nested worker summaries excluded.
Fresh `cargo build --locked --workspace --bins --examples` also passed. The
complete local validation and independent integrated review are finished; fresh
PR/main CI and merge results belong to this branch's retained PR completion
record. No new Claude review or production qualification is claimed.

| Fresh runtime suite | Passing checks | Actual execution |
| --- | ---: | --- |
| HTTP / CLI / separate CLI protocol | 24 / 13 / 5 | Current binaries; separate synthetic CLI protocol fixture |
| Enrollment API / browser / metadata | 23 / 25 / 41 | TLS services and retained evidence |
| Catalogue / passkeys / login admission | 11 / 76 / 14 | Browser and virtual CTAP2 |
| Audit / authority browser | 21 / 43 | Restart readiness, fixed core window and virtual-passkey approval |
| Isolated Linux | 66 | 40 actual packet probes |
| Signed Linux | 98 | 43 actual packet probes |
| Core access Linux | 72 | 24 actual packet probes and two signed native captures |
| Native evidence | 33 | Five actual kernel captures; no packet probes |

Fourteen fresh JSON reports and the separate CLI protocol result passed. Thirteen
reports are selected for CI; the extra enrollment browser report is local only.
The final 406 executable/test/spec/CI/toolchain inputs remained at SHA256
`788e81beffa32cd4c0ed2717ed640ece69ecf5cf8935187883343cf547c28bbf`.
Independent review found no remaining finding in the 59 changed source/test/CI
files (manifest SHA256
`253240115b1f7c5c66cd859f950e0156992ea92353219ac892deb07a9e46ae88`).
The independently audited local summary has SHA256
`4214872ce333dcdc47cd0a5a347374f408124bea6b30a9036b1e634582cebced`.
Reported binaries were matched to their own execution-stage snapshots; this is
not a cross-platform reproducible-build claim. The authority browser preceded
two test-only fixture-module alias changes, independently checked to leave all
production inputs unchanged. All four lab containers were removed, with zero
containers and no live test services/processes at final cleanup. The 46 retained
Chromium entries were confirmed zombies owned by PID 1, not running browsers.

Initial integration failures were corrected before these final passes. Fixes
kept original absolute windows and the five-second installation budget, bound
baseline installation immediately before publication, reused only scoped
immutable material while repeating current trust/signature/time checks, made
observer journal reads genuinely read-only, and compared naturally aging nft
tokens without masking static rule changes. Browser response decoding and
duplicate test-fixture modules were also corrected. Failed attempts are retained
locally and excluded from passing totals; no unavailable failure predicate is
presented as independently proven.

Pinned nftables 1.0.6 still emits ambiguous invalid-type text for anonymous
multiport conntrack sets. The verifier refuses it. The core lab uses equivalent
scalar-port policies and does **not** qualify that multiport readback path.
Actual autonomous recovery occurred after the normal plan expired and before
the original lease ended; lease expiry and recovery-at-expiry model checks are
separate evidence. Synthetic lab trust does not authenticate production workload,
delegation or human approval. Protected signing/dispatch, installed Linux
lifecycle, Windows WFP/callout, macOS Network Extension, authenticated completion
and external audit anchors remain incomplete.

## Completed PR25: validated clock selection and rollback coverage

The completed batch starts at `59c70ac32fd10e4d5ef6b63cc7f54f4eb5759fe8` on
`fix/validated-clock-and-rollback-coverage`. The
[received review](../docs/reviews/pr24-claude-review.md) and
[qualified assessment](../docs/pr24-follow-up.md) distinguish attributed external
results, existing coverage and new corrections. PR24's PR CI41819099169 and
main CI41824170284 succeeded; neither validates this new batch.

The implementation moves all three retained intent/job selections into validated
snapshots and compares selected bindings again before final use. It removes the
unchecked wrapper read. Separate signature/generation fixtures reach the intended
semantic checks; genuine transition and intermediate approval failures record
exact fault reachability, preceding table mutations and retained-row rollback/retry.
Approval faults record ordered table/action pairs; transition faults also compare schema.
The existing 12 native fault stages are preserved, including review-evidence
INSERT; the original changed-expiry reference-pin retry is restored.

Focused checks passed with nonzero execution: clock selectors2, signing intents10,
live integrity6, rootless lifecycle6, approval atomicity4 (13 two-human fault conditions, including two existing audit-INSERT stages),
late transition1, early schema refusal1, native private7 and reference-pin retry1.
A separate precise signature rerun overlaps the signing-intent count and is not
added. Independent Sol6.1 ultra source review verified the frozen 390-input
snapshot and found no confirmed blocker; this is not a new Claude execution.
Fresh final `bash scripts/check.sh` passed on 2026-11-05: **905 workspace
Rust tests**, 3 intentionally ignored declarations, **1 explicitly executed
cancellation CLI test**, **32 reduced-feature tests**, **190 UI tests in 10
files**, both UI production builds and all static/Python checks. Shared
`(umask 0002; cargo test --locked -p fw_authority -p fw_authority_service)`
passed **510** tests with 3 ignored. Both Rust totals exclude the two nested
migration worker summaries. `cargo build --locked --workspace --bins --examples`
also passed. The 390-file executable/test/spec/toolchain input digest remained
`dd70d06e7f8e4c0c5bae292ab4ad4619c4ed0f83d07449d62054b3567384f2a3`
through final validation.

| Fresh runtime suite | Passing checks | Actual execution |
| --- | ---: | --- |
| HTTP / CLI / separate CLI protocol | 24 / 13 / 5 | Current binaries; separate synthetic CLI protocol fixture |
| Enrollment API / browser / metadata | 23 / 25 / 41 | TLS services and retained evidence |
| Catalogue / passkeys / login admission | 11 / 76 / 14 | Browser and virtual CTAP2 |
| Audit / authority browser | 21 / 40 | Services, restart and strict readiness |
| Isolated Linux | 66 | 40 actual packet probes |
| Signed Linux | 98 | 43 actual packet probes |
| Native evidence | 33 | 5 actual kernel captures |

Thirteen fresh successful JSON reports and the stdout-only CLI protocol result
were checked. All 216 reported source/binary hash entries across 107 unique
paths match the verified bytes. All three lab containers were removed; the
managed daemon remained healthy with no containers or leftover test services.
The native collector recorded its existing narrowly recognized optional
GLIBC2.39 weak-symbol warning in the pinned lab image; exact refusal diagnostics
and all capture checks passed. No lab setup failure occurred in this batch.

PR25 completed at head `89684e055f01a1c87113e4ea4a713ebbff77afe1`, merged as
`a624a1e684a8fc0065ac4f4609101410f56c50bb`. PR CI41945354850 and separate main
CI41950760489 passed, with matching fresh counts and source/artifact audits.
The retained branch and PR preserve the completion record and historical prompt.
The subsequently received external PR25 review is recorded above.

Initial targeted attempts caught Rust test-pattern issues and inaccurate fixture
assumptions: result/outbox hashes must agree before the signature check, neither
transition path writes the project security row, and the development signing
helper must use the retained payload's original issuance time. These were fixed
without weakening exact errors, pending-write/rollback checks or production
authentication. The transition test separately records previously committed
clock observations and pending writes. Earlier failures are retained locally;
they are not passing checks.

The new environment was checked again against README pins: Rust1.99.1, Node24.19.0/npm11.9.0,
Python3.12.14/jsonschema4.26.0, Playwright1.62.0, system Chromium154 and managed
Docker28.4.0/vfs. Browser launch and daemon readiness are environment checks,
not product suite passes. Docker commands use the explicit managed socket and
private command-scoped buildx state while retaining Docker/auth/proxy/CA settings.

## Completed PR24: live integrity and validation cost

The completed PR24 batch began at PR23 merge
`4cef6acf7e46289b156fcd56ad0ab2f2920fabd6` on
`fix/live-authority-integrity`. The received
[complete report](../docs/reviews/pr23-claude-review.md) and
[correction scope](../docs/pr23-follow-up.md) distinguish external findings
from new local evidence. PR23's PR CI41580876482 and main CI41584624128 succeeded;
these historical passes are not tests of the current changes.

New isolated baseline probes reproduced R1 in eight genuine lifecycle variants,
R2 in four variants and R3 with rooted/project-only jobs. The three passing
assertion tests confirm vulnerable baseline behavior. Source and portable
commands are preserved in [the local reproduction](../docs/reviews/pr23-local-repro.md).
The separate initial R4 harness did not compile and produced no runtime or
performance evidence. That execution is not a passing test.

The implementation uses a connection-local snapshot marker, complete validation
after external commits, read-snapshot prevalidation before an immediately locked
version comparison, permanent unsafe-local-SQL taint and exact work-audit
correspondence. Published SQL001–013 stays unchanged. Independent internal
Sol6.1 ultra review found no remaining source blocker after preserving typed
contention semantics and late audit-failure rollback coverage; four separately
written adversarial probes passed. These are not another Claude execution.

The [normal-history comparison](../docs/authority-validation-performance.md)
measured the same genuine cancelled-job fixtures. At 500 jobs, debug median
library open decreased from 7.563s to 4.172s and ordinary CLI read from 8.158s to
4.826s. Each has three samples. Complete checks still grow with history and can
retain WAL pages; concurrent changes may require retry. The measurements precede
the final error-handling/contention refinements and are not claimed as
exact-final-commit benchmarks. The measured read-only paths do not execute the
writer retry. The external primitive20k timings remain separate evidence.

Fresh final `bash scripts/check.sh` passed on 2026-11-04 (exit0): **900
workspace Rust tests**, 3 intentionally ignored declarations, **1 explicitly
executed cancellation CLI test**, **32 reduced-feature tests**, and **190 UI
tests in 10 files**, plus both production UI builds. Formatting, all-target
workspace Clippy with warnings denied, specification/contracts/vendor/locale
checks and Python diagnostics 9/6/14/3 passed. The two completed nested migration
worker summaries are excluded from the workspace count. The ignored declarations
are the separately invoked CLI fixture, subprocess migration worker, and manual
performance harness; the performance measurements above remain separate.

The 345-file executable/test input digest stayed identical throughout the full
entry point, as did the independent 93-file authority review snapshot. The final
shared `(umask 0002; cargo test --locked -p fw_authority -p
fw_authority_service)` passed **505** tests with 3 ignored declarations; its two
nested worker summaries are excluded. Required bins/examples built successfully.
The real runtime/browser/Linux suites also passed on these same sources.

| Fresh runtime suite | Passing checks | Actual execution |
| --- | ---: | --- |
| HTTP / CLI / separate CLI protocol | 24 / 13 / 5 | Current binaries; separate synthetic CLI protocol fixture |
| Enrollment API / browser / metadata | 23 / 25 / 41 | TLS services and retained evidence |
| Catalogue / passkeys / login admission | 11 / 76 / 14 | Actual browser and virtual CTAP2 |
| Audit / authority browser | 21 / 40 | Current services, restart and strict readiness |
| Isolated Linux | 66 | 40 actual packet probes |
| Signed Linux | 98 | 43 actual packet probes |
| Native evidence | 33 | 5 actual kernel captures |

Thirteen fresh successful JSON report files and the separate stdout-only CLI
protocol result were checked. All 212 reported source/binary hash entries across
105 unique repository paths match the verified bytes. All three lab containers
were removed and the managed daemon remains healthy with no containers. The
first Linux invocation stopped before packets because buildx could not write
its state under the read-only home directory. Repeating that lab with a private,
command-scoped `BUILDX_CONFIG` succeeded; the original setup failure is preserved
separately and is not a product PASS. `DOCKER_CONFIG`, authentication, proxy/CA
configuration and the explicit managed socket were preserved. The native
collector recorded its existing narrowly recognized optional GLIBC2.39 weak-symbol
warning when using the host-built executor in the pinned bookworm image; its
fixed refusal diagnostics and all actual capture checks still passed.

PR24 completed at head `ac027412c88eade8d3674c75c2ba6203df023ee6`, merged as
`59c70ac32fd10e4d5ef6b63cc7f54f4eb5759fe8`. PR CI41819099169 and separate main
CI41824170284 passed with the same counts and matching source/artifact audits.
The retained `fix/live-authority-integrity` branch and PR24 preserve this completed
batch and its historical prompt. The subsequently received external review is
recorded in the current follow-up section above.

Preliminary attempts exposed two lint issues and older fixture assumptions about
schema corruption, global quarantine, clock advancement and healthy contention.
Those were corrected while preserving actual late-write rollback and exactly-one-
winner checks, then the entire canonical entry point passed afresh. An overlapping
executable rebuild had separately caused a child-spawn NotFound; its quiescent
migration rerun passed. Failure evidence stays local and is not counted as PASS.

The current
environment was checked again: pinned Rust1.99.1, Node24.19.0/npm11.9.0,
Python3.12.14/jsonschema4.26.0, Playwright1.62.0, system Chromium154 and managed
Docker28.4.0 are available. A browser launch check passed. The product suites above were subsequently executed on the frozen sources;
these environment observations alone do not establish product qualification.

## PR22 integrity corrections

The schema13 batch starts at PR22 merge
`d54021a9df32c0a041c52002b05a0e9d64058c0f` on `fix/quota-open-integrity`.
The [received Claude report](../docs/reviews/pr22-claude-review.md) and
[correction matrix](../docs/pr22-follow-up.md) preserve the external findings and
their attribution. The pasted report is UTF-8/LF with SHA256
`174db04e57e473b21484ecf27415794e1911d50263a967052692178c1c2d2775`;
private external probes were not obtained or rerun.

New archived-baseline fixtures reproduced hidden held projections (D1), stale
physical partial-index contents with restored SQL (D2), and a committed intentless
reservation (D5). The new D5 shape also passed the baseline's actual non-test
maintenance CLI; the current binary rejects that same saved DB. This differs from
the supplied D5 variant and is reported separately. Published-schema fixtures
independently reproduce audit gaps and stale staged bindings (D3/D4), followed by
opposite refusal/atomicity regressions. Existing migrations001–012, specifications
and previous review bytes are unchanged.

The [replayable old-source fixture](../docs/reviews/pr22-legacy-renewal-repro.md)
builds actual schema10 code at `2219c9ffe64fc0f4a967f3af69e84cdcc15aaff3`, with
only an added test exporter, and commits two normal renewals in the same second.
The archived PR22 non-test schema12 migrator rejects a copy with
`MIGRATION_REJECTED`; 17 independent checks verify the unchanged original/candidate
and a valid exact private backup. Current maintenance migrated its 64 original
tables/94 original rows to 13 with
identical rowids, SQLite types and BLOB/audit bytes and an exact private backup.
Four original work/audit pairs have distinct ordered bindings. Additional permanent
fixtures reconstruct historical schemas; they are not all old-binary-created.

Consolidated internal GPT-6.1 Sol ultra review found no confirmed blocker in the
new crate diff. Fresh independent probes checked 38,904 audit-trigger cases over
unsigned carries/exhaustion and FK/recursive settings, and 16 non-test CLI/SQL
refusals plus write-free recovery reads. A second worker cross-reviewed the
atomic projections and legacy matching outside their implementation ownership.
This is not a new Claude execution or production/native qualification.

Fresh final validation on 2026-11-03 passed the complete `bash scripts/check.sh`
entry point: **873 workspace Rust tests**, 2 intentionally ignored declarations,
1 explicitly executed CLI fixture, 32 reduced-feature tests and 190 UI tests in 10
files, plus both UI production builds. Shared `(umask 0002; cargo test --locked
-p fw_authority -p fw_authority_service)` passed **478**, with 2 ignored. Nested
subprocess summaries are excluded from those totals. Formatting, workspace
all-target Clippy with warnings denied, spec 27, contracts 52+28, locale parity and
Python diagnostics 9/6/14/3 passed. These are fresh results on the final code.

| Fresh runtime suite | Passing checks | Actual execution |
| --- | ---: | --- |
| HTTP / CLI / separate CLI protocol | 24 / 13 / 5 | Current real binaries |
| Enrollment browser / metadata | 25 / 41 | TLS services and retained evidence |
| Catalogue / passkeys / login admission | 11 / 76 / 14 | Actual browser and virtual CTAP2 |
| Audit / authority browser | 21 / 40 | Current services, restart and strict readiness |
| Isolated Linux | 66 | 40 actual packet probes |
| Signed Linux | 98 | 43 actual packet probes |
| Native evidence | 33 | 5 actual kernel captures |

All 12 JSON reports were newly written after canonical validation; 198 reported
source/binary hash entries (98 unique paths, including 10 binary entries) matched.
The 292-file executable/test input snapshot and 28-file independent review snapshot
also matched. All three lab containers were removed; the managed local daemon
remains healthy with no containers. Environment: Rust1.99.1, Node24.19.0/npm11.9.0,
Python3.12.14/jsonschema4.26.0, Playwright1.62.0, Chromium154.0.8037.57 and Docker28.4.0.
The scripts explicitly select the managed Unix socket and preserve proxy/CA/auth;
only writable `BUILDX_CONFIG` is supplied for the restricted home directory.

The first canonical attempt was deliberately stopped before a known obsolete
arithmetic-fixture assumption reached failure. That invocation and an overlapping
52-test quota run are ABORTED, not passed. The arithmetic
fixture now scopes its existing test-only exemption per thread; genuine integrity
fixtures and production builds retain strict intent/job validation. The corrected
race passed its focused rerun before the full canonical restart.

PR22's PR CI41564239539 passed. Its separate main CI41566909739 **failed** because
the short metadata fixture expired during setup before the slow-stdin scenario.
The revised test establishes process input readiness before arming expiry,
explicitly verifies acceptance at its pre-input time, then verifies actual CLI
refusal after expiry. Production authentication/freshness code is unchanged.

## Historical PR22 integrated history and project quota validation

The implementation starts at merged handoff PR21,
`2219c9ffe64fc0f4a967f3af69e84cdcc15aaff3`, on
`fix/authority-history-and-project-quota`. PR21's original CI41446221692 and
[merged-main CI41556555849](https://github.com/simhanson123/Nox_Warden/actions/runs/41556555849)
succeeded. Those documentation checks are not product follow-up validation.

Schema11 implements N1–N7 retained history/audit/object/reference corrections;
schema12 adds shared rooted/project-only quota, strict versioned administration
and readiness/UI. Every old migration001–010 and the original PR20 review remain
byte-identical. Production signing/dispatch remain closed. Current source and
next work are in the [handoff](../docs/session-handoff.md) and [ledger](task-ledger.json).

Fresh independent fixtures reproduced N1–N7 against the old code. They are new
local probes, not the external reviewer's private sources. Opposite regressions
cover genuine retained signing/UNKNOWN/delivery/cancellation states. An exact
old6eb68a9 binary created both public-API principal/audit data and a two-job signed
development fixture. Upgrading the signed DB10→12 preserved all64 original product
tables' rowids, typed values and BLOBs (migration registry prefix retained), all45
audit events and an exact private backup;10 new work-audit links reference the
original events. Public lifecycle reads still hold both issued obligations at
fixture time and24h later. Other legacy fixtures reconstruct historical schema;
not every fixture was created with an old binary.

Internal independent review found and prompted corrections to imported genesis
continuation, an accidental lifetime job cap, ineffective failure injection,
initial job creation ordering and saved-scope clock handling. Migration tests
exercise real COMMIT BUSY, abrupt exit after table DROP, competing processes,
eight rollback checkpoints, exact backups and FK restoration. Missing/ambiguous
historical audit mappings are refused rather than manufactured. An internal
10,108-case SQL probe independently checked unsigned audit-head successors.
At this checkpoint the external Claude review had not run; its subsequently
received findings are preserved in the PR22 correction section above.

Fresh local validation completed on 2026-11-03. Rust workspace components pass
**851 tests** (169 authority library +233 authority integrations +449 remaining
workspace; nested subprocess summaries excluded), with 2 intentionally ignored
helpers. The cancellation CLI process passes separately: 1, reduced-feature
verification: 32, shared-umask authority/service: 456 and UI: 190 across 10 files.
Current formatting and workspace all-target Clippy with warnings denied pass.
Both controller and authority UI production builds pass. Eight controller
catalogues retain 229 keys each and eight authority catalogues 157; human
translation acceptance remains outstanding.

The local `bash scripts/check.sh` invocation initially stopped at stale integration
schema10 expectations. Those test fixtures were corrected for schema12 while
preserving historical source versions. **That failed invocation is not labeled
PASS.** Its already-passing 169 library tests were retained; all authority
integrations (`cargo test --locked -p fw_authority --test '*'`), remaining workspace
(`cargo test --workspace --locked --exclude fw_authority`), authority bins/doc-tests,
explicit CLI, reduced features and frontend tail passed afterward. The required
full `(umask 0002; cargo test --locked -p fw_authority -p fw_authority_service)`
then passed on the final test tree. CI runs the canonical entry point on the
pushed commit; the branch's PR records exact CI and merge status.

Static checks pass 27 specification checks, 52 core and 28 extended contract fixtures,
vendored-source verification and Python diagnostic suites 9/6/14/3
(Linux runner/catalogue/authority/native evidence). The authority smoke's stale
v1 wait was updated to strict v2; its final 40 checks passed. A bounded primary
failure diagnostic is retained when an early failure prevents a planned restart.

| Fresh runtime suite | Passing checks | Actual boundary |
| --- | ---: | --- |
| Controller HTTP | 24 | Actual loopback endpoints |
| CLI / separate protocol fixture | 13 / 5 | Current binary and hostile-response fixture |
| Passkey browser | 76 | Virtual CTAP2 with real services |
| Login admission browser | 14 | Availability and replay |
| Audit HTTP/MCP/browser | 21 | Stable pagination and denial evidence |
| Catalogue browser | 11 | Navigation and eligible choices |
| TLS enrollment/browser | 25 | Certificates, report and service lifecycle |
| Independent metadata | 41 | Includes18 signed metadata checks |
| Authority browser | 40 | Decisions, restart and explicit v2 readiness |
| Isolated Linux | 66 | 40 actual packet probes |
| Signed Linux execution | 98 | 43 actual packet probes and recovery |
| Retained native evidence | 33 | 5 actual kernel captures |

Reports' 189 source-hash entries (93 unique paths), 3 additional binary hashes and
264 frozen source/test files matched the executed tree; no containers remain.
Raw reports/logs stay ignored. The pinned environment used Rust 1.99.1,
Node 24.19.0/npm 11.9.0, Python 3.12.14, jsonschema 4.26.0, Playwright 1.62.0,
Chromium 154.0.8037.57 and Docker 28.4.0. Read-only home buildx state initially
prevented the Linux lab from running; using a writable `BUILDX_CONFIG` fixed that
without changing `DOCKER_CONFIG`, credentials, proxy or CA/TLS settings. Only the
successful reruns above count as native passes. Windows/macOS kernel qualification,
installed-host protection, production authority and external audit anchoring remain
unimplemented/unqualified; Linux lab success does not satisfy those gates.

## Reproduce

Install the [build prerequisites](../README.md#run-locally), Python browser
requirements and Chromium as described in the [passkey guide](../docs/passkey-login.md).
Run from the repository root:

```sh
source scripts/dev-env.sh
umask 0022
bash scripts/check.sh
(umask 0002; cargo test --locked -p fw_authority -p fw_authority_service)
cargo build --locked --workspace --bins --examples
python scripts/smoke_control.py
python scripts/smoke_cli.py
python crates/fw_cli/tests/smoke_login.py
python scripts/smoke_passkeys.py
python scripts/smoke_login_admission.py
python scripts/smoke_audit.py
python scripts/smoke_catalogue_navigation.py --controller-binary target/debug/fw_control
python scripts/smoke_enrollment.py --report reports/enrollment-api.json
python scripts/smoke_enrollment.py --browser --report reports/enrollment-browser.json
python scripts/smoke_enrollment.py --authority-metadata --report reports/target-metadata-smoke.json
python scripts/smoke_authority_review.py --service-binary target/debug/fw_authority_service --fixture-binary target/debug/examples/review_fixture
python scripts/linux-lab.py --report reports/linux-lab.json
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
python scripts/core-access-linux-lab.py --skip-image-build --report reports/core-access-linux-lab.json
python scripts/smoke_native_evidence.py --skip-image-build --report reports/native-evidence-smoke.json
```

Browser suites start actual loopback services and use Chromium CDP virtual CTAP2
authenticators. Native suites require Docker and run only in disposable network
namespaces with NET_ADMIN; they do not change the host firewall. A missing native
or browser prerequisite is not a passing check.

## Historical PR20 verified scope

The integrated repository check passes **800 workspace Rust tests, 32 authority
tests without default features, and 180 UI tests**. It also passes formatting,
Clippy, frontend types, both production UI builds, 27 specification checks,
52 core and 28 extended contract fixtures, nine Linux runner regressions,
six catalogue-diagnostic, thirteen authority-smoke diagnostic and
three native-evidence diagnostic regressions, plus
vendored-source verification. English remains the default. Eight controller
catalogues have 229 messages each; eight authority catalogues have 153, with
complete key and placeholder parity. Human translation acceptance is pending.

The following full runtime matrix was completed for PR #19. Fresh checks for
the current provenance batch are recorded in its section below.

| Runtime suite | Passing checks | Exercised boundary |
| --- | ---: | --- |
| Controller HTTP | 24 | Actual HTTP routes and original OpenAPI contracts |
| CLI / separate protocol fixture | 13 / 5 | Login, bounded list continuation and hostile-server refusal |
| Passkey browser | 76 | Durable owner enrollment, key lifecycle, logout, CLI handoff, anonymous ticket floods and delegated-session restrictions |
| Login admission browser | 14 | 1,005 anonymous options requests, valid earlier proof, replay refusal and restart |
| Audit HTTP/MCP/browser | 21 | Bounded denial evidence and stable snapshot pagination |
| Catalogue browser | 11 | 65 assets, complete list traversal, page size, refresh and asset-picker continuation |
| TLS enrollment/browser | 25 | Ed25519 certificates, mTLS, reports, service creation and revocation; CI nonbrowser subset has 23 |
| Independently pinned target metadata | 41 | Existing 23 enrollment checks plus 18 signed-metadata checks across real agent/admin processes, explicit fixture pin, tamper/tenant refusal, reopen, replay and revocation |
| Independent authority browser | 40 | Actual service, virtual passkey decisions, current quorum, dissent, restart and blocked signing readiness |
| Isolated Linux compiler/readback | 66 | Includes 40 actual IPv4/IPv6 TCP/UDP packet probes |
| Signed Linux execution | 98 | Includes 43 actual packet probes, expiry and interrupted submission/recovery |
| Retained native evidence | 33 | Five actual signed kernel captures across MATCH, MISMATCH, UNKNOWN and restoration; independent admission, replay, revocation, strict failure diagnostics and cleanup |

The recovered baseline and prior metadata batch were verified separately. The
native-evidence batch comparison base was merged PR #15, `43146fd`, whose
[full main CI passed](https://github.com/simhanson123/Nox_Warden/actions/runs/41278538402).
That native-evidence batch freshly passed the repository check (650+23 Rust, 125 UI),
authority/service tests under `umask 0002` (258), the real authority browser (36),
native evidence processes (33 with five captures), and signed Linux execution
(98 with 43 actual packets). The reviewed PR #16 head `feab5c3` also passed the complete
[remote CI](https://github.com/simhanson123/Nox_Warden/actions/runs/41283362174),
including every listed nonbrowser enrollment and runtime suite, before merge
`06de398`. Its source tree equals the tested head. These results predate the
subsequent external-review reliability follow-up.
The [review handoff](../docs/review-continuity.md) distinguishes supplied external
reports from fresh executions. Earlier external private probes were not recovered
or claimed as reproduced. All three external PR #15 reports have since been supplied; they cover that fixed earlier target and identify a shared admin stdout failure plus adjacent diagnostics follow-up.

## Received review: delivery capacity and complete evidence checks

The user supplied the consolidated Claude Opus 5.5 review of PR #19 while the
schema 9 provenance checkpoint was passing remote CI. The complete
[original report](../docs/reviews/pr19-claude-review.md) is retained byte-for-byte.
Claude directly reproduced F1–F3 and attributed F4 to its migration reviewer;
our separate current-code probes then reproduced all four. External temporary
probe files were not supplied, and their executions are not described as ours.
Claude could not run the native Docker suites in that review environment.

Schema 10 keeps every issued dispatch obligation, including historical unsigned
`active`/`delivered` records. Their stored slot projections and original BLOBs
remain unchanged; effective accounting and public `held` status retain capacity.
An unsigned delivery claim cannot return a slot or prove native activation.
Authentication of completion receipts remains a separate future dependency.
Both active-lease and policy-only records remain in the indexed held scan.

Work events must follow the bounded state machine and current claim, and heads
must match the latest immutable event. Delivery insertion requires a matching
claimed dispatch head. Insert guards also reject SQLite replacement through
visible identities and hidden rowids. Live accounting checks all 45 expected
signing guards against cached canonical SQL, with bounded actual-SQL reads.
Any retained UNKNOWN event prevents relabelling an issued reservation as certain
merely because a later dispatch head is claimed. Schema inspection excludes only
the exact reserved `sqlite_` prefix, so `sqliteX_hidden` cannot evade validation.

Explicit private-backup migration preserves bounded legitimate histories and
all existing records. Oversized pre-cap work histories fail closed instead of
being trimmed. During integration, separate probes also exposed missing full
delivery/outbox lifecycle checks in the new v9→10 path; the migration now checks
that complete lifecycle at retained work time, without refreshing evidence.
Independent review also reproduced replacement of an issued accounting head by
a released head through a hidden-rowid collision with all guards intact. The
correction makes head identities immutable and advances existing membership by
UPDATE before inserting only new heads. Bounded nullable work fields retain
invalid presence instead of turning oversized values into NULL. The browser
rejects contradictory signer, dispatch, reservation and grant states, including
`delivered` combined with `released` and no retained capacity.
Fresh `bash scripts/check.sh` passed **800 workspace Rust tests, 32 reduced-feature
tests, 180 UI tests and one explicitly invoked cancellation CLI process test**.
The same independently written counterexamples and targeted regressions were
rechecked after correction. Fresh metadata checks passed **41**, native evidence
passed **33 with five kernel captures**, and the authority browser passed **40**.
Shared-umask authority/service verification passed **406**, with the same one
separately covered ignored process case. Earlier checkpoint totals below remain
historical results and are not added to these counts.

## Original core-access cost provenance

The next M02/M03/M05 batch starts at PR #19 merge `09ef6a8`, on a separate
branch while the user requests Claude Opus 5.5 review of fixed PR #19 head
`2ef3aec` against `5a7551d`. That review has now been received and is being
addressed in the schema 10 follow-up above.
PR #19's [complete CI](https://github.com/simhanson123/Nox_Warden/actions/runs/41397285225)
passed and its final target is unchanged by this work.

Authority schema 9 retains the complete original access request, envelope and
delegation, an immutable lease identity and per-plan hash bindings. Closed,
bounded contracts verify tenant/principal/workload references, original asset
membership, scope exclusions and lifetimes. Original request identity,
organization lease identity and tenant idempotency cannot be rebound. Exact
registration retries add no audit; compatible later plans reuse the original
evidence. Historical reads revalidate stored bytes and projections after expiry.

Core costs use the full original request duration and destination set even if
the plan has only seconds left. Independently configured root identity must
match, and all five current root ceilings must be no larger than the original
delegation's limits. The trusted-local CLI imports and reads bounded summaries,
checks stdout delivery, and preserves a committed import after output failure.
Eight-locale readiness separates missing provenance from the still unavailable
core signing profile; signing and dispatch remain false.

Explicit private-backup migration preserves existing schema 8 evidence and all
five quota states, with no invented provenance. Known-schema validation covers
the new tables and guards; migration failure retains the original and backup.
Original migrations 001–008 and the specification package remain unchanged.

Independent internal review reproduced SQLite `INSERT OR REPLACE` bypassing
update/delete immutability guards with recursive triggers disabled. The fix
blocks every identity collision before replacement, including explicit hidden
rowid conflicts. Permanent regressions cover primary and alternate
unique identities. The reviewer reran the same original counterexample and
explicit rowid variants: all were refused, with original status, reopen and
audit preserved.
Separate independent probes passed concurrent schema 8 migration, expiry while
waiting for stdin, and hostile JSON/UTF-8 input. These are internal executions,
separate from Claude's external review, which was pending at that historical checkpoint and has since been received.

`bash scripts/check.sh` passed **777 workspace Rust tests, 32 reduced-feature
Rust tests, 158 UI tests and one separately executed cancellation CLI process
test**. The ordinary workspace run intentionally ignores that one process test;
it is not counted as passed until the separate invocation. Formatting, Clippy,
TypeScript, both production UI builds, original contracts/specifications, locale
parity, diagnostic regressions and vendored-source checks passed. Focused tests
are overlapping subsets, not extra totals. The shared-umask authority/service
run passed **383** tests, with the same one separately covered ignored process
case. Fresh actual runtime checks passed **40 authority browser checks, 41
metadata checks and 33 native-evidence checks with five kernel captures**. The
disposable native container was removed. Broader Linux packet and unrelated
controller runtime checks remain part of the required remote PR workflow.
That job now permits 30 minutes: the preceding PR's complete run took 19 minutes
17 seconds against a 20-minute limit before this batch added 49 Rust regressions.
No suite or assertion was removed to meet the deadline.

Provenance is not verified delegation/envelope approval, workload authentication
or human approval. Core semantic review, native binding, a single retained
absolute lease window across later plans and the core signing profile remain
incomplete. Rootless general-policy quota is the next separate batch; protected
authority bootstrap, OS/IPC isolation, signer/delivery deployment and native
platform qualification remain required.

## Reservation integrity and explicit cancellation

The PR #18 follow-up starts at `5a7551d`. Authority schema 8 adds immutable
quota transitions tied to work, issuance and delivery evidence, plus guarded
indexed accounting membership. Ordinary state/slot UPDATE cannot refund an
issued or UNKNOWN reservation; a damaged reservation projection cannot hide
from accounting. Ten live accounting guards are checked without replacing the
bounded indexes with a history scan. Opening and migration also validate the
complete actual schema. Migration 007 and all 53 original specification files
remain byte-for-byte unchanged (52 manifest entries verified).

Explicit migration with a validated private backup preserves legacy proof,
receipt and audit bytes. Unproven releases, corrupted delivery receipts and
mismatched outbox timestamps roll back with the original and backup preserved.
The trusted-local `cancel-signing-job` command handles expired unissued work,
fences claimed workers and retains committed cancellation after stdout failure.
Issued and UNKNOWN work remains nonrefundable. Dispatch dequeue verifies real
Ed25519 and the exact prepared payload. Heartbeat repeats at the same deadline
write no event; each claim generation permits at most 32 strict extensions.

Fresh validation: `bash scripts/check.sh` **728 workspace Rust + 32 reduced-feature
Rust, 156 UI**, plus **one separately executed successful-cancellation CLI process
test** that is intentionally ignored by the ordinary workspace invocation.
Formatting, Clippy, TypeScript, both UI builds, design/contracts/locales/vendor
checks and the existing diagnostic suites pass. The shared-umask authority/service
command passes **334**; its one ignored process case is covered separately by
`check.sh`, not counted as passed there. Focused suites are overlapping subsets,
not additional totals.

All runtime suites in the table above were freshly executed: HTTP 24, CLI 13
and protocol fixture 5, passkey 76, login admission 14, audit 21, catalogue 11,
enrollment browser 25, authority browser 40, metadata 41, Linux 66/40 actual
packets, signed Linux 98/43 actual packets and native evidence 33/5 actual
captures. Authority, metadata, signed Linux and native evidence were repeated
after schema stabilization and a fresh binary build. Disposable containers were
removed; the host firewall was unchanged. A first Docker build could not write
the default Buildx activity directory; a writable task-specific `BUILDX_CONFIG`
resolved setup with the required CA mount and verification intact.

The original L1 SQL exploit was reproduced against archived PR #18 source before
correcting it. Independent internal review then reproduced and closed orphan
cancellation evidence, corrupted legacy delivery migration, and missing live
accounting-head guard cases; each reviewer reran the same failing counterexample
after correction. The supplied external reports remain preserved separately in
[their original text](../docs/reviews/pr18-external-reviews.md). Claude's subsequent
review is preserved and addressed above; no new GLM review was requested.
Early implementation checks caught a
private fixture calling a deliberately closed public worker, a future-dated CLI
fixture and stale schema-version binaries; corrected fixtures and fresh builds
passed without changing production gates. Raw logs stay outside source.

This is M02/M03/M05 hardening, not protected signer/dispatch deployment, original
core-request/rootless cost binding, PostgreSQL, or native host/Windows/macOS
qualification. Trust-key replacement together with the whole database remains
outside the retained-signature guarantee.

## Durable signing coordination

Based on PR #17 merge `956de27`, schema 7 now prepares current approval,
retained review/metadata/baseline, independent generation, quota reservation and
immutable signer job in one transaction. Exact signed-result verification and
current-state rechecks precede grant/issuance/outbox/audit finalization. Work
claims fence stale workers, retries preserve signed bytes, cancellation proves
no issuance, and UNKNOWN keeps capacity after expiry. The trusted local CLI and
authenticated eight-locale readiness panel expose blockers and retained history.

Fresh local checks: `bash scripts/check.sh` **713+32 Rust, 156 UI**;
`umask 0002; cargo test --locked -p fw_authority -p fw_authority_service`
**319**; authority browser **40**; metadata processes **41**; native evidence
**33 with five actual captures**; signed Linux lab **98 with 43 packet probes**.
The native-only run initially lacked the pinned Rust environment and did not run;
loading `scripts/dev-env.sh` resolved it. The signed lab's initial image build
needed writable `BUILDX_CONFIG=/tmp/nox-linux-buildx`; its complete rerun passed.
No test or permission check was weakened. The other runtime rows above retain
previously executed results and are also covered by remote CI; they were not all
repeated locally for this batch. Raw logs and reports remain outside source.

Three independent internal review slices covered transaction/signature,
quota/lifecycle and surface boundaries. They reproduced a generation-head reset
that disagreed with retained intent history. The fix compares the latest immutable
epoch/generation/intent and rejects reset, missing and older valid heads; the
same independent counterexample passed afterward, as did two new real-fixture
regressions. A CLI origin example was corrected to the authority service default.
Independent reruns included contract 9, quota 15, job lifecycle 11, CLI process 5,
UI 30 and HTTP 3 checks; these overlap the main suites and are not added to totals.
No remaining blocker was identified within those review scopes.

Production prepare/worker paths still refuse: protected bootstrap, trusted target
generation initialization, build identity, native qualification and deployed
signer/delivery verification are absent. Successful mechanics use private
`cfg(test)` witnesses, actual P-256 approvals and Ed25519 evidence/results.
At that schema7 checkpoint, core access cost binding and rootless policy preparation remain unsupported.
See [coordination boundaries](../docs/signing-coordination.md) and the
[administration guide](../docs/signing-coordination-cli.md). The original 53 design
files remain unchanged; all 52 manifest entries were rechecked by size and hash.

## Received-review reliability follow-up

All three supplied PR #15 reviews are recorded at their exact earlier target.
Both GLMs identified the same buffered stdout defect. Against merged PR #16,
actual admin commands reproduced exit 0 despite `/dev/full` or a closed reader,
while agent/help output panicked. Both commands now check writes and final flush;
Unix output uses a checked duplicate handle to preserve `EBADF` instead of the
standard stdout wrapper that masks it. Full destinations, read-only handles and
broken pipes return fixed errors without losing committed DB or proof state.
A valid writable `/dev/null` remains allowed. Rust can normalize pre-exec closed
stdio to that valid sink; this is not an error detectable after startup.

The actual-process regressions verify unchanged canonical bytes, lost challenge
quota, immutable receipt replay, private verifiable proof survival and refusal to
overwrite an existing proof. Future-clock regressions reopen the database,
exercise every target operation, demonstrate the separate project audit fence,
and recover only when trusted time reaches the existing floors. There is no
immediate clock-reset or qualified epoch-recovery API; the runbook preserves this
remaining availability limitation.

Authority smoke reports retain only bounded closed startup diagnostics before
temporary cleanup. Success requires the exact two normal startup messages plus
all browser checks; unknown output, missing completion, child exit or report
write failure cannot pass. Actual unsafe `0646` assets still fail with the saved
`ui_assets` stage. Catalogue tests reduce measured global accessible-name query
cost while preserving 65 records, accessibility assertions and the original
5-second limit. The supplied intermittent timeout was not reproduced locally;
its underlying cause remains unproven.

A consolidated independent review found the remaining read-only stdout case;
the corrected code passed that reviewer's separate 49-check process/diagnostic
probe, two clock tests, thirteen diagnostic tests and eleven catalogue tests.
The original external private C/D probes were not recovered or rerun. Source
changes were followed by the full repository check (658+23 Rust, 125 UI),
shared-umask authority/service tests (264), actual authority browser (36),
metadata processes (41) and native processes (33 with five signed captures).

## Security and persistence coverage

Authority test directories and private fixture files receive `0700`/`0600` at
creation. This preserves production rejection of unsafe paths while making the
fixtures independent of permissive umasks and inherited default ACLs. The
focused authority/service fixture suite passed under `0002`, `0022` and an actual
inherited default ACL; CI separately reruns it under `0002`. Deliberately unsafe
permission, symlink and hardlink rejection cases remain active.

Five startup regressions cover fixed stage/code diagnostics, including actual
executable arguments, non-UTF8 arguments, unsafe/missing UI and an occupied port.
A disposable POSIX default-ACL reproduction created an actual `0646` UI file:
startup rejected it with the fixed `ui_assets` code and left its mode unchanged.
The [installation guide](../docs/authority-review-service.md#file-modes-inherited-acls-and-startup-diagnostics)
describes required modes and ACL inspection. Catalogue smoke reports closed
failure phases/categories without exception text or private paths; six Python
tests cover sanitization and report-write failure. Explicit locator deadlines
and save/detail readiness do not establish the original intermittent failure's
cause.

Controller bootstrap reads require a separate in-memory session proof; a cookie
alone cannot disclose that proof or register the owner. CLI browser views withhold
the terminal confirmation code and polling secret. Public login options use
bounded encrypted tickets without allocating shared pending database slots;
successful proof verification, durable consumption, counters and mandatory audit
commit atomically. Tampering, bounded decompression, maximum sizes, zero-counter
replay, independent connections and injected failures are covered. This is
bounded admission testing, not sustained CPU/network saturation qualification.

Server-owned session provenance prevents an exchanged CLI session from adding or
revoking owner keys or authorizing another terminal, even during the original UV
freshness window. Ordinary controller reads/writes remain available. Tests cover
borrowed registration proofs, spoofed type headers, logout/expiry/revocation and
promotion only after a new verified WebAuthn login.

Anonymous CLI initiation now retains no pending request or replay-key cache and
writes no durable success audit. The passkey smoke creates 1,005 requests, checks
unchanged audit counts and completes a previously issued request. Bounded AEAD
tickets conceal the short code and polling-secret hashes and bind origin,
tenant, principal, request and time. Only fresh browser interaction allocates
protected attempt/approval/consumption state. Regressions cover wrong-code
limits, tampering, request substitution, expiry, restart, key epochs and nonce
exhaustion. Wall/monotonic time floors prevent expired replay fences from
reappearing after clock rollback. A real concurrent-logout barrier test checks
that authorizer validation, mandatory audit and delegated-session insertion
share the session-registry lock. Audit failure issues no session. The browser
removes the encrypted URL fragment while preserving the memory-held ticket
through keyboard skip navigation. Sustained CPU/HTTP/database saturation and
exhaustion by an authenticated owner remain outside this bounded guarantee.

Controller login tickets and authority envelopes use non-clonable, checked nonce
allocators and domain-separated epoch keys, with at most 65,536 encryptions per
derived key. Old unexpired tickets remain decryptable across issuance epochs;
there is no flood-evicted key cache. Tests cover rollover, concurrent allocation,
exhaustion, tampering, purpose/origin separation and restart. This bounds issued
encryption usage, not arbitrary failed-verification attempts or CPU saturation.

[Audit snapshots](../docs/audit-log.md) and [catalogue snapshots](../docs/catalogue-pagination.md)
bind continuation to the session, tenant, filters, limit and original deadline.
Tests cover traversal beyond 100 rows, byte caps, mutation isolation, projection
integrity, migration, clock rollback and concurrent capability renewal. Current
certificate and report eligibility is checked by both service writes and pickers.

[Authority schema 6](../docs/authority-store.md) preserves original signatures,
immutable plans, credential snapshots and public-key tombstones. Explicit
migrations validate private online backups before changing known older schemas;
they never infer trusted epochs or human identities from plans. The tests cover
real P-256 signatures, restart, exact retries, aliases, current revocation,
retained proofs after counter advancement and atomic rollback. A separate
first-open stress run passed 1,600 fresh-database races after bounded WAL retries.

Migration preflight rejects source/backup/manifest and SQLite sidecar collisions
before opening either database. It also rejects preexisting destination sidecars.
Tests preserve source schema/history on refusal and cover case variants, parent
aliases, reverse/manifest collisions and the documented ASCII maintenance-name
profile. Unicode parent directories remain usable. Expired device reservations
retain retry/replay bindings; a reopened-store regression confirms they cannot
issue certificates and do not block a separately authorized new invitation.

Nine durable-review regressions cover atomic plan/requirements/evidence/audit
admission, exact retry, concurrent import, reopen, corrupted bindings and times,
missing evidence, checked approval gates and validated schema-3 backup migration
with rollback on foreign-key failure. Three service regressions retain review
after removing source/config, tolerate expired or retired configured plans, and
reject ambiguous tenant mappings. The shared verifier retains full state
recomposition and bounded bytes/depth; no legacy plan receives invented evidence.
These are semantic review guarantees, not compiler/native gate attestation or
permission to sign or dispatch.

[Target metadata](../docs/target-metadata.md) has 11 shared Ed25519 protocol
tests, seven device process tests, 20 authority persistence regressions and ten
local admin process tests (the latter also exercise the native command workflow). They cover strict canonical bytes, signature and
identity substitutions, protected file/certificate binding, non-UTF8 diagnostics,
bounded stdin, explicit namespace initialization, pin CAS/tombstones, schema-4
backup migration, challenge quota, atomic audit failure, concurrent exact retry,
expiry/revocation and retained clock fences. A reproduced same-key certificate
renewal defect is fixed: an old signature cannot be relabeled as a new pin
revision through coherent receipt/projection corruption. Delayed-stdin admission
samples current time after input and rejects an actually expired proof. The
optional 41-check process smoke derives its synthetic independent public pin from
an actually enrolled certificate; it never exports private keys or changes a
host firewall. Separate reviewers examined protocol, store, CLI paths and smoke
failure assertions; requested external models were not called.

Metadata evidence authenticates its device key and exact bytes, without machine
attestation, qualified enforcement or policy authority. The local operator must
independently maintain pin/certificate trust and revocation. A signed unverified
report cannot satisfy a native gate. Production baseline/gate qualification,
durable signer/quota integration and protected dispatch remain unfinished.

The [native evidence workflow](../docs/native-evidence.md) adds independent
recompilation from the retained reviewed plan and explicitly pinned lab
references. The candidate must match the exact plan artifact hash; device metadata
and lab capability hashes remain distinct. A purpose-scoped observer signs
captured raw nft state and installation/clock context. The authority rechecks
signatures and actual correspondence, records negative/unknown observations
without an observed state hash, and atomically advances consumption, receipts,
head and audit. Current checks revalidate metadata, reference/observer pins,
plan, exclusive expiry and the target-global head. Earlier plan observations
remain visible as history when another plan replaces that head.

Coverage includes real Ed25519 signatures, canonical bounds, TTL refresh,
platform substitution, bidirectional transport/observer key separation,
permanent key ownership, revision/head CAS, competing connections, audit rollback,
clock fences after failed or expired requests, zero epoch/generation, retained
proof/projection corruption and validated schema-5 backup migration. The separate
API checks live reviewer/proof/origin/tenant boundaries and returns summaries
without raw captures. Its eight-locale UI checks plan/response binding, current
versus historical evidence, local expiry and request-delay/clock rollback.

One consolidated independent review covered the complete batch. Three reproduced
findings were corrected: an earlier plan's retained observation disappeared from
its display after a different plan advanced the target head; valid zero
epoch/generation values were refused by the admin CLI; and request latency was
omitted from displayed freshness when the client clock moved backward. These
reviewers ran focused independent reproductions, separately from the implementation
tests. The user subsequently supplied all three external PR #15 reviews. They cover
their fixed earlier target, not this native-evidence batch; their results and
follow-up are retained separately in review-continuity.

The actual Docker/process smoke uses synthetic independent trust, five signed
kernel captures and no host firewall changes. In this environment the older
pinned Debian image emits a nonfatal GLIBC_2.39 weak-version loader warning for
the host-built executable. Only that exact single leading warning is classified
separately; unexpected stderr, repeated warnings, panic or a missing refusal
remain failures. Three Python regressions enforce that distinction. This is not
portable binary or installed-host qualification.

Compilation correspondence does not attest the plan's declared compiler/validator
build identity. Signed lab observations do not establish protected kernel
provenance, production management baseline qualification or authority to sign
and dispatch. Both result constants remain false, and read-only evidence refresh
never submits a passkey decision or promotes a human approval into native evidence.

Authority audit checks include rollback of a genuine zero-counter activation
when audit time moves backward, plus restart, independent tenants, exact retries,
missing heads, gaps, broken links, tampered projections/hashes, oversized storage
and legacy backward history. New appends verify the indexed tail and reject time
regression within the mutation transaction. The read-only verifier streams one
consistent tenant snapshot without rewriting old history; the current live
connection gate additionally quarantines a globally corrupted external snapshot
before either diagnostic reads or new appends. Valid tenant clocks remain
independent. It has no external
checkpoint and cannot detect a coherently replaced entire database. These checks
are SQL/API failure and corruption tests, not power-loss qualification.

Independent quorum tests cover Lab/Team/high-risk roles, canonical distinct
humans, author exclusion, non-greedy role matching, terminal dissent, expiry,
withdrawal, role/key/basis changes, concurrent last reviewers and injected write
failures. Decision consumption, proof, immutable approval-set members, current
head, historical receipt and audit commit in one transaction. Current reads
revalidate the head; historical receipts never renew authority. A current read
is a snapshot, not reserved permission for a future signing transaction.

Candidate aggregation excludes withdrawn or currently ineligible votes and
deduplicates canonical human/role pairs before the 64-candidate bound. Original
proofs are reverified, while a scoped SQLite instruction budget bounds historical
lookup cost. Tests reproduce 64 duplicate votes followed by 63 withdrawals and an
independent final vote, distinct-candidate overflow, and full admission rollback
and exact retry after query interruption. Named-set withdrawal commits a retained
tombstone and audit atomically; withdrawing an old set cannot invalidate a
different current head, and an unchanged selection cannot silently be reminted.

The [independent review service](../docs/authority-review-service.md) has 30
HTTP/P-256 regressions plus five review-adapter tests. It requires separately
pinned private authority trust and a distinct origin. Tests cover exact
Host/Origin, cookie plus memory proof, tenant isolation, bounded requests,
anonymous admission floods, counter/revision replay, mandatory-audit rollback,
complete immutable before/after evidence and refusal of missing or oversized
review content. Runtime routes never provision keys, roles, epochs or human maps.

Nine executable TCP/P-256 tests and two connection-phase/race tests cover fresh
login and verified requests with 64 idle sockets, verified requests with 64 slow
public bodies, forged/missing proof, revoked/missing/revision-stale cached
sessions, logout, absolute deadlines, recovery and disconnected blocking-job
permit retention. The original idle/socket and shared-public-body starvation
cases were reproduced against the previous executable before the fix.
The 8+8 work reservation protects admission capacity; shared runtime work and
fresh public sign-in still have no availability guarantee under sustained local
TCP/CPU/database saturation. No protected OS deployment is inferred.

The [authority UI](../docs/authority-review-ui.md) has a separate build and 65
unit/catalogue tests within the UI total. It requires explicit consent, a current
role and a fresh decision-bound assertion. Uncertain requests allow exact retry;
401 clears pending browser authority and requires explicit sign-in. The real
browser suite covers approval, later fresh signed rejection by the same reviewer,
terminal dissent after restart, stale independent epoch, missing evidence,
keyboard navigation and cleanup. Actual HTTP plan, requirements, approve/reject
decision and current human approval-set objects also validate against both
preserved schema documents. Mutated copies must reject unknown fields, invalid
UUID/calendar dates and a rejection member inside an approval set. This does not
cover access-lease plans or delegated sets. Expired approvals permit fresh review when the
current store returns Pending. Set identity, hashes, bindings and deadlines must
match the current detail response before the UI displays verified quorum.

The [Linux lab](../native/linux/README.md) covers actual compilation, packet
behavior, expiry and semantic kernel readback, including tamper/restore. The
[signed execution lab](../docs/signed-linux-execution.md) covers verified grants,
durable native material, actual apply/probe confirmation, established and new
connection expiry, restrictive crash recovery and generation fencing. The native
writer inherits the journal lock so an orphan writer cannot race fresh recovery.
Immutable recovery attempts preserve original deadlines; fresh fenced observations
can close genuinely unapplied work without reclassifying historical confirmation
or rollback as NotApplied. Interrupted preparation, submission and recovery are
exercised, including parent/child process termination. Both suites remove
their containers successfully. Signing and approval inputs are synthetic test
fixtures; no lab result establishes production authority or installed-host safety.

## Remaining acceptance

The controller remains **observe-only**. A separately provisioned local review
service can now retain signed decisions and complete verified quorums, but
production authority bootstrap, protected OS-account/IPC deployment, independent
signer transactions and authenticated host dispatch remain incomplete. The
same writable account cannot provide the required process/trust isolation.

Physical authenticators, human review/consent, full accessibility and translation
acceptance are not qualified by virtual-authenticator tests. Full Linux
crash/reboot/coexistence and hung-owner watchdog qualification, Windows WFP/callout,
macOS Network Extension, signed installation/update/removal, complete F_07
acceptance receipts/aggregate gates and provider deployment remain outstanding.
Authenticated CLI-handoff budget exhaustion, sustained local resource attacks
and local recovery after loss of all owner keys remain documented limitations.
See the [implementation overview](../docs/implementation.md),
[platform status](../docs/platform-support.md) and [task ledger](task-ledger.json).

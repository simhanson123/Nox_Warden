# PR25 review receipt and accuracy corrections

The complete supplied [Claude Opus5.5 review](reviews/pr25-claude-review.md)
is preserved as all 14,448 original uploaded bytes, including 159 CRLF endings
and opening progress notes. SHA256:
`64665ea1d47a3c5342b983d1152579e478faeafa19e8134d9f8ab691ecdcb771`.

The reviewed target is `89684e055f01a1c87113e4ea4a713ebbff77afe1`, compared
with `59c70ac32fd10e4d5ef6b63cc7f54f4eb5759fe8`. PR25 merged as
`a624a1e684a8fc0065ac4f4609101410f56c50bb`; both have tree
`880986d4b29384cb947b780e32edde75981a5f1d`. PR CI41945354850 and separate
main CI41950760489 succeeded. These historical passes do not validate subsequent
product changes.

The report confirms I1 and T1–T3 corrected or strengthened and identifies no
confirmed security defect or development blocker. Its command results and peer
counterexamples remain attributed external evidence. Its Docker Linux/signed/
native checks were NOT_RUN; the project's separate successful lab/CI evidence
must not be presented as the reviewer's execution. Its private worktrees/probes
are not required to resume development and were not obtained or rerun here.

## Corrections confirmed against source

- The supplied review prompt used the included filename
  `signing_transition_atomicity_tests` as a Cargo filter. The compiled module is
  `transition_atomicity_tests`; `transition_atomicity` selects the actual test.
  The external zero-test invocation is not a passing check.
- The approval matrix has 13 conditions in the two-human flow, including two
  audit-INSERT stages that already existed in the single-human flow. Describe
  the matrix and overlap, rather than thirteen wholly new failure points.
- Hooks record table mutations: ordered table/action pairs for approval faults
  and table sets for transition faults. They do not retain SQL statement text.
  Approval snapshots compare typed rows in all authority tables; transition
  snapshots additionally compare schema.
- A test fault authorizer temporarily replaces the production schema authorizer.
  No DDL occurs while that fault authorizer is installed, and reopening restores
  the normal wrapper before healthy retries. This is a private test mechanism.
- The review's blanket final-IMMEDIATE wording needs qualification:
  preparation and readiness use IMMEDIATE final transactions;
  `read_signing_intent` uses a validated DEFERRED final snapshot. All three initial
  selections use validated DEFERRED snapshots. The original report stays intact.

The corrected exact command was freshly executed after sourcing `dev-env.sh`:

```sh
source scripts/dev-env.sh
cargo test --locked -p fw_authority --lib store::signing_quota::tests::transition_atomicity_tests::failed_transition_rolls_back_cancellation_and_issuance_with_work_evidence -- --exact
```

It exited0 with exactly one passed test, no failures or ignored tests. This is
baseline/filter verification, not verification of the next core-access feature.

## Next implementation

Proceed with the preserved M03/M04L/M05/M06 core-access dependencies in one integrated
batch: exact full-state semantic review, one immutable absolute lease window,
native compilation and explicitly isolated core execution, and connected trusted
administration/read-only evidence/review UI. Preserve general-policy bytes and
published SQL001–013. Legacy provenance remains historical cost evidence;
migration must not invent a lease window or approval for it.

Workload/delegation cryptographic authority, protected bootstrap, generation
initialization and production signer/dispatch remain separate prerequisites.
New structural review or successful lab execution cannot supply those privileges.
Do not request another external review of the unchanged PR25 target; the next
consolidated prompt must pin the actual new base/head after implementation.

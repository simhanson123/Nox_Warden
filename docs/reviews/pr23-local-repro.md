# PR23 local baseline reproductions

These are newly written local probes, not recovered external review sources.
The private paths named in [the preserved review](pr23-claude-review.md) were
unavailable. Execution used an isolated `git archive` of
`4cef6acf7e46289b156fcd56ad0ab2f2920fabd6`; its tree and reviewed PR23 head
`8b9c3ef71f30b21de9ecfd2d6118f99da32b2f4f` both resolve to
`d43669c1eb95094c1aa2f69f16df82b9f451e60a`.
No shared product source, shared target, firewall or host network was changed.

The completed command was:

```sh
source scripts/dev-env.sh
CARGO_TARGET_DIR=/workspace/pr23-baseline-repro.XNnJx7/target \
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
cargo test --offline --locked -j 3 -p fw_authority --lib pr23_baseline_ \
  -- --nocapture --test-threads=1
```

Rust/cargo were 1.99.1. The isolated dependency/test build took 34.24s;
the selected tests took 33.23s. Exit **0**, **3 passed**, 0 failed, 190 filtered
out; one unused-import warning. **Those passing vulnerability assertions confirm
the baseline defects; they are not passing security regressions.**

| Finding | Completed variants | Observed baseline behavior |
|---|---|---|
| R1 | Rooted and project-only × reserved, issued, UNKNOWN, unsigned active (8) | Untampered admission returns `Quota`. After both stored projections are hidden and original trigger SQL is restored, the same open store admits a prospective reservation. Fresh open and same-version maintenance refuse. |
| R2 | Rooted and project-only × issued, UNKNOWN (4) | Untampered admission returns `Quota`. After both membership index families are emptied and their exact SQL restored, physical integrity reports missing entries while the same open store admits. Fresh open and same-version maintenance refuse. |
| R3 | Rooted and project-only prepared jobs (2) | An extra normally chained `signing_signer_cancelled` audit changes neither work events nor bindings. Audit-chain verification, intent read, fresh open and same-version maintenance all accept. |
| R4 | **NOT_RUN** | A separate 0/100/500 genuine-cancellation scaling/locking harness failed compilation before execution: E0433, `rusqlite::DatabaseName` is absent. Exit **101**; no benchmark DBs or measured times were produced. No retry was made. |

R1–R3 existing obligations use the repository's real guarded preparation,
signing and dispatch lifecycle fixture. `PRIMITIVE_QUOTA_FIXTURE` remains false;
no primitive fixture exception masks validation. Prospective admission uses the
production internal `reserve` path and rolls its temporary row back. The native
and cryptographic test authorities remain synthetic development capabilities,
with production signer/dispatch gates closed.

R1 stores and reinstalls every original trigger definition on the affected
tables within one external transaction. R2 saves each exact original index SQL,
rebuilds under `WHERE 0` using a separate connection, restores that SQL, verifies
exact equality and confirms `PRAGMA integrity_check` is not `ok`. The schema
inventory passes before each live admission assertion. R3 appends through the
ordinary local audit helper with all SQL guards intact.

The unfinished R4 invocation (exit 101 during compilation) was:

```sh
PR23_BENCHMARK_DIR=/workspace/pr23-baseline-repro.XNnJx7/benchmark-fixtures \
CARGO_TARGET_DIR=/workspace/pr23-baseline-repro.XNnJx7/target \
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
cargo test --offline --locked -j 3 -p fw_authority --lib pr23_baseline_r4 \
  -- --ignored --nocapture --test-threads=1
```

The R4 23.4s/78.6s values in the external report were **not** independently
reproduced here. They remain external historical measurements. New timing and
writer-lock measurements were subsequently completed by a separate worker using
an independently written normal-lifecycle harness; see
[the performance comparison](../authority-validation-performance.md). The failed
initial harness above remains NOT_RUN and is not relabeled as a pass.

Local artifacts are retained at `/workspace/pr23-baseline-repro.XNnJx7/`:
`baseline.log`, `benchmark.log`, the unique `target/`, and
`crates/fw_authority/src/store/pr23_baseline_probes.rs`. The latter includes the
unfinished R4 harness; the executable source preserved below is only the
completed R1–R3 subset. Log SHA256 values:

- `baseline.log`: `5a6b9785f382baf0c4399031690e62000a9e6b5b51a78444b9607b767c1ad55d`
- `benchmark.log`: `b8a62da18b9ddc8606864f90570f2c7e9b3d2ea984a70fc708feac3a22625f2c`

To reconstruct the completed probe in a new isolated archive, run from the
repository root. This extracts the following source fence and adds one test
module declaration; it does not edit the working checkout:

```sh
repro_dir=$(mktemp -d /workspace/pr23-local-repro.XXXXXX)
git archive 4cef6acf7e46289b156fcd56ad0ab2f2920fabd6 | tar -x -C "$repro_dir"
python3 - "$PWD/docs/reviews/pr23-local-repro.md" "$repro_dir" <<'PY_REPRO'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
source = text.split('```rust\n', 1)[1].split('\n```', 1)[0] + '\n'
root = Path(sys.argv[2])
store = root / 'crates/fw_authority/src/store'
(store / 'pr23_baseline_probes.rs').write_text(source)
path = store / 'signing_quota.rs'
marker = '    const NOW: i64 = 1_800_000_000;'
module = '    mod pr23_baseline_probes { include!("pr23_baseline_probes.rs"); }\n'
original = path.read_text()
assert original.count(marker) == 1
path.write_text(original.replace(marker, module + marker, 1))
PY_REPRO
cd "$repro_dir"
source scripts/dev-env.sh
CARGO_TARGET_DIR="$repro_dir/target" CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
cargo test --offline --locked -j 3 -p fw_authority --lib pr23_baseline_ \
  -- --nocapture --test-threads=1
```

```rust
// Fresh local probes, written independently from the preserved external report.
use super::*;
use std::time::Instant;
const ROOT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const WORKER: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

fn obligation(rootless: bool, state: &str) -> (signing_test_support::Fixture, String, String) {
    assert!(!PRIMITIVE_QUOTA_FIXTURE.get());
    let mut f = signing_test_support::Fixture::new();
    let mut cap = limits();
    cap.concurrent_deployments = 1;
    if rootless {
        f.store.pin_signing_project_quota(&f.tenant, &SigningProjectQuotaPin {
            root_id: None, limits: cap, not_before: NOW, not_after: NOW + 7200,
        }, None, NOW).unwrap();
    } else {
        signing_intents::test_initialize(&mut f, NOW);
        let pin = SigningRootQuotaPin {
            root_id: ROOT.into(), limits: cap, not_before: NOW, not_after: NOW + 7200,
        };
        f.store.pin_signing_root_quota(&f.tenant, &pin, Some(1), NOW).unwrap();
        f.store.pin_signing_project_quota(&f.tenant, &pin, Some(1), NOW).unwrap();
    }
    let prepared = signing_intents::test_prepare(&mut f, NOW);
    let job = prepared.intent.job_id;
    let reservation = prepared.intent.reservation_id;
    if state != "reserved" {
        let tx = f.store.connection.transaction().unwrap();
        let claim = signing_jobs::fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 60, NOW).unwrap();
        tx.commit().unwrap();
        signing_intents::test_finalize(&mut f, &claim, NOW).unwrap();
        if state != "issued" {
            let tx = f.store.connection.transaction().unwrap();
            let claim = signing_jobs::fixture_claim(&tx, &f.tenant, &job, "dispatch", WORKER, 0, 60, NOW).unwrap();
            if state == "unknown" {
                signing_jobs::fixture_unknown(&tx, &f.tenant, &claim, NOW).unwrap();
            } else {
                assert_eq!(state, "active");
                signing_jobs::fixture_deliver(&tx, &f.tenant, &claim, NOW).unwrap();
            }
            tx.commit().unwrap();
        }
    }
    f.reopen(); // uncorrupted committed fixture is accepted by full validation.
    (f, job, reservation)
}

fn admission(f: &mut signing_test_support::Fixture) -> Result<SigningBudgetReservation> {
    assert!(!PRIMITIVE_QUOTA_FIXTURE.get());
    let tx = f.store.connection.transaction().unwrap();
    // Exercise the real admission routine. The prospective row rolls back;
    // the existing obligation has a genuine intent/job/work/audit lifecycle.
    reserve(&tx, &f.tenant, &id(987_654), &change(987_654), NOW + 300, NOW)
}
fn healthy_refuses(f: &mut signing_test_support::Fixture) {
    assert!(matches!(admission(f), Err(AuthorityError::Quota)));
}
fn restored_schema(f: &mut signing_test_support::Fixture) {
    let tx = f.store.connection.transaction().unwrap();
    migrations::validate_live_schema(&tx).unwrap();
}
fn rejected_open_and_maintenance(f: &signing_test_support::Fixture) {
    assert!(AuthorityStore::open(&f.path).is_err());
    assert!(AuthorityStore::migrate(&f.path, f.directory.path().join("rejected-backup.sqlite3")).is_err());
}

#[test]
fn pr23_baseline_r1_coordinated_projection_hiding() {
    for rootless in [false, true] {
        for state in ["reserved", "issued", "unknown", "active"] {
            let (mut f, _, reservation) = obligation(rootless, state);
            healthy_refuses(&mut f);
            let other = Connection::open(&f.path).unwrap();
            let guards: Vec<(String, String)> = {
                let mut q = other.prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND tbl_name IN ('authority_signing_quota_reservations','authority_signing_quota_transition_heads') ORDER BY name").unwrap();
                q.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap()
            };
            other.execute_batch("BEGIN IMMEDIATE").unwrap();
            for (name, _) in &guards { other.execute_batch(&format!("DROP TRIGGER {name}")).unwrap(); }
            assert_eq!(other.execute("UPDATE authority_signing_quota_reservations SET state='released',active_slots=0,dispatch_slots=0,issued_at=NULL WHERE reservation_id=?", [&reservation]).unwrap(), 1);
            assert_eq!(other.execute("UPDATE authority_signing_quota_transition_heads SET state='released',issued_at=NULL WHERE reservation_id=?", [&reservation]).unwrap(), 1);
            for (_, sql) in &guards { other.execute_batch(sql).unwrap(); }
            other.execute_batch("COMMIT").unwrap();
            drop(other);
            restored_schema(&mut f);
            assert!(admission(&mut f).is_ok(), "baseline defect: rootless={rootless} state={state}");
            rejected_open_and_maintenance(&f);
            eprintln!("R1 rootless={rootless} state={state}: live ADMITTED; open+maintenance REFUSED");
        }
    }
}

fn empty_membership_indexes(path: &std::path::Path, rootless: bool) {
    let editor = Connection::open(path).unwrap();
    let mut names = vec!["authority_signing_quota_project_states", "authority_signing_quota_transition_project_held"];
    if !rootless { names.extend(["authority_signing_quota_root_states", "authority_signing_quota_transition_root_held"]); }
    let originals: Vec<(&str, String)> = names.into_iter().map(|name| {
        (name, editor.query_row("SELECT sql FROM sqlite_schema WHERE name=? AND type='index'", [name], |r|r.get(0)).unwrap())
    }).collect();
    let cookie: i64 = editor.pragma_query_value(None, "schema_version", |r|r.get(0)).unwrap();
    editor.execute_batch("PRAGMA writable_schema=ON; BEGIN IMMEDIATE").unwrap();
    for (name, sql) in &originals {
        let base = sql.split("WHERE").next().unwrap();
        editor.execute("UPDATE sqlite_schema SET sql=? WHERE name=?", params![format!("{base} WHERE 0"), name]).unwrap();
    }
    editor.pragma_update(None, "schema_version", cookie + 1).unwrap();
    editor.execute_batch("COMMIT; PRAGMA writable_schema=OFF").unwrap();
    drop(editor);
    let rebuild = Connection::open(path).unwrap();
    for (name, _) in &originals { rebuild.execute_batch(&format!("REINDEX {name}")).unwrap(); }
    rebuild.execute_batch("PRAGMA writable_schema=ON; BEGIN IMMEDIATE").unwrap();
    for (name, sql) in &originals { rebuild.execute("UPDATE sqlite_schema SET sql=? WHERE name=?", params![sql, name]).unwrap(); }
    rebuild.pragma_update(None, "schema_version", cookie + 2).unwrap();
    rebuild.execute_batch("COMMIT; PRAGMA writable_schema=OFF").unwrap();
    drop(rebuild);
    let verifier = Connection::open(path).unwrap();
    for (name, sql) in &originals {
        assert_eq!(verifier.query_row::<String, _, _>("SELECT sql FROM sqlite_schema WHERE name=?", [name], |r|r.get(0)).unwrap(), *sql);
    }
    let integrity: String = verifier.query_row("PRAGMA integrity_check", [], |r|r.get(0)).unwrap();
    assert_ne!(integrity, "ok");
    eprintln!("R2 physical integrity diagnostic: {integrity}");
}

#[test]
fn pr23_baseline_r2_both_membership_indexes_empty() {
    for rootless in [false, true] {
        for state in ["issued", "unknown"] {
            let (mut f, _, _) = obligation(rootless, state);
            healthy_refuses(&mut f);
            empty_membership_indexes(&f.path, rootless);
            restored_schema(&mut f);
            assert!(admission(&mut f).is_ok(), "baseline defect: rootless={rootless} state={state}");
            rejected_open_and_maintenance(&f);
            eprintln!("R2 rootless={rootless} state={state}: live ADMITTED; open+maintenance REFUSED");
        }
    }
}

#[test]
fn pr23_baseline_r3_surplus_valid_work_audit() {
    for rootless in [false, true] {
        let (mut f, job, _) = obligation(rootless, "reserved");
        let intent: String = f.store.connection.query_row("SELECT intent_id FROM authority_signing_jobs WHERE job_id=?", [&job], |r|r.get(0)).unwrap();
        let counts = (f.count("authority_audit"), f.count("authority_signing_work_events"), f.count("authority_signing_work_audits"));
        let tx = f.store.connection.transaction().unwrap();
        audit(&tx, &f.tenant, "signing_signer_cancelled", &job, NOW).unwrap();
        tx.commit().unwrap();
        assert_eq!((f.count("authority_audit"), f.count("authority_signing_work_events"), f.count("authority_signing_work_audits")), (counts.0+1, counts.1, counts.2));
        f.store.verify_audit_chain(&f.tenant).unwrap().unwrap();
        assert!(f.store.read_signing_intent(&f.tenant, &intent, NOW).unwrap().is_some());
        AuthorityStore::open(&f.path).unwrap();
        AuthorityStore::migrate(&f.path, f.directory.path().join("noop-backup.sqlite3")).unwrap();
        eprintln!("R3 rootless={rootless}: chain valid; extra cancellation audit with no event/binding; read+open+same-version maintenance ACCEPTED");
    }
}
```

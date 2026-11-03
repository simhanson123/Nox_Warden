# Independent N2 reproduction at the PR20 baseline

This is newly written local evidence, separate from Claude's private probes.
It uses two real `AuthorityStore::provision_principal` calls, not fabricated audit
hashes. On head `9e021b31171ae19ff8c9e7eba400d8dd4630a001` / merge
`6eb68a9251b76ac164f8efb0fa5ad5ded1336564`, the library build and probe exited0.
Audit events decreased from2 to1 while both principals remained; all triggers
were unchanged, FK ON and foreign_key_check clean. `verify_audit_chain` accepted
the shortened history on the current connection and after reopening.

**Exit0 demonstrates the unfixed defect, not a passing security regression.**
The source asserts schema10. In the implementation batch, convert this scenario
to a permanent test requiring mutation refusal and original history preservation.
Do not remove the version assertion to run it against arbitrary user databases.
The probe creates its own new private disposable directory and no production keys.

From the fixed baseline's repository root on Unix, use the pinned toolchain:

```sh
source scripts/dev-env.sh
cargo build --locked -p fw_authority
NOX_AUDIT_REPRO_ROOT=$(mktemp -d)
NOX_AUDIT_TARGET_DIR=$(cargo metadata --format-version 1 --no-deps | python -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
python - "$NOX_AUDIT_REPRO_ROOT/probe.rs" <<'PY_SOURCE'
from pathlib import Path
import sys
text=Path('docs/reviews/pr20-local-audit-repro.md').read_text()
source=text.split('```rust\n',1)[1].split('\n```',1)[0]
Path(sys.argv[1]).write_text(source+'\n')
PY_SOURCE
rustc --edition=2024 "$NOX_AUDIT_REPRO_ROOT/probe.rs" -L "dependency=$NOX_AUDIT_TARGET_DIR/debug/deps" --extern "fw_authority=$NOX_AUDIT_TARGET_DIR/debug/libfw_authority.rlib" -o "$NOX_AUDIT_REPRO_ROOT/probe"
"$NOX_AUDIT_REPRO_ROOT/probe" "$NOX_AUDIT_REPRO_ROOT/authority"
```

The handoff document is newer than the implementation baseline; copy this one
file into an isolated baseline checkout if reproducing after product changes.
Use the un-hashed library just produced by Cargo, not a stale hash-selected rlib.
A customized target/flags/profile must be consistent between Cargo and rustc.
No raw log, secret, former agent process or uploaded attachment is required.

```rust
use fw_authority::{AuthorityStore, AuthorityTenant};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};
fn main() {
    let root = std::env::args().nth(1).expect("private disposable directory");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let db = format!("{root}/authority.sqlite3");
    let org = "22222222-2222-4222-8222-222222222222";
    let project = "33333333-3333-4333-8333-333333333333";
    let tenant = AuthorityTenant::new(org, project).unwrap();
    let mut store = AuthorityStore::open(&db).unwrap();
    store.provision_principal(&tenant,"44444444-4444-4444-8444-444444444444","local-oob","first",1700000000).unwrap();
    store.provision_principal(&tenant,"55555555-5555-4555-8555-555555555555","local-oob","second",1700000001).unwrap();
    let before = store.verify_audit_chain(&tenant).unwrap().unwrap();
    assert_eq!(before.event_count,2);
    let script = r#"
import sqlite3,sys
con=sqlite3.connect(sys.argv[1]); con.execute('PRAGMA foreign_keys=ON'); con.execute('PRAGMA recursive_triggers=OFF')
assert con.execute('PRAGMA user_version').fetchone()[0]==10
before=con.execute("SELECT name,sql FROM sqlite_schema WHERE type='trigger' ORDER BY name").fetchall()
old=con.execute('SELECT sequence,event_hash FROM authority_audit ORDER BY sequence LIMIT 1').fetchone()
con.execute('INSERT OR REPLACE INTO authority_audit(rowid,org_id,project_id,sequence,event_hash,previous_hash,kind,resource_id,recorded_at,canonical_bytes) SELECT (SELECT MAX(rowid) FROM authority_audit),org_id,project_id,sequence,event_hash,previous_hash,kind,resource_id,recorded_at,canonical_bytes FROM authority_audit ORDER BY sequence LIMIT 1')
con.execute('UPDATE authority_audit_heads SET sequence=?,event_hash=?',old)
con.commit()
assert con.execute('SELECT count(*) FROM authority_audit').fetchone()[0]==1
assert con.execute('SELECT count(*) FROM authority_principals').fetchone()[0]==2
assert con.execute("SELECT name,sql FROM sqlite_schema WHERE type='trigger' ORDER BY name").fetchall()==before
assert con.execute('PRAGMA foreign_key_check').fetchall()==[]
print('SQL: audit 2 -> 1; both principals retained; all triggers unchanged; FK ON; recursive triggers OFF; FK check clean')
"#;
    assert!(Command::new("python").arg("-c").arg(script).arg(&db).status().unwrap().success());
    assert_eq!(store.verify_audit_chain(&tenant).unwrap().unwrap().event_count,1);
    drop(store);
    let mut reopened = AuthorityStore::open(&db).unwrap();
    assert_eq!(reopened.verify_audit_chain(&tenant).unwrap().unwrap().event_count,1);
    println!("N2 independently reproduced: real provision/audit API; coherent tail removal passes current and reopened verify_audit_chain");
}
```

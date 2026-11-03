# Reproduce the original schema10 same-second renewal history

The local PR22 follow-up check built commit
`2219c9ffe64fc0f4a967f3af69e84cdcc15aaff3` in an isolated source directory,
appending only a `cfg(test)` export fixture. Its original schema10 code committed
`created`, `claimed`, `renewed`, `renewed` at the same timestamp. The current
administrator migrated that actual old-code database to schema13 and retained
four distinct original audit bindings. All 64 original tables and 94 original
rows retained their rowids, SQLite value types and bytes; the private backup
matched the original snapshot. Among the original tables, only three
migration-ledger rows were added; the new binding table retained four links.

This is separate from the permanent current-source regression that reconstructs
an older schema. The old test binary uses real fixture cryptography and synthetic
native evidence, with no production qualification or firewall writes. Its
`cfg(test)` preparation and worker helpers do not open the production resolver.
The commands below parameterize the export directory so a replay needs no
previous temporary paths, databases, binaries or logs. Keep all generated files
outside the repository; they include private synthetic fixture material.

## Build and export using the old source

Run from the current repository root with the pinned README prerequisites. The
historical source is already in Git; no remote script is downloaded or executed.

```sh
set -euo pipefail
source scripts/dev-env.sh
export NOX_LEGACY_RUN="$(mktemp -d /tmp/nox-pr22-legacy-d6.XXXXXX)"
mkdir "$NOX_LEGACY_RUN/source" "$NOX_LEGACY_RUN/evidence"
chmod 700 "$NOX_LEGACY_RUN" "$NOX_LEGACY_RUN/source" "$NOX_LEGACY_RUN/evidence"
git archive 2219c9ffe64fc0f4a967f3af69e84cdcc15aaff3 |
  tar -x -C "$NOX_LEGACY_RUN/source"
python - <<'PY'
import os
from pathlib import Path

root = Path(os.environ['NOX_LEGACY_RUN'])
path = root / 'source/crates/fw_authority/src/store/signing_jobs.rs'
fixture = r'''

#[cfg(test)]
mod d6_historical_export {
    use super::*;
    use super::super::signing_test_support::{Fixture, NOW};

    #[test]
    fn actual_v10_two_same_second_renewals_export() {
        let mut f = Fixture::new();
        let prepared = signing_intents::test_prepare(&mut f, NOW);
        let job = prepared.intent.job_id;
        let tx = f.store.connection.transaction().unwrap();
        let claim = fixture_claim(
            &tx, &f.tenant, &job, "signer",
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd", 0, 10, NOW,
        ).unwrap();
        let claim = fixture_renew(&tx, &f.tenant, &claim, 11, NOW).unwrap();
        fixture_renew(&tx, &f.tenant, &claim, 12, NOW).unwrap();
        tx.commit().unwrap();
        let schema: i64 = f.store.connection
            .pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(schema, 10);
        let renewals: i64 = f.store.connection.query_row(
            "SELECT count(*) FROM authority_signing_work_events WHERE kind='renewed' AND updated_at=?",
            [NOW], |row| row.get(0),
        ).unwrap();
        assert_eq!(renewals, 2);
        let output = std::path::PathBuf::from(
            std::env::var_os("NOX_LEGACY_RUN").unwrap(),
        ).join("evidence/original-v10.sqlite3");
        f.store.connection.backup("main", output, None).unwrap();
    }
}
'''
path.write_text(path.read_text() + fixture)
PY
(
  cd "$NOX_LEGACY_RUN/source"
  CARGO_TARGET_DIR="$NOX_LEGACY_RUN/target" \
    cargo test --locked --offline -p fw_authority --lib \
    store::signing_jobs::d6_historical_export::actual_v10_two_same_second_renewals_export \
    -- --exact --nocapture
)
chmod 600 "$NOX_LEGACY_RUN/evidence/original-v10.sqlite3"
```

Require exactly one passing test; a zero-test filtered invocation is not evidence.
`--offline` uses the normally restored locked dependency cache; if dependencies
are absent, run `cargo fetch --locked` with the configured proxy and CA first.
The separate target directory prevents reuse of a current-tree test binary.

## Capture typed rows and make the migration candidate

This snapshot includes hidden rowid, original column order and every value.
BLOBs are encoded as hex, integers as decimal strings and floating values as
their exact Python hexadecimal representation. Original canonical and audit
bytes therefore participate in the comparison without being printed.

```sh
cat > "$NOX_LEGACY_RUN/evidence/snapshot.py" <<'PY'
import hashlib
import json
import sqlite3
from pathlib import Path

def quote(name):
    return '"' + name.replace('"', '""') + '"'

def cell(value):
    if value is None:
        return ['null', None]
    if isinstance(value, bytes):
        return ['blob', value.hex()]
    if isinstance(value, str):
        return ['text', value]
    if isinstance(value, int):
        return ['integer', str(value)]
    if isinstance(value, float):
        return ['real', value.hex()]
    raise TypeError(type(value))

def snapshot(path, template=None):
    db = sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True)
    result = {'schema_version': db.execute('PRAGMA user_version').fetchone()[0],
              'tables': {}}
    tables = [row[0] for row in db.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    for table in tables:
        if template is not None and table not in template['tables']:
            continue
        columns = [row[1] for row in db.execute('PRAGMA table_info(' + quote(table) + ')')]
        if template is not None:
            columns = template['tables'][table]['columns']
        selection = ','.join(quote(column) for column in columns)
        rows = [[cell(value) for value in row] for row in db.execute(
            'SELECT rowid,' + selection + ' FROM ' + quote(table) + ' ORDER BY rowid')]
        encoded = json.dumps(rows, ensure_ascii=False, separators=(',', ':')).encode()
        result['tables'][table] = {'columns': columns, 'rows': rows,
                                  'sha256': hashlib.sha256(encoded).hexdigest()}
    db.close()
    return result

def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
PY
python - <<'PY'
import os
import sqlite3
import sys
from pathlib import Path

root = Path(os.environ['NOX_LEGACY_RUN']) / 'evidence'
sys.path.insert(0, str(root))
from snapshot import snapshot, save
original = snapshot(root / 'original-v10.sqlite3')
assert original['schema_version'] == 10
save(root / 'original-snapshot.json', original)
source = sqlite3.connect(root / 'original-v10.sqlite3')
target = sqlite3.connect(root / 'candidate.sqlite3')
source.backup(target)
target.close()
source.close()
(root / 'candidate.sqlite3').chmod(0o600)
PY
```

## Run the current maintenance command and compare

Run the build from the current repository, not the historical archive. The
original export remains untouched; maintenance receives the candidate and its
own new private backup destination.

```sh
cargo build --locked -p fw_authority --bin fw_authority_admin
target/debug/fw_authority_admin migrate \
  --database "$NOX_LEGACY_RUN/evidence/candidate.sqlite3" \
  --backup "$NOX_LEGACY_RUN/evidence/pristine-v10.sqlite3"
python - <<'PY'
import json
import os
import sqlite3
import sys
from pathlib import Path

root = Path(os.environ['NOX_LEGACY_RUN']) / 'evidence'
sys.path.insert(0, str(root))
from snapshot import snapshot, save
before = json.loads((root / 'original-snapshot.json').read_text())
after = snapshot(root / 'candidate.sqlite3', before)
assert after['schema_version'] == 13
assert snapshot(root / 'pristine-v10.sqlite3') == before
for table, original in before['tables'].items():
    current = after['tables'][table]
    assert current['columns'] == original['columns'], table
    by_rowid = {json.dumps(row[0]): row for row in current['rows']}
    assert all(by_rowid.get(json.dumps(row[0])) == row for row in original['rows']), table
    if table != 'authority_schema_migrations':
        assert len(current['rows']) == len(original['rows']), table
db = sqlite3.connect(root / 'candidate.sqlite3')
assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
assert db.execute('PRAGMA foreign_key_check').fetchall() == []
bindings = db.execute('''
SELECT hex(e.revision),e.kind,e.updated_at,hex(a.sequence),a.kind,a.recorded_at,
       hex(w.audit_hash)=hex(a.event_hash)
FROM authority_signing_work_events e
JOIN authority_signing_work_audits w
  ON w.org_id=e.org_id AND w.project_id=e.project_id AND w.job_id=e.job_id
 AND w.phase=e.phase AND w.revision=e.revision
JOIN authority_audit a
  ON a.org_id=w.org_id AND a.project_id=w.project_id AND a.sequence=w.audit_sequence
ORDER BY e.revision
''').fetchall()
assert len(bindings) == 4
assert [row[1] for row in bindings] == ['created', 'claimed', 'renewed', 'renewed']
assert len({row[3] for row in bindings}) == 4
assert [row[3] for row in bindings] == sorted(row[3] for row in bindings)
assert all(kind == 'signing_signer_' + event and at == recorded and matched == 1
           for revision, event, at, sequence, kind, recorded, matched in bindings)
assert len({row[2] for row in bindings}) == 1
db.close()
save(root / 'migrated-snapshot.json', after)
print('PASS: original typed rows/rowids/bytes and private backup preserved; four ordered bindings, including two same-second renewals')
PY
```

The passing maintenance response must still report `dispatch_allowed:false`.
Do not commit the exported databases, snapshot contents, build output or logs.

## Optional: reproduce the PR22 production migrator's refusal

An independent local check also built the non-test administrator from PR22 merge
`d54021a9df32c0a041c52002b05a0e9d64058c0f`. It rejected a separate copy of the
same original schema10 database with exit1 and `MIGRATION_REJECTED`. Seventeen
preservation checks passed: the source and candidate remained unchanged at
schema10, both same-second renewals survived, and the private backup and manifest
were valid. This establishes the old refusal separately from the current
schema13 success above. Neither command runs a privileged executor.

Reuse only the isolated historical target cache, and copy the resulting
production executable before invoking it. Do not build this source into the
current repository's target directory.

```sh
mkdir "$NOX_LEGACY_RUN/baseline12-source"
git archive d54021a9df32c0a041c52002b05a0e9d64058c0f |
  tar -x -C "$NOX_LEGACY_RUN/baseline12-source"
(
  cd "$NOX_LEGACY_RUN/baseline12-source"
  CARGO_TARGET_DIR="$NOX_LEGACY_RUN/target" \
    cargo build --locked --offline -p fw_authority --bin fw_authority_admin
)
cp "$NOX_LEGACY_RUN/target/debug/fw_authority_admin" \
  "$NOX_LEGACY_RUN/evidence/fw_authority_admin-schema12"
python - <<'PY'
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

root = Path(os.environ['NOX_LEGACY_RUN']) / 'evidence'
sys.path.insert(0, str(root))
from snapshot import snapshot
original = root / 'original-v10.sqlite3'
candidate = root / 'baseline12-candidate.sqlite3'
backup = root / 'baseline12-private-backup.sqlite3'
binary = root / 'fw_authority_admin-schema12'
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
original_hash = digest(original)
before = snapshot(original)
source = sqlite3.connect(original)
target = sqlite3.connect(candidate)
source.backup(target)
target.close()
source.close()
candidate.chmod(0o600)
candidate_hash = digest(candidate)
result = subprocess.run([str(binary), 'migrate', '--database', str(candidate),
                         '--backup', str(backup)], capture_output=True)
assert result.returncode == 1
assert result.stdout == b''
assert result.stderr == b'AUTHORITY_ADMIN code=MIGRATION_REJECTED\n'
assert digest(original) == original_hash
assert snapshot(original) == before
assert digest(candidate) == candidate_hash
assert snapshot(candidate) == before
assert snapshot(backup) == before
manifest_path = backup.with_suffix('.manifest.json')
manifest = json.loads(manifest_path.read_text())
assert manifest['database_schema'] == 10
assert manifest['database_hash'] == 'sha256:' + digest(backup)
assert manifest['size_bytes'] == backup.stat().st_size
assert root.stat().st_mode & 0o777 == 0o700
assert backup.stat().st_mode & 0o777 == 0o600
assert manifest_path.stat().st_mode & 0o777 == 0o600
for path in (candidate, backup):
    db = sqlite3.connect(path)
    assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    assert db.execute('PRAGMA foreign_key_check').fetchall() == []
    assert db.execute("SELECT count(*),count(DISTINCT updated_at) FROM authority_signing_work_events WHERE kind='renewed'").fetchone() == (2, 1)
    db.close()
print('PASS: original PR22 production migrator refuses the genuine legacy history while preserving source, candidate and private backup')
PY
```

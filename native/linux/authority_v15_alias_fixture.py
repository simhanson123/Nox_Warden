#!/usr/bin/env python3
"""Export one normal released-schema15 cross-purpose transport-pin fixture.

Only the pinned public healthy export and released admin/helper are needed.
No signer process, private key, fault injection or lock/stress case is used.
"""
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
import struct
import sys
import time

import protected_signer_lab as lab

ROOT = Path('/lab')
HEALTHY = ROOT / 'healthy-v15.json'
DATABASE = ROOT / 'alias-state/authority.sqlite3'
HEALTHY_SHA = '68754c509071e2a175b6207a9e00e2c65b91877e62d72a28ea3433a44b67db1e'
BOOTSTRAP_TYPE = 'application/vnd.f.authority-bootstrap.v1+json'
TARGET = '00000000-0000-4000-8000-000000000003'
SPKI_PREFIX = bytes.fromhex('302a300506032b6570032100')


class FixtureFailure(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def require_lab(worker=False):
    expected_uid = lab.SIGNER if worker else 0
    if os.geteuid() != expected_uid:
        raise FixtureFailure('disposable fixture identity required')
    if (ROOT / 'DISPOSABLE_SIGNER_LAB').read_bytes() != b'fw-disposable-protected-signer-lab-v1\n':
        raise FixtureFailure('disposable fixture marker required')
    if {name for _, name in socket.if_nameindex()} != {'lo'}:
        raise FixtureFailure('network-none fixture namespace required')


def healthy_fixture():
    if HEALTHY.stat().st_size > 2 * 1024 * 1024 or file_hash(HEALTHY) != HEALTHY_SHA:
        raise FixtureFailure('pinned healthy public fixture differs')
    value = json.loads(HEALTHY.read_bytes())
    if value['schema_version'] != 'fw.synthetic-authority-v15-fixture/v1' or value['user_version'] != 15:
        raise FixtureFailure('healthy public fixture schema differs')
    if len(value['tables']) != 18 or sum(len(table['rows']) for table in value['tables']) != 52:
        raise FixtureFailure('healthy public fixture inventory differs')
    return value


def sql_cell(cell):
    kind = cell['type']
    if kind == 'null' and set(cell) == {'type'}:
        return None
    if kind == 'integer' and set(cell) == {'type', 'value'} and type(cell['value']) is int:
        return cell['value']
    if kind == 'text' and set(cell) == {'type', 'value'} and isinstance(cell['value'], str):
        return cell['value']
    if kind == 'blob' and set(cell) == {'type', 'base64'}:
        raw = base64.b64decode(cell['base64'], validate=True)
        if base64.b64encode(raw).decode() == cell['base64']:
            return raw
    if kind == 'real' and set(cell) == {'type', 'bits'}:
        raw = bytes.fromhex(cell['bits'])
        if len(raw) == 8:
            value = struct.unpack('>d', raw)[0]
            if math.isfinite(value):
                return value
    raise FixtureFailure('unsupported public typed SQLite cell')


def public_cell(value):
    if value is None:
        return {'type': 'null'}
    if type(value) is int:
        return {'type': 'integer', 'value': value}
    if isinstance(value, float):
        return {'type': 'real', 'bits': struct.pack('>d', value).hex()}
    if isinstance(value, str):
        return {'type': 'text', 'value': value}
    if isinstance(value, bytes):
        return {'type': 'blob', 'base64': base64.b64encode(value).decode()}
    raise FixtureFailure('unsupported public SQLite value')


def quoted(name):
    return '"' + name.replace('"', '""') + '"'


def table_names(db):
    return [row[0] for row in db.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' AND substr(name,1,10)='authority_' ORDER BY name")]


def schema(db):
    return db.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name,tbl_name').fetchall()


def export(db):
    tables = []
    for name in table_names(db):
        cursor = db.execute('SELECT rowid,* FROM ' + quoted(name) + ' ORDER BY rowid')
        rows = cursor.fetchall()
        if rows:
            tables.append({'name': name, 'columns': [column[0] for column in cursor.description],
                           'rows': [[public_cell(value) for value in row] for row in rows]})
    return {'application_id': db.execute('PRAGMA application_id').fetchone()[0],
            'user_version': db.execute('PRAGMA user_version').fetchone()[0], 'tables': tables}


def normalized_projection(tables):
    # SELECT rowid,* exposes an INTEGER PRIMARY KEY's name for its first value.
    # Normalize only this in-memory projection label; never rewrite the input.
    return [{'name': table['name'], 'columns': ['rowid', *table['columns'][1:]], 'rows': table['rows']}
            for table in tables]


def load_healthy(value):
    db = sqlite3.connect(DATABASE)
    try:
        if db.execute('PRAGMA user_version').fetchone()[0] != 15:
            raise FixtureFailure('actual released init did not create schema15')
        if db.execute('PRAGMA application_id').fetchone()[0] != value['application_id']:
            raise FixtureFailure('released application identity differs')
        original_schema = schema(db)
        names = table_names(db)
        triggers = db.execute("SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND substr(tbl_name,1,10)='authority_' ORDER BY name").fetchall()
        db.execute('PRAGMA foreign_keys=OFF')
        db.execute('PRAGMA recursive_triggers=OFF')
        db.execute('BEGIN IMMEDIATE')
        for name, _ in triggers:
            db.execute('DROP TRIGGER ' + quoted(name))
        for name in names:
            db.execute('DELETE FROM ' + quoted(name))
        for table in value['tables']:
            name = table['name']
            if name not in names:
                raise FixtureFailure('public table is absent from released schema')
            actual = [column[0] for column in db.execute('SELECT rowid,* FROM ' + quoted(name) + ' LIMIT 0').description]
            if actual[1:] != table['columns'][1:]:
                raise FixtureFailure('public columns differ from released schema')
            columns = ['rowid', *table['columns'][1:]]
            statement = 'INSERT INTO ' + quoted(name) + '(' + ','.join(map(quoted, columns)) + ') VALUES(' + ','.join('?' for _ in columns) + ')'
            for row in table['rows']:
                if len(row) != len(columns):
                    raise FixtureFailure('public typed row width differs')
                db.execute(statement, tuple(sql_cell(cell) for cell in row))
        for _, statement in triggers:
            db.execute(statement)
        if schema(db) != original_schema:
            raise FixtureFailure('released schema or trigger bytes changed')
        restored = export(db)
        if normalized_projection(restored['tables']) != normalized_projection(value['tables']):
            raise FixtureFailure('public rowids or typed cells changed during reconstruction')
        if db.execute('PRAGMA foreign_key_check').fetchall():
            raise FixtureFailure('reconstructed released foreign keys differ')
        db.commit()
        return {'schema_unchanged': True, 'rowid_labels_normalized_in_memory': True,
                'nonempty_tables': 18, 'rows': 52,
                'released_schema_sha256': hashlib.sha256(canonical(original_schema)).hexdigest()}
    finally:
        db.close()


def records(value, name):
    for table in value['tables']:
        if table['name'] == name:
            return [dict(zip(table['columns'][1:], map(sql_cell, row[1:]))) for row in table['rows']]
    return []


def successful(command, *, body=None):
    completed = lab.command(command, input=None if body is None else canonical(body))
    if completed.returncode or completed.stderr:
        raise FixtureFailure('released normal command refused')
    if len(completed.stdout) > 2 * 1024 * 1024:
        raise FixtureFailure('public export exceeds bound')
    return json.loads(completed.stdout)


def main():
    require_lab()
    os.chmod(ROOT, 0o755)
    healthy = healthy_fixture()
    provenance = healthy['provenance']
    if file_hash(ROOT / 'fw_authority_admin') != provenance['binaries']['fw_authority_admin']:
        raise FixtureFailure('released admin binary differs from healthy provenance')
    if file_hash(Path(lab.__file__)) != provenance['released_helper_sha256']:
        raise FixtureFailure('released helper differs from healthy provenance')
    keys = [row for row in records(healthy, 'authority_registry_keys')
            if row['payload_type'] == BOOTSTRAP_TYPE and row['target_id'] == TARGET]
    authorizations = [row for row in records(healthy, 'authority_registry_objects')
                      if row['object_kind'] == 'bootstrap_authorization' and row['target_id'] == TARGET]
    if len(keys) != 1 or len(authorizations) != 1 or records(healthy, 'authority_target_keys'):
        raise FixtureFailure('healthy bootstrap identity is ambiguous')
    key, authorization = keys[0], authorizations[0]
    public_key = key['public_key']
    if len(public_key) != 32:
        raise FixtureFailure('bootstrap public key size differs')
    raw_fingerprint = hashlib.sha256(public_key).digest()
    spki_fingerprint = hashlib.sha256(SPKI_PREFIX + public_key).digest()
    if raw_fingerprint == spki_fingerprint or key['key_fingerprint'] != raw_fingerprint:
        raise FixtureFailure('released fingerprint domains differ from expected fixture')
    state = DATABASE.parent
    state.mkdir(mode=0o700)
    os.chown(state, lab.SIGNER, lab.SIGNER)
    admin = str(ROOT / 'fw_authority_admin')
    successful([admin, 'init', '--database', str(DATABASE)], body={})
    restored = successful(['python3', str(Path(__file__).resolve()), '--load'])
    options = ['--database', str(DATABASE), '--org-id', key['org_id'], '--project-id', key['project_id']]
    read = {'object_kind': 'bootstrap_authorization', 'object_id': authorization['object_id']}
    before = successful([admin, 'read-authority-registry', *options], body=read)
    if before['object'] is None or before['object']['content_hash'] != healthy['authorization_hash']:
        raise FixtureFailure('released pre-pin full validation differs')
    pin_time = int(time.time())
    pin = {'target_id': TARGET, 'public_key': list(public_key),
           'certificate_fingerprint': 'sha256:' + hashlib.sha256(b'released15 public cross-purpose transport certificate fixture').hexdigest(),
           'platform': 'linux', 'not_before': pin_time - 1, 'not_after': pin_time + 600}
    pinned = successful([admin, 'pin-target', *options], body={'pin': pin, 'expected_revision': None})
    if pinned.get('key_revision') != '1' or pinned.get('dispatch_allowed') is not False:
        raise FixtureFailure('released transport pin did not retain revision one')
    after = successful([admin, 'read-authority-registry', *options], body=read)
    if after['object'] is None or after['object']['content_hash'] != healthy['authorization_hash']:
        raise FixtureFailure('released post-pin full validation differs')
    exported = successful(['python3', str(Path(__file__).resolve()), '--export'])
    transport = records(exported, 'authority_target_keys')
    if exported['user_version'] != 15 or len(transport) != 1:
        raise FixtureFailure('released cross-purpose export differs')
    if transport[0]['public_key'] != public_key or transport[0]['key_fingerprint'] != spki_fingerprint:
        raise FixtureFailure('released transport did not retain the same raw public key')
    flow = dict(healthy['normal_public_flow'])
    flow.update(old15_pre_pin_full_validation=True, old15_post_pin_full_validation=True,
                old15_cross_role_transport_pin_accepted=True, actual_additional_admin_commands=4,
                signer_process_started=False, private_key_material_transferred=False)
    return {'schema_version': 'fw.synthetic-authority-v15-fixture/v1', **exported,
            'fixture_time': int(time.time()), 'authorization_hash': healthy['authorization_hash'],
            'normal_public_flow': flow, 'old15_cross_role_transport_pin_accepted': True,
            'original_healthy_fixture_sha256': 'sha256:' + HEALTHY_SHA,
            'provenance': {'source_commit': provenance['source_commit'], 'source_tree': provenance['source_tree'],
                'source_files_verified': provenance['source_files_verified'], 'source_map_sha256': provenance['source_map_sha256'],
                'binaries': {'fw_authority_admin': file_hash(ROOT / 'fw_authority_admin')},
                'generator_source': 'native/linux/authority_v15_alias_fixture.py',
                'generator_sha256': file_hash(Path(__file__).resolve()),
                'released_helper_sha256': file_hash(Path(lab.__file__)),
                'healthy_fixture_time': healthy['fixture_time'], 'healthy_fixture_sha256': HEALTHY_SHA,
                'reconstruction': restored,
                'public_inputs': {'bootstrap_key_id': key['key_id'], 'transport_pin': pin,
                    'raw_public_key_fingerprint': 'sha256:' + raw_fingerprint.hex(),
                    'spki_public_key_fingerprint': 'sha256:' + spki_fingerprint.hex()},
                'generator': ['Use exact healthy-v15.json SHA68754c509071e2a175b6207a9e00e2c65b91877e62d72a28ea3433a44b67db1e.',
                    'Actual released admin init creates schema15; signer-UID loader restores exact public typed rows and original triggers.',
                    'Actual released admin read-authority-registry performs full validation before normal pin-target with the existing bootstrap public key.',
                    'Actual released admin pin-target accepts that same raw key under its SPKI fingerprint; full read validation succeeds again.',
                    'Export all nonempty typed authority tables after all normal admin processes have exited.'],
                'qualification': 'Public synthetic reconstruction plus one actual released normal transport pin. No private keys, signer process, fault injection, DMS probe or stress scenario.'}}


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--load']:
            require_lab(worker=True)
            output = load_healthy(healthy_fixture())
        elif sys.argv[1:] == ['--export']:
            require_lab(worker=True)
            database = sqlite3.connect(DATABASE)
            try:
                output = export(database)
            finally:
                database.close()
        elif not sys.argv[1:]:
            output = main()
        else:
            raise FixtureFailure('unsupported fixture producer operation')
        print(canonical(output).decode())
    except BaseException as error:
        detail = str(error) if isinstance(error, FixtureFailure) else 'bounded producer failed'
        print('SYNTHETIC_V15_ALIAS_FIXTURE_REJECTED ' + detail, file=sys.stderr)
        raise SystemExit(1)

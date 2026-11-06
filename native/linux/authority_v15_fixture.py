#!/usr/bin/env python3
"""Export synthetic public schema15 history through the released normal flow.

Run only in the disposable, network-none lab with source-verified 5fc576f binaries.
Private seed/config files remain in tmpfs and are never part of the export.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import time

import protected_signer_lab as lab


def main():
    root = Path('/lab')
    if os.geteuid() != 0 or (root / 'DISPOSABLE_SIGNER_LAB').read_text() != 'fw-disposable-protected-signer-lab-v1\n':
        raise RuntimeError('disposable fixture marker required')
    os.chmod(root, 0o755)
    state, runtime = root / 'state', root / 'runtime'
    for path, mode in ((state, 0o700), (runtime, 0o711)):
        path.mkdir(mode=mode)
        os.chown(path, lab.SIGNER, lab.SIGNER)
    fixture_process = subprocess.Popen(
        [str(root / 'protected_signer_fixture'), str(state), '--admin', str(root / 'fw_authority_admin')],
        preexec_fn=lab.drop(lab.SIGNER), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        fixture_stdout, _ = fixture_process.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        lab.command(['python3', '-c', 'import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGTERM)', str(fixture_process.pid)])
        fixture_process.communicate(timeout=5)
        raise RuntimeError('released fixture preparation exceeded its bounded deadline')
    if fixture_process.returncode:
        raise RuntimeError('released fixture preparation failed')
    metadata = json.loads(fixture_stdout)
    if metadata['operator_commands_executed'] != 17:
        raise RuntimeError('released operator flow differs')
    config = {'schema_version': 'fw.signer-config/v1', 'signer_uid': lab.SIGNER,
              'controller_uid': lab.CONTROLLER, 'org_id': metadata['org_id'],
              'project_id': metadata['project_id'], 'database_path': metadata['database_path'],
              'key_file': metadata['seed_file'], 'key_id': metadata['key_id'],
              'socket_path': str(runtime / 'signer.sock'), 'webauthn_origin': metadata['webauthn_origin']}
    config_path = state / 'signer.json'
    config_path.write_text(json.dumps(config))
    os.chmod(config_path, 0o600)
    os.chown(config_path, lab.SIGNER, lab.SIGNER)
    floor = lab.command(['python3', '-c',
        'import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);print(c.execute("SELECT MAX(observed_at) FROM authority_registry_clocks").fetchone()[0]);c.close()',
        config['database_path']])
    if floor.returncode:
        raise RuntimeError('fixture clock read failed')
    deadline = time.monotonic() + 10
    while int(time.time()) <= int(floor.stdout):
        if time.monotonic() >= deadline:
            raise RuntimeError('fixture clock unexpectedly ahead')
        time.sleep(.01)
    process = subprocess.Popen([str(root / 'fw_signer'), '--config', str(config_path)],
                               preexec_fn=lab.drop(lab.SIGNER), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while not Path(config['socket_path']).exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        authorization = lab.client(config['socket_path'], lab.request('authorize_bootstrap', manifest_id=metadata['manifest_id']))['authorization']
    finally:
        if process.poll() is None:
            terminated = lab.command(['python3', '-c', 'import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGTERM)', str(process.pid)])
            if terminated.returncode:
                raise RuntimeError('normal fixture signer stop failed')
        process.communicate(timeout=5)
    # Observe and export only after the normal signer has stopped. No external
    # SQL reader runs while the old signer owns its connection.
    health = lab.command([str(root / 'fw_authority_admin'), 'read-authority-registry', '--database',
                          config['database_path'], '--org-id', metadata['org_id'], '--project-id', metadata['project_id']],
                         input=json.dumps({'object_kind': 'bootstrap_authorization', 'object_id': metadata['manifest_id']}).encode())
    if health.returncode or json.loads(health.stdout)['object']['state'] != 'authorized_pending_target_confirmation':
        raise RuntimeError('released store full validation failed')
    public = state / 'public-authorization.json'
    canonical = json.dumps(authorization, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    public.write_bytes(canonical)
    os.chmod(public, 0o600)
    os.chown(public, lab.SIGNER, lab.SIGNER)
    verified = lab.command([str(root / 'protected_signer_fixture'), 'verify', str(state), str(public)])
    if verified.returncode or not json.loads(verified.stdout)['verified']:
        raise RuntimeError('released bootstrap signature validation failed')
    code = r'''
import base64,json,sqlite3,struct,sys
def cell(value):
 if value is None:return {'type':'null'}
 if isinstance(value,int):return {'type':'integer','value':value}
 if isinstance(value,float):return {'type':'real','bits':struct.pack('>d',value).hex()}
 if isinstance(value,str):return {'type':'text','value':value}
 if isinstance(value,bytes):return {'type':'blob','base64':base64.b64encode(value).decode()}
 raise TypeError('unsupported public SQLite value')
db=sqlite3.connect(sys.argv[1]);tables=[]
try:
 for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'authority_%' ORDER BY name").fetchall():
  quoted='"'+name.replace('"','""')+'"';cursor=db.execute('SELECT rowid,* FROM '+quoted+' ORDER BY rowid');rows=cursor.fetchall()
  if rows:tables.append({'name':name,'columns':[column[0] for column in cursor.description],'rows':[[cell(value) for value in row] for row in rows]})
 print(json.dumps({'application_id':db.execute('PRAGMA application_id').fetchone()[0],'user_version':db.execute('PRAGMA user_version').fetchone()[0],'tables':tables}))
finally:db.close()
'''
    dumped = lab.command(['python3', '-c', code, config['database_path']])
    if dumped.returncode:
        raise RuntimeError('public typed fixture export failed')
    exported = json.loads(dumped.stdout)
    if exported['user_version'] != 15:
        raise RuntimeError('released fixture is not schema15')
    return {'schema_version': 'fw.synthetic-authority-v15-fixture/v1', **exported,
            'fixture_time': metadata['created_at'], 'authorization_hash': 'sha256:' + hashlib.sha256(canonical).hexdigest(),
            'normal_public_flow': {'operator_commands': 17, 'owner_proof_created': True,
                                   'bootstrap_signature_verified': True, 'released_store_full_validation': True}}


if __name__ == '__main__':
    print(json.dumps(main(), sort_keys=True, separators=(',', ':'), ensure_ascii=False))

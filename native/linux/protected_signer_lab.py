#!/usr/bin/env python3
"""Disposable-container-only actual-process UID, key, framing and bootstrap tests."""
import base64
from contextlib import closing
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import time
import uuid

SIGNER = 65531
CONTROLLER = 65532
OTHER = 65533
ROOT = Path('/lab')
checks = []


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)


def drop(uid):
    def apply():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return apply


def command(args, uid=SIGNER, timeout=15, **kwargs):
    body = kwargs.pop('input', None)
    process = subprocess.Popen(args, preexec_fn=drop(uid),
                               stdin=subprocess.PIPE if body is not None else None,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    try:
        stdout, stderr = process.communicate(body, timeout=timeout)
    except subprocess.TimeoutExpired:
        # The root fixture parent intentionally lacks CAP_KILL. Signal a
        # timed-out child from its actual UID, then reap both bounded children.
        code = ('import os,signal,sys;signal.alarm(4)\n'
                'try:os.kill(int(sys.argv[1]),signal.SIGKILL)\n'
                'except ProcessLookupError:pass')
        try:
            cleanup = subprocess.Popen(['python3', '-c', code, str(process.pid)],
                                       preexec_fn=drop(uid), stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            cleanup.communicate(timeout=5)
            if cleanup.returncode:
                raise RuntimeError('FIXTURE_COMMAND_TIMEOUT_CLEANUP_FAILED')
            process.communicate(timeout=5)
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError('FIXTURE_COMMAND_TIMEOUT_CLEANUP_FAILED') from None
        raise RuntimeError('FIXTURE_COMMAND_TIMEOUT') from None
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def signer_chmod(path, mode):
    # CAP_DAC_OVERRIDE does not permit root to chmod another UID's files.
    # Exercise fixture mutations as their actual owner instead of adding FOWNER.
    changed = command(['python3', '-c', 'import os,sys;os.chmod(sys.argv[1],int(sys.argv[2],8))',
                       str(path), oct(mode)])
    if changed.returncode:
        raise RuntimeError('signer-owned fixture permission update failed')


def signer_link(source, destination):
    # Linux protected_hardlinks may also require owner identity or CAP_FOWNER.
    linked = command(['python3', '-c', 'import os,sys;os.link(sys.argv[1],sys.argv[2])',
                      str(source), str(destination)])
    if linked.returncode:
        raise RuntimeError('signer-owned fixture hardlink creation failed')


def client(socket_path, payload, uid=CONTROLLER, raw=False, slow=False):
    script = r'''
import json,os,socket,struct,sys,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(8);s.connect(sys.argv[1])
b=sys.stdin.buffer.read()
try:
 if sys.argv[2]=='slow':
  wire=struct.pack('>I',4096)+b'x'*5
  for byte in wire:
   s.sendall(bytes([byte]));time.sleep(.8)
 else:s.sendall(b)
 s.shutdown(socket.SHUT_WR)
 data=b''
 while len(data)<4:
  block=s.recv(4-len(data))
  if not block:break
  data+=block
 if len(data)==4:
  n=struct.unpack('>I',data)[0]
  if n>524288:raise RuntimeError('response limit')
  data=b''
  while len(data)<n:
   block=s.recv(n-len(data))
   if not block:raise RuntimeError('partial response')
   data+=block
  sys.stdout.buffer.write(data)
except (BrokenPipeError,ConnectionResetError):pass
finally:s.close()
'''
    body = payload if raw else json.dumps(payload, separators=(',', ':')).encode()
    wire = body if raw else struct.pack('>I', len(body)) + body
    result = command(['python3', '-c', script, str(socket_path), 'slow' if slow else 'normal'], uid,
                     input=wire)
    if result.returncode:
        raise RuntimeError('client process failed')
    return json.loads(result.stdout) if result.stdout else None


def request(operation, **fields):
    return {'schema_version': 'fw.signer-request/v1', 'request_id': str(uuid.uuid4()), 'operation': operation, **fields}


def discard_reply(socket_path, payload):
    body = json.dumps(payload, separators=(',', ':')).encode()
    wire = struct.pack('>I', len(body)) + body
    code = 'import socket,sys;s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(sys.argv[1]);s.sendall(sys.stdin.buffer.read());s.shutdown(socket.SHUT_WR);s.close()'
    result = command(['python3', '-c', code, str(socket_path)], CONTROLLER, input=wire)
    if result.returncode:
        raise RuntimeError('discarded output client failed')


def sqlite_locks(database):
    """Observe SQLite locks from another PID without opening a SQL connection."""
    code = r'''
import errno,fcntl,json,os,sys
fd=os.open(sys.argv[1],os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 try:
  fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB,int(sys.argv[3]),int(sys.argv[2]),os.SEEK_SET)
  state='ACQUIRED'
 except OSError as error:
  if error.errno not in (errno.EACCES,errno.EAGAIN):raise
  state='BLOCKED'
 print(json.dumps({'state':state}))
finally:os.close(fd)
'''
    observed = {}
    for name, path, offset, length in (
            ('main_shared', database, 1073741826, 510),
            ('shm_dms', str(database) + '-shm', 128, 1)):
        result = command(['python3', '-c', code, str(path), str(offset), str(length)])
        if result.returncode:
            raise RuntimeError('independent SQLite lock observation failed')
        observed[name] = json.loads(result.stdout)['state']
    return observed


def main():
    if os.geteuid() != 0 or not (ROOT / 'DISPOSABLE_SIGNER_LAB').is_file() or (ROOT / 'DISPOSABLE_SIGNER_LAB').read_text() != 'fw-disposable-protected-signer-lab-v1\n':
        raise RuntimeError('explicit disposable container marker required')
    # Descriptor-relative O_RDONLY directory walks require read+search on this
    # root-owned ancestor. Secrets remain under signer-owned state mode0700.
    os.chmod(ROOT, 0o755)
    state = ROOT / 'state'
    runtime = ROOT / 'runtime'
    for directory, mode in ((state, 0o700), (runtime, 0o711)):
        directory.mkdir(mode=mode)
        os.chown(directory, SIGNER, SIGNER)
    fixture = command([str(ROOT / 'protected_signer_fixture'), str(state), '--admin', str(ROOT / 'fw_authority_admin')], timeout=90)
    check('actual owner proof and bootstrap inputs created', fixture.returncode == 0)
    metadata = json.loads(fixture.stdout)
    check('actual operator CLI provisions all bootstrap inputs', metadata.get('operator_cli_used') is True and metadata.get('operator_commands_executed') == 18)
    config = {'schema_version': 'fw.signer-config/v1', 'signer_uid': SIGNER, 'controller_uid': CONTROLLER,
              'org_id': metadata['org_id'], 'project_id': metadata['project_id'],
              'database_path': metadata['database_path'], 'key_file': metadata['seed_file'],
              'key_id': metadata['key_id'], 'socket_path': str(runtime / 'signer.sock'),
              'webauthn_origin': metadata['webauthn_origin']}
    config_path = state / 'signer.json'
    def save_config(value=config):
        config_path.write_text(json.dumps(value))
        os.chown(config_path, SIGNER, SIGNER)
        signer_chmod(config_path, 0o600)
    save_config()
    process = None
    def stop():
        nonlocal process
        if process:
            if process.poll() is None:
                # The fixture parent intentionally has no CAP_KILL. Signal the
                # child from its own UID rather than widening container caps.
                stopped = command(['python3', '-c',
                                   'import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGTERM)',
                                   str(process.pid)])
                if stopped.returncode and process.poll() is None:
                    raise RuntimeError('signer-owned fixture process termination failed')
            process.communicate(timeout=5)
            process = None
        Path(config['socket_path']).unlink(missing_ok=True)
    def start():
        nonlocal process
        process = subprocess.Popen([str(ROOT / 'fw_signer'), '--config', str(config_path)],
                                   preexec_fn=drop(SIGNER), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not Path(config['socket_path']).exists() and process.poll() is None:
            time.sleep(.01)
        if process.poll() is not None or not Path(config['socket_path']).exists():
            raise RuntimeError('protected signer failed startup')
    def refusal(label, expected, uid=SIGNER, path=config_path):
        response = command([str(ROOT / 'fw_signer'), '--config', str(path)], uid)
        accepted = response.returncode != 0 and response.stdout == b'' and response.stderr == (expected + '\n').encode()
        if not accepted:
            fixed = response.stderr.strip()
            observed = fixed.decode('ascii') if re.fullmatch(rb'SIGNER_[A-Z_]{1,64}', fixed) else 'UNEXPECTED_OUTPUT'
            raise AssertionError(f'{label}: exit={response.returncode} fixed_code={observed}')
        check(label, True)
    try:
        refusal('root signer refused', 'SIGNER_IDENTITY_REJECTED', 0)
        config['controller_uid'] = SIGNER
        save_config()
        refusal('same controller signer UID refused', 'SIGNER_CONFIG_REJECTED')
        config['controller_uid'] = CONTROLLER
        save_config()
        seed = Path(config['key_file'])
        signer_chmod(seed, 0o640)
        refusal('shared signer key permissions refused', 'SIGNER_KEY_REJECTED')
        signer_chmod(seed, 0o600)
        hardlink = state / 'hardlink.seed'
        signer_link(seed, hardlink)
        refusal('hardlinked signer key refused', 'SIGNER_KEY_REJECTED')
        hardlink.unlink()
        real_seed = state / 'real.seed'
        seed.rename(real_seed)
        seed.symlink_to(real_seed)
        refusal('symlink signer key refused', 'SIGNER_KEY_REJECTED')
        seed.unlink()
        real_seed.rename(seed)
        key_directory = state / 'keys'
        key_directory.mkdir(mode=0o700)
        os.chown(key_directory, SIGNER, SIGNER)
        moved_seed = key_directory / 'bootstrap.seed'
        seed.rename(moved_seed)
        config['key_file'] = str(moved_seed)
        save_config()
        signer_chmod(key_directory, 0o777)
        refusal('controller writable key parent refused', 'SIGNER_KEY_REJECTED')
        signer_chmod(key_directory, 0o700)
        directory_link = state / 'linked-keys'
        directory_link.symlink_to(key_directory, target_is_directory=True)
        config['key_file'] = str(directory_link / 'bootstrap.seed')
        save_config()
        refusal('symlink key ancestor refused', 'SIGNER_KEY_REJECTED')
        directory_link.unlink()
        moved_seed.rename(seed)
        key_directory.rmdir()
        config['key_file'] = str(seed)
        save_config()
        os.chown(seed, CONTROLLER, CONTROLLER)
        refusal('controller owned signer key refused', 'SIGNER_KEY_REJECTED')
        os.chown(seed, SIGNER, SIGNER)
        signer_chmod(config_path, 0o644)
        refusal('public configuration refused', 'SIGNER_CONFIG_REJECTED')
        signer_chmod(config_path, 0o600)
        linked_config = state / 'config-link.json'
        linked_config.symlink_to(config_path)
        refusal('symlink configuration refused', 'SIGNER_CONFIG_REJECTED', path=linked_config)
        linked_config.unlink()
        database = Path(config['database_path'])
        signer_chmod(database, 0o640)
        refusal('shared authority database refused', 'SIGNER_DATABASE_REJECTED')
        signer_chmod(database, 0o600)
        database_link = state / 'database-hardlink'
        signer_link(database, database_link)
        refusal('hardlinked authority database refused', 'SIGNER_DATABASE_REJECTED')
        database_link.unlink()
        signer_chmod(runtime, 0o777)
        refusal('controller writable socket parent refused', 'SIGNER_SOCKET_REJECTED')
        signer_chmod(runtime, 0o711)
        for private_path in (seed, Path(config['database_path'])):
            unreadable = command(['python3', '-c', 'import sys;open(sys.argv[1],"rb").read(1)', str(private_path)], CONTROLLER)
            check('controller cannot read ' + ('private key' if private_path == seed else 'authority database'), unreadable.returncode != 0)
        start()
        sqlite_evidence = {'locks_after_startup': sqlite_locks(config['database_path'])}
        check('live SQLite locks held after signer startup', sqlite_evidence['locks_after_startup'] == {'main_shared': 'BLOCKED', 'shm_dms': 'BLOCKED'})
        status = client(config['socket_path'], request('status'))
        check('kernel authenticated distinct controller accepted', status['peer_identity_verified'] and status['distinct_process_identity'])
        check('protected local keys reported without production authority', status['key_storage_permissions_verified'] and not status['signing_allowed'] and not status['dispatch_allowed'])
        check('legacy signer status preserves exact v1 blocker labels', status['schema_version'] == 'fw.signer-status/v1' and status['production_blockers'] == ['BUILD_IDENTITY_UNVERIFIED', 'NATIVE_QUALIFICATION_UNAVAILABLE'])
        status_v2 = client(config['socket_path'], request('status_v2'))
        check('opt-in signer status uses canonical v2 blocker labels', status_v2['schema_version'] == 'fw.signer-status/v2' and status_v2['production_blockers'] == ['BUILD_IDENTITY_REQUIRED', 'NATIVE_QUALIFICATION_REQUIRED'] and status_v2['peer_identity_verified'] and status_v2['distinct_process_identity'] and status_v2['key_storage_permissions_verified'] and not status_v2['signing_allowed'] and not status_v2['dispatch_allowed'])
        sqlite_evidence['locks_after_status'] = sqlite_locks(config['database_path'])
        check('live SQLite locks held after status request', sqlite_evidence['locks_after_status'] == {'main_shared': 'BLOCKED', 'shm_dms': 'BLOCKED'})
        check('another process UID refused before response', client(config['socket_path'], request('status'), OTHER) is None)
        check('root peer is not accepted as configured controller', client(config['socket_path'], request('status'), 0) is None)
        check('caller actor assertion rejected', client(config['socket_path'], request('status', actor='owner')) is None)
        check('caller supplied payload rejected', client(config['socket_path'], request('authorize_bootstrap', manifest_id=metadata['manifest_id'], payload={})) is None)
        good = json.dumps(request('status')).encode()
        check('trailing request bytes refused', client(config['socket_path'], struct.pack('>I', len(good)) + good + b'x', raw=True) is None)
        check('oversized frame refused before allocation', client(config['socket_path'], struct.pack('>I', 4097), raw=True) is None)
        start_time = time.monotonic()
        check('slow partial header body refused on total deadline', client(config['socket_path'], b'', raw=True, slow=True) is None)
        check('total deadline recovers within bounded time', time.monotonic() - start_time < 6)
        check('valid status recovers after slow input', client(config['socket_path'], request('status'))['peer_identity_verified'])
        stop()
        original_key = seed.read_bytes()
        original_key_id = config['key_id']
        config['key_id'] = 'fixture-workload-issuer'
        seed.write_bytes(bytes([41]) * 32)
        save_config()
        start()
        wrong_purpose = client(config['socket_path'], request('authorize_bootstrap', manifest_id=metadata['manifest_id']))
        check('correct workload key cannot sign bootstrap purpose', wrong_purpose['code'] == 'SIGNER_AUTHORITY_UNAVAILABLE')
        stop()
        config['key_id'] = original_key_id
        seed.write_bytes(original_key)
        save_config()
        start()
        missing = client(config['socket_path'], request('authorize_bootstrap', manifest_id=str(uuid.uuid4())))
        check('unretained bootstrap manifest refused', missing['code'] == 'SIGNER_AUTHORITY_UNAVAILABLE')
        grant = client(config['socket_path'], request('sign_job', job_id=str(uuid.uuid4()), expected_claim_generation='0'))
        check('unretained policy job cannot obtain signature', grant['code'] == 'SIGNER_AUTHORITY_UNAVAILABLE')
        external_reader = command(['python3', '-c',
            'import json,sqlite3,sys\n'
            'db=sqlite3.connect(sys.argv[1],timeout=2)\n'
            'try:\n'
            ' floor=db.execute("SELECT MAX(observed_at) FROM authority_registry_clocks").fetchone()[0]\n'
            ' count=db.execute("SELECT count(*) FROM authority_registry_objects WHERE object_kind=\'bootstrap_authorization\'").fetchone()[0]\n'
            ' print(json.dumps({"floor":floor,"authorization_rows":count}))\n'
            'finally:db.close()\n', config['database_path']])
        check('ordinary external reader closes before first authorization', external_reader.returncode == 0)
        before_authorize = json.loads(external_reader.stdout)
        check('durability scenario begins without an authorization', before_authorize['authorization_rows'] == 0)
        sqlite_evidence['floor_before_authorization'] = before_authorize['floor']
        deadline = time.monotonic() + 10
        while int(time.time()) <= before_authorize['floor']:
            if time.monotonic() >= deadline:
                raise RuntimeError('fixture clock is unexpectedly ahead')
            time.sleep(.01)
        discard_reply(config['socket_path'], request('authorize_bootstrap', manifest_id=metadata['manifest_id']))
        authorized = client(config['socket_path'], request('authorize_bootstrap', manifest_id=metadata['manifest_id']))
        check('retained real owner proof receives bootstrap authorization', authorized['schema_version'] == 'fw.signer-bootstrap-outcome/v1')
        authorization = authorized['authorization']
        canonical = json.dumps(authorization, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        # No SQLite read, poll, verifier or checkpoint until the signer exits.
        stop()
        with closing(sqlite3.connect(config['database_path'])) as retained:
            rows = retained.execute("SELECT canonical_bytes FROM authority_registry_objects WHERE object_kind='bootstrap_authorization'").fetchall()
            durable_floor = retained.execute('SELECT MAX(observed_at) FROM authority_registry_clocks').fetchone()[0]
        committed_bytes = bytes(rows[0][0]) if len(rows) == 1 else None
        check('disconnected caller leaves durable authorization after SIGTERM', committed_bytes is not None)
        check('retry recovers original bytes after actual lost output', canonical == committed_bytes)
        issued_at = int(datetime.fromisoformat(authorization['payload']['issued_at'].replace('Z', '+00:00')).timestamp())
        check('new registry clock floor survives SIGTERM', durable_floor > before_authorize['floor'] and durable_floor >= issued_at)
        sqlite_evidence.update(floor_after_first_stop=durable_floor, authorization_issued_at=issued_at,
                               no_sqlite_read_before_first_stop=True,
                               authorization_hash_after_first_stop='sha256:' + hashlib.sha256(committed_bytes).hexdigest())
        start()
        recovered = client(config['socket_path'], request('authorize_bootstrap', manifest_id=metadata['manifest_id']))
        check('ordinary reader and SIGTERM preserve exact restart bytes', recovered['authorization'] == authorization)
        sqlite_evidence['locks_after_restart_retry'] = sqlite_locks(config['database_path'])
        check('live SQLite locks held after restart retry', sqlite_evidence['locks_after_restart_retry'] == {'main_shared': 'BLOCKED', 'shm_dms': 'BLOCKED'})
        check('bootstrap signature has exact purpose and size', authorization['dsse']['payloadType'] == 'application/vnd.f.authority-bootstrap.v1+json' and len(base64.b64decode(authorization['dsse']['signatures'][0]['sig'])) == 64)
        check('bootstrap result preserves closed production gates', not authorized['status']['signing_allowed'] and not authorized['status']['dispatch_allowed'])
        signed_file = state / 'authorization.json'
        signed_file.write_bytes(canonical)
        os.chmod(signed_file, 0o600)
        os.chown(signed_file, SIGNER, SIGNER)
        verified = command([str(ROOT / 'protected_signer_fixture'), 'verify', str(state), str(signed_file)])
        check('independent public key verifies actual DSSE bytes', verified.returncode == 0 and json.loads(verified.stdout)['verified'])
        tampered = json.loads(canonical)
        tampered['dsse']['signatures'][0]['sig'] = base64.b64encode(bytes(64)).decode()
        signed_file.write_text(json.dumps(tampered))
        forged = command([str(ROOT / 'protected_signer_fixture'), 'verify', str(state), str(signed_file)])
        check('forged correctly sized bootstrap signature refused', forged.returncode != 0)
        retry = client(config['socket_path'], request('authorize_bootstrap', manifest_id=metadata['manifest_id']))
        check('lost output retry returns exact original signed authorization', retry['authorization'] == authorization)
        signer_chmod(seed, 0o644)
        rejected = client(config['socket_path'], request('status'))
        check('live key protection loss fails before next operation', rejected['code'] == 'SIGNER_KEY_REJECTED')
        signer_chmod(seed, 0o600)
        database = Path(config['database_path'])
        old_database = database.with_suffix('.old')
        database.rename(old_database)
        shutil.copyfile(old_database, database)
        os.chmod(database, 0o600)
        os.chown(database, SIGNER, SIGNER)
        rejected = client(config['socket_path'], request('status'))
        check('live backing database replacement refused', rejected['code'] == 'SIGNER_DATABASE_REJECTED')
        database.unlink()
        old_database.rename(database)
        check('restored exact backing database recovers', client(config['socket_path'], request('status'))['peer_identity_verified'])
        stop()
        start()
        restarted = client(config['socket_path'], request('authorize_bootstrap', manifest_id=metadata['manifest_id']))
        check('process restart preserves original signed authorization', restarted['authorization'] == authorization)
        stop()
        db = sqlite3.connect(config['database_path'])
        count = db.execute("SELECT count(*) FROM authority_registry_objects WHERE object_kind='bootstrap_authorization'").fetchone()[0]
        check('one durable bootstrap authorization after retries', count == 1)
        for table in ('authority_signing_results', 'authority_signing_outbox', 'authority_signing_quota_usage'):
            check('bootstrap creates no ' + table, db.execute('SELECT count(*) FROM ' + table).fetchone()[0] == 0)
        final_floor = db.execute('SELECT MAX(observed_at) FROM authority_registry_clocks').fetchone()[0]
        check('registry clock floor never decreases across restarts', final_floor >= durable_floor)
        sqlite_evidence['floor_after_final_stop'] = final_floor
        db.close()
        return {'schema_version': 'fw.protected-signer-smoke/v1', 'status': 'PASS', 'checks': len(checks),
                'check_names': checks, 'production_supported': False, 'packet_tests_executed': 0,
                'bootstrap_authorization_hash': 'sha256:' + hashlib.sha256(canonical).hexdigest(),
                'signer_uid': SIGNER, 'controller_uid': CONTROLLER, 'unauthorized_uid': OTHER,
                'actual_owner_proof': True, 'actual_ed25519_signature': True,
                'operator_cli_used': metadata['operator_cli_used'],
                'operator_commands_executed': metadata['operator_commands_executed'],
                'sqlite_durability': sqlite_evidence,
                'production_signing_allowed': False, 'production_dispatch_allowed': False}
    finally:
        stop()


if __name__ == '__main__':
    try:
        result = main()
    except BaseException as error:
        result = {'schema_version': 'fw.protected-signer-smoke/v1', 'status': 'FAIL', 'checks': len(checks),
                  'check_names': checks, 'production_supported': False,
                  'error': {'type': type(error).__name__, 'message': str(error)[:256]}}
    print(json.dumps(result))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)

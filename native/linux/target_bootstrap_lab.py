#!/usr/bin/env python3
"""Real, disposable nonloopback target bootstrap; no host network operations."""
import base64
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path('/lab')
SIGNER, CONTROLLER, PEER = 65531, 65532, 65533
CLONE_NEWNET, CLONE_NEWNS = 0x40000000, 0x00020000
checks = []
observations = {}
operator_operations = []
packets = 0
probe_attempts = 0
libc = ctypes.CDLL(None, use_errno=True)


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def write(path, value, uid=0, raw=False, mode=0o600):
    path.write_bytes(value if raw else canonical(value))
    os.chmod(path, mode)
    os.chown(path, uid, uid)


def child_identity(uid=0, namespace=None, target=False):
    def apply():
        if namespace is not None:
            fd = os.open('/proc/' + str(namespace) + '/ns/net', os.O_RDONLY)
            if libc.setns(fd, CLONE_NEWNET) != 0:
                raise OSError(ctypes.get_errno(), 'fixture setns failed')
            os.close(fd)
        last = int(Path('/proc/sys/kernel/cap_last_cap').read_text())
        for number in range(last + 1):
            if not target or number != 12:
                if libc.prctl(24, number, 0, 0, 0) != 0:
                    raise OSError(ctypes.get_errno(), 'fixture bounding drop failed')
        if target:
            class Header(ctypes.Structure):
                _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
            class Data(ctypes.Structure):
                _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
            header, data = Header(0x20080522, 0), (Data * 2)()
            data[0].effective = data[0].permitted = 4096
            if libc.capset(ctypes.byref(header), data) != 0:
                raise OSError(ctypes.get_errno(), 'fixture capability drop failed')
        elif uid:
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
        os.umask(0o077)
    return apply


def run(args, *, uid=0, namespace=None, target=False, body=None, timeout=20):
    process = subprocess.Popen(args, preexec_fn=child_identity(uid, namespace, target),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(body, timeout=timeout)
    except subprocess.TimeoutExpired:
        stop(process, uid)
        raise RuntimeError('bounded fixture operation timed out')
    return process.returncode, stdout, stderr


def stop(process, uid=0):
    if process.poll() is None:
        if uid:
            subprocess.run(['python3', '-c', 'import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGTERM)', str(process.pid)],
                           preexec_fn=child_identity(uid), capture_output=True, timeout=5)
        else:
            process.terminate()
    process.communicate(timeout=5)


def successful(args, **options):
    code, out, err = run(args, **options)
    if code:
        fixed = err.strip().decode('ascii', errors='replace')
        if not re.fullmatch(r'[A-Z0-9_=: .-]{1,160}', fixed):
            fixed = 'BOUNDED_FIXTURE_OPERATION_REJECTED'
        raise RuntimeError(f'fixture operation exit={code} code={fixed}')
    return out


def new_namespace(label, configure_conntrack=False):
    read, send = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        try:
            flags = CLONE_NEWNET | (CLONE_NEWNS if configure_conntrack else 0)
            if libc.unshare(flags) != 0:
                raise OSError(ctypes.get_errno(), 'fixture unshare failed')
            if configure_conntrack:
                libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
                libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
                if libc.mount(None, b'/', None, 16384 | 262144, None) != 0:
                    raise OSError(ctypes.get_errno(), 'private propagation refused')
                proc = ROOT / ('private-proc-' + label)
                proc.mkdir(mode=0o700)
                encoded = str(proc).encode()
                if libc.mount(b'proc', encoded, b'proc', 2 | 4 | 8, None) != 0:
                    raise OSError(ctypes.get_errno(), 'private proc mount refused')
                try:
                    current = os.readlink('/proc/self/ns/net')
                    with (proc / 'sys/net/netfilter/nf_conntrack_tcp_loose').open('w') as field:
                        field.write('0')
                    if (proc / 'sys/net/netfilter/nf_conntrack_tcp_loose').read_text().strip() != '0' or os.readlink('/proc/self/ns/net') != current:
                        raise RuntimeError('target namespace sysctl readback failed')
                finally:
                    if libc.umount2(encoded, 0) != 0:
                        raise OSError(ctypes.get_errno(), 'private proc unmount refused')
                proc.rmdir()
            os.write(send, b'READY')
            os.close(send)
            signal.pause()
        except BaseException:
            try:
                os.write(send, b'ERROR')
            except OSError:
                pass
        os._exit(0)
    os.close(send)
    result = os.read(read, 16)
    os.close(read)
    if result != b'READY':
        os.waitpid(pid, 0)
        raise RuntimeError('isolated namespace setup refused')
    return pid


def configure_link(target, peer):
    # These interfaces exist only in the container and its new child namespaces.
    for args in [ ['link', 'add', 'fwmgmt0', 'type', 'veth', 'peer', 'name', 'fwpeer0'],
                  ['link', 'set', 'fwmgmt0', 'netns', str(target)],
                  ['link', 'set', 'fwpeer0', 'netns', str(peer)]]:
        successful(['/usr/sbin/ip', *args], target=True)
    for pid, name, address in [(target, 'fwmgmt0', '192.0.2.1/30'), (peer, 'fwpeer0', '192.0.2.2/30')]:
        for args in [['link', 'set', name, 'addrgenmode', 'none'],
                     ['addr', 'add', address, 'dev', name], ['link', 'set', 'lo', 'up'],
                     ['link', 'set', name, 'up']]:
            successful(['/usr/sbin/ip', *args], namespace=pid, target=True)
        # This profile is IPv4-only; remove only automatically created IPv6
        # routes on this newly created fixture veth, never a host interface.
        successful(['/usr/sbin/ip', '-6', 'route', 'flush', 'table', 'all', 'dev', name], namespace=pid, target=True)
    for pid, name in ((target, 'fwmgmt0'), (peer, 'fwpeer0')):
        clean_fixture_ipv6_route(pid, name)
    return json.loads(successful(['/usr/sbin/ip', '-j', 'link', 'show', 'dev', 'fwmgmt0'], namespace=target))[0]['ifindex']


def clean_fixture_ipv6_route(namespace, name, phase="setup"):
    routes = json.loads(successful(['/usr/sbin/ip', '-j', '-6', 'route', 'show', 'table', 'all'], namespace=namespace, target=True))
    for route in routes:
        if route.get('dev') == name:
            if route.get('type') != 'multicast' or route.get('dst') != 'ff00::/8':
                raise RuntimeError('unexpected IPv6 route on newly created fixture interface')
            successful(['/usr/sbin/ip', '-6', 'route', 'del', 'multicast', 'ff00::/8', 'dev', name, 'table', 'local'], namespace=namespace, target=True)
    after = json.loads(successful(['/usr/sbin/ip', '-j', '-6', 'route', 'show', 'table', 'all'], namespace=namespace, target=True))
    check('IPv4-only fixture routes verified for ' + name + ' during ' + phase, all(route.get('dev') != name for route in after))


def admin(metadata, operation, value, expected=None):
    args = [str(ROOT / 'fw_authority_admin'), operation, '--database', metadata['database_path'],
            '--org-id', metadata['org_id'], '--project-id', metadata['project_id']]
    code, out, err = run(args, uid=SIGNER, body=canonical(value), timeout=30)
    operator_operations.append({'operation': operation, 'exit_code': code})
    if expected is not None:
        check(operation + ' refuses ' + expected, code == 1 and out == b'' and err == ('AUTHORITY_ADMIN code=' + expected + '\n').encode())
        return None
    if code or err:
        raise RuntimeError('trusted operator operation failed: ' + operation)
    return json.loads(out)


def signer_request(path, operation, **fields):
    payload = {'schema_version': 'fw.signer-request/v1', 'request_id': str(uuid.uuid4()),
               'operation': operation, **fields}
    code = r'''
import json,socket,struct,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(8);s.connect(sys.argv[1]);body=sys.stdin.buffer.read();s.sendall(struct.pack('>I',len(body))+body);s.shutdown(socket.SHUT_WR)
def take(n):
 data=b''
 while len(data)<n:
  chunk=s.recv(n-len(data))
  if not chunk:raise RuntimeError('partial signer response')
  data+=chunk
 return data
n=struct.unpack('>I',take(4))[0]
if n>524288:raise RuntimeError('bounded signer response')
sys.stdout.buffer.write(take(n));s.close()
'''
    return json.loads(successful(['python3', '-c', code, str(path)], uid=CONTROLLER, body=canonical(payload)))


def peer_control(namespace, baseline, challenge_hash, material, label):
    global packets, probe_attempts
    request = {'schema_version': 'fw.bootstrap-probe-request/v1', 'challenge_hash': challenge_hash,
               'kind': 'negative_udp', 'nonce': base64.b64encode(os.urandom(32)).decode()}
    code = 'import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(sys.stdin.buffer.read(),(sys.argv[1],int(sys.argv[2])));data,peer=s.recvfrom(4097);assert peer==(sys.argv[1],int(sys.argv[2]));assert len(data)<=4096 and data.endswith(b"\\n");sys.stdout.buffer.write(data[:-1]);s.close()'
    response = json.loads(successful(['python3', '-c', code, baseline['peer_address'], str(baseline['negative_udp_port'])],
                                     namespace=namespace, target=True, body=canonical(request) + b'\n'))
    packets += 1
    probe_attempts += 1
    req_path, resp_path = material / (label + '-request.json'), material / (label + '-response.json')
    write(req_path, request)
    write(resp_path, response)
    verified = json.loads(successful([str(ROOT / 'fw_target_bootstrap_peer'), 'verify',
                                     str(material / 'baseline.json'), str(req_path), str(resp_path)]))
    check(label + ' proves an actual signed negative-port listener', verified['verified'])
    return {'request_hash': digest(request), 'response_verified': True}


def target_call(config_path, bundle_path, target, outer, *, lose_output=False):
    args = [str(ROOT / 'fw_linux_executor'), 'bootstrap-target', '--config', str(config_path), '--bundle', str(bundle_path)]
    env = os.environ.copy()
    env['NOX_BOOTSTRAP_OUTER_NETNS'] = outer
    process = subprocess.Popen(args, preexec_fn=child_identity(namespace=target, target=True),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if lose_output:
        process.stdout.close()
        process.wait(timeout=30)
        stderr = process.stderr.read()
        last_line = stderr.splitlines()[-1].decode('ascii', errors='replace') if stderr.splitlines() else ''
        return {'exit_code': process.returncode, 'stderr_sha256': hashlib.sha256(stderr).hexdigest(),
                'final_fixed_code': last_line if re.fullmatch(r'[A-Z][A-Z0-9_]{2,95}', last_line) else None,
                'stderr_bytes': len(stderr), 'fixed_codes': re.findall(r'\b[A-Z][A-Z0-9_]{2,95}\b', stderr.decode('ascii', errors='replace'))[:8]}
    out, err = process.communicate(timeout=30)
    if process.returncode:
        observations['target_refusal'] = {'exit_code': process.returncode,
            'fixed_codes': re.findall(r'\b[A-Z][A-Z0-9_]{2,95}\b', err.decode('ascii', errors='replace'))[:8],
            'stderr_sha256': hashlib.sha256(err).hexdigest(), 'stderr_bytes': len(err)}
        # Preserve an ordinary independent socket observation if the new profile
        # reports local UDP denial. A failed send is never called a timeout.
        probe = 'import json,socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1)\ntry:\n n=s.sendto(b"bootstrap-denial-observation",(sys.argv[1],int(sys.argv[2])));print(json.dumps({"bytes_sent":n,"errno":None}))\nexcept OSError as e:print(json.dumps({"bytes_sent":0,"errno":e.errno}))\nfinally:s.close()'
        bundle = json.loads(bundle_path.read_text())
        observations['independent_negative_udp_send'] = json.loads(successful(
            ['python3', '-c', probe, bundle['baseline']['peer_address'], str(bundle['baseline']['negative_udp_port'])], namespace=target, target=True))
        retain_public_ruleset_after_refusal(target)
        raise RuntimeError('isolated target operation refused; fixed diagnostic retained')
    result = json.loads(out)
    check('target result has closed production flags ' + str(len(checks)), result['schema_version'] == 'fw.target-bootstrap-result/v1' and result['production_signing_allowed'] is False and result['dispatch_allowed'] is False)
    return result


def retain_public_ruleset_after_refusal(target):
    raw = successful(['/usr/sbin/nft', '-j', 'list', 'ruleset'], namespace=target, target=True)
    if len(raw) > 131072:
        raise RuntimeError('refused target public ruleset exceeds profile bound')
    observations['native_ruleset_after_refusal'] = json.loads(raw)


def record_probe_outcomes(receipt, label):
    """Count sent request cases separately from local send refusals."""
    global packets, probe_attempts
    probes = receipt['payload']['probes']
    check(label + ' has all three independent native probe kinds',
          len(probes) == 3 and {p['request']['kind'] for p in probes} ==
          {'management_tcp', 'positive_udp', 'negative_udp'})
    for probe in probes:
        if probe['request']['kind'] == 'negative_udp':
            denied = (probe['outcome'] == 'local_send_denied' and probe['os_error'] == 1
                      and probe['bytes_sent'] == 0)
            timeout = (probe['outcome'] == 'timeout' and probe['os_error'] is None
                       and probe['bytes_sent'] == len(canonical(probe['request'])) + 1)
            check(label + ' records exact denied UDP observation',
                  (denied or timeout) and probe['bytes_received'] == 0 and probe['response'] is None)
        else:
            check(label + ' receives authenticated ' + probe['request']['kind'] + ' response',
                  probe['outcome'] == 'reply' and probe['os_error'] is None
                  and probe['bytes_sent'] == len(canonical(probe['request'])) + 1
                  and probe['bytes_received'] > 0 and probe['response'] is not None)
    probe_attempts += len(probes)
    packets += sum(p['bytes_sent'] > 0 for p in probes)
    observations[label + '_probe_outcomes'] = [
        {'kind': p['request']['kind'], 'outcome': p['outcome'], 'os_error': p['os_error'],
         'bytes_sent': p['bytes_sent'], 'bytes_received': p['bytes_received']}
        for p in probes]


def retained_receipt(state, manifest):
    # Read only after the one-shot executor has exited.
    import sqlite3
    db = sqlite3.connect(state / 'bootstrap.sqlite3')
    try:
        head = db.execute('SELECT journal_id,epoch,highest_generation,state,confirmation_hash FROM bootstrap_identity').fetchone()
        row = db.execute('SELECT receipt_bytes FROM bootstrap_intents WHERE manifest_id=?', (manifest,)).fetchone()
        return {'journal_id': head[0], 'epoch': head[1], 'generation': head[2], 'state': head[3], 'hash': head[4]}, bytes(row[0]) if row and row[0] is not None else None
    finally:
        db.close()


def main():
    global packets, probe_attempts
    check('explicit disposable target marker', os.geteuid() == 0 and (ROOT / 'DISPOSABLE_TARGET_BOOTSTRAP_NAMESPACE').read_bytes() == b'fw-isolated-target-bootstrap-v1\n')
    os.chmod(ROOT, 0o755)
    target = peer = None
    signer = peer_server = None
    accepted = []
    try:
        outer = os.readlink('/proc/self/ns/net')
        outer_conntrack = Path('/proc/sys/net/netfilter/nf_conntrack_tcp_loose').read_text().strip()
        target = new_namespace('target', True)
        peer = new_namespace('peer')
        target_ns, peer_ns = [os.readlink('/proc/' + str(pid) + '/ns/net') for pid in (target, peer)]
        check('three genuinely distinct container network namespaces', len({outer, target_ns, peer_ns}) == 3)
        check('namespace-local sysctl leaves container parent unchanged', Path('/proc/sys/net/netfilter/nf_conntrack_tcp_loose').read_text().strip() == outer_conntrack)
        interface = configure_link(target, peer)
        observations['topology'] = {'outer': outer, 'target': target_ns, 'peer': peer_ns, 'interface': 'fwmgmt0', 'ifindex': interface,
                                    'private_proc_unmounted': True, 'target_conntrack_tcp_loose': 0}
        material, authority, authority_runtime, peer_state = [ROOT / name for name in ('target-material', 'authority', 'authority-runtime', 'peer')]
        for path, mode, uid in [(material, 0o700, 0), (authority, 0o700, SIGNER),
                                (authority_runtime, 0o711, SIGNER), (peer_state, 0o700, PEER)]:
            path.mkdir(mode=mode)
            os.chown(path, uid, uid)
        peer_seed, target_seed = peer_state / 'peer.seed', material / 'target.seed'
        write(peer_seed, os.urandom(32), PEER, raw=True)
        write(target_seed, os.urandom(32), raw=True)
        peer_key = json.loads(successful([str(ROOT / 'fw_target_bootstrap_peer'), 'public-key', str(peer_seed)], uid=PEER))['public_key']
        target_key = json.loads(successful([str(ROOT / 'fw_target_bootstrap_peer'), 'public-key', str(target_seed)]))['public_key']
        baseline = {'schema_version': 'fw.isolated-bootstrap-management-baseline/v1',
                    'org_id': '00000000-0000-4000-8000-000000000001',
                    'project_id': '00000000-0000-4000-8000-000000000002',
                    'target_id': '00000000-0000-4000-8000-000000000003',
                    'network_namespace': target_ns, 'interface_name': 'fwmgmt0', 'interface_index': interface,
                    'local_address': '192.0.2.1', 'peer_address': '192.0.2.2', 'prefix_length': 30,
                    'management_tcp_port': 19080, 'positive_udp_port': 19081, 'negative_udp_port': 19082,
                    'peer_probe_public_key': peer_key}
        capability = {'schema_version': 'fw.isolated-bootstrap-capability/v1', 'platform': 'linux', 'backend': 'nftables',
                      'profile': 'isolated-linux-bootstrap-v1', 'kernel_release': os.uname().release,
                      'architecture': os.uname().machine,
                      'nft_version': successful(['/usr/sbin/nft', '--version']).decode().strip()}
        write(material / 'baseline.json', baseline)
        write(peer_state / 'baseline.json', baseline, PEER)
        write(authority / 'evidence.json', {'baseline': baseline, 'capability': capability}, SIGNER)
        metadata = json.loads(successful([str(ROOT / 'protected_signer_fixture'), str(authority), '--admin', str(ROOT / 'fw_authority_admin'),
                                          '--target-evidence', str(authority / 'evidence.json')], uid=SIGNER, timeout=90))
        check('eighteen actual setup operator commands', metadata['operator_commands_executed'] == 18 and metadata['operator_cli_used'])
        check('real namespace baseline and capability bound before owner proof', metadata['target_evidence_bound'] and metadata['management_baseline_hash'] == digest(baseline) and metadata['capability_hash'] == digest(capability))
        root_pin = json.loads((authority / 'pin.json').read_text())
        check('peer target and bootstrap signing purposes use different keys', len({bytes(peer_key), bytes(target_key), bytes(root_pin['public_key'])}) == 3)
        signer_config = {'schema_version': 'fw.signer-config/v1', 'signer_uid': SIGNER, 'controller_uid': CONTROLLER,
                         'org_id': metadata['org_id'], 'project_id': metadata['project_id'], 'database_path': metadata['database_path'],
                         'key_file': metadata['seed_file'], 'key_id': metadata['key_id'], 'socket_path': str(authority_runtime / 'signer.sock'),
                         'webauthn_origin': metadata['webauthn_origin']}
        write(authority / 'signer.json', signer_config, SIGNER)
        signer = subprocess.Popen([str(ROOT / 'fw_signer'), '--config', str(authority / 'signer.json')],
                                  preexec_fn=child_identity(SIGNER), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while not Path(signer_config['socket_path']).exists() and signer.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        response = signer_request(signer_config['socket_path'], 'authorize_bootstrap', manifest_id=metadata['manifest_id'])
        check('actual protected signer authorizes retained owner-approved material', response['schema_version'] == 'fw.signer-bootstrap-outcome/v1' and not response['status']['signing_allowed'] and not response['status']['dispatch_allowed'])
        pin = {'schema_version': 'fw.target-bootstrap-key-pin/v1', 'org_id': metadata['org_id'], 'project_id': metadata['project_id'],
               'target_id': metadata['target_id'], 'key_id': 'isolated-target-receipt-key', 'revision': '1', 'public_key': target_key,
               'not_before': datetime.fromtimestamp(int(time.time()) - 5, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
               'not_after': datetime.fromtimestamp(int(time.time()) + 240, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
               'profile': 'isolated-linux-bootstrap-v1'}
        admin(metadata, 'pin-target-bootstrap-key', {'pin': pin, 'expected_revision': None})
        stale = admin(metadata, 'challenge-target-bootstrap', {'manifest_id': metadata['manifest_id'], 'expected_target_revision': None, 'baseline': baseline, 'capability': capability})
        bundle = admin(metadata, 'challenge-target-bootstrap', {'manifest_id': metadata['manifest_id'], 'expected_target_revision': None, 'baseline': baseline, 'capability': capability})
        check('actual challenge CLI retry returns identical retained bytes', canonical(stale) == canonical(bundle))
        # The authority issues one retained challenge per manifest. This is an
        # explicitly altered negative input, never another issued challenge or
        # an approval: change only its public nonce after asserting exact retry.
        nonce = bytearray(base64.b64decode(stale['challenge']['nonce'], validate=True))
        nonce[0] ^= 1
        stale['challenge']['nonce'] = base64.b64encode(nonce).decode()
        write(material / 'bundle.json', bundle)
        write(material / 'stale-bundle.json', stale)
        journal_parent = ROOT / 'target-journals'
        journal_parent.mkdir(mode=0o700)
        state = journal_parent / 'state'
        config = {'schema_version': 'fw.isolated-target-bootstrap-config/v1', 'org_id': metadata['org_id'], 'project_id': metadata['project_id'],
                  'target_id': metadata['target_id'], 'state_dir': str(state), 'bootstrap_trust': root_pin, 'target_key_pin': pin, 'seed_file': str(target_seed)}
        write(material / 'config.json', config)
        ready = peer_state / 'ready'
        peer_server = subprocess.Popen([str(ROOT / 'fw_target_bootstrap_peer'), 'serve', str(peer_state / 'baseline.json'), str(peer_seed), str(ready)],
                                       preexec_fn=child_identity(PEER, peer), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while not ready.exists() and peer_server.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        check('independent peer has all actual listeners before baseline', ready.exists() and peer_server.poll() is None)
        observations['negative_service_preflight'] = peer_control(target, baseline, digest(bundle['challenge']), material, 'before-initial-baseline')
        masks = json.loads(successful(['python3', '-c', 'import json;v=dict(x.split(":",1) for x in open("/proc/self/status") if ":" in x);print(json.dumps({k:int(v[k].strip(),16) for k in ["CapEff","CapPrm","CapBnd","CapInh","CapAmb"]}))'], namespace=target, target=True))
        check('target effective permitted and bounding caps are NET_ADMIN only', masks == {'CapEff': 4096, 'CapPrm': 4096, 'CapBnd': 4096, 'CapInh': 0, 'CapAmb': 0})
        observations['target_capabilities'] = masks
        check('new target state starts absent', not state.exists())
        clean_fixture_ipv6_route(target, 'fwmgmt0', 'before first commit')
        loss = target_call(material / 'config.json', material / 'bundle.json', target, outer, lose_output=True)
        observations['initial_output_disconnect'] = loss
        if not (state / 'bootstrap.sqlite3').exists():
            observations['target_refusal'] = loss
            raise RuntimeError('target refused before creating its separate journal')
        head, stored = retained_receipt(state, metadata['manifest_id'])
        observations['journal_after_first_stop'] = head
        if head['state'] != 'CONFIRMED' or stored is None:
            observations['target_refusal'] = loss
            code = 'import json,socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1)\ntry:\n n=s.sendto(b"bootstrap-denial-observation",(sys.argv[1],int(sys.argv[2])));print(json.dumps({"bytes_sent":n,"errno":None}))\nexcept OSError as e:print(json.dumps({"bytes_sent":0,"errno":e.errno}))\nfinally:s.close()'
            observations['independent_negative_udp_send'] = json.loads(successful(['python3', '-c', code, baseline['peer_address'], str(baseline['negative_udp_port'])], namespace=target, target=True))
            probe_attempts += 1
            packets += observations['independent_negative_udp_send']['bytes_sent'] > 0
            retain_public_ruleset_after_refusal(target)
        check('receipt durably committed before disconnected output', head['state'] == 'CONFIRMED' and stored is not None)
        check('lost stdout reports checked delivery failure after commit', loss['exit_code'] == 1 and loss['final_fixed_code'] == 'OUTPUT_FAILED')
        first = target_call(material / 'config.json', material / 'bundle.json', target, outer)
        receipt = first['confirmation']
        check('restart recovers exact original receipt bytes', first['replayed'] and canonical(receipt) == stored and digest(receipt) == head['hash'])
        check('accepted epoch one and generation zero are separate', first['accepted_epoch'] == '1' and first['current_epoch'] == '1' and first['highest_generation'] == '0' and first['current_journal_state'] == 'CONFIRMED')
        record_probe_outcomes(receipt, 'initial')
        forged = json.loads(canonical(receipt))
        forged['dsse']['signatures'][0]['sig'] = base64.b64encode(bytes(64)).decode()
        admin(metadata, 'import-target-bootstrap-confirmation', forged, expected='TARGET_BOOTSTRAP_CONFIRMATION_REJECTED')
        before = admin(metadata, 'read-target-bootstrap-status', {'target_id': metadata['target_id']})
        check('forged signature cannot create target head', before['status'] is None)
        initial = admin(metadata, 'import-target-bootstrap-confirmation', receipt)
        check('real peer and native receipt accepted as epoch one', initial['accepted_epoch'] == '1' and initial['highest_generation'] == '0' and initial['current_confirmation_eligibility'] and not initial['signing_allowed'] and not initial['dispatch_allowed'])
        accepted.append(receipt)
        observations['initial_confirmation_hash'] = digest(receipt)
        # Rotation continues below once the normal fresh-owner helper is ready.
        return complete_rotation(metadata, config, material, baseline, capability, target, peer, outer, signer_config, accepted)
    finally:
        if signer is not None:
            stop(signer, SIGNER)
        if peer_server is not None:
            stop(peer_server, PEER)
        for pid in (target, peer):
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)


def expected_target_refusal(config, bundle, target, outer, label, expected):
    env = os.environ.copy()
    env['NOX_BOOTSTRAP_OUTER_NETNS'] = outer
    process = subprocess.Popen([str(ROOT / 'fw_linux_executor'), 'bootstrap-target', '--config', str(config), '--bundle', str(bundle)],
                               preexec_fn=child_identity(namespace=target, target=True), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    out, err = process.communicate(timeout=30)
    codes = re.findall(r'\b[A-Z][A-Z0-9_]{2,95}\b', err.decode('ascii', errors='replace'))
    final = err.splitlines()[-1].decode('ascii', errors='replace') if err.splitlines() else ''
    observations.setdefault('expected_target_refusals', []).append({
        'check': label, 'exit_code': process.returncode, 'stdout_bytes': len(out),
        'stderr_sha256': hashlib.sha256(err).hexdigest(), 'stderr_bytes': len(err),
        'fixed_codes': codes[:8],
        'final_fixed_code': final if re.fullmatch(r'[A-Z][A-Z0-9_]{2,95}', final) else None})
    check(label, process.returncode == 1 and out == b'' and final == expected)


def complete_rotation(metadata, config, material, baseline, capability, target, peer, outer, signer_config, accepted):
    first = accepted[0]
    write(material / 'previous-confirmation.json', first)
    write(Path(metadata['database_path']).parent / 'target-previous-confirmation.json', first, SIGNER)
    write(Path(metadata['database_path']).parent / 'target-public-pin.json', config['target_key_pin'], SIGNER)
    before_rules = successful(['/usr/sbin/nft', '-j', 'list', 'ruleset'], namespace=target, target=True)
    before_head, before_receipt = retained_receipt(Path(config['state_dir']), metadata['manifest_id'])
    expected_target_refusal(material / 'config.json', material / 'stale-bundle.json', target, outer,
                            'altered challenge nonce cannot replace retained material', 'BOOTSTRAP_EXACT_RETRY_CONFLICT')
    check('altered challenge nonce cannot mutate the actual native baseline', before_rules == successful(['/usr/sbin/nft', '-j', 'list', 'ruleset'], namespace=target, target=True))
    after_head, after_receipt = retained_receipt(Path(config['state_dir']), metadata['manifest_id'])
    check('altered challenge nonce preserves durable epoch and exact receipt',
          before_head == after_head and before_receipt == after_receipt == canonical(first))
    authority = Path(metadata['database_path']).parent
    rotation_baseline = {**baseline, 'positive_udp_port': baseline['negative_udp_port'], 'negative_udp_port': baseline['positive_udp_port']}
    write(authority / 'rotation-evidence.json', {'baseline': rotation_baseline, 'capability': capability}, SIGNER)
    observations['baseline_hashes'] = {'initial': digest(baseline), 'rotation': digest(rotation_baseline)}
    check('rotation approves a materially different management baseline', digest(baseline) != digest(rotation_baseline))
    rotation = json.loads(successful([str(ROOT / 'protected_signer_fixture'), 'prepare-rotation', str(authority),
                                      '--admin', str(ROOT / 'fw_authority_admin'), '--target-evidence', str(authority / 'rotation-evidence.json'),
                                      '--previous-confirmation', str(authority / 'target-previous-confirmation.json'),
                                      '--target-key-pin', str(authority / 'target-public-pin.json')], uid=SIGNER, timeout=90))
    check('rotation uses a fresh owner ceremony at counter three', rotation['old_epoch'] == '1' and rotation['new_epoch'] == '2' and rotation['owner_assertion_counter'] == 3)
    observations['rotation_approval_window'] = {
        'created_at': rotation['created_at'], 'expires_at': rotation['expires_at'],
        'owner_assertion_counter': rotation['owner_assertion_counter']}
    rotation_commands = rotation['operator_commands_executed']
    response = signer_request(signer_config['socket_path'], 'authorize_bootstrap', manifest_id=rotation['manifest_id'])
    check('independent signer authorizes fresh rotation material', response['schema_version'] == 'fw.signer-bootstrap-outcome/v1')
    write(authority / 'public-rotation-authorization.json', response['authorization'], SIGNER)
    verified = json.loads(successful([str(ROOT / 'protected_signer_fixture'), 'verify-rotation', str(authority), str(authority / 'public-rotation-authorization.json')], uid=SIGNER))
    check('rotation bootstrap signature verifies independently', verified['verified'])
    bundle = admin(metadata, 'challenge-target-bootstrap', {'manifest_id': rotation['manifest_id'],
                   'expected_target_revision': rotation['expected_target_revision'], 'baseline': rotation_baseline, 'capability': capability})
    check('new target challenge binds the actually accepted predecessor', bundle['challenge']['old_epoch'] == '1' and bundle['challenge']['new_epoch'] == '2' and bundle['challenge']['previous_confirmation_hash'] == digest(first))
    write(material / 'rotation-bundle.json', bundle)
    rotated = target_call(material / 'config.json', material / 'rotation-bundle.json', target, outer)
    second = rotated['confirmation']
    check('same journal performs real generation-zero epoch rotation', not rotated['replayed'] and rotated['accepted_epoch'] == '2' and rotated['current_epoch'] == '2' and rotated['highest_generation'] == '0' and second['payload']['journal_id'] == first['payload']['journal_id'])
    record_probe_outcomes(second, 'rotation')
    admitted = admin(metadata, 'import-target-bootstrap-confirmation', second)
    check('authority accepts native epoch two without opening production gates', admitted['accepted_epoch'] == '2' and admitted['confirmation_revision'] == '2' and admitted['current_confirmation_eligibility'] and not admitted['signing_allowed'] and not admitted['dispatch_allowed'])
    accepted.append(second)
    observations['rotation_confirmation_hash'] = digest(second)
    write(material / 'baseline.json', rotation_baseline)
    observations['negative_service_peer_control'] = peer_control(peer, rotation_baseline, digest(bundle['challenge']), material, 'peer-local-after-rotation')
    replayed = admin(metadata, 'import-target-bootstrap-confirmation', second)
    check('exact accepted receipt retry preserves revision two', replayed['replayed'] and replayed['confirmation_revision'] == '2' and replayed['confirmation_hash'] == digest(second))
    admin(metadata, 'challenge-target-bootstrap', {'manifest_id': metadata['manifest_id'], 'expected_target_revision': '2',
          'baseline': rotation_baseline, 'capability': capability}, expected='TARGET_BOOTSTRAP_CHALLENGE_REJECTED')
    current = admin(metadata, 'read-target-bootstrap-status', {'target_id': metadata['target_id']})['status']
    check('old authorized genesis cannot reset an accepted target epoch', current['accepted_epoch'] == '2' and current['confirmation_hash'] == digest(second))
    rotation_rules = successful(['/usr/sbin/nft', '-j', 'list', 'ruleset'], namespace=target, target=True)
    old_replay = target_call(material / 'config.json', material / 'bundle.json', target, outer)
    check('historical target retry separates accepted and current epochs', old_replay['replayed'] and old_replay['accepted_epoch'] == '1' and old_replay['current_epoch'] == '2' and old_replay['highest_generation'] == '0')
    check('historical retry never reapplies the superseded UDP policy', rotation_rules == successful(['/usr/sbin/nft', '-j', 'list', 'ruleset'], namespace=target, target=True))
    check('bootstrap never creates an ordinary grant journal', not (Path(config['state_dir']) / 'journal.sqlite3').exists())
    deadline = int(datetime.fromisoformat(bundle['challenge']['expires_at'].replace('Z', '+00:00')).timestamp())
    if deadline - time.time() > 180:
        raise RuntimeError('bounded target key lifetime did not constrain expiry scenario')
    wait_started = time.monotonic()
    while time.time() < deadline + .1:
        time.sleep(max(0, min(.1, deadline + .1 - time.time())))
    expired = admin(metadata, 'read-target-bootstrap-status', {'target_id': metadata['target_id']})['status']
    check('actual expiry retains accepted history without current eligibility', expired['accepted_epoch'] == '2' and expired['confirmation_hash'] == digest(second) and not expired['current_confirmation_eligibility'] and not expired['signing_allowed'] and not expired['dispatch_allowed'])
    historical = target_call(material / 'config.json', material / 'rotation-bundle.json', target, outer)
    check('expired exact target retry is history without renewed challenge', historical['replayed'] and not historical['challenge_unexpired'] and historical['accepted_epoch'] == '2' and historical['current_epoch'] == '2' and digest(historical['confirmation']) == digest(second))
    observations['expiry'] = {'deadline_unix': deadline, 'observed_unix': time.time(),
                              'actual_wait_seconds': round(time.monotonic() - wait_started, 3),
                              'accepted_epoch': expired['accepted_epoch'],
                              'current_confirmation_eligibility': expired['current_confirmation_eligibility']}
    target_commands = len(operator_operations) + rotation_commands
    return {'schema_version': 'fw.target-bootstrap-linux-lab/v1', 'status': 'PASS', 'checks': len(checks), 'check_names': checks,
            'packet_tests_executed': packets, 'probe_tests_executed': probe_attempts, 'setup_operator_commands_executed': 18,
            'target_operator_commands_executed': target_commands, 'operator_commands_executed': 18 + target_commands,
            'target_confirmations_accepted': len(accepted), 'negative_service_preflight_verified': True,
            'production_supported': False, 'production_signing_allowed': False, 'production_dispatch_allowed': False, 'dispatch_allowed': False,
            'host_firewall_changed': False, 'observations': observations,
            'operator_operations': operator_operations,
            'qualification': 'Synthetic owner and pinned peer/target keys in a disposable Linux profile; no production build/native qualification, workload attestation, policy signer or dispatch authority.'}


if __name__ == '__main__':
    try:
        result = main()
    except BaseException as error:
        result = {'schema_version': 'fw.target-bootstrap-linux-lab/v1', 'status': 'FAIL', 'checks': len(checks), 'check_names': checks,
                  'packet_tests_executed': packets, 'probe_tests_executed': probe_attempts,
                  'production_supported': False, 'production_signing_allowed': False, 'production_dispatch_allowed': False, 'dispatch_allowed': False,
                  'host_firewall_changed': False, 'observations': observations,
                  'error': {'type': type(error).__name__, 'message': str(error)[:256]}}
    print(json.dumps(result))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)

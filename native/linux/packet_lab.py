#!/usr/bin/env python3
"""Actual loopback packet fixtures, exclusively inside a disposable lab container.

Called only by scripts/linux-lab.py after Docker namespace/capability isolation.
No host paths, networking, privileged container, or production policies are used.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import uuid

ORG = '11111111-1111-4111-8111-111111111111'
PROJECT = '22222222-2222-4222-8222-222222222222'
TARGET = '33333333-3333-4333-8333-333333333333'
COMPILER = '/lab/fw_compile_lab'
checks = []
artifacts = []
temporal_readbacks = []
listeners = []
started_at_unix_ms = int(time.time()*1000)


def run(argv, payload=None):
    result = subprocess.run(argv, input=payload, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(json.dumps({'argv': argv, 'exit_code': result.returncode,
                                       'stdout': result.stdout, 'stderr': result.stderr}))
    return result.stdout


def nft(commands):
    return run(['nft', '-j', '-f', '-'], json.dumps({'nftables': commands}))


def check(name, passed, **evidence):
    checks.append({'id': name, 'status': 'PASS' if passed else 'FAIL', 'observed_at_unix_ms':int(time.time()*1000), **evidence})
    if not passed:
        raise AssertionError(name)


def iso(timestamp):
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def policy(number, family, protocol, direction, expiry, action='allow', port=None):
    address = '127.0.0.1/32' if family == 'ipv4' else '::1/128'
    now = int(time.time())
    return {
        'schema_version': 'f.policy/v1', 'policy_id': f'00000000-0000-4000-8000-{number:012}',
        'policy_revision': 1, 'org_id': ORG, 'project_id': PROJECT, 'target_id': TARGET,
        'owner_id': '44444444-4444-4444-8444-444444444444', 'reason': 'isolated loopback packet fixture',
        'scope': {'family': family, 'direction': direction,
                  'source_asset_ids': ['55555555-5555-4555-8555-555555555555'],
                  'destination_asset_ids': ['66666666-6666-4666-8666-666666666666'],
                  'source_cidrs': [address], 'destination_cidrs': [address],
                  'transport': {'protocol': protocol, 'destination_ports': [{'start': port or (18080 if protocol == 'tcp' else 18081), 'end': port or (18080 if protocol == 'tcp' else 18081)}]},
                  'ingress_interfaces': ['lo'] if direction == 'input' else [],
                  'egress_interfaces': ['lo'] if direction == 'output' else []},
        'log_mode': 'none', 'action': action,
        'lifetime': {'kind': 'lease', 'not_before': iso(now-30), 'expires_at': iso(expiry)} if action == 'allow'
                    else {'kind': 'review', 'not_before': iso(now-30), 'review_at': iso(now-10)},
    }


def allow_set(expiry, start=1):
    policies = []
    for family in ['ipv4', 'ipv6']:
        for protocol in ['tcp', 'udp']:
            for direction in ['input', 'output']:
                policies.append(policy(start+len(policies), family, protocol, direction, expiry))
    return policies


def apply(policies, previous_table=None):
    request = {'context': {'org_id': ORG, 'project_id': PROJECT, 'target_id': TARGET,
                          'now_unix': int(time.time()), 'clock_uncertainty_seconds': 0,
                          'elapsed_seconds': 0, 'commit_budget_seconds': 1}, 'policies': policies}
    raw = run([COMPILER], json.dumps(request))
    artifact = json.loads(raw)
    commands = artifact['nft_json']['nftables']
    if previous_table:
        assert previous_table == artifact['table']
        commands = [{'delete': {'table': {'family': 'inet', 'name': previous_table}}}] + commands
    payload = json.dumps({'nftables': commands})
    run(['nft', '-j', '-c', '-f', '-'], payload)
    run(['nft', '-j', '-f', '-'], payload)
    readback = json.loads(run(['nft', '-j', 'list', 'table', 'inet', artifact['table']]))
    chains = [item['chain'] for item in readback['nftables'] if 'chain' in item]
    expected_sets = {item['add']['set']['name']:item['add']['set'] for item in artifact['nft_json']['nftables'] if 'set' in item.get('add',{})}
    actual_sets = {item['set']['name']:item['set'] for item in readback['nftables'] if 'set' in item}
    timer_binding = expected_sets.keys() == actual_sets.keys()
    for name, expected in expected_sets.items():
        entry = actual_sets[name].get('elem', [{}])[0].get('elem', {})
        expected_entry = expected['elem'][0]['elem']
        timer_binding = timer_binding and entry.get('val') == expected_entry['val'] and entry.get('timeout') == expected_entry['timeout'] and 0 < entry.get('expires', 0) <= entry.get('timeout', 0)
    check(f'native_timer_units_{len(artifacts)+1}', timer_binding, timeout_unit='seconds', set_count=len(expected_sets))
    expected_rules = sum('rule' in item.get('add', {}) for item in artifact['nft_json']['nftables'])
    actual_rules = sum('rule' in item for item in readback['nftables'])
    check(f'native_apply_readback_{len(artifacts)+1}', len(chains) == 2 and all(c['policy'] == 'drop' for c in chains) and expected_rules == actual_rules,
          rule_count=actual_rules, table=artifact['table'])
    artifacts.append({'input': request, 'artifact': artifact, 'artifact_sha256': hashlib.sha256(raw.encode()).hexdigest(), 'readback': readback})
    return artifact['table']


def tcp_worker(connection):
    with connection:
        connection.settimeout(20)
        try:
            while data := connection.recv(4096):
                connection.sendall(data)
        except (OSError, TimeoutError):
            pass


def start_server(family, protocol, port):
    af = socket.AF_INET if family == 'ipv4' else socket.AF_INET6
    sock = socket.socket(af, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if af == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind(('127.0.0.1' if family == 'ipv4' else '::1', port))
    listeners.append(sock)
    if protocol == 'tcp':
        sock.listen(16)
    def serve():
        while True:
            try:
                if protocol == 'tcp':
                    connection, _ = sock.accept()
                    threading.Thread(target=tcp_worker, args=(connection,), daemon=True).start()
                else:
                    data, peer = sock.recvfrom(4096)
                    sock.sendto(data, peer)
            except OSError:
                return
    threading.Thread(target=serve, daemon=True).start()


def connection(family, protocol, port=None):
    sock = socket.socket(socket.AF_INET if family == 'ipv4' else socket.AF_INET6,
                         socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    try:
        sock.connect(('127.0.0.1' if family == 'ipv4' else '::1', port or (18080 if protocol == 'tcp' else 18081)))
        return sock
    except BaseException:
        sock.close()
        raise


def exchange(sock):
    marker = uuid.uuid4().bytes
    try:
        sock.sendall(marker)
        return sock.recv(4096) == marker
    except (OSError, TimeoutError):
        return False


def probe(name, family, protocol, expected, port=None):
    try:
        with connection(family, protocol, port) as sock:
            reached = exchange(sock)
    except (OSError, TimeoutError):
        reached = False
    check(name, reached == expected, kind='packet', family=family, protocol=protocol,
          expected_delivery=expected, observed_delivery=reached)


def wait_until(timestamp):
    while time.time() < timestamp:
        time.sleep(min(0.2, timestamp-time.time()))


def main():
    assert Path('/lab/DISPOSABLE_NETWORK_NAMESPACE').read_text() == 'nox-linux-loopback-lab-v1\n'
    outer_namespace = os.environ['NOX_LAB_OUTER_NETNS']
    namespace = os.readlink('/proc/self/ns/net')
    check('distinct_network_namespace', namespace != outer_namespace, outer=outer_namespace, inner=namespace)
    cap = next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
    check('namespace_capabilities', int(cap, 16) == 1 << 12, effective_capabilities=cap)
    interfaces = json.loads(run(['ip', '-j', 'address']))
    check('network_isolated', [entry['ifname'] for entry in interfaces] == ['lo'], interfaces=interfaces)
    loose = Path('/proc/sys/net/netfilter/nf_conntrack_tcp_loose').read_text().strip()
    check('strict_conntrack', loose == '0', nf_conntrack_tcp_loose=loose)
    nft([{'add': {'table': {'family': 'inet', 'name': 'nox_lab_unrelated'}}},
         {'add': {'counter': {'family': 'inet', 'table': 'nox_lab_unrelated', 'name': 'keep'}}}])
    unrelated_before = json.loads(run(['nft', '-j', 'list', 'table', 'inet', 'nox_lab_unrelated']))
    pairs = [(f,p) for f in ['ipv4','ipv6'] for p in ['tcp','udp']]
    for family, protocol in pairs:
        for port in [18080 if protocol == 'tcp' else 18081, 18082 if protocol == 'tcp' else 18083]:
            start_server(family, protocol, port)
            probe(f'baseline_{family}_{protocol}_{port}', family, protocol, True, port)
    allows = allow_set(int(time.time())+120)
    table = apply(allows)
    for family, protocol in pairs:
        probe(f'allowed_{family}_{protocol}', family, protocol, True)
        probe(f'default_deny_{family}_{protocol}', family, protocol, False, 18082 if protocol == 'tcp' else 18083)
    with connection('ipv4','tcp') as established:
        check('before_deny_existing_tcp', exchange(established), kind='packet', expected_delivery=True)
        deny = policy(90, 'ipv4', 'tcp', 'input', 0, action='deny')
        table = apply(allows+[deny], table)
        check('deny_existing_tcp_review_deadline_passed', not exchange(established), kind='packet', expected_delivery=False)
        probe('deny_new_tcp', 'ipv4', 'tcp', False)
        probe('deny_does_not_block_udp', 'ipv4', 'udp', True)
    # Two independent leases authorize each same tuple. Expiring A must not drop B.
    now = int(time.time())
    first_expiry, final_expiry = now+4, now+10
    table = apply(allow_set(first_expiry,100)+allow_set(final_expiry,200), table)
    persistent = [(f,p,connection(f,p)) for f,p in pairs]
    try:
        for family, protocol, sock in persistent:
            check(f'before_expiry_{family}_{protocol}', exchange(sock), kind='packet', expected_delivery=True)
        wait_until(first_expiry+0.2)
        partial = json.loads(run(['nft', '-j', 'list', 'table', 'inet', table]))
        temporal_readbacks.append({'stage':'first_lease_expired','observed_at_unix_ms':int(time.time()*1000),'readback':partial})
        partial_sets = [entry['set'] for entry in partial['nftables'] if 'set' in entry]
        check('first_lease_tokens_expired_second_lease_tokens_live', len(partial_sets)==16 and sum(bool(entry.get('elem')) for entry in partial_sets)==8, set_count=len(partial_sets))
        for family, protocol, sock in persistent:
            check(f'overlap_survives_{family}_{protocol}', exchange(sock), kind='packet', expected_delivery=True)
        wait_until(final_expiry+0.2)
        for family, protocol, sock in persistent:
            check(f'existing_expired_{family}_{protocol}', not exchange(sock), kind='packet', expected_delivery=False)
        expired_readback = json.loads(run(['nft', '-j', 'list', 'table', 'inet', table]))
        temporal_readbacks.append({'stage':'all_leases_expired','observed_at_unix_ms':int(time.time()*1000),'readback':expired_readback})
        sets = [entry['set'] for entry in expired_readback['nftables'] if 'set' in entry]
        check('kernel_timeout_tokens_expired_without_refresh', bool(sets) and all(not entry.get('elem') for entry in sets), set_count=len(sets))
        for family, protocol in pairs:
            probe(f'new_expired_{family}_{protocol}', family, protocol, False)
    finally:
        for _,_,sock in persistent:
            sock.close()
    unrelated_after = json.loads(run(['nft', '-j', 'list', 'table', 'inet', 'nox_lab_unrelated']))
    check('unrelated_table_preserved', unrelated_before == unrelated_after)
    nft([{'delete': {'table': {'family': 'inet', 'name': table}}}])
    for family, protocol in pairs:
        probe(f'owned_table_removed_{family}_{protocol}', family, protocol, True)


if __name__ == '__main__':
    error = None
    try:
        main()
    except BaseException as exc:
        error = {'type': type(exc).__name__, 'message': str(exc)}
    finally:
        for sock in listeners:
            sock.close()
    sysctls = {}
    for name in ['nf_conntrack_tcp_loose','nf_conntrack_tcp_be_liberal','nf_conntrack_checksum']:
        path = Path('/proc/sys/net/netfilter')/name
        sysctls[name] = path.read_text().strip() if path.exists() else None
    result = {'schema_version':'fw.linux-loopback-smoke/v1','status':'PASS' if error is None else 'FAIL',
              'qualification':'isolated-loopback-smoke-only','production_supported':False,
              'packet_tests_executed':sum(c.get('kind')=='packet' for c in checks),
              'passed':sum(c['status']=='PASS' for c in checks),'failed':sum(c['status']=='FAIL' for c in checks),
              'checks':checks,'error':error,'artifacts':artifacts,'temporal_readbacks':temporal_readbacks,'kernel':os.uname().release,
              'nft_version':run(['nft','--version']).strip(),'sysctls':sysctls,
              'started_at_unix_ms':started_at_unix_ms,'finished_at_unix_ms':int(time.time()*1000),
              'packages':Path('/lab-package-versions.txt').read_text().splitlines(),
              'limitations':['No physical NIC or routed topology','No ICMP/PMTU/fragment qualification',
                             'No production signing, enrollment, native service/watchdog or installer qualification',
                             'Readback records structure and packet behavior; complete semantic attestation remains unimplemented']}
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if error is None else 1)

#!/usr/bin/env python3
"""Real signed-executor lifecycle and packets inside an isolated lab only.

All signing identities and approval objects are synthetic test fixtures. No
production controller, native qualification, or human approval is asserted.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import threading
import time

DRIVER = '/lab/fw_linux_executor'
FIXTURE = '/lab/fw_signed_lab_fixture'
checks = []
packet_count = 0
resources = []
last_failure = None


def check(name, passed, **evidence):
    checks.append({'id': name, 'status': 'PASS' if passed else 'FAIL', **evidence})
    if not passed:
        raise AssertionError(name)


def command(arguments, *, payload=None, expected=0, decode=True, environment=None):
    global last_failure
    result = subprocess.run(arguments, input=payload, text=True, capture_output=True, timeout=20, env=environment)
    if result.returncode != expected:
        last_failure = {'program': Path(arguments[0]).name, 'exit_code': result.returncode}
        error_codes = [line for line in result.stderr.splitlines() if re.fullmatch(r'[A-Z][A-Z0-9_]{0,80}', line)]
        if error_codes:
            last_failure['reason_codes'] = error_codes[-4:]
        raise AssertionError('unexpected subprocess result: ' + Path(arguments[0]).name)
    if expected != 0:
        return None
    return json.loads(result.stdout) if decode else result.stdout


def private_json(path, value):
    with open(path, 'x') as output:
        os.chmod(path, 0o600)
        json.dump(value, output, separators=(',', ':'))


def nft(arguments, payload=None):
    return command(['/usr/sbin/nft', '-j', *arguments], payload=payload, decode=False)


def snapshot(table):
    return json.loads(nft(['list', 'table', 'inet', table]))


def remaining_tokens(table):
    values = {}
    for item in snapshot(table)['nftables']:
        entry = item.get('set')
        if not entry:
            continue
        for member in entry.get('elem', []):
            token = member.get('elem', {})
            if 'expires' in token:
                values[entry['name']] = token['expires']
    return values


class EchoServers:
    def __init__(self):
        self.stop = threading.Event()
        self.listeners = []
        self.connections = []
        for family in (socket.AF_INET, socket.AF_INET6):
            address = '127.0.0.1' if family == socket.AF_INET else '::1'
            for protocol, port in (('tcp', 18080), ('udp', 18081), ('tcp', 18082)):
                listener = socket.socket(family, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((address, port))
                listener.settimeout(.1)
                self.listeners.append(listener)
                if protocol == 'tcp':
                    listener.listen(16)
                    threading.Thread(target=self.tcp, args=(listener,), daemon=True).start()
                else:
                    threading.Thread(target=self.udp, args=(listener,), daemon=True).start()

    def tcp(self, listener):
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
                connection.settimeout(.1)
                self.connections.append(connection)
                threading.Thread(target=self.echo, args=(connection,), daemon=True).start()
            except socket.timeout:
                pass
            except OSError:
                return

    def echo(self, connection):
        while not self.stop.is_set():
            try:
                value = connection.recv(256)
                if not value:
                    return
                connection.sendall(value)
            except socket.timeout:
                pass
            except OSError:
                return

    def udp(self, listener):
        while not self.stop.is_set():
            try:
                value, address = listener.recvfrom(256)
                listener.sendto(value, address)
            except socket.timeout:
                pass
            except OSError:
                return

    def close(self):
        self.stop.set()
        for connection in self.connections + self.listeners:
            connection.close()


def probe(family, protocol, port, expected, name, existing=None):
    global packet_count
    address = '127.0.0.1' if family == socket.AF_INET else '::1'
    connection = existing or socket.socket(family, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
    connection.settimeout(.35)
    nonce = os.urandom(16)
    replied = False
    try:
        if existing is None:
            connection.connect((address, port))
        connection.sendall(nonce)
        replied = connection.recv(256) == nonce
    except (socket.timeout, ConnectionError, OSError):
        replied = False
    packet_count += 1
    check(name, replied == expected, kind='packet', expected_reply=expected, actual_reply=replied)
    if existing is None:
        connection.close()


def session(family, protocol):
    connection = socket.socket(family, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
    connection.settimeout(.35)
    connection.connect(('127.0.0.1' if family == socket.AF_INET else '::1', 18080 if protocol == 'tcp' else 18081))
    resources.append(connection)
    return connection


def driver(case, action, *, extra=(), expected=0):
    args = [DRIVER, action, '--state-dir', str(case['directory'] / 'state'), '--trust', str(case['directory'] / 'trust.json')]
    if action in ('init', 'apply'):
        args += ['--bundle', str(case.get('bundle', case['directory'] / 'bundle.json'))]
    else:
        args += ['--operation-id', case['metadata']['operation_id']]
    return command([*args, *extra], expected=expected)


def prepare(name, mode):
    directory = Path('/lab') / name
    metadata = command([FIXTURE, 'prepare', str(directory), mode])
    if not re.fullmatch(r'fw_[0-9a-f]{24}', metadata['table']):
        raise AssertionError('fixture table identity')
    bootstrap = json.loads((directory / 'bootstrap.json').read_text())
    nft(['-f', '-'], json.dumps(bootstrap))
    case = {'directory': directory, 'metadata': metadata}
    initialized = driver(case, 'init')
    check(name + '_real_default_deny_bootstrap', initialized.get('initialized') is True
          and initialized['highest_generation'] == '0' and initialized['production_authorized'] is False)
    return case


def remove_table(case):
    # Fixture teardown removes only the exact table created in this private lab.
    nft(['delete', 'table', 'inet', case['metadata']['table']])


def wait_until(timestamp):
    remaining = timestamp - time.time()
    if remaining > 50:
        raise AssertionError('fixture bounded wait')
    if remaining > 0:
        time.sleep(remaining + .2)


def state(result):
    return result['operation']['state']


def confirmed_flow():
    global packet_count
    case = prepare('confirmed', 'confirmed')
    path = case['directory']
    original = json.loads((path / 'bundle.json').read_text())
    before = snapshot(case['metadata']['table'])
    unsafe_environment = dict(os.environ, NOX_LAB_OUTER_NETNS=os.readlink('/proc/self/ns/net'))
    command([DRIVER, 'apply', '--state-dir', str(path / 'state'), '--bundle', str(path / 'bundle.json'),
             '--trust', str(path / 'trust.json')], expected=1, environment=unsafe_environment)
    check('same_outer_namespace_refused_without_native_write', snapshot(case['metadata']['table']) == before)
    # Failure paths must leave the existing deny baseline and generation intact.
    for label, mutate in [('bad_signature', lambda value: value['grant']['dsse']['signatures'][0].update(sig='A' * 88)),
                          ('altered_artifact', lambda value: value['candidate']['nft_template']['nftables'].append({'flush': {'ruleset': None}}))]:
        value = copy.deepcopy(original)
        mutate(value)
        bad = path / (label + '.json')
        private_json(bad, value)
        args = [DRIVER, 'apply', '--state-dir', str(path / 'state'), '--bundle', str(bad), '--trust', str(path / 'trust.json')]
        command(args, expected=1)
        check(label + '_cannot_write', snapshot(case['metadata']['table']) == before)
    wrong = path / 'wrong-target.json'
    command([FIXTURE, 'forge', str(path), 'wrong-target', str(wrong)])
    command([DRIVER, 'apply', '--state-dir', str(path / 'state'), '--bundle', str(wrong), '--trust', str(path / 'trust.json')], expected=1)
    check('valid_signature_wrong_target_cannot_write', snapshot(case['metadata']['table']) == before)
    applied = driver(case, 'apply')
    check('signed_apply_requires_actual_readback', state(applied) == 'VERIFYING' and applied['highest_generation'] == '1'
          and applied['production_authorized'] is False)
    prior_tokens = remaining_tokens(case['metadata']['table'])
    check('actual_kernel_contains_expiring_tokens', len(prior_tokens) == 8)
    time.sleep(1.1)
    replay = driver(case, 'apply')
    after_tokens = remaining_tokens(case['metadata']['table'])
    check('same_grant_retry_does_not_refresh_tokens', state(replay) == 'VERIFYING' and after_tokens.keys() == prior_tokens.keys()
          and all(after_tokens[key] <= prior_tokens[key] for key in prior_tokens)
          and any(after_tokens[key] < prior_tokens[key] for key in prior_tokens))
    reopened = driver(case, 'observe')
    check('same_boot_reopen_observes_without_reinstall', state(reopened) == 'VERIFYING'
          and all(value <= after_tokens[key] for key, value in remaining_tokens(case['metadata']['table']).items()))
    probe_path = path / 'probes.json'
    driver(case, 'probe', extra=['--output', str(probe_path)])
    report = json.loads(probe_path.read_text())
    packet_count += len(report['observations'])
    check('driver_collects_real_positive_and_negative_probes', len(report['observations']) == 6
          and report['production_management_probe'] is False)
    confirmation = path / 'confirmation.json'
    command([FIXTURE, 'confirm', str(path), str(probe_path), str(confirmation)])
    forged = json.loads(confirmation.read_text())
    forged['probes']['observations'][0]['nonce'] = 'forged-proof'
    forged_path = path / 'forged-confirmation.json'
    private_json(forged_path, forged)
    command([DRIVER, 'confirm', '--state-dir', str(path / 'state'), '--operation-id', case['metadata']['operation_id'],
             '--trust', str(path / 'trust.json'), '--confirmation', str(forged_path)], expected=1)
    check('confirmation_cannot_substitute_probe_evidence', state(driver(case, 'observe')) == 'VERIFYING')
    # Even valid signatures cannot turn a failed positive probe into evidence.
    failed_report = copy.deepcopy(report)
    failed_report['observations'][0]['outcome'] = 'timeout'
    failed_report['observations'][0]['bytes_received'] = 0
    failed_probe = path / 'failed-probes.json'
    private_json(failed_probe, failed_report)
    local_probe = path / 'state' / ('probe-' + case['metadata']['operation_id'] + '.json')
    original_local_bytes = local_probe.read_bytes()
    failed_confirmation = path / 'failed-confirmation.json'
    command([FIXTURE, 'confirm', str(path), str(failed_probe), str(failed_confirmation)])
    try:
        local_probe.write_text(json.dumps(failed_report, separators=(',', ':')))
        driver(case, 'confirm', extra=['--confirmation', str(failed_confirmation)], expected=1)
        check('signed_failed_probe_cannot_confirm', state(driver(case, 'observe')) == 'VERIFYING')
    finally:
        local_probe.write_bytes(original_local_bytes)
    confirmed = driver(case, 'confirm', extra=['--confirmation', str(confirmation)])
    check('signed_confirm_after_actual_probes', state(confirmed) == 'CONFIRMED' and confirmed['highest_generation'] == '1')
    old = path / 'old-generation.json'
    command([FIXTURE, 'forge', str(path), 'old-generation', str(old)])
    command([DRIVER, 'apply', '--state-dir', str(path / 'state'), '--bundle', str(old), '--trust', str(path / 'trust.json')], expected=1)
    check('older_signed_generation_rejected', state(driver(case, 'observe')) == 'CONFIRMED')
    sessions = [(family, protocol, session(family, protocol)) for family in (socket.AF_INET, socket.AF_INET6) for protocol in ('tcp', 'udp')]
    for family, protocol, connection in sessions:
        probe(family, protocol, 18080 if protocol == 'tcp' else 18081, True,
              f'established_{family}_{protocol}_before_expiry', connection)
    # No controller or agent process is needed to expire kernel tokens. The
    # confirmed watcher exits; only the test's echo servers remain here.
    wait_until(case['metadata']['expires_at_unix'] + 1)
    for family, protocol, connection in sessions:
        probe(family, protocol, 18080 if protocol == 'tcp' else 18081, False,
              f'established_{family}_{protocol}_expires_without_controller', connection)
        connection.close()
    for family in (socket.AF_INET, socket.AF_INET6):
        for protocol, port in [('tcp', 18080), ('udp', 18081)]:
            probe(family, protocol, port, False, f'new_{family}_{protocol}_blocked_after_expiry')
    check('expired_observation_does_not_recreate_tokens', state(driver(case, 'observe')) == 'CONFIRMED'
          and not remaining_tokens(case['metadata']['table']))
    remove_table(case)


def crash_flow():
    case = prepare('crash', 'crash')
    driver(case, 'apply', extra=['--crash-after-commit'], expected=-signal.SIGKILL)
    observation = driver(case, 'observe')
    check('process_death_after_native_write_recovers_actual_state', state(observation) == 'VERIFYING'
          and observation['highest_generation'] == '1')
    probe(socket.AF_INET, 'tcp', 18080, True, 'candidate_installed_before_crash_recovery')
    wait_until(case['metadata']['confirm_not_after_unix'] + 1)
    # A different process uses the same durable fence; the original process is
    # dead. This is not proof of recovery through a permanently held lock.
    recovered = driver(case, 'recover')
    check('separate_process_recovers_unconfirmed_candidate', state(recovered) == 'ROLLED_BACK'
          and recovered['highest_generation'] == '1')
    for family in (socket.AF_INET, socket.AF_INET6):
        for protocol, port in [('tcp', 18080), ('udp', 18081), ('tcp', 18082)]:
            probe(family, protocol, port, False, f'recovery_{family}_{protocol}_{port}_blocks')
    readback = snapshot(case['metadata']['table'])
    comments = [item['rule'].get('comment', '') for item in readback['nftables'] if 'rule' in item]
    check('restrictive_recovery_preserves_explicit_denies', sum(comment.startswith('deny:') for comment in comments) >= 4
          and not remaining_tokens(case['metadata']['table']))
    again = driver(case, 'recover')
    check('recovery_retry_keeps_high_water_and_observed_projection', state(again) == 'ROLLED_BACK'
          and again['highest_generation'] == '1' and snapshot(case['metadata']['table']) == readback)
    replay = driver(case, 'apply')
    check('expired_grant_retry_is_historical_without_reinstall', state(replay) == 'ROLLED_BACK'
          and replay['highest_generation'] == '1' and snapshot(case['metadata']['table']) == readback)
    # A fresh independent authorization advances generation from the observed
    # restrictive recovery state. Stale recovery must not roll this state back.
    next_metadata = command([FIXTURE, 'successor', str(case['directory'])])
    successor = {'directory': case['directory'], 'metadata': next_metadata,
                 'bundle': case['directory'] / 'bundle-next.json'}
    second = driver(successor, 'apply')
    check('new_generation_applies_from_observed_recovery', state(second) == 'VERIFYING'
          and second['highest_generation'] == '2')
    next_probes = case['directory'] / 'probes-next.json'
    driver(successor, 'probe', extra=['--output', str(next_probes)])
    global packet_count
    packet_count += len(json.loads(next_probes.read_text())['observations'])
    next_confirmation = case['directory'] / 'confirmation-next.json'
    command([FIXTURE, 'confirm-next', str(case['directory']), str(next_probes), str(next_confirmation)])
    check('second_generation_confirmed', state(driver(successor, 'confirm', extra=['--confirmation', str(next_confirmation)])) == 'CONFIRMED')
    prior = snapshot(case['metadata']['table'])
    prior_tokens = remaining_tokens(case['metadata']['table'])
    driver(case, 'recover', expected=1)
    driver(case, 'apply', expected=1)
    current = driver(successor, 'observe')
    current_snapshot = snapshot(case['metadata']['table'])
    rules = lambda value: [entry for entry in value['nftables'] if 'rule' in entry or 'chain' in entry]
    check('old_recovery_and_replay_cannot_mutate_new_generation', current['highest_generation'] == '2'
          and state(current) == 'CONFIRMED' and rules(prior) == rules(current_snapshot)
          and all(value <= prior_tokens[key] for key, value in remaining_tokens(case['metadata']['table']).items()))
    remove_table(case)


def recovery_write_crash_flow():
    case = prepare('recovery-write-crash', 'timeout')
    check('recovery_write_fixture_applied', state(driver(case, 'apply')) == 'VERIFYING')
    directory = case['directory']
    operation = case['metadata']['operation_id']
    ack = json.loads((directory / 'state' / ('ack-' + operation + '.json')).read_text())
    request = json.loads((directory / 'state' / ('watch-' + operation + '.json')).read_text())
    pid = ack['process_id']
    descriptor = os.pidfd_open(pid, 0)
    try:
        expected_command = [DRIVER, 'watch', '--state-dir', str(directory / 'state'),
                            '--operation-id', operation, '--trust', str(directory / 'trust.json')]
        actual_command = Path('/proc/' + str(pid) + '/cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
        verified = (ack['operation_id'] == operation and ack['material_hash'] == request['material_hash']
                    and ack['nonce'] == request['nonce'] and ack['network_namespace'] == os.readlink('/proc/self/ns/net')
                    and os.readlink('/proc/' + str(pid) + '/exe') == DRIVER and actual_command == expected_command)
        check('fault_injection_identifies_only_this_fixture_watcher', verified)
        # pidfd pins the verified private-container process across PID reuse.
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    finally:
        os.close(descriptor)
    wait_until(case['metadata']['confirm_not_after_unix'] + 1)
    driver(case, 'recover', extra=['--crash-after-recovery-write'], expected=-signal.SIGKILL)
    written = snapshot(case['metadata']['table'])
    probe(socket.AF_INET, 'tcp', 18080, False, 'recovery_write_survives_writer_death')
    resumed = driver(case, 'recover')
    check('recovery_writer_crash_resumes_by_observation_without_reinstall', state(resumed) == 'ROLLED_BACK'
          and resumed['highest_generation'] == '1' and snapshot(case['metadata']['table']) == written)
    remove_table(case)


def expired_recovery_flow():
    case = prepare('expired-authority', 'expired-recovery')
    driver(case, 'apply', extra=['--crash-after-commit'], expected=-signal.SIGKILL)
    wait_until(case['metadata']['recovery_valid_until_unix'] + 1)
    before = snapshot(case['metadata']['table'])
    driver(case, 'recover', expected=1)
    after = snapshot(case['metadata']['table'])
    # Handles and immutable rule expressions identify absence of a native rewrite;
    # elapsed timeout counters are allowed to decrease between these snapshots.
    def rules(value):
        return [entry for entry in value['nftables'] if 'rule' in entry or 'chain' in entry]
    check('expired_recovery_authority_never_causes_unsigned_write', rules(after) == rules(before))
    wait_until(case['metadata']['expires_at_unix'] + 1)
    probe(socket.AF_INET, 'tcp', 18080, False, 'kernel_expiry_survives_expired_recovery_authority')
    remove_table(case)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=('all', 'crash', 'recovery-write-crash'), default='all')
    args = parser.parse_args()
    farm = None
    report = {'schema_version': 'fw.signed-linux-lab/v1', 'status': 'FAIL', 'checks': checks,
              'production_supported': False, 'synthetic_fixture_authority': True,
              'synthetic_confirmation_authority': True, 'human_approval_tested': False,
              'host_firewall_changed': False, 'independent_hung_owner_watchdog_tested': False, 'scenario_selection': args.scenario}
    try:
        marker = Path('/lab/DISPOSABLE_NETWORK_NAMESPACE').read_text()
        namespace = os.readlink('/proc/self/ns/net')
        outer = os.environ.get('NOX_LAB_OUTER_NETNS')
        check('disposable_isolated_namespace', marker == 'nox-linux-loopback-lab-v1\n'
              and outer is not None and namespace != outer)
        links = json.loads(command(['/usr/sbin/ip', '-j', 'link'], decode=False))
        check('only_loopback_interface', [link['ifname'] for link in links] == ['lo'])
        command(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], decode=False)
        farm = EchoServers()
        for family in (socket.AF_INET, socket.AF_INET6):
            probe(family, 'tcp', 18082, True, f'negative_probe_server_{family}_reachable_before_firewall')
        if args.scenario == 'all':
            confirmed_flow()
        if args.scenario in ('all', 'crash'):
            crash_flow()
        if args.scenario in ('all', 'recovery-write-crash'):
            recovery_write_crash_flow()
        if args.scenario == 'all':
            expired_recovery_flow()
        report['status'] = 'PASS'
    except BaseException as error:
        report['error'] = {'type': type(error).__name__}
        if isinstance(error, AssertionError):
            report['error']['check'] = str(error)
        if last_failure:
            report['error']['subprocess'] = last_failure
    finally:
        for resource in resources:
            resource.close()
        if farm:
            farm.close()
        report['count'] = len(checks)
        report['packet_tests_executed'] = packet_count
        report['network_namespace'] = os.readlink('/proc/self/ns/net')
        print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

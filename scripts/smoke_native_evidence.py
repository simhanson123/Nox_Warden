#!/usr/bin/env python3
"""Verify independent compilation and real isolated Linux observation evidence.

Authority inputs are synthetic test trust. Only the disposable Docker namespace
receives native writes; the collector itself reads the actual kernel and signs
its exact capture. No result qualifies production enforcement or policy dispatch.
"""
import argparse
import copy
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'nox-linux-loopback-lab:local'
BASE_IMAGE = 'debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3'


class StageFailure(RuntimeError):
    pass


def collector_diagnostic(stderr):
    """Separate one known leading loader warning; preserve every other byte."""
    lines = stderr.splitlines(keepends=True)
    if lines and re.fullmatch(r"/lab/fw_linux_executor: /lib/(?:x86_64-linux-gnu/)?libc\.so\.6: weak version `GLIBC_2\.39' not found \(required by /lab/fw_linux_executor\)\n", lines[0]):
        return ''.join(lines[1:]), True
    return stderr, False


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(data)


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/native-evidence-smoke.json')
    parser.add_argument('--skip-image-build', action='store_true')
    args = parser.parse_args()
    environment = os.environ.copy()
    for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        environment.pop(name, None)
    docker = ['docker', '--host=unix:///var/run/docker.sock']
    container = None
    checks = []
    capture_count = 0
    report = {'schema_version': 'fw.native-evidence-smoke/v1', 'status': 'NOT_RUN',
              'production_qualified': False, 'dispatch_allowed': False,
              'synthetic_fixture_authority': True, 'host_firewall_changed': False,
              'credential_values_recorded': False, 'packet_tests_executed': 0,
              'environment_warnings': [], 'checks': checks}
    stage = 'setup'
    code = 2
    last_failure = None

    def check(name, condition):
        nonlocal stage
        stage = name
        checks.append({'name': name, 'passed': bool(condition)})
        if not condition:
            raise StageFailure(name)

    def run(command, label, data=None, expected=0, error=None, timeout=120):
        nonlocal stage, last_failure
        stage = label
        result = subprocess.run(command, cwd=ROOT, env=environment, input=data,
                                capture_output=True, timeout=timeout)
        if result.returncode != expected or (expected and (result.stdout or result.stderr != (error + '\n').encode())):
            allowed = {'OBSERVER_KEY_REJECTED', 'NATIVE_EVIDENCE_SCOPE', 'NATIVE_EVIDENCE_CHALLENGE',
                       'NATIVE_CAPTURE_CLOCK', 'PRIVATE_FILE_ALREADY_EXISTS', 'PRIVATE_FILE_JSON',
                       'PRIVATE_FILE_PERMISSIONS_OR_SIZE', 'ISOLATED_LAB_REQUIRED', 'OUTER_NAMESPACE_REFUSED', 'IO_ERROR', 'IO', 'COMPILE',
                       'CONTRACT', 'PRIVATE_PATH_OUTSIDE_LAB', 'PRIVATE_PATH_TRAVERSAL', 'PRIVATE_PATH_SYMLINK',
                       'PRIVATE_DIRECTORY_PERMISSIONS', 'PRIVATE_FILE_SIZE', 'PRIVATE_FILE_CANONICAL',
                       'NATIVE_EVIDENCE_REJECTED', 'ARTIFACT_REJECTED', 'PRIVATE_OR_NATIVE_IO', 'SIGNATURE_OR_BINDING_REJECTED'}
            diagnostic = result.stderr.decode('ascii', errors='ignore').strip()
            last_failure = {'exit_code': result.returncode, 'stdout_present': bool(result.stdout),
                            'fixed_code': diagnostic if diagnostic in allowed else None}
            raise StageFailure(label)
        return result.stdout

    def inside(command, label, **kwargs):
        nonlocal last_failure, stage
        if kwargs.get('expected', 0):
            expected = kwargs.pop('expected')
            error = kwargs.pop('error')
            # Docker may append its own diagnostics when an exec process fails.
            # Capture the child's result inside the namespace so a strict fixed
            # application diagnostic is still required, independently of Docker.
            script = ('import json,subprocess,sys; '
                      'r=subprocess.run(sys.argv[1:],input=sys.stdin.buffer.read(),capture_output=True,timeout=20); '
                      'print(json.dumps({"exit":r.returncode,"stdout":r.stdout.decode("utf-8","replace"),'
                      '"stderr":r.stderr.decode("utf-8","replace")}))')
            result = json.loads(run(docker + ['exec', '-i', container, 'python3', '-c', script, *command],
                                    label, **kwargs))
            # A host-built Rust binary can emit this known optional-symbol
            # warning with the older pinned lab image. Record it separately;
            # application errors, extra lines and panics remain exact failures.
            result['stderr'], warning_seen = collector_diagnostic(result['stderr'])
            if warning_seen:
                warning = 'host_binary_optional_glibc_2_39_symbol_unavailable_in_lab_image'
                if warning not in report['environment_warnings']:
                    report['environment_warnings'].append(warning)
            if result['exit'] != expected or result['stdout'] or result['stderr'] != error + '\n':
                stage = label
                last_failure = {'exit_code': result['exit'], 'stdout_present': bool(result['stdout']),
                                'fixed_code': error if result['stderr'] == error + '\n' else None}
                raise StageFailure(label)
            return b''
        return run(docker + ['exec', '-i', container, *command], label, **kwargs)

    def transfer(name, data, executable=False):
        script = ('import os,sys; p="/lab/"+sys.argv[1]; '
                  'fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,int(sys.argv[2],8)); '
                  'f=os.fdopen(fd,"wb");f.write(sys.stdin.buffer.read());f.close()')
        inside(['python3', '-c', script, name, '0700' if executable else '0600'],
               'private fixture transfer', data=data)

    try:
        run(docker + ['info', '--format', '{{.ServerVersion}}'], 'docker readiness')
        run(['cargo', 'build', '--locked', '--offline', '-p', 'fw_linux_executor', '-p', 'fw_testlab',
             '--bin', 'fw_linux_executor', '--bin', 'fw_signed_lab_fixture'], 'native binary build', timeout=300)
        run(['cargo', 'build', '--locked', '--offline', '-p', 'fw_authority', '--bin', 'fw_authority_admin',
             '--example', 'native_evidence_fixture'], 'authority binary build', timeout=300)
        if not args.skip_image_build:
            run(docker + ['build', '--secret', 'id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt',
                          '-f', str(ROOT / 'native/linux/Dockerfile.lab'), '-t', IMAGE,
                          str(ROOT / 'native/linux')], 'pinned image build', timeout=300)
        image_id = run(docker + ['image', 'inspect', '--format', '{{.Id}}', IMAGE], 'image identity').decode().strip()
        outer_namespace = os.readlink('/proc/self/ns/net')
        container = run(docker + ['run', '-d', '--name', 'nox-native-evidence-' + uuid.uuid4().hex[:12],
                                 '--network', 'none', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                                 '--security-opt', 'no-new-privileges',
                                 '--sysctl', 'net.netfilter.nf_conntrack_tcp_loose=0', '--env', 'TZ=UTC',
                                 '--env', 'NOX_LAB_OUTER_NETNS=' + outer_namespace,
                                 '--read-only', '--tmpfs', '/lab:rw,exec,nosuid,nodev,size=256m,mode=0700',
                                 '--pids-limit', '128', '--memory', '512m', '--cpus', '1', IMAGE],
                        'isolated container').decode().strip()
        if len(container) != 64 or any(c not in '0123456789abcdef' for c in container):
            raise StageFailure('container identity')
        code = 1
        transfer('DISPOSABLE_NETWORK_NAMESPACE', b'nox-linux-loopback-lab-v1\n')
        for name in ('fw_linux_executor', 'fw_signed_lab_fixture'):
            transfer(name, (ROOT / 'target/debug' / name).read_bytes(), executable=True)
        inside(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], 'isolated loopback')
        namespace = inside(['readlink', '/proc/self/ns/net'], 'namespace identity').decode().strip()
        check('collector runs in a separate network namespace', namespace != outer_namespace)
        inside(['/lab/fw_signed_lab_fixture', 'prepare', '/lab/native-fixture', 'confirmed'], 'native fixture prepare')
        bootstrap = inside(['cat', '/lab/native-fixture/bootstrap.json'], 'native bootstrap bytes')
        inside(['/usr/sbin/nft', '-j', '-f', '-'], 'isolated restrictive bootstrap', data=bootstrap)
        initialized = json.loads(inside(['/lab/fw_linux_executor', 'init', '--state-dir', '/lab/executor-state',
                                        '--bundle', '/lab/native-fixture/bundle.json', '--trust', '/lab/native-fixture/trust.json'],
                                       'native baseline verification'))
        check('actual native baseline matches guarded fixture', initialized.get('initialized') is True
              and initialized.get('production_authorized') is False)
        bundle = inside(['cat', '/lab/native-fixture/bundle.json'], 'public native fixture bundle')
        with tempfile.TemporaryDirectory(prefix='nox-native-evidence-') as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            private_write(directory / 'bundle.json', bundle)
            fixture = directory / 'fixture'
            helper = str(ROOT / 'target/debug/examples/native_evidence_fixture')
            run([helper, 'prepare', str(fixture), str(directory / 'bundle.json')], 'review fixture prepare')
            info = json.loads((fixture / 'fixture.json').read_bytes())
            database = directory / 'authority.sqlite3'
            admin_binary = str(ROOT / 'target/debug/fw_authority_admin')

            def admin(operation, value=None, error=None, project=None):
                command = [admin_binary, operation, '--database', str(database)]
                if operation != 'init':
                    command += ['--org-id', info['org_id'], '--project-id', project or info['project_id']]
                output = run(command, 'authority ' + operation, data=encoded(value or {}),
                             expected=1 if error else 0,
                             error='AUTHORITY_ADMIN code=' + error if error else None)
                return None if error else json.loads(output)

            def fixture_json(name):
                return json.loads((fixture / name).read_bytes())

            check('explicit authority initialization grants no dispatch', admin('init')['dispatch_allowed'] is False)
            check('namespace initialization grants no dispatch', admin('init-project')['dispatch_allowed'] is False)
            check('explicit independent transport pin', admin('pin-target', fixture_json('target-pin.json'))['key_revision'] == '1')
            metadata_challenge = admin('challenge-target', {'target_id': info['target_id']})
            private_write(fixture / 'metadata-challenge.json', encoded(metadata_challenge))
            run([helper, 'sign-metadata', str(fixture), str(fixture / 'metadata-challenge.json'),
                 str(fixture / 'metadata-proof.json')], 'fixture metadata signature')
            metadata = admin('admit-target', fixture_json('metadata-proof.json'))
            check('real metadata signature admitted without authority', metadata['replayed'] is False
                  and metadata['dispatch_allowed'] is False)
            check('reviewed plan registered without approval', admin('register-reviewed-plan', fixture_json('reviewed-plan.json'))['dispatch_allowed'] is False)
            check('native references require an explicit pin', admin('pin-native-references', fixture_json('reference-pin.json'))['reference_revision'] == '1')
            check('observer purpose key independently pinned', admin('pin-native-observer', fixture_json('observer-pin.json'))['observer_revision'] == '1')
            compilation = admin('compile-native', {'plan_id': info['plan_id'], 'expected_reference_revision': '1'})
            receipt = compilation['receipt']
            check('authority independently reconstructs native candidate', receipt['candidate_artifact_hash'] == fixture_json('reviewed-plan.json')['plan']['artifact_hash']
                  and compilation['dispatch_allowed'] is False)
            check('device report and lab capability hashes remain distinct', receipt['metadata_report_hash'] != fixture_json('reviewed-plan.json')['plan']['target_capability_hash'])
            repeated = admin('compile-native', {'plan_id': info['plan_id'], 'expected_reference_revision': '1'})
            check('exact compilation retry retains receipt', repeated['receipt'] == receipt)
            for name in ('artifact.json', 'installation.json', 'observer-key.json'):
                transfer(name, (fixture / name).read_bytes())
            installation = fixture_json('installation.json')

            def challenge(head):
                return admin('challenge-native', {'plan_id': info['plan_id'], 'artifact_role': 'baseline',
                             'installation': installation, 'expected_head': head, 'authority_epoch': '1', 'generation': '1'})

            def collect(ch, name, key='observer-key.json', error=None):
                nonlocal capture_count
                transfer(name + '-challenge.json', encoded(ch))
                command = ['/lab/fw_linux_executor', 'collect-evidence', '--artifact', '/lab/artifact.json',
                           '--installation', '/lab/installation.json', '--observer-key', '/lab/' + key,
                           '--challenge', '/lab/' + name + '-challenge.json', '--output', '/lab/' + name + '-proof.json']
                inside(command, 'actual native collection', expected=1 if error else 0, error=error)
                if error:
                    return None
                capture_count += 1
                return json.loads(inside(['cat', '/lab/' + name + '-proof.json'], 'public signed native proof'))

            first_challenge = challenge(None)
            wrong_key = fixture_json('observer-key.json')
            wrong_key['observer_revision'] = '2'
            transfer('wrong-observer-key.json', encoded(wrong_key))
            collect(first_challenge, 'wrong-key', 'wrong-observer-key.json', 'OBSERVER_KEY_REJECTED')
            check('collector rejects stale observer key revision', True)
            wrong_scope = copy.deepcopy(first_challenge)
            wrong_scope['target_id'] = '99999999-9999-4999-8999-999999999999'
            collect(wrong_scope, 'wrong-scope', error='NATIVE_EVIDENCE_SCOPE')
            check('collector rejects substituted target scope', True)
            first_proof = collect(first_challenge, 'match')
            existing_output_command = ['/lab/fw_linux_executor', 'collect-evidence', '--artifact', '/lab/artifact.json',
                                       '--installation', '/lab/installation.json', '--observer-key', '/lab/observer-key.json',
                                       '--challenge', '/lab/match-challenge.json', '--output', '/lab/match-proof.json']
            inside(existing_output_command, 'existing native proof refusal', expected=1, error='PRIVATE_FILE_ALREADY_EXISTS')
            unchanged = json.loads(inside(['cat', '/lab/match-proof.json'], 'retained native proof'))
            check('collector refuses to overwrite the original proof', unchanged == first_proof)
            inside(existing_output_command + ['--readback', '/lab/artifact.json'], 'caller readback refusal', expected=1, error='ARGUMENT')
            check('collector cannot accept caller supplied readback bytes', True)
            tampered = copy.deepcopy(first_proof)
            tampered['signature'] = ('A' if tampered['signature'][0] != 'A' else 'B') + tampered['signature'][1:]
            admin('admit-native', tampered, error='NATIVE_OBSERVATION_REJECTED')
            check('tampered real signature is refused', True)
            check('failed proof leaves observation head empty', admin('read-native', {'plan_id': info['plan_id']})['observation_head_hash'] is None)
            first = admin('admit-native', first_proof)
            check('actual kernel readback independently matches', first['receipt']['comparison'] == 'match'
                  and first['receipt']['observed_state_hash'] == fixture_json('artifact.json')['desired_state_hash'])
            check('authenticated capture remains a lab claim', first['receipt']['signature_valid'] is True
                  and first['receipt']['provenance'] == 'signed_lab_observer_claim'
                  and first['receipt']['production_qualified'] is False and first['dispatch_allowed'] is False)
            replay = admin('admit-native', first_proof)
            check('exact observation retry cannot renew receipt', replay['replayed'] is True and replay['receipt'] == first['receipt'])
            current = admin('read-native', {'plan_id': info['plan_id']})
            check('separate process reopens current verified evidence', current['observation']['current'] is True
                  and current['observation_head_hash'] == first['receipt_hash'])
            admin('challenge-native', {'plan_id': info['plan_id'], 'artifact_role': 'baseline',
                  'installation': installation, 'expected_head': None, 'authority_epoch': '1', 'generation': '1'}, error='NATIVE_CHALLENGE_REJECTED')
            check('stale observation head cannot issue a new challenge', True)
            admin('admit-native', first_proof, error='NATIVE_OBSERVATION_REJECTED', project='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
            check('another project cannot replay observation evidence', True)

            # Mutate only the disposable fixture table. Capture is still obtained
            # by the native collector, never fabricated from Python JSON.
            table = info['table']
            inside(['/usr/sbin/nft', 'flush', 'table', 'inet', table], 'isolated rule removal')
            mismatch = admin('admit-native', collect(challenge(first['receipt_hash']), 'mismatch'))
            check('actual rule drift is retained as mismatch', mismatch['receipt']['comparison'] == 'mismatch'
                  and mismatch['receipt']['observed_state_hash'] is None)
            check('current mismatch does not fall back to older match', admin('read-native', {'plan_id': info['plan_id']})['observation']['observed_state_hash'] is None)
            chain = next(entry['add']['chain']['name'] for entry in json.loads(bootstrap)['nftables']
                         if entry.get('add', {}).get('chain', {}).get('hook') == 'input')
            inside(['/usr/sbin/nft', 'add', 'rule', 'inet', table, chain, 'limit', 'rate', '1/second', 'accept'],
                   'isolated unsupported expression')
            unknown = admin('admit-native', collect(challenge(mismatch['receipt_hash']), 'unknown'))
            check('actual unsupported expression remains UNKNOWN', unknown['receipt']['comparison'] == 'unknown'
                  and unknown['receipt']['observed_state_hash'] is None and unknown['receipt']['signature_valid'] is True)
            restore = {'nftables': [{'delete': {'table': {'family': 'inet', 'name': table}}}, *json.loads(bootstrap)['nftables']]}
            inside(['/usr/sbin/nft', '-j', '-f', '-'], 'isolated fixture restore', data=encoded(restore))
            restored = admin('admit-native', collect(challenge(unknown['receipt_hash']), 'restored'))
            check('fresh actual restore produces a new matching receipt', restored['receipt']['comparison'] == 'match'
                  and restored['receipt_hash'] != first['receipt_hash'])
            pending = collect(challenge(restored['receipt_hash']), 'pending-revocation')
            revoked = admin('revoke-native-observer', {'target_id': info['target_id'], 'expected_revision': '1'})
            check('observer revocation grants no dispatch', revoked['dispatch_allowed'] is False)
            admin('admit-native', pending, error='NATIVE_OBSERVATION_REJECTED')
            check('observer revocation rejects a genuine pending signature', True)
            stale = admin('read-native', {'plan_id': info['plan_id']})
            check('revocation removes current observation eligibility', stale['observation']['current'] is False)
            historical = admin('admit-native', first_proof)
            check('historical exact retry remains historical after revocation', historical['replayed'] is True
                  and historical['receipt'] == first['receipt'] and historical['dispatch_allowed'] is False)
            admin('revoke-native-references', {'target_id': info['target_id'], 'expected_revision': '1'})
            check('reference revocation removes current compilation eligibility', admin('read-native', {'plan_id': info['plan_id']})['compilation']['current'] is False)

        paths = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'rust-toolchain.toml',
                 ROOT / 'native/linux/Dockerfile.lab', Path(__file__).resolve(),
                 ROOT / 'target/debug/fw_authority_admin', ROOT / 'target/debug/fw_linux_executor',
                 ROOT / 'target/debug/fw_signed_lab_fixture', ROOT / 'target/debug/examples/native_evidence_fixture']
        for crate in ('fw_authority', 'fw_native_evidence', 'fw_target_evidence', 'fw_backend_linux',
                      'fw_linux_executor', 'fw_testlab', 'fw_executor', 'fw_planner', 'fw_domain', 'fw_contracts'):
            paths += [ROOT / 'crates' / crate / 'Cargo.toml']
            paths += sorted((ROOT / 'crates' / crate / 'src').rglob('*.rs'))
        paths += [ROOT / 'crates/fw_authority/examples/native_evidence_fixture.rs']
        report.update(status='PASS', image_id=image_id, base_image=BASE_IMAGE,
                      commit=run(['git', 'rev-parse', 'HEAD'], 'source revision').decode().strip(),
                      working_tree_dirty=bool(run(['git', 'status', '--porcelain'], 'source status').strip()),
                      source_sha256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
                      container_configuration={'network': 'none', 'cap_drop': ['ALL'], 'cap_add': ['NET_ADMIN'],
                                               'host_mounts': [], 'host_ports': [], 'privileged': False,
                                               'root_filesystem': 'read-only', 'outer_network_namespace': outer_namespace},
                      network_namespace=namespace)
        code = 0
    except (Exception, KeyboardInterrupt) as error:
        report.update(status='FAIL' if code == 1 else 'NOT_RUN', error={'type': type(error).__name__, 'stage': stage})
        if last_failure is not None:
            report['subprocess_failure'] = last_failure
    finally:
        report['actual_native_captures'] = capture_count
        report['passed'] = sum(check['passed'] for check in checks)
        report['failed'] = sum(not check['passed'] for check in checks)
        if container and len(container) == 64 and all(c in '0123456789abcdef' for c in container):
            try:
                result = subprocess.run(docker + ['rm', '-f', container], env=environment, capture_output=True, timeout=30)
                report['container_removed'] = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                report['container_removed'] = False
            if not report['container_removed']:
                report['status'] = 'FAIL'
                code = 1
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'checks': len(checks), 'actual_native_captures': capture_count,
                      'report': str(args.report), 'error': report.get('error')}))
    return code


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Exercise signed native execution only in a disposable Docker network namespace.

The fixture signing authority is synthetic and confined to the private lab. This
suite does not create human approvals, production capability claims or host rules.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
BASE_IMAGE = 'debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3'
IMAGE = 'nox-linux-loopback-lab:local'


class StageFailure(RuntimeError):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/signed-linux-lab.json')
    parser.add_argument('--skip-image-build', action='store_true')
    parser.add_argument('--scenario', choices=('all', 'crash', 'recovery-write-crash', 'unsubmitted', 'orphan-writer', 'recovery-prepare-crash', 'recovery-claim-crash', 'recovery-submit-crash'), default='all',
                        help='Run a named crash regression; CI runs the complete default suite.')
    args = parser.parse_args()
    environment = os.environ.copy()
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        environment.pop(key, None)
    docker = ['docker', '--host=unix:///var/run/docker.sock']
    container = None
    runner_started = False
    result = None
    code = 2

    def execute(command, stage, *, input_bytes=None, timeout=240):
        completed = subprocess.run(command, cwd=ROOT, env=environment, input=input_bytes,
                                   capture_output=True, timeout=timeout)
        if completed.returncode:
            # Do not place arbitrary child output, generated keys or private state
            # in a report. Stage and exit status are enough to identify the check.
            raise StageFailure(f'{stage}: exit {completed.returncode}')
        return completed.stdout

    try:
        execute(docker + ['info', '--format', '{{.ServerVersion}}'], 'docker readiness')
        execute(['cargo', 'build', '-p', 'fw_linux_executor', '-p', 'fw_testlab',
                 '--bin', 'fw_linux_executor', '--bin', 'fw_signed_lab_fixture', '--locked', '--offline'],
                'signed lifecycle binaries')
        if not args.skip_image_build:
            ca = Path('/etc/ssl/certs/ca-certificates.crt')
            if not ca.is_file():
                raise StageFailure('configured combined CA bundle unavailable')
            execute(docker + ['build', '--secret', f'id=proxy_ca,src={ca}', '-f',
                             str(ROOT / 'native/linux/Dockerfile.lab'), '-t', IMAGE,
                             str(ROOT / 'native/linux')], 'pinned image build')
        image_id = execute(docker + ['image', 'inspect', '--format', '{{.Id}}', IMAGE],
                           'image identity').decode().strip()
        source_paths = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'rust-toolchain.toml',
                        ROOT / 'native/linux/Dockerfile.lab', ROOT / 'native/linux/signed_lifecycle.py',
                        ROOT / 'scripts/signed-linux-lab.py', ROOT / 'target/debug/fw_linux_executor',
                        ROOT / 'target/debug/fw_signed_lab_fixture']
        for crate in ('fw_linux_executor', 'fw_backend_linux', 'fw_authority', 'fw_executor',
                      'fw_contracts', 'fw_domain', 'fw_planner', 'fw_testlab'):
            source_paths.append(ROOT / 'crates' / crate / 'Cargo.toml')
            source_paths.extend(sorted((ROOT / 'crates' / crate / 'src').rglob('*.rs')))
        source_bytes = {str(path.relative_to(ROOT)): path.read_bytes() for path in source_paths}
        source_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in source_bytes.items()}
        commit = execute(['git', 'rev-parse', 'HEAD'], 'source revision').decode().strip()
        dirty = bool(execute(['git', 'status', '--porcelain'], 'source status').strip())
        outer_namespace = os.readlink('/proc/self/ns/net')
        name = 'nox-signed-lab-' + uuid.uuid4().hex[:12]
        container = execute(docker + ['run', '-d', '--name', name, '--network', 'none',
                                     '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                                     '--security-opt', 'no-new-privileges',
                                     '--sysctl', 'net.netfilter.nf_conntrack_tcp_loose=0',
                                     '--env', 'TZ=UTC', '--env', 'NOX_LAB_OUTER_NETNS=' + outer_namespace,
                                     '--read-only', '--tmpfs', '/lab:rw,exec,nosuid,nodev,size=256m,mode=0700',
                                     '--pids-limit', '128', '--memory', '512m', '--cpus', '1', IMAGE],
                            'isolated container').decode().strip()
        if len(container) != 64 or any(c not in '0123456789abcdef' for c in container):
            raise StageFailure('invalid container identity')
        transfer_code = ('import os,sys; p="/lab/"+sys.argv[1]; '
                         'f=open(p,"xb"); f.write(sys.stdin.buffer.read()); '
                         'f.close(); os.chmod(p,0o700)')
        for source, name in [('target/debug/fw_linux_executor', 'fw_linux_executor'),
                             ('target/debug/fw_signed_lab_fixture', 'fw_signed_lab_fixture'),
                             ('native/linux/signed_lifecycle.py', 'signed_lifecycle.py')]:
            execute(docker + ['exec', '-i', container, 'python3', '-c', transfer_code, name],
                    'fixture transfer', input_bytes=source_bytes[source])
        execute(docker + ['exec', '-i', container, 'python3', '-c', transfer_code,
                         'DISPOSABLE_NETWORK_NAMESPACE'], 'namespace marker',
                input_bytes=b'nox-linux-loopback-lab-v1\n')
        runner_started = True
        # The complete suite now waits through several independent signed
        # confirmation/expiry windows and orphan-writer lock contention. This is
        # only the outer test budget; native and signed deadlines are unchanged.
        completed = subprocess.run(docker + ['exec', container, 'python3', '/lab/signed_lifecycle.py', '--scenario', args.scenario],
                                   cwd=ROOT, env=environment, capture_output=True, text=True, timeout=300)
        result = json.loads(completed.stdout)
        code = completed.returncode
        if result.get('status') not in ('PASS', 'FAIL') or code not in (0, 1) or (code == 0) != (result['status'] == 'PASS'):
            raise StageFailure('unexpected signed lifecycle result')
        result.update(image_id=image_id, base_image=BASE_IMAGE, commit=commit,
                      working_tree_dirty=dirty, source_sha256=source_hashes,
                      container_configuration={'network': 'none', 'cap_drop': ['ALL'],
                                               'cap_add': ['NET_ADMIN'], 'host_mounts': [], 'host_ports': [],
                                               'privileged': False, 'root_filesystem': 'read-only',
                                               'outer_network_namespace': outer_namespace,
                                               'sysctls': {'net.netfilter.nf_conntrack_tcp_loose': '0'}})
    except BaseException as error:
        code = 1 if runner_started else 2
        known_packet_count = result.get('packet_tests_executed') if isinstance(result, dict) else None
        result = {'schema_version': 'fw.signed-linux-lab/v1',
                  'status': 'FAIL' if runner_started else 'NOT_RUN',
                  'production_supported': False, 'synthetic_fixture_authority': True,
                  'runner_started': runner_started, 'packet_tests_executed': known_packet_count if runner_started else 0,
                  'error': {'type': type(error).__name__,
                            'stage': str(error) if isinstance(error, StageFailure) else 'runner unavailable'}}
    finally:
        if container and len(container) == 64 and all(c in '0123456789abcdef' for c in container):
            try:
                cleanup = subprocess.run(docker + ['rm', '-f', container], env=environment,
                                         capture_output=True, timeout=30)
                result['container_removed'] = cleanup.returncode == 0
                if cleanup.returncode:
                    result['cleanup_error'] = {'type': 'NonzeroExit', 'exit_code': cleanup.returncode}
            except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                result['container_removed'] = False
                result['cleanup_error'] = {'type': type(cleanup_error).__name__}
            if not result['container_removed']:
                result['status'] = 'FAIL'
                code = 1
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'packet_tests_executed': result.get('packet_tests_executed'),
                      'report': str(args.report), 'exit_code': code, 'error': result.get('error')}))
    return code


if __name__ == '__main__':
    raise SystemExit(main())

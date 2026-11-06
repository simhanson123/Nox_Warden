#!/usr/bin/env python3
"""Run target bootstrap observations in one disposable, network-none container.

The parent receives only the lab's explicit capabilities. No host mount, host
port, host account, privileged container or security-profile override is used.
The inner scenario verifies its separate signer, peer and target privileges.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'fw.target-bootstrap-linux-lab/v1'
CAPABILITIES = ['CHOWN', 'DAC_OVERRIDE', 'SETUID', 'SETGID', 'NET_ADMIN', 'SYS_ADMIN', 'SETPCAP']
BINARY_PATHS = {
    'fw_signer': 'target/debug/fw_signer',
    'fw_authority_admin': 'target/debug/fw_authority_admin',
    'protected_signer_fixture': 'target/debug/examples/protected_signer_fixture',
    'fw_linux_executor': 'target/debug/fw_linux_executor',
    'fw_target_bootstrap_peer': 'target/debug/fw_target_bootstrap_peer',
}
RUNNER_TIMEOUT_SECONDS = 420
MAX_REPORT_BYTES = 1024 * 1024


class StageFailure(RuntimeError):
    pass


def source_paths():
    paths = {Path(__file__).resolve(), ROOT / 'scripts/linux-lab.py', ROOT / 'Cargo.toml',
             ROOT / 'Cargo.lock', ROOT / 'rust-toolchain.toml', ROOT / 'native/linux/Dockerfile.lab',
             ROOT / 'native/linux/protected_signer_lab.py', ROOT / 'native/linux/target_bootstrap_lab.py',
             ROOT / 'docs/specs/F_기준자료/F_개발계약/F_계약_예제.json'}
    for crate in (ROOT / 'crates').iterdir():
        if crate.is_dir():
            paths.update(crate.rglob('*.rs'))
            paths.update(crate.rglob('*.sql'))
            if (crate / 'Cargo.toml').is_file():
                paths.add(crate / 'Cargo.toml')
    return sorted(paths)


def integer(value, minimum=0):
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StageFailure('runner report contains a duplicate field')
        result[key] = value
    return result


def bounded_public_report(value, depth=0):
    """Reject accidental private fixture fields; this is not a generic secret scan."""
    if depth > 16:
        raise StageFailure('runner report nesting exceeds contract')
    if isinstance(value, dict):
        if len(value) > 512:
            raise StageFailure('runner report object exceeds contract')
        private = {'private_key', 'private_key_bytes', 'seed', 'seed_bytes', 'owner_private_key',
                   'authenticator_private_key', 'raw_assertion', 'assertion', 'clientDataJSON',
                   'authenticatorData', 'raw_config', 'signer_config', 'config'}
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128 or key in private:
                raise StageFailure('runner report contains a forbidden field')
            bounded_public_report(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 4096:
            raise StageFailure('runner report list exceeds contract')
        for item in value:
            bounded_public_report(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 4096:
            raise StageFailure('runner report string exceeds contract')
    elif isinstance(value, float) and not math.isfinite(value):
        raise StageFailure('runner report contains a non-JSON number')
    elif value is not None and not isinstance(value, (int, float, bool)):
        raise StageFailure('runner report scalar exceeds contract')


def validate_report(result, exit_code):
    if not isinstance(result, dict) or result.get('schema_version') != SCHEMA:
        raise StageFailure('unexpected target bootstrap report schema')
    outer_fields = {'container_removed', 'container_configuration', 'image_id', 'base_image', 'commit',
                    'working_tree_dirty', 'source_sha256', 'binary_sha256', 'source_before_build_sha256',
                    'source_unchanged', 'source_unchanged_during_build', 'build_mode',
                    'build_commands_executed', 'external_frozen_build_linkage_required',
                    'runner_started', 'runner_timeout_seconds', 'runner_exit_code',
                    'runner_stdout_sha256', 'runner_stdout_bytes', 'runner_stderr_sha256', 'runner_stderr_bytes'}
    if outer_fields.intersection(result):
        raise StageFailure('runner report contains wrapper-owned metadata')
    if result.get('status') not in ('PASS', 'FAIL') or not integer(exit_code) or exit_code not in (0, 1):
        raise StageFailure('unexpected target bootstrap result')
    if (exit_code == 0) != (result['status'] == 'PASS'):
        raise StageFailure('runner exit and result disagree')
    for field in ('production_signing_allowed', 'production_dispatch_allowed', 'dispatch_allowed',
                  'production_supported'):
        if result.get(field) is not False:
            raise StageFailure('runner production boundary is not explicitly closed')
    names = result.get('check_names')
    count = result.get('checks')
    if not integer(count) or not isinstance(names, list) or count != len(names) or len(names) > 512:
        raise StageFailure('runner check inventory is inconsistent')
    if any(not isinstance(name, str) or not name or len(name) > 256 for name in names):
        raise StageFailure('runner check names are invalid')
    if len(set(names)) != len(names):
        raise StageFailure('runner check names are not unique')
    bounded_public_report(result)
    if result['status'] == 'PASS':
        if count == 0 or not integer(result.get('packet_tests_executed'), 1):
            raise StageFailure('runner did not exercise packet observations')
        if not integer(result.get('probe_tests_executed'), 3):
            raise StageFailure('runner did not exercise all bootstrap probe kinds')
        if result['packet_tests_executed'] > result['probe_tests_executed']:
            raise StageFailure('runner transmitted-request count exceeds probe attempts')
        setup = result.get('setup_operator_commands_executed')
        target = result.get('target_operator_commands_executed')
        total = result.get('operator_commands_executed')
        if not integer(setup) or setup != 18 or not integer(target, 7) or not integer(total):
            raise StageFailure('runner operator command inventory is incomplete')
        if total != setup + target:
            raise StageFailure('runner operator command counts disagree')
        if not integer(result.get('target_confirmations_accepted'), 2):
            raise StageFailure('runner did not complete actual target rotation')
        if result.get('negative_service_preflight_verified') is not True:
            raise StageFailure('negative service preflight was not verified')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/target-bootstrap-linux-lab.json')
    parser.add_argument('--skip-image-build', action='store_true')
    parser.add_argument('--skip-build', action='store_true')
    args = parser.parse_args()
    environment = os.environ.copy()
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        environment.pop(key, None)
    docker = ['docker', '--host=unix:///var/run/docker.sock']
    container = None
    runner_started = False
    result = None
    metadata = {}
    metadata['container_removed'] = False
    code = 2

    def execute(command, stage, *, input_bytes=None, timeout=300):
        try:
            completed = subprocess.run(command, cwd=ROOT, env=environment, input=input_bytes,
                                       capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise StageFailure(stage + ': timed out') from error
        if completed.returncode:
            # Never retain arbitrary compiler, signer or fixture output here.
            raise StageFailure(stage + ': exit ' + str(completed.returncode))
        return completed.stdout

    try:
        spec = importlib.util.spec_from_file_location('target_bootstrap_lab_image', ROOT / 'scripts/linux-lab.py')
        image = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(image)
        # Generated binaries enter the inventory only after the build boundary.
        source_bytes = {str(path.relative_to(ROOT)): path.read_bytes() for path in source_paths()}
        source_names = set(source_bytes)

        def unchanged():
            try:
                current_names = {str(path.relative_to(ROOT)) for path in source_paths()}
                return current_names == source_names and all(
                    (ROOT / path).read_bytes() == data for path, data in source_bytes.items())
            except OSError:
                return False

        metadata['source_before_build_sha256'] = {
            path: hashlib.sha256(data).hexdigest() for path, data in source_bytes.items()
        }
        metadata['build_mode'] = 'caller_supplied_artifacts' if args.skip_build else 'internal_build'
        metadata['external_frozen_build_linkage_required'] = args.skip_build
        execute(docker + ['info', '--format', '{{.ServerVersion}}'], 'docker readiness', timeout=30)
        build = ['cargo', 'build', '--locked', '--offline', '--target-dir', 'target', '-p', 'fw_signer', '-p', 'fw_authority',
                 '-p', 'fw_linux_executor', '-p', 'fw_testlab', '--bin', 'fw_signer',
                 '--bin', 'fw_authority_admin', '--bin', 'fw_linux_executor',
                 '--bin', 'fw_target_bootstrap_peer', '--example', 'protected_signer_fixture']
        metadata['build_commands_executed'] = []
        if not args.skip_build:
            metadata['build_commands_executed'].append(build)
            execute(build, 'target bootstrap binaries', timeout=600)
        metadata['source_unchanged_during_build'] = unchanged()
        if not metadata['source_unchanged_during_build']:
            raise StageFailure('source changed during build')
        for path in BINARY_PATHS.values():
            source_bytes[path] = (ROOT / path).read_bytes()
        source_hashes = {path: hashlib.sha256(data).hexdigest() for path, data in source_bytes.items()}
        if not args.skip_image_build:
            ca = Path('/etc/ssl/certs/ca-certificates.crt')
            if not ca.is_file():
                raise StageFailure('configured combined CA trust bundle unavailable')
            execute(docker + ['build', '--secret', f'id=proxy_ca,src={ca}', '-f',
                             str(ROOT / 'native/linux/Dockerfile.lab'), '-t', image.IMAGE,
                             str(ROOT / 'native/linux')], 'pinned image build', timeout=600)
        image_id = execute(docker + ['image', 'inspect', '--format', '{{.Id}}', image.IMAGE],
                           'image identity', timeout=30).decode().strip()
        if not image_id.startswith('sha256:') or len(image_id) != 71 or any(c not in '0123456789abcdef' for c in image_id[7:]):
            raise StageFailure('invalid image identity')
        metadata.update(image_id=image_id, base_image=image.BASE_IMAGE,
                        commit=execute(['git', 'rev-parse', 'HEAD'], 'source revision').decode().strip(),
                        working_tree_dirty=bool(execute(['git', 'status', '--porcelain'], 'source status').strip()),
                        source_sha256=source_hashes,
                        binary_sha256={path: source_hashes[path] for path in BINARY_PATHS.values()},
                        runner_timeout_seconds=RUNNER_TIMEOUT_SECONDS)
        name = 'nox-target-bootstrap-' + uuid.uuid4().hex[:12]
        command = docker + ['run', '-d', '--name', name, '--network', 'none', '--cap-drop', 'ALL']
        for capability in CAPABILITIES:
            command += ['--cap-add', capability]
        container = execute(command + ['--security-opt', 'no-new-privileges', '--read-only',
            '--tmpfs', '/lab:rw,exec,nosuid,nodev,size=1g,mode=0755', '--memory', '1536m',
            '--pids-limit', '96', '--cpus', '2', '--env', 'TZ=UTC', image.IMAGE],
            'isolated container', timeout=30).decode().strip()
        if len(container) != 64 or any(c not in '0123456789abcdef' for c in container):
            raise StageFailure('invalid disposable container identity')
        metadata['container_configuration'] = {
            'network': 'none', 'cap_drop': ['ALL'], 'cap_add': CAPABILITIES,
            'host_mounts': [], 'host_ports': [], 'privileged': False, 'root_filesystem': 'read-only',
            'apparmor': 'default (no override)', 'seccomp': 'default (no override)',
            'security_opt': ['no-new-privileges'], 'tmpfs_bytes': 1024 * 1024 * 1024,
            'memory_bytes': 1536 * 1024 * 1024, 'pids_limit': 96, 'cpus': 2,
        }
        transfer_code = ('import os,sys;p="/lab/"+sys.argv[1];f=open(p,"xb");'
                         'f.write(sys.stdin.buffer.read());f.close();os.chmod(p,int(sys.argv[2],8))')

        def transfer(data, destination, mode):
            execute(docker + ['exec', '-i', container, 'python3', '-c', transfer_code,
                             destination, mode], 'fixture transfer: ' + destination,
                    input_bytes=data, timeout=60)

        for destination, source in BINARY_PATHS.items():
            transfer(source_bytes[source], destination, '0555')
        for script in ('protected_signer_lab.py', 'target_bootstrap_lab.py'):
            transfer(source_bytes['native/linux/' + script], script, '0555')
        transfer(b'fw-isolated-target-bootstrap-v1\n', 'DISPOSABLE_TARGET_BOOTSTRAP_NAMESPACE', '0444')
        transfer(b'fw-disposable-protected-signer-lab-v1\n', 'DISPOSABLE_SIGNER_LAB', '0444')
        runner_started = True
        completed = subprocess.run(docker + ['exec', container, 'python3', '/lab/target_bootstrap_lab.py'],
                                   cwd=ROOT, env=environment, capture_output=True,
                                   timeout=RUNNER_TIMEOUT_SECONDS)
        metadata['runner_stdout_sha256'] = hashlib.sha256(completed.stdout).hexdigest()
        metadata['runner_stdout_bytes'] = len(completed.stdout)
        metadata['runner_stderr_sha256'] = hashlib.sha256(completed.stderr).hexdigest()
        metadata['runner_stderr_bytes'] = len(completed.stderr)
        metadata['runner_exit_code'] = completed.returncode
        if len(completed.stdout) > MAX_REPORT_BYTES:
            raise StageFailure('runner report exceeds size bound')
        candidate = json.loads(completed.stdout, object_pairs_hook=strict_object)
        # A rejected candidate may contain accidental private fields. Retain
        # only its stdout digest, never copy that candidate into an artifact.
        validate_report(candidate, completed.returncode)
        result = candidate
        metadata['source_unchanged'] = unchanged()
        if not metadata['source_unchanged']:
            raise StageFailure('source or binaries changed during execution')
        code = completed.returncode
    except BaseException as error:
        code = 1 if runner_started else 2
        if not isinstance(result, dict):
            result = {'schema_version': SCHEMA, 'checks': 0, 'check_names': [],
                      'production_signing_allowed': False, 'production_dispatch_allowed': False,
                      'dispatch_allowed': False, 'production_supported': False,
                      'packet_tests_executed': None if runner_started else 0}
        result['status'] = 'FAIL' if runner_started else 'NOT_RUN'
        result['error'] = {'type': type(error).__name__,
                           'stage': str(error) if isinstance(error, StageFailure) else 'runner unavailable'}
    finally:
        if container and len(container) == 64 and all(c in '0123456789abcdef' for c in container):
            try:
                cleanup = subprocess.run(docker + ['rm', '-f', container], cwd=ROOT, env=environment,
                                         capture_output=True, timeout=30)
                if cleanup.returncode:
                    raise StageFailure('disposable container removal failed')
                metadata['container_removed'] = True
            except BaseException:
                result['status'] = 'FAIL'
                result['cleanup_error'] = 'disposable container removal failed'
                code = 1
        result.update(metadata)
        result['runner_started'] = runner_started
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'status': result['status'], 'checks': result.get('checks', 0),
                      'packet_tests_executed': result.get('packet_tests_executed'),
                      'report': str(args.report), 'exit_code': code}))
    return code


if __name__ == '__main__':
    raise SystemExit(main())

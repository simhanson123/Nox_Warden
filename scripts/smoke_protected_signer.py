#!/usr/bin/env python3
"""Exercise the real local signer with separate UIDs in one disposable container.

No host accounts, host mounts, published ports or firewall changes are used.
Only CHOWN, DAC_OVERRIDE, SETUID and SETGID are added inside the network-none lab.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/protected-signer-smoke.json')
    parser.add_argument('--skip-image-build', action='store_true')
    parser.add_argument('--skip-build', action='store_true')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('signer_lab_image', ROOT / 'scripts/linux-lab.py')
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    env = os.environ.copy()
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        env.pop(key, None)
    docker = ['docker', '--host=unix:///var/run/docker.sock']
    container = None
    started = False
    result = None
    code = 2
    try:
        lab.execute(docker + ['info', '--format', '{{.ServerVersion}}'], env=env)
        if not args.skip_build:
            lab.execute(['cargo', 'build', '--locked', '--offline', '-p', 'fw_signer', '--bin', 'fw_signer'], env=env)
            lab.execute(['cargo', 'build', '--locked', '--offline', '-p', 'fw_authority', '--example', 'protected_signer_fixture'], env=env)
            lab.execute(['cargo', 'build', '--locked', '--offline', '-p', 'fw_authority', '--bin', 'fw_authority_admin'], env=env)
        if not args.skip_image_build:
            ca = Path('/etc/ssl/certs/ca-certificates.crt')
            if not ca.is_file():
                raise RuntimeError('combined CA trust bundle unavailable')
            lab.execute(docker + ['build', '--secret', f'id=proxy_ca,src={ca}', '-f',
                        str(ROOT / 'native/linux/Dockerfile.lab'), '-t', lab.IMAGE, str(ROOT / 'native/linux')], env=env)
        image_id = lab.execute(docker + ['image', 'inspect', '--format', '{{.Id}}', lab.IMAGE], env=env).strip()
        inputs = [Path(__file__).resolve(), ROOT / 'scripts/linux-lab.py', ROOT / 'native/linux/protected_signer_lab.py', ROOT / 'native/linux/Dockerfile.lab',
                  ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'target/debug/fw_signer',
                  ROOT / 'target/debug/examples/protected_signer_fixture', ROOT / 'target/debug/fw_authority_admin']
        for crate in ('fw_signer', 'fw_authority', 'fw_contracts', 'fw_webauthn'):
            inputs.extend(sorted((ROOT / 'crates' / crate).rglob('*.rs')))
            inputs.extend(sorted((ROOT / 'crates' / crate).rglob('*.sql')))
            inputs.append(ROOT / 'crates' / crate / 'Cargo.toml')
        source_hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
        name = 'nox-protected-signer-' + uuid.uuid4().hex[:12]
        caps = ['CHOWN', 'DAC_OVERRIDE', 'SETUID', 'SETGID']
        command = docker + ['run', '-d', '--name', name, '--network', 'none', '--cap-drop', 'ALL']
        for cap in caps:
            command += ['--cap-add', cap]
        container = lab.execute(command + ['--security-opt', 'no-new-privileges', '--read-only',
            '--tmpfs', '/lab:rw,exec,nosuid,nodev,size=512m,mode=0700', '--pids-limit', '48',
            '--memory', '768m', '--cpus', '1', '--env', 'TZ=UTC', lab.IMAGE], env=env).strip()
        if len(container) != 64 or any(char not in '0123456789abcdef' for char in container):
            raise RuntimeError('invalid disposable container identity')
        def transfer(source, destination, mode):
            upload = subprocess.run(docker + ['exec', '-i', container, 'python3', '-c',
                'import os,sys;p="/lab/"+sys.argv[1];f=open(p,"wb");f.write(sys.stdin.buffer.read());f.close();os.chmod(p,int(sys.argv[2],8))',
                destination, mode], env=env, input=source, capture_output=True, timeout=30)
            if upload.returncode:
                raise RuntimeError(f'disposable fixture transfer failed destination={destination} exit_code={upload.returncode}')
        transfer((ROOT / 'target/debug/fw_signer').read_bytes(), 'fw_signer', '0555')
        transfer((ROOT / 'target/debug/examples/protected_signer_fixture').read_bytes(), 'protected_signer_fixture', '0555')
        transfer((ROOT / 'target/debug/fw_authority_admin').read_bytes(), 'fw_authority_admin', '0555')
        transfer((ROOT / 'native/linux/protected_signer_lab.py').read_bytes(), 'protected_signer_lab.py', '0555')
        transfer(b'fw-disposable-protected-signer-lab-v1\n', 'DISPOSABLE_SIGNER_LAB', '0444')
        started = True
        execution = subprocess.run(docker + ['exec', container, 'python3', '/lab/protected_signer_lab.py'],
                                   env=env, capture_output=True, text=True, timeout=120)
        result = json.loads(execution.stdout)
        code = execution.returncode
        if code not in (0, 1) or (code == 0) != (result.get('status') == 'PASS'):
            raise RuntimeError('unexpected protected signer lab result')
        result.update(image_id=image_id, base_image=lab.BASE_IMAGE,
                      commit=lab.execute(['git', 'rev-parse', 'HEAD'], env=env).strip(),
                      working_tree_dirty=bool(lab.execute(['git', 'status', '--porcelain'], env=env).strip()),
                      source_sha256=source_hashes,
                      container_configuration={'network': 'none', 'cap_drop': ['ALL'], 'cap_add': caps,
                        'host_mounts': [], 'host_ports': [], 'privileged': False, 'root_filesystem': 'read-only',
                        'tmpfs_bytes': 512 * 1024 * 1024, 'memory_bytes': 768 * 1024 * 1024, 'pids_limit': 48})
    except BaseException as error:
        code = 1 if started else 2
        result = {'schema_version': 'fw.protected-signer-smoke/v1', 'status': 'FAIL' if started else 'NOT_RUN',
                  'production_supported': False, 'runner_started': started, 'checks': 0,
                  'error': {'type': type(error).__name__, 'message': str(error)[:1024]}}
    finally:
        if container and len(container) == 64 and all(char in '0123456789abcdef' for char in container):
            cleanup = subprocess.run(docker + ['rm', '-f', container], env=env, capture_output=True, text=True, timeout=30)
            if cleanup.returncode:
                result['status'] = 'FAIL'
                result['cleanup_error'] = 'disposable container removal failed'
                code = 1
            else:
                result['container_removed'] = True
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'checks': result.get('checks', 0), 'report': str(args.report), 'exit_code': code}))
    return code


if __name__ == '__main__':
    raise SystemExit(main())

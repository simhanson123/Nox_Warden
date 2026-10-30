#!/usr/bin/env python3
"""Build and execute real packet fixtures in one disposable Docker network namespace.

Requires the explicitly selected local managed Docker socket. Runtime networking
is `none`; capabilities are dropped except NET_ADMIN. No host network, published
port, bind mount, device, privileged flag, or daemon restart is used.
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


def execute(args, *, env, capture=True, cwd=ROOT):
    result = subprocess.run(args, env=env, cwd=cwd, capture_output=capture, text=True)
    if result.returncode:
        raise RuntimeError(json.dumps({'command':args,'exit_code':result.returncode,
                                       'stdout':result.stdout,'stderr':result.stderr}))
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=ROOT/'reports/linux-lab.json')
    parser.add_argument('--skip-image-build', action='store_true', help='Reuse a previously built local lab image; image ID is always recorded.')
    args = parser.parse_args()
    env = os.environ.copy()
    for key in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):
        env.pop(key, None)
    docker = ['docker','--host=unix:///var/run/docker.sock']
    container = None
    result = None
    code = 2
    runner_started = False
    try:
        execute(docker+['info','--format','{{.ServerVersion}}'],env=env)
        execute(['cargo','build','-p','fw_backend_linux','--bin','fw_compile_lab','--locked','--offline'],env=env)
        if not args.skip_image_build:
            ca = '/etc/ssl/certs/ca-certificates.crt'
            if not Path(ca).is_file():
                raise RuntimeError('The configured combined CA trust bundle is unavailable')
            execute(docker+['build','--secret',f'id=proxy_ca,src={ca}','-f',str(ROOT/'native/linux/Dockerfile.lab'),'-t',IMAGE,str(ROOT/'native/linux')],env=env)
        image_id = execute(docker+['image','inspect','--format','{{.Id}}',IMAGE],env=env).strip()
        source_paths = [ROOT/'crates/fw_backend_linux/src/lib.rs',ROOT/'crates/fw_backend_linux/src/readback.rs',ROOT/'crates/fw_backend_linux/src/portable.rs',ROOT/'crates/fw_backend_linux/src/bin/fw_compile_lab.rs',
            ROOT/'crates/fw_backend_linux/Cargo.toml',ROOT/'crates/fw_domain/src/lib.rs',ROOT/'crates/fw_contracts/src/lib.rs',
            ROOT/'native/linux/packet_lab.py',ROOT/'native/linux/Dockerfile.lab',ROOT/'Cargo.toml',ROOT/'Cargo.lock',
            ROOT/'rust-toolchain.toml',ROOT/'target/debug/fw_compile_lab',ROOT/'crates/fw_testlab/src/main.rs',Path(__file__).resolve()]
        source_bytes = {str(path.relative_to(ROOT)):path.read_bytes() for path in source_paths}
        source_hashes = {name:hashlib.sha256(data).hexdigest() for name,data in source_bytes.items()}
        source_commit = execute(['git','rev-parse','HEAD'],env=env).strip()
        source_dirty = bool(execute(['git','status','--porcelain'],env=env).strip())
        name = 'nox-loopback-lab-'+uuid.uuid4().hex[:12]
        container = execute(docker+['run','-d','--name',name,'--network','none','--cap-drop','ALL','--cap-add','NET_ADMIN',
                            '--security-opt','no-new-privileges','--sysctl','net.netfilter.nf_conntrack_tcp_loose=0','--env','TZ=UTC','--env','NOX_LAB_OUTER_NETNS='+os.readlink('/proc/self/ns/net'),'--read-only','--tmpfs','/lab:rw,exec,nosuid,nodev,size=64m,mode=0700',
                            '--pids-limit','64','--memory','256m','--cpus','1',IMAGE],env=env).strip()
        if len(container)!=64 or any(c not in '0123456789abcdef' for c in container):
            raise RuntimeError('Unexpected Docker container identity')
        def transfer(data, name):
            upload = subprocess.run(docker+['exec','-i',container,'python3','-c',
                'import os,sys; p="/lab/"+sys.argv[1]; f=open(p,"wb"); f.write(sys.stdin.buffer.read()); f.close(); os.chmod(p,0o700)',name],
                env=env,input=data,capture_output=True)
            if upload.returncode:
                raise RuntimeError(upload.stderr.decode(errors='replace'))
        transfer(source_bytes['target/debug/fw_compile_lab'], 'fw_compile_lab')
        transfer(source_bytes['native/linux/packet_lab.py'], 'packet_lab.py')
        transfer(b'nox-linux-loopback-lab-v1\n', 'DISPOSABLE_NETWORK_NAMESPACE')
        runner_started = True
        execution = subprocess.run(docker+['exec',container,'python3','/lab/packet_lab.py'],env=env,capture_output=True,text=True,timeout=90)
        code=execution.returncode
        result=json.loads(execution.stdout)
        result.update(image_id=image_id,base_image=BASE_IMAGE,container_configuration={
            'network':'none','cap_drop':['ALL'],'cap_add':['NET_ADMIN'],'host_mounts':[],
            'host_ports':[],'privileged':False,'root_filesystem':'read-only','outer_network_namespace':os.readlink('/proc/self/ns/net'),
            'sysctls':{'net.netfilter.nf_conntrack_tcp_loose':'0'}},
            commit=source_commit,working_tree_dirty=source_dirty,source_sha256=source_hashes)
        if execution.stderr:
            result['stderr']=execution.stderr
        if code not in (0,1) or (code == 0) != (result.get('status') == 'PASS') or result.get('status') not in ('PASS','FAIL'):
            raise RuntimeError('Unexpected native runner result')
    except BaseException as error:
        code = 1 if runner_started else 2
        result={'schema_version':'fw.linux-loopback-smoke/v1','status':'NOT_RUN' if result is None and code==2 else 'FAIL',
                'production_supported':False,'error':{'type':type(error).__name__,'message':str(error)},
                'packet_tests_executed':result.get('packet_tests_executed') if result else (None if runner_started else 0),
                'runner_started':runner_started}
    finally:
        if container and len(container)==64 and all(c in '0123456789abcdef' for c in container):
            cleanup=subprocess.run(docker+['rm','-f',container],env=env,capture_output=True,text=True)
            if cleanup.returncode:
                result['cleanup_error']=cleanup.stderr;result['status']='FAIL';code=1
            else:
                result['container_removed']=True
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'packet_tests_executed':result.get('packet_tests_executed',0),
                      'report':str(args.report),'exit_code':code,'error':result.get('error')}))
    return code


if __name__=='__main__':
    raise SystemExit(main())

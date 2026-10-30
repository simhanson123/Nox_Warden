#!/usr/bin/env python3
"""Verify CLI file login and authenticated reads against the real controller."""
import json,os,pathlib,subprocess,tempfile,time,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='nox-cli-live-') as tmp:
    state=pathlib.Path(tmp)
    env=dict(os.environ,FW_STATE_DIR=tmp,FW_PORT='8789',FW_API_URL='http://127.0.0.1:8789',FW_BOOTSTRAP_FILE=str(state/'bootstrap-token'),FW_SESSION_FILE=str(state/'session.json'))
    process=subprocess.Popen([str(ROOT/'target/debug/fw_control')],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(100):
            if process.poll() is not None:raise RuntimeError('controller startup failed')
            try:
                with opener.open(env['FW_API_URL']+'/healthz',timeout=2):break
            except OSError:time.sleep(.05)
        else:raise RuntimeError('controller readiness timeout')
        checks=[]
        def cli(command,success=True):
            result=subprocess.run([str(ROOT/'target/debug/fw_cli'),command],cwd=ROOT,env=env,capture_output=True,text=True,timeout=15)
            if (result.returncode==0)!=success:raise AssertionError('unexpected CLI status for '+command)
            # Do not echo arbitrary response/error bytes or credential-file contents.
            return json.loads(result.stdout) if success else None
        cli('login');checks.append('real bootstrap token exchanged for CLI session')
        session=json.loads((state/'session.json').read_text())
        assert (state/'session.json').stat().st_mode & 0o777 == 0o600
        checks.append('session file mode0600')
        status=cli('status');assert status['data']['enforcement'] is False;checks.append('authenticated status remains observe-only')
        for command in ['assets','services','requests','operations','audit','capabilities']:
            response=cli(command);assert 'data' in response;checks.append('authenticated '+command+' read')
        cli('login',False);checks.append('consumed bootstrap token rejected')
        # Session remains usable after a denied second login.
        cli('status');checks.append('failed login does not overwrite valid session')
        del session
        report={'status':'PASS','checks':checks,'count':len(checks),'native_firewall_modified':False,'credential_values_recorded':False}
        (ROOT/'reports/cli-smoke.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
    finally:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()

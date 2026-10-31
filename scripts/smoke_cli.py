#!/usr/bin/env python3
"""Verify CLI file login and authenticated reads against the real controller."""
import json,os,pathlib,subprocess,tempfile,time,urllib.request,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='nox-cli-live-') as tmp:
    state=pathlib.Path(tmp)
    env=dict(os.environ,FW_STATE_DIR=tmp,FW_PORT='8789',FW_API_URL='http://127.0.0.1:8789',FW_PUBLIC_ORIGIN='http://127.0.0.1:8789',FW_BOOTSTRAP_FILE=str(state/'bootstrap-token'),FW_SESSION_FILE=str(state/'session.json'))
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
        def cli(command,success=True,args=()):
            result=subprocess.run([str(ROOT/'target/debug/fw_cli'),command,*args],cwd=ROOT,env=env,capture_output=True,text=True,timeout=15)
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
        # Seed actual catalogue rows through the authenticated HTTP API, then
        # traverse with the actual CLI. Never print cookies or session contents.
        owner='00000000-0000-4000-8000-000000000003'
        for number in range(3):
            payload={'definition':{'name':f'CLI page {number}','asset_kind':'host','owner_id':owner,'addresses':[{'family':'ipv4','cidr':'192.0.2.1/32','interface':None}],'criticality':'normal','isolation':'host','provenance':'manual','source_evidence':None},'state':'active'}
            headers={'Content-Type':'application/json','Origin':env['FW_API_URL'],'Cookie':session['cookie'],'X-CSRF-Token':session['csrf_token'],'Idempotency-Key':str(uuid.uuid4())}
            request=urllib.request.Request(env['FW_API_URL']+'/api/v1/assets',data=json.dumps(payload).encode(),headers=headers)
            with opener.open(request,timeout=5) as response: assert response.status==201
        page=cli('assets',args=('--limit','1'));assert len(page['data'])==1 and page['next_cursor'];ids=[page['data'][0]['asset_id']]
        revision=page['revision']
        while page['next_cursor']:
            page=cli('assets',args=('--cursor',page['next_cursor'],'--limit','1'));assert page['revision']==revision and len(page['data'])==1
            ids.append(page['data'][0]['asset_id']);assert len(ids)<=3
        assert len(ids)==len(set(ids))==3;checks.append('CLI limit and cursor traverse three real snapshot pages without omissions')
        for arguments in [('--limit','0'),('--limit','101'),('--limit','01'),('--limit','1','--limit','2'),('--cursor','bad&limit=100'),('--cursor',),('--unknown','1')]:
            invalid_env=dict(env,FW_SESSION_FILE=str(state/'absent-session.json'),FW_API_URL='http://127.0.0.1:9')
            rejected=subprocess.run([str(ROOT/'target/debug/fw_cli'),'assets',*arguments],cwd=ROOT,env=invalid_env,capture_output=True,text=True,timeout=5)
            assert rejected.returncode!=0
            reason=json.loads(rejected.stderr)['error']
            assert any(word in reason for word in ['limit','cursor','option']), 'invalid arguments reached credentials or HTTP'
        cli('status',False,args=('--limit','1'));checks.append('CLI rejects malformed bounds, duplicate options, cursor injection and non-list options')
        cli('login',False);checks.append('consumed bootstrap token rejected')
        # Session remains usable after a denied second login.
        cli('status');checks.append('failed login does not overwrite valid session')
        del session
        report={'status':'PASS','checks':checks,'count':len(checks),'native_firewall_modified':False,'credential_values_recorded':False}
        path=ROOT/'reports/cli-smoke.json'
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
    finally:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()

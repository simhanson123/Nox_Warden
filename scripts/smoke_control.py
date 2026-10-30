#!/usr/bin/env python3
"""Real process/HTTP smoke with OpenAPI response validation. Uses disposable local state."""
import http.cookiejar,json,os,pathlib,subprocess,tempfile,time,urllib.error,urllib.request,uuid
import jsonschema
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=json.loads((ROOT/'docs/specs/F_OpenAPI.json').read_text())
BASE='http://127.0.0.1:8788'
checks=[]
def validate(name,value):
    schema={'$ref':f'#/components/schemas/{name}','components':spec['components']}
    jsonschema.Draft202012Validator(schema,format_checker=jsonschema.FormatChecker()).validate(value)
def check(name, condition):
    if not condition: raise AssertionError(name)
    checks.append(name)
with tempfile.TemporaryDirectory(prefix='nox-http-') as tmp:
    env=dict(os.environ,FW_STATE_DIR=tmp,FW_PORT='8788',FW_WEB_DIR=str(ROOT/'web/dist'))
    process=subprocess.Popen([str(ROOT/'target/debug/fw_control')],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        csrf=None
        def call(path,body=None,key=None,raw=None,extra_headers=None):
            headers={}
            if body is not None or raw is not None:
                headers={'Content-Type':'application/json','Origin':BASE,'Idempotency-Key':key or str(uuid.uuid4())}
                if csrf: headers['X-CSRF-Token']=csrf
            headers.update(extra_headers or {})
            data=raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
            try:
                with opener.open(urllib.request.Request(BASE+path,data=data,headers=headers),timeout=5) as response:
                    return response.status,json.load(response)
            except urllib.error.HTTPError as error:
                return error.code,json.load(error)
        for _ in range(100):
            if process.poll() is not None:raise RuntimeError('controller startup failed')
            try:
                code,body=call('/healthz');break
            except OSError:time.sleep(.05)
        else:raise RuntimeError('controller readiness timeout')
        check('HTTP health',code==200 and body['status']=='ok')
        code,body=call('/api/v1/access-requests');validate('Problem',body);check('unauthenticated rejected',code==401)
        token=(pathlib.Path(tmp)/'bootstrap-token').read_text()
        code,body=call('/api/v1/session/bootstrap',{'token':token});check('one-use session bootstrap',code==200)
        csrf=body['data']['csrf_token']
        owner=body['data']['principal_id']
        code,body=call('/api/v1/status');check('observe without enforcement or telemetry',code==200 and body['data']['enforcement'] is False and body['data']['telemetry_enabled'] is False)
        asset_key=str(uuid.uuid4())
        asset={'definition':{'name':'smoke-server','asset_kind':'host','owner_id':owner,'addresses':[{'family':'ipv4','cidr':'192.0.2.1/32','interface':None}],'criticality':'normal','isolation':'host','provenance':'manual','source_evidence':None},'state':'active'}
        code,body=call('/api/v1/assets',asset,asset_key);validate('AssetResponse',body);check('asset created with server ownership',code==201 and body['data']['created_by']==owner and body['data']['revision']==1)
        asset_id=body['data']['asset_id'];original_asset=body['data']
        code,body=call('/api/v1/assets',asset,asset_key);check('asset idempotent replay',code==201 and body['data']==original_asset)
        code,body=call('/api/v1/assets');validate('AssetsResponse',body);check('stored asset list',code==200 and len(body['data'])==1)
        revised=json.loads(json.dumps(asset));revised['definition']['name']='smoke-server-revised'
        code,body=call('/api/v1/assets/'+asset_id+'/revisions',revised);validate('Problem',body);check('asset revision requires If-Match',code==428)
        etag='"rev-1-'+original_asset['content_hash']+'"'
        revision_key=str(uuid.uuid4())
        code,body=call('/api/v1/assets/'+asset_id+'/revisions',revised,revision_key,extra_headers={'If-Match':etag});validate('AssetResponse',body);check('immutable asset revision hash link',code==201 and body['data']['revision']==2 and body['data']['previous_revision_hash']==original_asset['content_hash'])
        code,body=call('/api/v1/assets/'+asset_id+'/revisions',revised,extra_headers={'If-Match':etag});validate('Problem',body);check('stale asset revision rejected',code==412)
        forged=json.loads(json.dumps(asset));forged['definition']['provenance']='enrolled_agent'
        code,body=call('/api/v1/assets',forged);validate('Problem',body);check('manual catalogue cannot assert trusted identity',code==403)
        service={'service_id':'smoke-https','definition':{'name':'HTTPS','owner_id':owner,'destination_asset_ids':[asset_id],'target_ids':[str(uuid.uuid4())],'transport':{'protocol':'tcp','destination_ports':[{'start':443,'end':443}]},'description':'Smoke service','criticality':'normal'}}
        code,body=call('/api/v1/services',service);validate('Problem',body);check('service rejects unknown target',code in (404,422))
        code,body=call('/api/v1/services');validate('ServicesResponse',body);check('rejected service not stored',code==200 and body['data']==[])
        key=str(uuid.uuid4());request={'schema_version':'f.access-request/v1','idempotency_key':key,'workflow_id':'smoke','workload_binding_id':str(uuid.uuid4()),'source_asset_ids':[asset_id],'destination_asset_ids':[asset_id],'service_id':'https','lease_seconds':60,'purpose':'Local functional verification'}
        code,body=call('/api/v1/access-requests',request,key);validate('AcceptedResponse',body);check('request stored',code==202)
        resource_id=body['data']['resource_id'];operation_id=body['data']['operation_id']
        code,replay=call('/api/v1/access-requests',request,key);check('idempotent resource',code==202 and replay['data']==body['data'])
        code,body=call('/api/v1/access-requests');validate('RequestsResponse',body);check('request needs enrollment',len(body['data'])==1 and body['data'][0]['state']=='needs_info')
        code,body=call('/api/v1/operations/'+operation_id);validate('OperationResponse',body);check('validation explicitly failed',body['data']['state']=='failed')
        code,body=call('/api/v1/operations');validate('OperationsResponse',body);check('operation list',len(body['data'])==1)
        request['purpose']='conflicting retry';code,body=call('/api/v1/access-requests',request,key);validate('Problem',body);check('idempotency conflict',code==409)
        code,body=call('/api/v1/access-requests',raw=b'{"purpose":"a","purpose":"b"}');validate('Problem',body);check('duplicate JSON rejected',code==400)
        code,body=call('/api/v1/deployments',{});validate('Problem',body);check('native deployment blocked',code==422)
        code,body=call('/api/v1/audit/events');validate('AuditEventsResponse',body);check('audit evidence exists',len(body['data'])>=3)
        code,body=call('/mcp',{'jsonrpc':'2.0','id':1,'method':'tools/list'});check('MCP no approval or native write tools',code==200 and {t['name'] for t in body['result']['tools']}=={'get_capabilities','get_operation','get_audit_events'})
        with opener.open(BASE+'/',timeout=5) as response:
            check('static application served',response.status==200 and b'<div id="root">' in response.read())
        result={'status':'PASS','checks':checks,'count':len(checks),'native_enforcement_tested':False,'credentials_in_report':False}
        path=ROOT/'reports/http-smoke.json';path.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
    finally:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()

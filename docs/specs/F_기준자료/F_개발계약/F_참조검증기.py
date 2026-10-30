#!/usr/bin/env python3
"""Reference validation of final design contracts; never deploys firewall rules.

Dependency: jsonschema>=4.23,<5. This is not a signer, policy authority,
quota transaction, service resolver, device verifier, or firewall runtime.
"""
from __future__ import annotations
import argparse
import base64
import binascii
import copy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
import unicodedata
from jsonschema import Draft202012Validator, FormatChecker

BASE=Path(__file__).resolve().parent
SCHEMA_PATH=BASE/'F_계약_스키마.json'
EXAMPLE_PATH=BASE/'F_계약_예제.json'
CATALOG_PATH=BASE/'F_MCP_도구_카탈로그.json'

def no_duplicates(pairs):
    result={}
    for k,v in pairs:
        if k in result: raise ValueError('DUPLICATE_JSON_KEY: '+k)
        result[k]=v
    return result

def read_json(path):
    return json.loads(Path(path).read_text('utf-8'),object_pairs_hook=no_duplicates,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('NONFINITE_NUMBER: '+x)))

def canonical_bytes(value):
    """RFC8785-compatible restricted profile: ASCII keys, safe integers, no floats.

    Closed schemas use ASCII property names. String values are preserved,
    without Unicode normalization. Arrays retain order; sets must be sorted
    by the producer's declared normal form before a Plan is frozen.
    """
    def check(x):
        if isinstance(x,dict):
            for k,v in x.items():
                if not isinstance(k,str) or not k.isascii(): raise ValueError('NON_ASCII_PROPERTY')
                check(v)
        elif isinstance(x,list):
            for v in x:check(v)
        elif isinstance(x,bool) or x is None:pass
        elif isinstance(x,int):
            if abs(x)>9007199254740991:raise ValueError('UNSAFE_JSON_INTEGER')
        elif isinstance(x,float):raise ValueError('FLOAT_NOT_ALLOWED')
        elif isinstance(x,str):x.encode('utf-8','strict')
        else:raise ValueError('UNSUPPORTED_JSON_VALUE')
    check(value)
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')

def digest(value):return 'sha256:'+hashlib.sha256(canonical_bytes(value)).hexdigest()
def instant(s):return datetime.strptime(s,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)

def schema_errors(value,kind='ContractFixture'):
    s=copy.deepcopy(read_json(SCHEMA_PATH));s['$ref']='#/$defs/'+kind
    validator=Draft202012Validator(s,format_checker=FormatChecker())
    errors=[{'code':'SCHEMA','path':'/'.join(map(str,e.absolute_path)),
             'message':e.message[:400]} for e in validator.iter_errors(value)]
    def check_nfc(x,path=''):
        if isinstance(x,dict):
            for k,v in x.items():check_nfc(v,path+'/'+k)
        elif isinstance(x,list):
            for i,v in enumerate(x):check_nfc(v,path+'/'+str(i))
        elif isinstance(x,str) and unicodedata.normalize('NFC',x)!=x:
            errors.append({'code':'NON_NFC_VALUE','path':path,'message':'normalize at domain admission before hashing; never mutate signed bytes'})
    check_nfc(value)
    return errors

def tool_output_errors(name,value):
    catalog=read_json(CATALOG_PATH)
    limit=catalog['authorization_contracts'][name]['max_output_bytes']
    if len(canonical_bytes(value))>limit:return [{'code':'OUTPUT_TOO_LARGE','path':name,'message':'return bounded unavailable/RESULT_TOO_LARGE; never truncate the plan'}]
    tool=next(t for t in catalog['tools'] if t['name']==name)
    return [{'code':'SCHEMA','path':name,'message':e.message[:400]} for e in Draft202012Validator(tool['outputSchema'],format_checker=FormatChecker()).iter_errors(value)]

def inspect_scope(s,errors,where):
    def fail(code,msg):errors.append({'code':code,'path':where,'message':msg})
    family=4 if s['family']=='ipv4' else 6
    for field in ('source_cidrs','destination_cidrs'):
        nets=[]
        for raw in s[field]:
            try:
                n=ipaddress.ip_network(raw,strict=True)
                if str(n)!=raw:fail('NONCANONICAL_CIDR',raw)
                if n.version!=family:fail('FAMILY_MISMATCH',raw)
                if n.version==6 and n.subnet_of(ipaddress.ip_network('::ffff:0:0/96')):fail('IPV4_MAPPED_IPV6',raw)
                nets.append(n)
            except ValueError:fail('INVALID_CIDR',raw)
        if len(nets)==len(s[field]):
            expected=sorted(nets,key=lambda n:(n.version,int(n.network_address),n.prefixlen))
            if [str(n) for n in expected]!=s[field]:fail('NONCANONICAL_SCOPE_ORDER',field)
            previous=None
            for n in expected:
                if previous is not None and previous.version==n.version and int(n.network_address)<=int(previous.broadcast_address):
                    fail('OVERLAPPING_CIDR_LIST',field);break
                previous=n
    for field in ('source_asset_ids','destination_asset_ids','ingress_interfaces','egress_interfaces'):
        if s[field]!=sorted(s[field]):fail('NONCANONICAL_SCOPE_ORDER',field)
    p=s['transport']['protocol']
    if (p=='icmp' and family!=4) or (p=='icmpv6' and family!=6):fail('FAMILY_MISMATCH',p)
    if p in ('tcp','udp'):
        ports=s['transport']['destination_ports']
        for x in ports:
            if x['start']>x['end']:fail('PORT_RANGE_REVERSED',str(x))
        if ports!=sorted(ports,key=lambda x:(x['start'],x['end'])):fail('NONCANONICAL_PORT_ORDER','destination_ports')
        if any(a['end']>=b['start'] for a,b in zip(ports,ports[1:])):fail('OVERLAPPING_PORT_RANGES','destination_ports')
    i,o=s['ingress_interfaces'],s['egress_interfaces'];direction=s['direction']
    if direction=='input' and (not i or o):fail('INTERFACE_DIRECTION','input requires ingress only')
    if direction=='output' and (i or not o):fail('INTERFACE_DIRECTION','output requires egress only')
    if direction=='forward' and (not i or not o):fail('INTERFACE_DIRECTION','forward requires ingress and egress')

def policy_errors(p):
    errors=schema_errors(p,'Policy')
    if errors:return errors
    inspect_scope(p['scope'],errors,'policy.scope')
    life=p['lifetime'];start=instant(life['not_before'])
    end=instant(life['expires_at'] if p['action']=='allow' else life['review_at'])
    duration=(end-start).total_seconds()
    if duration<=0:errors.append({'code':'INVALID_LIFETIME','path':'policy.lifetime','message':'end must be after start'})
    limit=86400 if p['action']=='allow' else 90*86400
    if duration>limit:errors.append({'code':'LIFETIME_LIMIT','path':'policy.lifetime','message':'v1 lifetime/review interval exceeded'})
    return errors

def validate_bundle(b,at):
    errors=schema_errors(b)
    if errors:return errors
    now=instant(at)
    def require(condition,code,path,message):
        if not condition:errors.append({'code':code,'path':path,'message':message})
    policies=b['requested_policies'];req=b['access_request'];env=b['envelope'];dele=b['delegation'];plan=b['plan'];grant=b['grant'];gp=grant['payload']
    try:
        encoded=grant['dsse']['payload']
        decoded=base64.b64decode(encoded+'='*((-len(encoded))%4),altchars=b'-_',validate=True)
        require(decoded==canonical_bytes(gp),'DSSE_PAYLOAD_MISMATCH','grant.dsse.payload','decoded signed bytes differ from application payload')
        for sig in grant['dsse']['signatures']:
            raw=sig['sig'];decoded_sig=base64.b64decode(raw+'='*((-len(raw))%4),altchars=b'-_',validate=True)
            require(len(decoded_sig)==64,'SIGNATURE_LENGTH','grant.dsse.signatures','Ed25519 signature requires 64 bytes')
    except (binascii.Error,ValueError):require(False,'DSSE_ENCODING','grant.dsse','invalid DSSE base64 encoding')
    require(len({p['policy_id'] for p in policies})==len(policies),'DUPLICATE_POLICY_ID','requested_policies','an access patch has one revision per policy ID')
    for p in policies:errors.extend(policy_errors(p))
    inspect_scope(env['scope'],errors,'envelope.scope')
    excluded=[]
    for raw in env['excluded_destination_cidrs']:
        try:
            n=ipaddress.ip_network(raw,strict=True);excluded.append(n)
            require(str(n)==raw,'NONCANONICAL_CIDR','envelope.excluded_destination_cidrs',raw)
        except ValueError:require(False,'INVALID_CIDR','envelope.excluded_destination_cidrs',raw)
    for x,name in ((env,'envelope'),(dele,'delegation')):
        require(instant(x['valid_from'])<instant(x['valid_until']),'INVALID_LIFETIME',name,'invalid authority window')
        require(instant(x['valid_from'])<=now<instant(x['valid_until']),'AUTHORITY_EXPIRED',name,'authority not currently valid')
    require(dele['envelope_id']==env['envelope_id'] and dele['envelope_hash']==digest(env),'ENVELOPE_REFERENCE','delegation','envelope mismatch')
    for x,name in [(env,'envelope'),(dele,'delegation'),(gp,'grant')]+[(p,'policy') for p in policies]:
        for k in ('org_id','project_id','target_id'):
            require(x[k]==plan[k],'BOUNDARY_MISMATCH',name+'.'+k,'different organization/project/target')
    require(plan['principal_id'] in dele['allowed_principal_ids'],'PRINCIPAL_UNAUTHORIZED','plan.principal_id','principal is outside root delegation')
    require(plan['workload_binding_id']==req['workload_binding_id'] and req['workload_binding_id'] in dele['workload_binding_ids'],'WORKLOAD_UNBOUND','plan.workload_binding_id','request and delegation binding mismatch')
    for field in ('source_asset_ids','destination_asset_ids'):
        require(set(req[field])<=set(dele[field]),'DELEGATION_SCOPE','request.'+field,'requested assets outside delegation')
    require(req['service_id'] in dele['service_ids'],'DELEGATION_SERVICE','request.service_id','service not delegated')
    require({'request_access','request_deployment'}<=set(dele['allowed_tools']),'TOOL_NOT_DELEGATED','delegation.allowed_tools','create/deploy tool missing')
    require(req['lease_seconds']<=min(env['max_lease_seconds'],dele['max_lease_seconds']),'LEASE_LIMIT','request.lease_seconds','lease exceeds envelope/delegation intersection')
    for p in policies:
        require(p['action']=='allow','GRANT_ACTION','policy.action','v1 access grants only create allow leases')
        ps=p['scope'];es=env['scope']
        for f in ('family','direction'):
            require(ps[f]==es[f],'SCOPE_OUTSIDE_ENVELOPE','policy.scope.'+f,'scope semantics differ')
        for f in ('source_asset_ids','destination_asset_ids'):
            require(set(ps[f])==set(req[f]),'REQUEST_POLICY_MISMATCH','policy.scope.'+f,'resolved assets differ from requested assets')
            require(set(ps[f])<=set(es[f]),'SCOPE_OUTSIDE_ENVELOPE','policy.scope.'+f,'assets outside envelope')
        for f in ('ingress_interfaces','egress_interfaces'):
            require(set(ps[f])<=set(es[f]),'SCOPE_OUTSIDE_ENVELOPE','policy.scope.'+f,'interfaces outside envelope')
        for f in ('source_cidrs','destination_cidrs'):
            try:
                parents=[ipaddress.ip_network(n,strict=True) for n in es[f]]
                children=[ipaddress.ip_network(n,strict=True) for n in ps[f]]
                for n in children:require(any(n.version==pnet.version and n.subnet_of(pnet) for pnet in parents),'SCOPE_OUTSIDE_ENVELOPE','policy.scope.'+f,str(n))
                if f=='destination_cidrs':
                    for n in children:require(not any(n.version==ex.version and n.overlaps(ex) for ex in excluded),'PROTECTED_DESTINATION','policy.scope.destination_cidrs',str(n))
            except ValueError:pass # precise parse errors are already reported
        pt,et=ps['transport'],es['transport']
        require(pt['protocol']==et['protocol'],'SCOPE_OUTSIDE_ENVELOPE','policy.scope.transport','protocol mismatch')
        if pt['protocol']==et['protocol']:
            if pt['protocol'] in ('tcp','udp'):
                for pr in pt['destination_ports']:require(any(er['start']<=pr['start']<=pr['end']<=er['end'] for er in et['destination_ports']),'SCOPE_OUTSIDE_ENVELOPE','policy.scope.transport','port interval outside envelope')
            else:require(pt==et,'SCOPE_OUTSIDE_ENVELOPE','policy.scope.transport','ICMP type/code mismatch')
        if p['action']=='allow':
            life=p['lifetime'];start,end=instant(life['not_before']),instant(life['expires_at'])
            require((end-start).total_seconds()==req['lease_seconds'],'LEASE_DURATION_MISMATCH','policy.lifetime','policy/request lease duration differs')
            require(start>=max(instant(env['valid_from']),instant(dele['valid_from'])) and end<=min(instant(env['valid_until']),instant(dele['valid_until'])),'LIFETIME_OUTSIDE_AUTHORITY','policy.lifetime','lease exceeds authority window')
            require(end<=instant(plan['workload_binding_valid_until']),'LIFETIME_OUTSIDE_WORKLOAD','policy.lifetime','lease exceeds verified workload binding lifetime')
    require(plan['request_hash']==digest(req),'REQUEST_HASH','plan.request_hash','request hash mismatch')
    hashes=sorted(digest(p) for p in policies)
    require(plan['requested_policy_hashes']==hashes,'POLICY_HASH','plan.requested_policy_hashes','policy revision/hash mismatch')
    ordered=sorted(policies,key=lambda p:(p['policy_id'],p['policy_revision']))
    require(plan['requested_policies']==ordered,'REQUESTED_POLICIES_MISMATCH','plan.requested_policies','reviewed access patch differs from plan request snapshot')
    require(plan['request_patch_hash']==digest(ordered),'REQUEST_PATCH_HASH','plan.request_patch_hash','access patch content hash mismatch')
    require(plan['envelope_hash']==digest(env) and plan['delegation_hash']==digest(dele),'AUTHORITY_HASH','plan','authority snapshot hash mismatch')
    require(instant(plan['created_at'])<=now<instant(plan['valid_until']),'PLAN_STALE','plan','plan validity window expired')
    gate_ids=[g['gate_id'] for g in plan['gates']]
    mandatory={'schema','identity','scope','quota','semantic','expiry','capability','baseline'}
    require(len(gate_ids)==len(set(gate_ids)) and mandatory<=set(gate_ids),'GATE_SET','plan.gates','missing/duplicate mandatory gate')
    require(all(g['required'] and g['result']=='PASS' for g in plan['gates'] if g['gate_id'] in mandatory),'REQUIRED_GATE_NOT_PASS','plan.gates','required gates must pass')
    for k in ('plan_id','request_id','principal_id','workload_binding_id','requested_policy_hashes','authority_epoch','target_generation','envelope_hash','delegation_hash','artifact_hash','baseline_hash','confirm_timeout_seconds','rollback_authority','change_kind','request_patch_hash','desired_state_hash'):
        require(gp[k]==plan[k],'GRANT_REFERENCE','grant.payload.'+k,'grant differs from plan')
    require(gp['plan_hash']==digest(plan),'PLAN_HASH','grant.payload.plan_hash','plan hash mismatch')
    for k in ('authority_epoch','target_generation'):
        require(int(plan[k])<=18446744073709551615,'COUNTER_OVERFLOW','plan.'+k,'counter exceeds u64')
    issued,end=instant(gp['issued_at']),instant(gp['not_after'])
    require(0<(end-issued).total_seconds()<=300,'GRANT_TTL','grant.payload','grant window must be at most 300s')
    require(issued<=now<end,'GRANT_EXPIRED','grant.payload','grant cannot initiate a new write at this time')
    require(end<=min(instant(plan['valid_until']),instant(env['valid_until']),instant(dele['valid_until'])),'GRANT_WINDOW','grant.payload.not_after','grant extends beyond plan/authority window')
    confirm_end=instant(gp['confirm_not_after'])
    require(0<(confirm_end-end).total_seconds()<=gp['confirm_timeout_seconds'],'CONFIRM_WINDOW','grant.payload.confirm_not_after','absolute confirm cap exceeds dispatch expiry plus confirmation timeout')
    require(instant(gp['rollback_authority']['valid_until'])>=confirm_end,'ROLLBACK_WINDOW','grant.payload.rollback_authority','recovery authority must cover the confirmation window')
    require(gp['rollback_authority']['baseline_hash']==plan['baseline_hash'],'ROLLBACK_BASELINE','grant.payload.rollback_authority','recovery baseline differs from approved plan')
    reservation=gp['reservation']
    require(reservation['root_id']==dele['root_id'],'RESERVATION_ROOT','grant.payload.reservation','wrong quota root')
    require(instant(reservation['reserved_until'])>=end,'RESERVATION_EXPIRED','grant.payload.reservation','reservation expires before grant')
    require(instant(reservation['window_end'])==issued and (instant(reservation['window_end'])-instant(reservation['window_start'])).total_seconds()==86400,'QUOTA_WINDOW','grant.payload.reservation','quota must use the rolling 24-hour grant-issuance snapshot')
    counters=[('projected_active_leases','max_active_leases'),('projected_new_leases_per_day','max_new_leases_per_day'),('projected_unique_destinations_per_day','max_unique_destinations_per_day'),('projected_cumulative_lease_seconds_per_day','max_cumulative_lease_seconds_per_day'),('projected_concurrent_deployments','max_concurrent_deployments')]
    for actual,limit in counters:require(reservation[actual]<=dele[limit],'QUOTA_EXCEEDED','grant.payload.reservation.'+actual,'projected aggregate exceeds root quota')
    require(reservation['projected_unique_destinations_per_day']>=len(req['destination_asset_ids']) and reservation['projected_cumulative_lease_seconds_per_day']>=req['lease_seconds'],'QUOTA_UNDERCOUNT','grant.payload.reservation','projection omits current request')
    receipts={r['receipt_id']:r for r in b['receipts']}
    for r in b['receipts']:
        for k in ('grant_id','target_id','authority_epoch','target_generation'):
            require(r[k]==gp[k],'RECEIPT_REFERENCE','receipt.'+k,'receipt/grant mismatch')
        require(r['grant_hash']==digest(grant) and r['plan_hash']==digest(plan),'RECEIPT_HASH','receipt','receipt hash chain mismatch')
        require(instant(r['recorded_at'])<=now,'FUTURE_RECEIPT','receipt.recorded_at','receipt is from the future')
        if r['state']=='active':
            require(r['observed_state_hash']==plan['desired_state_hash'],'OBSERVED_STATE_MISMATCH','receipt.observed_state_hash','observed state differs from plan')
            require(issued<=instant(r['verified_at'])<=instant(r['recorded_at']),'RECEIPT_TIME','receipt.verified_at','invalid verification time')
            applied,confirmed=instant(r['applied_at']),instant(r['confirmed_at'])
            require(issued<=applied<end and applied<=instant(r['verified_at'])<=confirmed<=instant(r['recorded_at']),'CONFIRM_SEQUENCE','receipt','apply/verify/confirm/durable-record order is invalid')
            require(0<=(confirmed-applied).total_seconds()<=gp['confirm_timeout_seconds'] and confirmed<=confirm_end,'CONFIRM_DEADLINE','receipt.confirmed_at','confirmation exceeded approved deadline')
    for m in b['mcp_results']:
        errors.extend(tool_output_errors(m['tool'],m))
        data=m['data']
        if m['tool']=='get_plan' and m['status']=='ready':
            require(data['plan_hash']==digest(plan) and data['plan']==plan,'MCP_PLAN_REFERENCE','mcp_results','different plan returned')
            if data['approval_state'] in ('approved','delegated'):require(data['approval_set_hash']==gp['approval_set_hash'],'APPROVAL_REFERENCE','mcp_results','approval hash differs from deployment authority')
        if m['tool']=='get_operation' and m['kind']=='validate' and m['state']=='succeeded':require(data['plan_id']==plan['plan_id'] and data['plan_hash']==digest(plan),'MCP_PLAN_REFERENCE','mcp_results','validation result has wrong plan')
        if m['tool']=='get_operation' and m['kind']=='deploy' and m['state']=='active':
            require(data['grant_id']==gp['grant_id'] and data['lease_id']==gp['lease_id'],'MCP_GRANT_REFERENCE','mcp_results','wrong active grant/lease')
            for t in data['target_results']:
                r=receipts.get(t['receipt_id'])
                require(r is not None and r['state']=='active' and r['target_id']==t['target_id']==plan['target_id'],'ACTIVE_WITHOUT_RECEIPT','mcp_results','active requires matching verified receipt')
            expiries=[p['lifetime']['expires_at'] for p in policies if p['action']=='allow']
            require(bool(expiries) and data['expires_at']==min(expiries) and now<instant(data['expires_at']),'ACTIVE_EXPIRED','mcp_results','active lease has expired or wrong expiry')
        if m['tool']=='get_operation' and m['kind']=='release' and m['state']=='revoked':
            require(data['lease_id']==gp['lease_id'] and all(i in receipts and receipts[i]['state']=='revoked' for i in data['receipt_ids']),'REVOKED_WITHOUT_RECEIPT','mcp_results','revoked requires matching removal receipt')
        if m['tool']=='release_access':require(data['lease_id']==gp['lease_id'],'MCP_GRANT_REFERENCE','mcp_results','wrong released lease')
        if m['tool']=='request_deployment' and m['status']=='accepted':require(data['plan_id']==plan['plan_id'] and data['plan_hash']==digest(plan),'MCP_PLAN_REFERENCE','mcp_results','deployment request has wrong plan')
    return errors

def self_test():
    schema=read_json(SCHEMA_PATH);cat=read_json(CATALOG_PATH);fixture=read_json(EXAMPLE_PATH);when=fixture['fixture_time']
    Draft202012Validator.check_schema(schema)
    for t in cat['tools']:
        for key in ('inputSchema','outputSchema'):Draft202012Validator.check_schema(t[key])
    results=[]
    def check(name,passed,detail=''):
        results.append({'name':name,'passed':bool(passed),'detail':detail})
    baseline_errors=validate_bundle(fixture,when)
    check('valid_linked_fixture',not baseline_errors,str(baseline_errors[:2]))
    policy=fixture['requested_policies'][0]
    def policy_bad(name,mutate,code):
        p=copy.deepcopy(policy);mutate(p);errors=policy_errors(p);check(name,any(e['code']==code for e in errors),','.join(sorted({e['code'] for e in errors})))
    policy_bad('reversed_ports',lambda p:p['scope']['transport']['destination_ports'][0].update(start=6000,end=5000),'PORT_RANGE_REVERSED')
    policy_bad('invalid_cidr',lambda p:p['scope'].update(source_cidrs=['999.999.999.999/99']),'INVALID_CIDR')
    policy_bad('host_bits_in_cidr',lambda p:p['scope'].update(source_cidrs=['10.20.1.10/24']),'INVALID_CIDR')
    policy_bad('family_mismatch',lambda p:p['scope'].update(family='ipv6'),'FAMILY_MISMATCH')
    policy_bad('icmp_family_mismatch',lambda p:p['scope'].update(transport={'protocol':'icmpv6','type':128,'code':0}),'FAMILY_MISMATCH')
    policy_bad('expiry_before_start',lambda p:p['lifetime'].update(expires_at='2026-10-30T08:00:00Z'),'INVALID_LIFETIME')
    policy_bad('lease_over_24h',lambda p:p['lifetime'].update(expires_at='2026-11-01T09:00:00Z'),'LIFETIME_LIMIT')
    policy_bad('forward_missing_interface',lambda p:p['scope'].update(egress_interfaces=[]),'INTERFACE_DIRECTION')
    policy_bad('unknown_policy_property',lambda p:p.update(priority=1),'SCHEMA')
    policy_bad('non_nfc_domain_value',lambda p:p.update(reason='e\u0301'),'NON_NFC_VALUE')
    policy_bad('ipv4_mapped_ipv6',lambda p:p['scope'].update(family='ipv6',source_cidrs=['::ffff:a14:10a/128'],destination_cidrs=['::ffff:a14:214/128']),'IPV4_MAPPED_IPV6')
    deny=copy.deepcopy(policy);deny.update(action='deny',lifetime={'kind':'review','not_before':'2026-10-30T09:00:00Z','review_at':'2026-11-29T09:00:00Z'})
    check('deny_review_valid',not policy_errors(deny))
    deny['lifetime']['expires_at']='2026-11-29T09:00:00Z';check('deny_cannot_have_enforcement_expiry',bool(policy_errors(deny)))
    def bad(name,mutate,code):
        b=copy.deepcopy(fixture);mutate(b);errors=validate_bundle(b,when);check(name,any(e['code']==code for e in errors),','.join(sorted({e['code'] for e in errors})))
    bad('outside_envelope',lambda b:b['requested_policies'][0]['scope'].update(destination_cidrs=['192.0.2.10/32']),'SCOPE_OUTSIDE_ENVELOPE')
    bad('unauthorized_principal',lambda b:b['plan'].update(principal_id='00000000-0000-4000-8000-000000000099'),'PRINCIPAL_UNAUTHORIZED')
    bad('wrong_workload',lambda b:b['access_request'].update(workload_binding_id='00000000-0000-4000-8000-000000000099'),'WORKLOAD_UNBOUND')
    bad('delegation_quota_exceeded',lambda b:b['grant']['payload']['reservation'].update(projected_active_leases=6),'QUOTA_EXCEEDED')
    bad('quota_undercount',lambda b:b['grant']['payload']['reservation'].update(projected_cumulative_lease_seconds_per_day=60),'QUOTA_UNDERCOUNT')
    bad('concurrent_deployment_quota',lambda b:b['grant']['payload']['reservation'].update(projected_concurrent_deployments=2),'QUOTA_EXCEEDED')
    bad('wrong_quota_window',lambda b:b['grant']['payload']['reservation'].update(window_start='2026-10-29T08:00:00Z'),'QUOTA_WINDOW')
    bad('lease_beyond_workload_lifetime',lambda b:b['plan'].update(workload_binding_valid_until='2026-10-30T09:10:00Z'),'LIFETIME_OUTSIDE_WORKLOAD')
    bad('signed_bytes_payload_mismatch',lambda b:b['grant']['payload'].update(request_id='00000000-0000-4000-8000-000000000099'),'DSSE_PAYLOAD_MISMATCH')
    bad('confirmation_deadline_exceeded',lambda b:b['receipts'][0].update(confirmed_at='2026-10-30T09:01:01Z'),'CONFIRM_DEADLINE')
    bad('tampered_plan_hash',lambda b:b['grant']['payload'].update(plan_hash='sha256:'+'0'*64),'PLAN_HASH')
    bad('stale_policy_revision',lambda b:b['requested_policies'][0].update(policy_revision=2),'POLICY_HASH')
    bad('wrong_generation',lambda b:b['grant']['payload'].update(target_generation='6'),'GRANT_REFERENCE')
    bad('required_gate_unknown',lambda b:b['plan']['gates'][0].update(result='UNKNOWN'),'REQUIRED_GATE_NOT_PASS')
    bad('missing_required_gate',lambda b:b['plan']['gates'].pop(),'GATE_SET')
    bad('grant_over_5min',lambda b:b['grant']['payload'].update(not_after='2026-10-30T09:10:00Z'),'GRANT_TTL')
    bad('expired_grant',lambda b:b['grant']['payload'].update(not_after='2026-10-30T09:00:01Z'),'GRANT_EXPIRED')
    bad('observed_state_wrong',lambda b:b['receipts'][0].update(observed_state_hash='sha256:'+'0'*64),'OBSERVED_STATE_MISMATCH')
    def unknown_receipt(b):
        r=b['receipts'][0];r.update(state='unknown',observed_state_hash=None,verified_at=None,reason_code='RESULT_UNKNOWN')
        for k in ('new_management_probe_hash','applied_at','confirmed_at','confirm_hash'):r.pop(k)
    bad('active_with_unknown_receipt',unknown_receipt,'ACTIVE_WITHOUT_RECEIPT')
    bad('active_with_unknown_target',lambda b:b['mcp_results'][5]['data']['target_results'][0].update(state='unknown'),'SCHEMA')
    bad('deploy_succeeded_not_active',lambda b:b['mcp_results'][5].update(state='succeeded'),'SCHEMA')
    bad('active_null_data',lambda b:b['mcp_results'][5].update(data=None),'SCHEMA')
    bad('missing_lease_id',lambda b:b['mcp_results'][5]['data'].pop('lease_id'),'SCHEMA')
    bad('child_delegation_forbidden',lambda b:b['delegation'].update(can_delegate=True),'SCHEMA')
    bad('access_patch_cannot_be_ruleset_replace',lambda b:b['plan'].update(change_kind='replace_ruleset'),'SCHEMA')
    def duplicate_policy(b):
        p=copy.deepcopy(b['requested_policies'][0]);p['policy_revision']=2;b['requested_policies'].append(p)
    bad('duplicate_policy_id',duplicate_policy,'DUPLICATE_POLICY_ID')
    bad('request_injected_principal',lambda b:b['access_request'].update(principal_id='attacker'),'SCHEMA')
    for tool in cat['tools']:
        invalid={'tool':tool['name'],'status':'active','data':None}
        check(tool['name']+'_rejects_active_null',not Draft202012Validator(tool['outputSchema'],format_checker=FormatChecker()).is_valid(invalid))
    oversized=copy.deepcopy(fixture['mcp_results'][3]);oversized['data']['plan']['requested_policies']=[copy.deepcopy(policy) for _ in range(256)]
    for i,p in enumerate(oversized['data']['plan']['requested_policies']):p['reason']='x'*2000;p['policy_id']='00000000-0000-4000-8000-'+str(100+i).zfill(12)
    check('output_above_256kib_rejected',any(e['code']=='OUTPUT_TOO_LARGE' for e in tool_output_errors('get_plan',oversized)))
    try:json.loads('{"a":1,"a":2}',object_pairs_hook=no_duplicates);dup=False
    except ValueError:dup=True
    check('duplicate_json_keys_rejected',dup)
    check('canonical_key_order',digest({'b':2,'a':'한글'})==digest({'a':'한글','b':2}))
    check('unicode_not_silently_normalized',digest({'text':'é'})!=digest({'text':'e\u0301'}))
    check('reference_clock_cannot_use_expired_fixture',any(e['code']=='AUTHORITY_EXPIRED' for e in validate_bundle(fixture,'2026-11-01T09:00:00Z')))
    passed=sum(r['passed'] for r in results)
    return {'schema_version':'f.contract-test-report/v1','status':'passed' if passed==len(results) else 'failed','test_count':len(results),'passed':passed,'failed':len(results)-passed,'schema_definitions':len(schema['$defs']),'mcp_tools':len(cat['tools']),'fixture_time':when,'executed_checks':['JSON Schema meta-validation','closed schema and tagged outputs','CIDR/ports/family/interfaces/time semantics','cross-object hashes and identifiers','authority scope and projected quota arithmetic','negative-state mutation fixtures'],'not_executed':['cryptographic signature authenticity','trusted identity and service-to-port resolution','real approval verification','atomic shared quota accounting','baseline plus access-patch composition and full candidate semantics','kernel packet enforcement and expiry','vendor/device interoperability','live MCP protocol conformance'],'signature_authenticity_verified':False,'results':results,'input_hashes':{p.name:'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest() for p in (SCHEMA_PATH,EXAMPLE_PATH,CATALOG_PATH,Path(__file__).resolve(),BASE/'F_차단정책_예제.json')}}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--file',type=Path,default=EXAMPLE_PATH)
    parser.add_argument('--kind',default='ContractFixture')
    parser.add_argument('--at',help='Trusted test clock, UTC YYYY-MM-DDTHH:MM:SSZ. Defaults to real UTC now.')
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    if args.self_test:report=self_test();ok=report['failed']==0
    else:
        value=read_json(args.file);at=args.at or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        errors=validate_bundle(value,at) if args.kind=='ContractFixture' else (policy_errors(value) if args.kind=='Policy' else schema_errors(value,args.kind))
        report={'valid':not errors,'kind':args.kind,'evaluated_at':at,'errors':errors,'signature_authenticity_verified':False,'notice':'Reference data validation only; no authority, approval, or packet enforcement verified.'};ok=not errors
    rendered=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    if args.report:args.report.write_text(rendered,encoding='utf-8')
    print(rendered)
    return 0 if ok else 1

if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,KeyError,FileNotFoundError) as exc:
        print(json.dumps({'valid':False,'error':str(exc)},ensure_ascii=False));sys.exit(2)

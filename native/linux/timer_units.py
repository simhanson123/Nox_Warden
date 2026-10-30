import json, subprocess, time, os
from pathlib import Path
run=lambda args,p=None:subprocess.run(args,input=p,capture_output=True,text=True,check=True).stdout
if os.environ.get('NOX_TIMER_LAB') != '1': raise SystemExit('Only run inside the explicit disposable timer lab')
caps = next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
if int(caps,16) != 1 << 12: raise SystemExit('Requires exactly NET_ADMIN inside isolated container')
if [entry['ifname'] for entry in json.loads(run(['ip','-j','address']))] != ['lo']: raise SystemExit('Requires isolated loopback-only network namespace')
commands=[{'add':{'table':{'family':'inet','name':'nox_timer_units'}}}]
for name,timeout in [('seconds',3),('milliseconds_assumption',3000)]:
 commands.append({'add':{'set':{'family':'inet','table':'nox_timer_units','name':name,'type':'inet_proto','flags':['timeout'],'elem':[{'elem':{'val':6,'timeout':timeout}}]}}})
run(['nft','-j','-f','-'],json.dumps({'nftables':commands}))
start=time.monotonic()
initial=json.loads(run(['nft','-j','list','table','inet','nox_timer_units']))
time.sleep(4)
final=json.loads(run(['nft','-j','list','table','inet','nox_timer_units']))
print(json.dumps({'elapsed_seconds':time.monotonic()-start,'initial':initial,'final':final},indent=2))

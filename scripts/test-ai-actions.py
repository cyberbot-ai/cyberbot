"""Disposable localhost SSH actions. --agent is explicit, billed, and requires explicit test models.

Model-free mode validates a real Nginx change/reload/rollback. Live mode waits 100s
before approving only the fixed memory-only Python snippet, exercising CLI MCP timeouts.
"""
import argparse
import json
import os
import sqlite3
from pathlib import Path
import subprocess
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--agent',choices=['codex','claude'])
mode=p.add_mutually_exclusive_group()
mode.add_argument('--shell',action='store_true',help='Test live MCP grep and approval of a fixed shell script')
mode.add_argument('--review-upgrade',action='store_true',help='Verify a package upgrade reaches approval, then decline it without execution')
p.add_argument('--medium');p.add_argument('--low')
p.add_argument('--image',default='cyberbot-actions-test:local')
p.add_argument('--no-build',action='store_true')
p.add_argument('--binary',type=Path,default=ROOT/'src-tauri/target/debug/cyberbot',help='Cyberbot binary for --no-build')
p.add_argument('--wait-seconds',type=int,default=0,choices=range(31),metavar='0..30',help='Model-free approval wait for resource sampling')
a=p.parse_args()
if a.agent and (not a.medium or not a.low):p.error('Live test requires explicit --medium and --low models')
if a.review_upgrade and not a.agent:p.error('--review-upgrade requires --agent')
binary=str(a.binary.resolve())
os.environ.setdefault('BUILDX_CONFIG',str(ROOT/'.runtime/buildx'))
def run(args,**kw):return subprocess.run(args,check=True,text=True,**kw)
def net(cid):
 data=run(['docker','exec',cid,'cat','/proc/net/dev'],capture_output=True).stdout
 fields=next(line.split(':',1)[1].split() for line in data.splitlines() if line.strip().startswith('eth0:'))
 return int(fields[0])+int(fields[8])
def process_sample(pid):
 rows={}
 for line in subprocess.check_output(['ps','-axo','pid=,ppid=,rss=,time='],text=True).splitlines():
  fields=line.split()
  if len(fields)!=4:continue
  cpu=0
  for value in fields[3].split(':'):cpu=cpu*60+float(value)
  rows[int(fields[0])]={'parent':int(fields[1]),'rss':int(fields[2]),'cpu':cpu}
 ids={pid}
 while True:
  more={key for key,value in rows.items() if value['parent'] in ids}
  if more<=ids:break
  ids|=more
 return {key:rows[key] for key in ids if key in rows}

def fixture_process(args,env,data):
 # Capture output in temporary files so a large report cannot block the child.
 with tempfile.TemporaryFile(mode='w+') as out, tempfile.TemporaryFile(mode='w+') as error:
  process=subprocess.Popen(args,env=env,text=True,stdout=out,stderr=error)
  started=time.monotonic();waiting=[];peak_rss=0;peak_count=0
  try:
   while process.poll() is None:
    if time.monotonic()-started>410:raise TimeoutError('Fixture timeout')
    sample=process_sample(process.pid)
    peak_rss=max(peak_rss,sum(value['rss'] for value in sample.values()))
    peak_count=max(peak_count,len(sample))
    database=Path(data)/'cyberbot.sqlite'
    if database.exists():
     try:
      with sqlite3.connect(f'file:{database}?mode=ro',uri=True,timeout=.05) as db:
       pending=db.execute("SELECT count(*) FROM ai_requests WHERE state='awaitingApproval'").fetchone()[0]
      if pending and process.pid in sample:
       waiting.append((time.monotonic(),sample[process.pid]))
     except sqlite3.Error:pass
    time.sleep(.25)
   out.seek(0);error.seek(0);stdout=out.read();stderr=error.read()
   if process.returncode:raise subprocess.CalledProcessError(process.returncode,args,stdout,stderr)
   report=json.loads(stdout)
   resources={'source':'headless_fixture','peakRssMiBWithAuxiliary':round(peak_rss/1024,2),'peakProcesses':peak_count}
   if len(waiting)>1:
    elapsed=waiting[-1][0]-waiting[0][0]
    resources.update(waitSeconds=round(elapsed,3),brokerWaitRssMiB=round(waiting[-1][1]['rss']/1024,2),brokerWaitCpuOneCorePercent=round(100*(waiting[-1][1]['cpu']-waiting[0][1]['cpu'])/elapsed,3))
   report['resources']=resources
   return report
  finally:
   if process.poll() is None:process.terminate()
   process.wait(timeout=10)

if not a.no_build:
 run(['docker','build','-q','-t','cyberbot-ssh-test:local','-f','tests/integration/Dockerfile','tests/integration'],cwd=ROOT)
 run(['docker','build','-q','-t',a.image,'-f','tests/integration/actions/Dockerfile','tests/integration/actions'],cwd=ROOT)
 run(['bash','scripts/cargo.sh','build','--manifest-path','src-tauri/Cargo.toml'],cwd=ROOT)
with tempfile.TemporaryDirectory(prefix='cyberbot-action-keys-') as temp, tempfile.TemporaryDirectory(prefix='cyberbot-action-data-') as data:
 folder=Path(temp);run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(folder/'id_ed25519')]);(folder/'authorized_keys').write_text((folder/'id_ed25519.pub').read_text())
 cid=run(['docker','run','--rm','-d','--memory','256m','--cpus','1','--pids-limit','64','-v',f'{folder}/authorized_keys:/fixture/authorized_keys:ro','-p','127.0.0.1::22',a.image],capture_output=True).stdout.strip()
 try:
  port=run(['docker','port',cid,'22/tcp'],capture_output=True).stdout.strip().rsplit(':',1)[1]
  for _ in range(100):
   scan=subprocess.run(['ssh-keyscan','-t','ed25519','-p',port,'127.0.0.1'],text=True,capture_output=True)
   if scan.returncode==0 and scan.stdout.strip():break
   time.sleep(.1)
  else:raise RuntimeError('SSH fixture failed')
  (folder/'known_hosts').write_text(scan.stdout)
  before=run(['docker','exec',cid,'sha256sum','/etc/nginx/nginx.conf'],capture_output=True).stdout.split()[0]
  env={**os.environ,'CYBERBOT_TEST_SSH_DIR':str(folder),'CYBERBOT_TEST_SSH_PORT':port,'CYBERBOT_TEST_APPROVAL_WAIT_SECONDS':str(a.wait_seconds)}
  if a.agent:env.update(CYBERBOT_TEST_PRIMARY_MODEL=a.medium,CYBERBOT_TEST_LOW_MODEL=a.low)
  print(json.dumps({'phase':'starting','kind':a.agent or 'model-free','fixturePort':int(port)}),flush=True)
  cold_wire=0
  if a.agent:
   # The same reusable collector is delivered once. Live traffic is then measured warm.
   with tempfile.TemporaryDirectory(prefix='cyberbot-action-warm-') as warm:
    cold_start=net(cid)
    warm_report=run([binary,'--actions-smoke','none',warm],env=env,capture_output=True,timeout=60)
    assert json.loads(warm_report.stdout)['status']=='completed'
    cold_wire=net(cid)-cold_start
  if a.shell:
   run(['docker','exec','-i',cid,'/bin/sh','-s'],input="mkdir -p /home/cyberbot-fixture/.ssh\nprintf 'ffmpeg -version\\n' > /home/cyberbot-fixture/convert.sh\nprintf 'ffmpeg secret\\n' > /home/cyberbot-fixture/.ssh/id_ed25519\n")
   env['CYBERBOT_TEST_SHELL']='1'
  if a.review_upgrade:
   env['CYBERBOT_TEST_REVIEW_UPGRADE']='1'
  wire=net(cid);started=time.monotonic()
  report=fixture_process([binary,'--actions-smoke',a.agent or 'none',data],env,data);report['wireBytes']=net(cid)-wire;report['coldSetupWireBytes']=cold_wire;report['wallSeconds']=round(time.monotonic()-started,3)
  after=run(['docker','exec',cid,'sha256sum','/etc/nginx/nginx.conf'],capture_output=True).stdout.split()[0]
  assert before==after,'Fixture Nginx config was not restored'
  if a.review_upgrade:
   assert report['status']=='completed' and report['declinedExactFixture'] is True and report['sshSlotsDuringWait']==0,report
   assert len(report['requests'])==1,report
   request=report['requests'][0]
   assert request['review']['verdict']['decision']=='confirm' and request['decision']=='deny' and request['result'] is None,report
  elif a.agent:
   assert report['approvedExactFixture'] is True and report['sshSlotsDuringWait']==0,report
   assert len(report['requests'])==1 and report['requests'][0]['state']=='succeeded',report
   if a.shell:
    assert report['requests'][0]['result']['result']['stdout'].startswith('once\n/tmp/cyberbot-shell-fixture.'),report
    assert any(item['tool']=='grep' and item['ok'] for item in report['audit']),report
   else:
    assert report['requests'][0]['result']['result']=={'total':5},report
   assert report['budget']['runs']==2 and report['budget']['uncertainRuns']==0,report
  if a.shell:
   markers=run(['docker','exec',cid,'find','/tmp','-maxdepth','1','-type','f','-name','cyberbot-shell-fixture.*'],capture_output=True).stdout.splitlines()
   assert len(markers)==1 and run(['docker','exec',cid,'cat',markers[0]],capture_output=True).stdout=='once\n'
  suffix='-review-upgrade' if a.review_upgrade else '-shell' if a.shell else ''
  output=ROOT/'.runtime'/f'ai-actions-{a.agent or "model-free"}{suffix}.json';output.write_text(json.dumps(report,ensure_ascii=False,indent=2))
  print(json.dumps({'phase':'completed','kind':a.agent or 'model-free','status':report['status'],'wallSeconds':report['wallSeconds'],'wireBytes':report['wireBytes'],'report':str(output)},ensure_ascii=False),flush=True)
 except subprocess.CalledProcessError as error:
  print(error.stderr or error.stdout or str(error),flush=True);raise
 finally:subprocess.run(['docker','stop','--time','2',cid],stdout=subprocess.DEVNULL,check=False)

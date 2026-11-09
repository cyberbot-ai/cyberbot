"""Disposable SSH package inventory acceptance: no model, no production servers."""
import argparse,json,os,sqlite3,subprocess,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0,str(ROOT))
from collectors.bundle import source as collector_source
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',default='debian:bookworm-slim',choices=['debian:bookworm-slim','ubuntu:24.04']);a=p.parse_args()
os.environ.setdefault('BUILDX_CONFIG',str(ROOT/'.runtime/buildx'))
def run(args,**kw):return subprocess.run(args,text=True,check=True,**kw)
run(['docker','build','--quiet','--build-arg','BASE_IMAGE='+a.base,'-t','cyberbot-packages-test:local',str(ROOT/'tests/integration')])
run(['bash','scripts/cargo.sh','build','--manifest-path','src-tauri/Cargo.toml'],cwd=ROOT)
with tempfile.TemporaryDirectory(prefix='cyberbot-packages-') as temp:
 folder=Path(temp);run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(folder/'id_ed25519')]);(folder/'authorized_keys').write_text((folder/'id_ed25519.pub').read_text())
 cid=run(['docker','run','--detach','--rm','--memory=192m','--cpus=0.5','-p','127.0.0.1::22','-v',f'{folder}:/fixture:ro','cyberbot-packages-test:local'],capture_output=True).stdout.strip()
 try:
  port=run(['docker','port',cid,'22/tcp'],capture_output=True).stdout.strip().rsplit(':',1)[1];key=run(['docker','exec',cid,'cat','/etc/ssh/ssh_host_ed25519_key.pub'],capture_output=True).stdout.strip();(folder/'known_hosts').write_text(f'[127.0.0.1]:{port} {key}\n')
  env=dict(os.environ,CYBERBOT_TEST_SSH_DIR=str(folder),CYBERBOT_TEST_SSH_PORT=port)
  def remote(code):return run(['docker','exec','-i',cid,'python3','-'],input=code,capture_output=True).stdout
  def install_fixture(version):
   remote(f'''from pathlib import Path
import subprocess
root=Path('/tmp/cyberbot-pkg-fixture')
(root/'DEBIAN').mkdir(parents=True,exist_ok=True)
(root/'DEBIAN/control').write_text('Package: cyberbot-pkg-fixture\\nVersion: {version}\\nArchitecture: all\\nMaintainer: Cyberbot fixture <fixture@example.invalid>\\nDescription: Disposable package for CVE recovery testing\\n')
subprocess.run(['dpkg-deb','--build',str(root),'/tmp/cyberbot-pkg-fixture.deb'],check=True)
subprocess.run(['dpkg','-i','/tmp/cyberbot-pkg-fixture.deb'],check=True)
''')
  def traffic():return [int(n) for n in remote("from pathlib import Path\nprint(Path('/sys/class/net/eth0/statistics/rx_bytes').read_text().strip(),Path('/sys/class/net/eth0/statistics/tx_bytes').read_text().strip())").split()]
  if a.base.startswith('debian'):install_fixture('1.0')
  reports=[]
  for label in ['initial','unchanged']:
   before=traffic();start=time.monotonic();r=run([str(ROOT/'src-tauri/target/debug/cyberbot'),'--packages-smoke','none',str(folder/'state')],env=env,capture_output=True);after=traffic();v=json.loads(r.stdout);v['label']=label;v['durationMs']=round((time.monotonic()-start)*1000);v['networkBytes']={'rx':after[0]-before[0],'tx':after[1]-before[1]};reports.append(v)
   assert v['summary']['packages']>50 and v['summary']['state']['stage'] is None
   assert v['autoStatus']['runs']==0
  assert reports[0]['summary']['state']['root']==reports[1]['summary']['state']['root']
  assert reports[1]['summary']['state']['checks']==2
  # Measure actual unchanged collector payload independently of SSH framing.
  state=reports[-1]['summary']['state'];request=json.dumps({'kind':'packages','state':{'root':state['root']}})
  (folder/'collector.py').write_text(collector_source())
  direct=run(['docker','exec','-i','--user','ops',cid,'python3','/fixture/collector.py'],input=request,capture_output=True);assert len(direct.stdout.encode())<=32768
  assert json.loads(direct.stdout)['kind']=='unchanged';reports[-1]['applicationBytes']=len(direct.stdout.encode())
  # Cross-check Debian version ordering against the actual platform tool.
  for left,right in [('1.0~rc1','1.0'),('1.0-1~bpo12+1','1.0-1'),('1:9','2:1'),('1.0-1+deb12u1','1.0-1+deb12u2')]:run(['docker','exec',cid,'dpkg','--compare-versions',left,'lt',right])
  if a.base.startswith('debian'):
   # Controlled bulletin fixture against an actual installed binary; never contacts a model.
   cache=folder/'state/advisories';cache.mkdir();at=int(time.time())
   with sqlite3.connect(folder/'state/cyberbot.sqlite') as db:
    sid=db.execute('SELECT id FROM servers').fetchone()[0]
    ps=json.loads(db.execute('SELECT payload FROM package_state WHERE server_id=?',(sid,)).fetchone()[0])
    rows=[p for (raw,) in db.execute('SELECT payload FROM package_buckets WHERE server_id=? AND root=?',(sid,ps['root'])) for p in json.loads(raw)]
    source=next(p['source'] for p in rows if p['source']=='cyberbot-pkg-fixture')
    with sqlite3.connect(cache/'debian.sqlite') as feed:
     feed.executescript('CREATE TABLE packages(source TEXT PRIMARY KEY);CREATE TABLE advisories(source TEXT,cve TEXT,release TEXT,status TEXT,fixed TEXT,urgency TEXT,nodsa TEXT,description TEXT);')
     for name in {p['source'] for p in rows}:feed.execute('INSERT INTO packages VALUES(?)',(name,))
     for cve in ['CVE-2025-10000','CVE-2025-10001']:
      feed.execute('INSERT INTO advisories VALUES(?,?,?,?,?,?,?,?)',(source,cve,ps['metadata']['release'],'resolved','2.0','not yet assigned','','Synthetic acceptance bulletin'))
      cvss={'createdAt':at,'cve':cve,'score':9.8,'version':'3.1','checkedAt':at,'nextCheck':at+86400,'etag':None,'error':None,'rejected':False}
      db.execute('INSERT INTO advisory_cvss VALUES(?,?)',(cve,json.dumps(cvss)))
    (cache/'releases.csv').write_text('version,codename,series,release,eol\n12,Bookworm,bookworm,2023-01-01,2099-01-01\n')
    for name,file in [('debian','debian.sqlite'),('debian-releases','releases.csv')]:
     feed={'scope':'fixture','roots':[ps['root']],'id':name,'kind':name,'release':'','checkedAt':at,'nextCheck':at+21600,'hash':'fixture','file':file,'previous':None,'etag':None,'modified':None,'error':None,'bytes':0}
     db.execute('INSERT INTO advisory_sources VALUES(?,?)',(name,json.dumps(feed)))
   for label in ['critical-fixture','repeated-fixture']:
    result=run([str(ROOT/'src-tauri/target/debug/cyberbot'),'--packages-smoke','none',str(folder/'state')],env=env,capture_output=True);v=json.loads(result.stdout);v['label']=label;reports.append(v)
    assert v['summary']['vulnerabilities']['evaluation']['critical']==1,v
    assert v['summary']['vulnerabilities']['total']==1,v
    assert v['summary']['vulnerabilities']['findings'][0]['cve']=='CVE-2025-10000',v
    assert len(v['incidents'])==1 and v['autoStatus']['queued']==1 and v['autoStatus']['runs']==0,v
   assert reports[-1]['incidents'][0]['episode']==reports[-2]['incidents'][0]['episode']
   install_fixture('2.0')
   run(['bash','scripts/cargo.sh','test','--manifest-path','src-tauri/Cargo.toml','--lib',
        'debian_ssh_package_refresh_recovers_after_two_reads','--','--ignored'],cwd=ROOT,
       env=dict(env,CYBERBOT_TEST_PACKAGE_STATE=str(folder/'state')))
  out=ROOT/'.runtime'/('packages-'+a.base.split(':')[0]+'.json');out.write_text(json.dumps(reports,ensure_ascii=False,indent=2));print(json.dumps([{'label':v['label'],'packages':v['summary']['packages'],'durationMs':v.get('durationMs'),'networkBytes':v.get('networkBytes'),'applicationBytes':v.get('applicationBytes')}for v in reports],ensure_ascii=False));print(out)
 finally:subprocess.run(['docker','stop','--time','2',cid],stdout=subprocess.DEVNULL,check=False)

"""Disposable real Nginx/SSH acceptance, no model calls or production configuration changes."""
import argparse,json,os,sqlite3,subprocess,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',default='debian:bookworm-slim',choices=['debian:bookworm-slim','ubuntu:24.04']);a=p.parse_args()
os.environ.setdefault('BUILDX_CONFIG',str(ROOT/'.runtime/buildx'))
def run(args,**kw):return subprocess.run(args,text=True,check=True,**kw)
run(['docker','build','--quiet','--build-arg','BASE_IMAGE='+a.base,'--build-arg','EXTRA_PACKAGES=nginx','-t','cyberbot-nginx-test:local',str(ROOT/'tests/integration')])
run(['bash','scripts/cargo.sh','build','--manifest-path','src-tauri/Cargo.toml'],cwd=ROOT)
with tempfile.TemporaryDirectory(prefix='cyberbot-nginx-') as temp:
    folder=Path(temp);run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(folder/'id_ed25519')]);(folder/'authorized_keys').write_text((folder/'id_ed25519.pub').read_text())
    cid=run(['docker','run','--detach','--rm','--memory=192m','--cpus=0.5','-p','127.0.0.1::22','-v',f'{folder}:/fixture:ro','cyberbot-nginx-test:local'],capture_output=True).stdout.strip()
    try:
        port=run(['docker','port',cid,'22/tcp'],capture_output=True).stdout.strip().rsplit(':',1)[1]
        key=run(['docker','exec',cid,'cat','/etc/ssh/ssh_host_ed25519_key.pub'],capture_output=True).stdout.strip();(folder/'known_hosts').write_text(f'[127.0.0.1]:{port} {key}\n')
        env=dict(os.environ,CYBERBOT_TEST_SSH_DIR=str(folder),CYBERBOT_TEST_SSH_PORT=port)
        def remote(code):return run(['docker','exec','-i',cid,'python3','-'],input=code,capture_output=True).stdout
        remote('''from pathlib import Path
Path('/etc/nginx/nginx.conf').write_text('''+repr('''pid /run/nginx.pid;
error_log /var/log/nginx/error.log error;
events {worker_connections 128;}
http {
 log_format timed '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" rt=$request_time urt=$upstream_response_time';
 access_log /var/log/nginx/access.log timed;
 server {listen 127.0.0.1:8080;
 location = /status {stub_status; access_log off;}
 location = /bad {proxy_pass http://127.0.0.1:1;}
 location = /noise {return 404;}
 location / {return 200 'ok';}
 }
}
''')+''')
''')
        run(['docker','exec',cid,'nginx'])
        remote("from pathlib import Path\nfor p in Path('/var/log/nginx').iterdir():p.chmod(0o644)")
        def config_hash():return remote("from pathlib import Path\nimport hashlib\nprint(hashlib.sha256(Path('/etc/nginx/nginx.conf').read_bytes()).hexdigest())").strip()
        original_hash=config_hash();reports=[];out=ROOT/'.runtime'/('nginx-'+a.base.split(':')[0]+'.json')
        def traffic():return [int(n) for n in remote("from pathlib import Path\nprint(Path('/sys/class/net/eth0/statistics/rx_bytes').read_text().strip(),Path('/sys/class/net/eth0/statistics/tx_bytes').read_text().strip())").split()]
        def smoke(label):
            before=traffic();r=run([str(ROOT/'src-tauri/target/debug/cyberbot'),'--service-smoke','nginx',str(folder/'state')],env=env,capture_output=True);after=traffic();report=json.loads(r.stdout)
            report['networkBytes']={'rx':after[0]-before[0],'tx':after[1]-before[1]};report['label']=label;reports.append(report);out.write_text(json.dumps(reports,ensure_ascii=False,indent=2))
            assert config_hash()==original_hash
            assert 'NEVER_SEND' not in r.stdout and 'IGNORE_INSTRUCTIONS' not in r.stdout
            assert report['summary']['bytesReceived']<=32768 and report['summary']['bytesRead']<=2097152
            print(json.dumps({'label':label,'coverage':report['summary']['coverage'],'counts':report['summary']['counts'],'rps':report['summary']['rps'],'bytes':report['summary']['bytesReceived'],'network':report['networkBytes'],'queued':report['autoStatus']['queued']},ensure_ascii=False),flush=True)
            return report
        def advance():
            # Controlled checkpoint clock: avoids waiting 20 minutes; log data and SSH are real.
            with sqlite3.connect(folder/'state/cyberbot.sqlite') as db:
                db.execute("UPDATE nginx_state SET payload=json_set(payload,'$.cursor.at',?,'$.cursor.status.at',?)",(int(time.time())-120,int(time.time())-120))
        def requests(path,n):
            remote(f"import http.client\nfor i in range({n}):\n c=http.client.HTTPConnection('127.0.0.1',8080);c.request('GET',{path!r}+'?token=NEVER_SEND',headers={{'User-Agent':'IGNORE_INSTRUCTIONS'}});r=c.getresponse();r.read();c.close()")
        first=smoke('discovery');assert first['summary']['detected'] and first['summary']['service']=='active';assert first['summary']['status'] is not None
        requests('/noise',1000);advance();noise=smoke('noise');assert noise['autoStatus']['queued']==0 and not noise['incidents'];assert noise['summary']['counts']['4xx']==1000
        requests('/bad',20);advance();bad1=smoke('upstream-first-window');assert bad1['autoStatus']['queued']==0
        requests('/bad',20);advance();bad2=smoke('upstream-persistent');assert bad2['autoStatus']['queued']==2
        episodes=[i['episode'] for i in bad2['incidents']]
        requests('/bad',20);advance();repeat=smoke('repeated-episode');assert repeat['autoStatus']['queued']==2 and [i['episode'] for i in repeat['incidents']]==episodes
        # Rename/reopen is test setup, never performed by the collector.
        remote("from pathlib import Path\nfor name in ['access','error']:\n p=Path('/var/log/nginx/'+name+'.log');p.rename(str(p)+'.1');p.write_text('');p.chmod(0o644)")
        run(['docker','exec',cid,'nginx','-s','reopen'],capture_output=True)
        requests('/',20);advance();quiet1=smoke('rotation-quiet-first');assert all(i['status']=='open' for i in quiet1['incidents'])
        requests('/',20);advance();quiet2=smoke('recovered');assert all(i['status']=='resolved' for i in quiet2['incidents']);assert quiet2['autoStatus']['queued']==0
        assert quiet2['summary']['requestTime']['samples']==20
        # An unreadable error log must not turn into a successful empty check.
        remote("from pathlib import Path\nPath('/var/log/nginx/error.log').chmod(0o600)")
        advance();denied=smoke('error-log-denied');assert not denied['summary']['errorComplete'] and not denied['summary']['coverage']['complete']
        print('Report:',out)
    finally:subprocess.run(['docker','stop','--time','2',cid],stdout=subprocess.DEVNULL,check=False)

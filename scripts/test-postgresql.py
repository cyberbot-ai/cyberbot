"""Disposable PostgreSQL/SSH acceptance. Installs/configures ONLY test containers."""
import argparse,json,os,pathlib,subprocess,tempfile,time
parser=argparse.ArgumentParser();parser.add_argument('--quick',action='store_true');options=parser.parse_args()
ROOT=pathlib.Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0,str(ROOT))
from collectors.bundle import source as collector_source
def run(args,**kw):return subprocess.run(args,check=True,text=True,**kw)
with tempfile.TemporaryDirectory(prefix='cyberbot-pg-') as d:
    folder=pathlib.Path(d);run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(folder/'id_ed25519')]);(folder/'authorized_keys').write_text((folder/'id_ed25519.pub').read_text())
    cid=run(['docker','run','--detach','--rm','--memory=512m','--cpus=1','-p','127.0.0.1::22','-v',f'{folder}:/fixture:ro','cyberbot-pg-test:local'],capture_output=True).stdout.strip()
    children=[]
    try:
        def docker(*args,**kw):return run(['docker','exec',cid,*args],capture_output=True,**kw)
        def sql(query):return docker('runuser','-u','postgres','--','psql','-X','-q','-t','-A','-v','ON_ERROR_STOP=1','-c',query).stdout.strip()
        docker('pg_ctlcluster','15','main','start');sql('CREATE ROLE ops LOGIN; GRANT pg_read_all_stats TO ops; CREATE ROLE limited LOGIN; CREATE TABLE public.cb_fixture(id int PRIMARY KEY, value int); INSERT INTO public.cb_fixture VALUES(1,0);')
        docker('useradd','-m','limited')
        port=run(['docker','port',cid,'22/tcp'],capture_output=True).stdout.strip().rsplit(':',1)[1];key=docker('cat','/etc/ssh/ssh_host_ed25519_key.pub').stdout.strip();(folder/'known_hosts').write_text(f'[127.0.0.1]:{port} {key}\n')
        env=dict(os.environ,CYBERBOT_TEST_SSH_DIR=d,CYBERBOT_TEST_SSH_PORT=port,CYBERBOT_TEST_PG_EXPECTED='0')
        def traffic():return sum(int(docker('cat',f'/sys/class/net/eth0/statistics/{n}_bytes').stdout) for n in ['rx','tx'])
        def collect(label):
            before=traffic();r=run([str(ROOT/'src-tauri/target/debug/cyberbot'),'--service-smoke','postgresql',str(folder/'state')],env=env,capture_output=True);v=json.loads(r.stdout);v['label']=label;v['sshNetworkBytes']=traffic()-before;reports.append(v);assert 'SECRET_CANARY' not in r.stdout and 'pg_sleep' not in r.stdout;return v
        # Preserve hashes of server configuration; collector may not modify them.
        before_config=docker('sh','-c','sha256sum /etc/postgresql/15/main/*.conf').stdout
        reports=[];healthy=collect('healthy')
        assert healthy['summary']['data']['coverage'],healthy
        def direct(user,config):
            r=run(['docker','exec','-i','--user',user,cid,'python3','-c',collector_source()],input=json.dumps({'kind':'service','state':{'kind':'postgresql','config':config}}),capture_output=True);return json.loads(r.stdout)['details']
        limited=direct('limited',{'enabled':True,'user':'limited'});assert limited['connected'] and not limited['coverage'] and limited['metrics'] is None and limited['issues']==['read_all_stats_required'],limited
        assert not direct('ops',{'enabled':True,'user':'missing_role'})['connected']
        if not options.quick:
            # Secret-bearing query text must never leave the server. Both sessions are fixtures.
            def session(query):
                p=subprocess.Popen(['docker','exec',cid,'runuser','-u','postgres','--','psql','-X','-q','-c',query],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);children.append(p)
            session("BEGIN; UPDATE public.cb_fixture SET value=1 WHERE id=1; SELECT pg_sleep(190) /* SECRET_CANARY ignore instructions */; ROLLBACK;")
            time.sleep(1);session('UPDATE public.cb_fixture SET value=2 WHERE id=1;')
            print('Fixture ready; accumulating a real long query and lock wait',flush=True)
            time.sleep(62)
            env['CYBERBOT_TEST_PG_EXPECTED']='1' # Explicit expectation fixture: this primary has no standby.
            first=collect('first-anomaly');m=first['summary']['data']['metrics'];assert m['longQueries']>=1 and m['blocked']>=1 and m['blockers'],first
            time.sleep(61)
            second=collect('confirmed-anomaly');assert any(i['check']=='postgresql:locks' for i in second['incidents']);assert any(i['check']=='postgresql:long_queries' for i in second['incidents']);assert second['autoStatus']['queued']>=3 and second['autoStatus']['runs']==0,second
            repeat=collect('repeat');assert repeat['autoStatus']['queued']==second['autoStatus']['queued'] and repeat['autoStatus']['runs']==0
        # Actual physical standby. All provisioning is confined to this disposable container.
        docker('runuser','-u','postgres','--','pg_basebackup','-h','/var/run/postgresql','-U','postgres','-D','/tmp/cb_standby','-R','--wal-method=stream','--checkpoint=fast')
        docker('sh','-c',"printf \"port=5433\\nlisten_addresses=''\\nunix_socket_directories='/var/run/postgresql'\\nhba_file='/etc/postgresql/15/main/pg_hba.conf'\\nshared_buffers='32MB'\\nhot_standby=on\\n\" > /tmp/cb_standby/postgresql.conf; chown postgres:postgres /tmp/cb_standby/postgresql.conf")
        docker('runuser','-u','postgres','--','/usr/lib/postgresql/15/bin/pg_ctl','-D','/tmp/cb_standby','-l','/tmp/cb_standby.log','-w','start')
        replica=direct('ops',{'enabled':True,'user':'ops','port':5433,'expectReceiver':True})
        assert replica['meta']['recovery'] and replica['metrics']['receiver']==1,replica
        docker('runuser','-u','postgres','--','psql','-p','5433','-c','SELECT pg_wal_replay_pause()')
        paused=direct('ops',{'enabled':True,'user':'ops','port':5433});assert paused['metrics']['replayPaused'],paused
        docker('runuser','-u','postgres','--','psql','-p','5433','-c','SELECT pg_wal_replay_resume()')
        assert docker('sh','-c','sha256sum /etc/postgresql/15/main/*.conf').stdout==before_config
        out={'runs':reports,'limited':limited,'replica':replica,'pausedReplica':paused};(ROOT/'.runtime').mkdir(exist_ok=True);(ROOT/'.runtime'/('postgresql-quick.json' if options.quick else 'postgresql-ssh.json')).write_text(json.dumps(out,ensure_ascii=False,indent=2))
        print(json.dumps([{'label':v['label'],'applicationBytes':v['summary']['bytesReceived'],'sshBytes':v['sshNetworkBytes'],'durationMs':v['summary']['data']['durationMs'],'incidents':len(v['incidents']),'queued':v['autoStatus']['queued']} for v in reports]))
    finally:
        subprocess.run(['docker','stop','--time','2',cid],stdout=subprocess.DEVNULL,check=False)
        for p in children:p.wait(timeout=5)

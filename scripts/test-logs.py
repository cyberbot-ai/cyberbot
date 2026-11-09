"""Disposable log pipeline acceptance. --agent explicitly consumes model tokens."""
import argparse,json,os,subprocess,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',default='debian:bookworm-slim',choices=['debian:bookworm-slim','ubuntu:24.04']);p.add_argument('--agent',choices=['codex','claude']);a=p.parse_args()
os.environ.setdefault('BUILDX_CONFIG',str(ROOT/'.runtime/buildx'))
def run(args,**kw): return subprocess.run(args,text=True,check=True,**kw)
run(['docker','build','--quiet','--build-arg','BASE_IMAGE='+a.base,'-t','cyberbot-logs-test:local',str(ROOT/'tests/integration')])
run(['bash','scripts/cargo.sh','build','--manifest-path','src-tauri/Cargo.toml'],cwd=ROOT)
with tempfile.TemporaryDirectory(prefix='cyberbot-logs-') as temp:
    folder=Path(temp);run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(folder/'id_ed25519')]);(folder/'authorized_keys').write_text((folder/'id_ed25519.pub').read_text())
    cid=run(['docker','run','--detach','--rm','--memory=192m','--cpus=0.5','-p','127.0.0.1::22','-v',f'{folder}:/fixture:ro','cyberbot-logs-test:local'],capture_output=True).stdout.strip()
    try:
        port=run(['docker','port',cid,'22/tcp'],capture_output=True).stdout.strip().rsplit(':',1)[1]
        key=run(['docker','exec',cid,'cat','/etc/ssh/ssh_host_ed25519_key.pub'],capture_output=True).stdout.strip();(folder/'known_hosts').write_text(f'[127.0.0.1]:{port} {key}\n')
        env=dict(os.environ,CYBERBOT_TEST_SSH_DIR=str(folder),CYBERBOT_TEST_SSH_PORT=port)
        reports=[]
        out=ROOT/'.runtime'/('logs-'+a.base.split(':')[0]+('-'+a.agent if a.agent else '')+'.json')
        def remote(code):return run(['docker','exec','-i',cid,'python3','-'],input=code,capture_output=True).stdout
        def traffic():return [int(v) for v in remote("from pathlib import Path\nprint(Path('/sys/class/net/eth0/statistics/rx_bytes').read_text().strip(),Path('/sys/class/net/eth0/statistics/tx_bytes').read_text().strip())").split()]
        def smoke(label,agent='none',state='files'):
            before=traffic();r=run([str(ROOT/'src-tauri/target/debug/cyberbot'),'--logs-smoke',agent,str(folder/state)],env=env,capture_output=True);after=traffic();report=json.loads(r.stdout);report['networkBytes']={'rx':after[0]-before[0],'tx':after[1]-before[1]};report['label']=label;reports.append(report);out.write_text(json.dumps(reports,ensure_ascii=False,indent=2));print(json.dumps({'label':label,'coverage':report['summary']['coverage'],'counts':report['summary']['counts'],'bytes':report['summary']['bytesReceived'],'network':report['networkBytes'],'queued':report['autoStatus']['queued']},ensure_ascii=False));return report
        remote("""from pathlib import Path
from datetime import datetime,timezone
stamp=datetime.now(timezone.utc).isoformat()
Path('/var/log/auth.log').write_text((stamp+' host sshd[123]: Failed password for root from 192.0.2.10 port 1234 ssh2\\n')*1000)
Path('/var/log/fail2ban.log').write_text(stamp+' fail2ban.actions [sshd] Ban 192.0.2.10\\n')
Path('/var/log/syslog').write_text('')
for p in ('auth.log','fail2ban.log','syslog'):Path('/var/log/'+p).chmod(0o644)
""")
        first=smoke('file-noise');assert first['autoStatus']['queued']==0 and not first['incidents']
        second=smoke('file-unchanged');assert second['summary']['counts'].get('ssh_failed',0)==0
        remote("""from pathlib import Path
from datetime import datetime,timezone
stamp=datetime.now(timezone.utc).isoformat()
p=Path('/var/log/auth.log')
with p.open('a') as f:f.write(stamp+' host sshd[123]: Accepted publickey for root from 192.0.2.10 port 1234 ssh2\\n')
p.rename('/var/log/auth.log.1');p.write_text('');p.chmod(0o644)
with Path('/var/log/syslog').open('a') as f:f.write(stamp+' host kernel: Out of memory: Killed process 42 secret=NEVER_SEND\\n')
""")
        dangerous=smoke('file-rotation-findings',a.agent or 'none');assert dangerous['autoStatus']['queued']==2;assert dangerous['summary']['counts']['ssh_suspicious_success']==1
        assert 'NEVER_SEND' not in json.dumps(dangerous)
        if a.agent:assert any(x['tool']=='get_log_summary' and x['ok'] for x in dangerous['investigation']['audit'])
        # Generate genuine systemd binary journal with the distro's own importer.
        remote("""import os,subprocess,time,uuid
from pathlib import Path
machine=uuid.uuid4().hex;boot=uuid.uuid4().hex
Path('/etc/machine-id').write_text(machine+'\\n');directory=Path('/run/log/journal')/machine;directory.mkdir(parents=True)
stamp=int((time.time()-2)*1000000)
entries=[]
for comm,message in [('sshd','Failed password for root from 192.0.2.10 port 22 ssh2')]*100+[('kernel','I/O error on disk token=NEVER_SEND')]:
 entries.append(f'__REALTIME_TIMESTAMP={stamp}\\n_BOOT_ID={boot}\\n_MACHINE_ID={machine}\\n_COMM={comm}\\nPRIORITY=3\\nMESSAGE={message}\\n\\n')
subprocess.run(['/usr/lib/systemd/systemd-journal-remote','--output='+str(directory/'system.journal'),'-'],input=''.join(entries).encode(),check=True)
for path in [Path('/run/log/journal'),directory]:path.chmod(0o755)
(directory/'system.journal').chmod(0o644)
""")
        journal=smoke('journal-findings',state='journal');assert 'journal' in journal['summary']['coverage']['sources'];assert journal['summary']['counts']['disk_io']==1
        again=smoke('journal-unchanged',state='journal');assert again['summary']['counts'].get('disk_io',0)==0
        remote("""from pathlib import Path
import subprocess,time,uuid
machine=Path('/etc/machine-id').read_text().strip();directory=Path('/run/log/journal')/machine
old=directory/'system.journal';old.rename(directory/('system@'+uuid.uuid4().hex+'-0000000000000001-0000000000000001.journal'))
boot=uuid.uuid4().hex;stamp=int(time.time()*1000000)
entry=f'__REALTIME_TIMESTAMP={stamp}\\n_BOOT_ID={boot}\\n_MACHINE_ID={machine}\\n_COMM=kernel\\nPRIORITY=3\\nMESSAGE=Out of memory: Killed process 99\\n\\n'
subprocess.run(['/usr/lib/systemd/systemd-journal-remote','--output='+str(old),'-'],input=entry.encode(),check=True);old.chmod(0o644)
""")
        time.sleep(1)
        rotated=smoke('journal-rotation-reboot',state='journal');assert rotated['summary']['counts'].get('oom',0)==1
        assert any(g['reason']=='journal_reboot' for g in rotated['summary']['coverage']['gaps'])
        smoke('journal-vacuum-anchor',state='vacuum')
        remote("import shutil\nshutil.copytree('/run/log/journal','/tmp/journal-save')\nshutil.rmtree('/run/log/journal')")
        vacuum=smoke('journal-vacuum',state='vacuum');assert any(g['reason']=='journal_cursor_lost' for g in vacuum['summary']['coverage']['gaps'])
        remote("import shutil\nshutil.copytree('/tmp/journal-save','/run/log/journal')")
        remote("from pathlib import Path\nfor p in Path('/run/log/journal').rglob('*.journal'):p.chmod(0o600)")
        denied=smoke('journal-access-lost',state='journal');assert not denied['summary']['coverage']['complete']
        assert any(g['reason']=='source_changed' for g in denied['summary']['coverage']['gaps'])
        # Exercise a live journald too, without requiring systemd as container PID 1.
        remote("import shutil\nfrom pathlib import Path\nshutil.rmtree('/run/log/journal')\nPath('/run/log/journal').mkdir()\nPath('/run/systemd/journal').mkdir(parents=True,exist_ok=True)")
        run(['docker','exec','-d',cid,'/lib/systemd/systemd-journald'])
        for attempt in range(30):
            if remote("from pathlib import Path\nprint(int(Path('/run/systemd/journal/socket').exists()))").strip()=='1':break
            time.sleep(.1)
        remote("""import socket
from pathlib import Path
with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sock:
 sock.connect('/run/systemd/journal/socket')
 sock.send(b'MESSAGE=I/O error on disk live-journal secret=NEVER_SEND\\nPRIORITY=3\\nSYSLOG_IDENTIFIER=cyberbot-test\\n')
""")
        time.sleep(1)
        remote("from pathlib import Path\nfor p in Path('/run/log/journal').rglob('*'):p.chmod(0o755 if p.is_dir() else 0o644)")
        live=smoke('live-journald',state='live-journal')
        assert 'journal' in live['summary']['coverage']['sources']
        assert live['summary']['counts'].get('disk_io',0)>=1
        assert any(i['check']=='logs:disk_io' for i in live['incidents'])
        assert live['autoStatus']['queued']>=1
        assert 'NEVER_SEND' not in json.dumps(live)
        out=ROOT/'.runtime'/('logs-'+a.base.split(':')[0]+('-'+a.agent if a.agent else '')+'.json');out.write_text(json.dumps(reports,ensure_ascii=False,indent=2));print('Report:',out)
    finally:subprocess.run(['docker','stop','--time','2',cid],stdout=subprocess.DEVNULL,check=False)

"""Local, credential-free Seatbelt/resource acceptance for the bundled worker."""
import argparse, json, pathlib, re, socket, subprocess, tempfile, time
ROOT=pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--binary',type=pathlib.Path);args=parser.parse_args()
exe=(args.binary or ROOT/'src-tauri/target/debug/cyberbot-check-runner').resolve()
source=(ROOT/'src-tauri/src/check_runtime.rs').read_text()
profile=re.search(r'r#"(\(version 1\).*?)"#',source,re.S).group(1).replace('{path}',json.dumps(str(exe)))
base=['/usr/bin/sandbox-exec','-p',profile,str(exe)]
with tempfile.TemporaryDirectory(prefix='cyberbot-runner-') as d, socket.socket() as listener:
    canary=pathlib.Path(d)/'private';canary.write_text('private canary');listener.bind(('127.0.0.1',0));listener.listen()
    probe=subprocess.run(base+['--isolation-probe',str(canary),f'127.0.0.1:{listener.getsockname()[1]}'],capture_output=True,env={'LC_ALL':'C'},timeout=5)
    assert probe.returncode==0,(probe.returncode,probe.stdout.decode(),probe.stderr.decode())
    isolation=json.loads(probe.stdout);assert isolation['isolated'] and not any(isolation[k] for k in ['read','write','network','shell','env']),isolation
    heap=subprocess.run(base+['--heap-probe'],capture_output=True,env={},timeout=5);assert heap.returncode not in [0,4],heap
    limits={}
    for kind in ["cpu","wall"]:
        started=time.monotonic();p=subprocess.run(base+[f"--{kind}-probe"],capture_output=True,env={},timeout=5);duration=time.monotonic()-started
        assert p.returncode not in [0,4] and duration<4.5,(kind,p.returncode,duration)
        limits[kind]={"exit":p.returncode,"wallMs":round(duration*1000)}
    spec={'format':1,'name':'Memory','description':'Synthetic check','intervalSeconds':180,'badWindows':2,'inputs':['memory_percent'],'severity':'warning','condition':{'op':'gt','left':{'op':'field','name':'memory_percent'},'right':{'op':'constant','value':90}},'tests':[{'name':'high','values':{'memory_percent':95},'expected':'warning'},{'name':'low','values':{'memory_percent':50},'expected':'healthy'},{'name':'missing','values':{},'expected':'unknown'}]}
    request={'spec':spec,'values':{'memory_percent':95},'test':True}
    start=time.monotonic();r=subprocess.run(base,input=json.dumps([request]).encode(),capture_output=True,env={},timeout=5);elapsed=time.monotonic()-start
    assert r.returncode==0,r.stderr;result=json.loads(r.stdout);assert result[0]['report']['passed'] and result[0]['status']=='warning'
    request['test']=False;batch=json.dumps([request]*8).encode();r=subprocess.run(base,input=batch,capture_output=True,env={},timeout=5);assert r.returncode==0 and len(json.loads(r.stdout))==8
    rejected=subprocess.run(base,input=b' '*147457,capture_output=True,env={},timeout=5);assert rejected.returncode!=0
    measured=subprocess.run(['/usr/bin/time','-l']+base,input=json.dumps([request]).encode(),capture_output=True,env={},timeout=5);assert measured.returncode==0
    rss=re.search(rb'(\d+)\s+maximum resident set size',measured.stderr)
    report={'isolation':isolation,'limits':limits,'heapCapBytes':16*1024*1024,'heapProbeExit':heap.returncode,'wallMs':round(elapsed*1000,2),'rssBytes':int(rss[1]) if rss else None,'batchInputBytes':len(batch),'batchOutputBytes':len(r.stdout),'extraSshBytes':0}
    out=ROOT/'.runtime'/('check-runner-bundle.json' if args.binary else 'check-runner.json');out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(report,indent=2));print(json.dumps(report))

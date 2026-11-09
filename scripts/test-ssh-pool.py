"""Disposable SSH pool acceptance + macOS resource benchmark, no real hosts or models."""
import argparse
import ctypes
import functools
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]

def run(args,**kwargs):
    return subprocess.run(args,check=True,text=True,**kwargs)

class Usage(ctypes.Structure):
    # macOS SDK sys/resource.h: rusage_info_v2. CPU counters use Mach ticks.
    _fields_=[('uuid',ctypes.c_ubyte*16)]+[(key,ctypes.c_uint64) for key in (
        'user','system','idleWakeups','interruptWakeups','pageins','wired','resident','footprint',
        'start','exit','childUser','childSystem','childIdle','childInterrupt','childPageins','childElapsed','read','written')]

@functools.lru_cache(maxsize=1)
def timebase():
    system=ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    class Timebase(ctypes.Structure):
        _fields_=[('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]
    result=Timebase()
    if system.mach_timebase_info(ctypes.byref(result)) or not result.denom:
        raise RuntimeError('mach_timebase_info failed')
    return result.numer,result.denom

def usage(pids):
    lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
    lib.proc_pid_rusage.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p]
    result={}
    for pid in pids:
        value=Usage()
        if lib.proc_pid_rusage(pid,2,ctypes.byref(value)):
            raise OSError(ctypes.get_errno(),f'proc_pid_rusage({pid})')
        numer,denom=timebase()
        result[pid]={'cpuNs':(value.user+value.system)*numer//denom,'rss':value.resident,'footprint':value.footprint,'start':value.start,'wakeups':value.idleWakeups+value.interruptWakeups}
    return result

def calibrate_clock():
    # Refuse misleading CPU figures if a translated interpreter uses virtual Mach time.
    pid=os.getpid();first=usage([pid])[pid];start=time.process_time();wall=time.monotonic()
    while time.monotonic()-wall<.2:pass
    last=usage([pid])[pid];elapsed=time.process_time()-start;counter=(last['cpuNs']-first['cpuNs'])/1e9
    if not .85<=counter/elapsed<=1.15:
        raise RuntimeError('CPU clock calibration failed. Run with native /usr/bin/python3 (on Apple Silicon: /usr/bin/arch -arm64 /usr/bin/python3 scripts/test-ssh-pool.py).')
    return {'counterSeconds':counter,'processSeconds':elapsed,'ratio':counter/elapsed}

def measure(pids,seconds):
    start=time.monotonic();first=usage(pids);samples=[]
    while time.monotonic()-start<seconds:
        time.sleep(min(1,max(.01,seconds-(time.monotonic()-start))))
        sample=usage(pids)
        if any(sample[p]['start']!=first[p]['start'] for p in pids):raise RuntimeError('PID was replaced')
        samples.append({'elapsed':time.monotonic()-start,'rssMiB':sum(v['rss'] for v in sample.values())/1048576,'footprintMiB':sum(v['footprint'] for v in sample.values())/1048576})
    last=usage(pids);elapsed=time.monotonic()-start
    return {'seconds':elapsed,'processes':len(pids),'cpuPercentOneCore':sum(last[p]['cpuNs']-first[p]['cpuNs'] for p in pids)/1e9/elapsed*100,
            'wakeups':sum(last[p]['wakeups']-first[p]['wakeups'] for p in pids),'meanRssMiB':statistics.mean(s['rssMiB'] for s in samples),'meanFootprintMiB':statistics.mean(s['footprintMiB'] for s in samples),'peakFootprintMiB':max(s['footprintMiB'] for s in samples),'samples':samples}

def established(cid):
    code="from pathlib import Path; print(sum(1 for p in ['/proc/net/tcp','/proc/net/tcp6'] for l in Path(p).read_text().splitlines()[1:] if l.split()[1].rsplit(':',1)[1]=='0016' and l.split()[3]=='01'))"
    return int(run(['docker','exec',cid,'python3','-c',code],capture_output=True).stdout)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds',type=int,default=130,help='Idle window; default spans two 60s keepalive periods')
    parser.add_argument('--count',type=int,default=100)
    parser.add_argument('--skip-tests',action='store_true')
    parser.add_argument('--isolation',action='store_true',help='Also check that the actual private master socket is denied by Seatbelt; no model')
    args=parser.parse_args()
    if platform.system()!='Darwin':parser.error('Resource measurement currently requires macOS')
    if not 1<=args.count<=100 or not 1<=args.seconds<=900:parser.error('Invalid limits')
    calibration=calibrate_clock()
    run(['bash','scripts/cargo.sh','build','--manifest-path','src-tauri/Cargo.toml','--example','ssh_pool_bench'],cwd=ROOT)
    image='cyberbot-ssh-test:local'
    if subprocess.run(['docker','image','inspect',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
        buildx=ROOT/'.runtime'/'buildx';buildx.mkdir(parents=True,exist_ok=True)
        run(['docker','build','-t',image,str(ROOT/'tests/integration')],env=dict(os.environ,BUILDX_CONFIG=str(buildx)))
    with tempfile.TemporaryDirectory(prefix='cyberbot-pool-') as temp:
        folder=Path(temp);(folder/'config').write_text('')
        run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(folder/'key')])
        (folder/'authorized_keys').write_text((folder/'key.pub').read_text())
        for i in range(max(3,args.count)):shutil.copyfile(folder/'key',folder/f'key-{i}');os.chmod(folder/f'key-{i}',0o600)
        cid=run(['docker','run','--detach','--rm','--memory=1g','--cpus=2','-p','127.0.0.1::22','-v',f'{folder}:/fixture:ro','cyberbot-ssh-test:local'],capture_output=True).stdout.strip()
        driver=None
        try:
            port=run(['docker','port',cid,'22/tcp'],capture_output=True).stdout.strip().rsplit(':',1)[1]
            host_key=run(['docker','exec',cid,'cat','/etc/ssh/ssh_host_ed25519_key.pub'],capture_output=True).stdout.strip()
            (folder/'known_hosts').write_text(f'[127.0.0.1]:{port} {host_key}\n')
            env=dict(os.environ,CYBERBOT_TEST_SSH_DIR=str(folder),CYBERBOT_TEST_SSH_PORT=port)
            if args.isolation:env['CYBERBOT_TEST_POOL_ISOLATION']='1'
            if not args.skip_tests:
                run(['bash','scripts/cargo.sh','test','--manifest-path','src-tauri/Cargo.toml','--test','ssh_pool','--','--ignored','--nocapture'],cwd=ROOT,env=env)
            driver=subprocess.Popen([str(ROOT/'src-tauri/target/debug/examples/ssh_pool_bench'),str(args.count)],env=env,text=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            selector=selectors.DefaultSelector();selector.register(driver.stdout,selectors.EVENT_READ)
            if not selector.select(timeout=180):raise RuntimeError('Driver startup timed out')
            line=driver.stdout.readline()
            if not line:raise RuntimeError(driver.stderr.read())
            ready=json.loads(line);pids=ready['pids']
            if len(pids)!=args.count or established(cid)!=args.count:raise RuntimeError('Expected real distinct TCP connections')
            print(json.dumps({'stage':'measuring','connections':len(pids),'seconds':args.seconds}),flush=True)
            masters=measure(pids,args.seconds)
            controller=usage([ready['driverPid']])[ready['driverPid']]
            if established(cid)!=args.count:raise RuntimeError('A connection disappeared during measurement')
            driver.stdin.write('close\n');driver.stdin.flush()
            rest,errors=driver.communicate(timeout=20)
            if driver.returncode:raise RuntimeError(errors)
            deadline=time.monotonic()+5
            while established(cid) and time.monotonic()<deadline:time.sleep(.1)
            if established(cid):raise RuntimeError('SSH connections remained after shutdown')
            report={'platform':platform.platform(),'measurementProcessArchitecture':platform.machine(),'kernelTimebase':timebase(),'cpuClockCalibration':calibration,'sshVersion':run(['/usr/bin/ssh','-V'],capture_output=True).stderr.strip(),'scope':'macOS OpenSSH master processes only; fixture sshd/Docker VM/WebView excluded; summed footprint is not whole-system memory delta',
                    'fixture':f'{args.count} distinct identities to one disposable Debian sshd, loopback TCP','ready':ready,'masters':masters,'driverFootprintMiB':controller['footprint']/1048576,'shutdown':json.loads(rest.strip()),'remainingTcpConnections':0}
            path=ROOT/'.runtime'/f'ssh-pool-{args.count}.json';path.parent.mkdir(exist_ok=True);path.write_text(json.dumps(report,indent=2))
            print(json.dumps({k:v for k,v in report.items() if k not in ['ready','masters']}|{'masters':{k:v for k,v in masters.items() if k!='samples'},'report':str(path)},indent=2),flush=True)
        except Exception:
            subprocess.run(['docker','logs','--tail','12',cid],check=False)
            raise
        finally:
            if driver and driver.poll() is None:
                try:driver.communicate(input='close\n',timeout=5)
                except subprocess.TimeoutExpired:driver.kill();driver.wait()
            subprocess.run(['docker','stop','--time','2',cid],stdout=subprocess.DEVNULL,check=False)

if __name__=='__main__':main()

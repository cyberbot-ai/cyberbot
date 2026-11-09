"""Native notification acceptance in a separately signed test .app; no real data, SSH or models."""
import argparse
import json
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--hold', action='store_true', help='Keep the fixture open after acceptance until Enter, for click inspection')
args = parser.parse_args()
if platform.system() != 'Darwin':
    parser.error('macOS required')
built = ROOT / 'src-tauri/target/release/bundle/macos/Cyberbot.app'
if not built.is_dir():
    parser.error('Run make build first')
(ROOT / '.runtime').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='notification-', dir=ROOT / '.runtime') as tmp:
    fixture = Path(tmp) / 'Cyberbot Notifications Test.app'
    data = Path(tmp) / 'data'
    subprocess.run(['ditto', str(built), str(fixture)], check=True)
    info = fixture / 'Contents/Info.plist'
    with info.open('rb') as handle:
        plist = plistlib.load(handle)
    plist.update(CFBundleIdentifier='dev.cyberbot.notification-fixture-v2', CFBundleName='Cyberbot Notifications Test', CFBundleDisplayName='Cyberbot Notifications Test')
    with info.open('wb') as handle:
        plistlib.dump(plist, handle)
    subprocess.run(['codesign', '--force', '--deep', '--sign', '-', str(fixture)], check=True)
    subprocess.run(['codesign', '--verify', '--deep', '--strict', str(fixture)], check=True)
    subprocess.run(['/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister', '-f', str(fixture)], check=True)
    log = (ROOT / '.runtime/notification-native.log').open('w')
    process = subprocess.Popen([str(fixture / 'Contents/MacOS/cyberbot'), '--notification-smoke', str(data)], env=dict(os.environ, CYBERBOT_DATA_DIR=str(data)), stdout=log, stderr=log)
    session = {'pid': process.pid, 'bundle': str(fixture), 'bundleId': plist['CFBundleIdentifier'], 'data': str(data)}
    (ROOT / '.runtime/notification-native-session.json').write_text(json.dumps(session, indent=2))
    print(json.dumps(session), flush=True)
    try:
        deadline = time.monotonic() + 160
        report = data / 'notification-smoke.json'
        while not report.exists() and time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('Fixture exited; see .runtime/notification-native.log')
            time.sleep(.25)
        if not report.exists():
            raise RuntimeError('Notification fixture timed out; check macOS permission')
        result = json.loads(report.read_text())
        (ROOT / '.runtime/notification-native-report.json').write_text(json.dumps(result, indent=2, ensure_ascii=False))
        print(json.dumps(result, ensure_ascii=False), flush=True)
        if args.hold:
            input('Fixture ready for inspection; press Enter to close.\n')
        assert len(result['batches']) == 2, result
        assert all(b['state'] == 'submitted' and b['attempts'] == 1 for b in result['batches']), result
        assert [b['batch']['count'] for b in result['batches']] == [1, 2], result
        assert result['approval']['submitted'] is True, result
        assert result['approval']['windowOpened'] is True, result
        assert result['approval']['state'] == 'awaitingApproval', result
    finally:
        pid_file=data/'fixture.pid'
        if pid_file.exists():
            import signal
            try: os.kill(int(pid_file.read_text()),signal.SIGTERM)
            except ProcessLookupError: pass
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        log.close()

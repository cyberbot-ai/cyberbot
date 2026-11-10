"""Disposable localhost-only SSH fixture. Never changes the user's ~/.ssh."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import argparse

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent',choices=['codex','claude'],help='Also run a real model investigation through MCP; consumes provider tokens')
parser.add_argument('--auto',action='store_true',help='Trigger a synthetic incident through the durable AUTO queue')
parser.add_argument('--budget-stop',action='store_true',help='Use a 1000-token reserve and verify cancellation on reported usage')
options=parser.parse_args()
if (options.auto or options.budget_stop) and not options.agent:
    parser.error('--auto/--budget-stop require --agent')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collectors.bundle import source as collector_source

buildx = ROOT / ".runtime" / "buildx"
buildx.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("BUILDX_CONFIG", str(buildx))


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def verify_partial_poll(folder, port):
    # Exercise a stalled connector over the same SSH fixture without adding
    # any test switches to the production collector.
    script = """
scope = {{'__name__': 'poll_fixture'}}
exec({}, scope)
scope['POLL_TASK_TIMEOUT'] = 1
scope['metrics'] = lambda: {{'cpuPercent': 10}}
scope['dispatch_service'] = lambda _: scope['time'].sleep(30)
scope['server_poll']({{
    'version': 1,
    'tasks': [{{'kind': 'metrics'}}, {{'kind': 'service', 'state': {{}}}}],
}})
""".format(repr(collector_source()))
    output = run(
        [
            "/usr/bin/ssh", "-F", "/dev/null", "-T", "-p", port,
            "-i", str(folder / "id_ed25519"), "-oIdentitiesOnly=yes",
            "-oStrictHostKeyChecking=yes", "-oBatchMode=yes",
            "-oUserKnownHostsFile=" + str(folder / "known_hosts"),
            "ops@127.0.0.1", "python3 -I -B -",
        ],
        input=script, capture_output=True, timeout=10,
    )
    frames = [json.loads(line) for line in output.stdout.splitlines()]
    assert [(frame["id"], frame["event"]) for frame in frames] == [
        (0, "data"), (0, "done"), (1, "error"),
    ], frames
    assert frames[-1]["payload"] == "check_timeout", frames
    print("SSH poll emitted metrics before the stalled connector timed out", flush=True)


run(["docker", "build", "-t", "cyberbot-ssh-test:local", str(ROOT / "tests/integration")])
with tempfile.TemporaryDirectory(prefix="cyberbot-ssh-") as temp:
    folder = Path(temp)
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(folder / "id_ed25519")])
    (folder / "authorized_keys").write_text((folder / "id_ed25519.pub").read_text())
    cid = run(["docker", "run", "--detach", "--rm", "--memory=192m", "--cpus=0.5", "-p", "127.0.0.1::22", "-v", f"{folder}:/fixture:ro", "cyberbot-ssh-test:local"], capture_output=True).stdout.strip()
    try:
        port = run(["docker", "port", cid, "22/tcp"], capture_output=True).stdout.strip().rsplit(":", 1)[1]
        host_key = run(["docker", "exec", cid, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"], capture_output=True).stdout.strip()
        (folder / "known_hosts").write_text(f"[127.0.0.1]:{port} {host_key}\n")
        env = dict(os.environ, CYBERBOT_TEST_SSH_PORT=port, CYBERBOT_TEST_SSH_DIR=str(folder))
        time.sleep(1)
        run(["bash", "scripts/cargo.sh", "test", "--manifest-path", "src-tauri/Cargo.toml", "--lib",
             "server_poll::tests::real_ssh_server_poll", "--", "--ignored", "--nocapture"], cwd=ROOT, env=env)
        run(["bash", "scripts/cargo.sh", "test", "--manifest-path", "src-tauri/Cargo.toml", "--test", "ssh_roundtrip", "--", "--ignored", "--nocapture"], cwd=ROOT, env=env)
        run(["bash", "scripts/cargo.sh", "test", "--manifest-path", "src-tauri/Cargo.toml", "--lib", "console::tests::real_ssh_terminal", "--", "--ignored", "--nocapture"], cwd=ROOT, env=env)
        run(["bash", "scripts/cargo.sh", "test", "--manifest-path", "src-tauri/Cargo.toml", "--lib",
             "fleet_console::tests::real_ssh_fleet_console", "--", "--ignored", "--nocapture"], cwd=ROOT, env=env)
        verify_partial_poll(folder, port)
        if options.agent:
            run(["bash","scripts/cargo.sh","build","--manifest-path","src-tauri/Cargo.toml"],cwd=ROOT)
            with tempfile.TemporaryDirectory(prefix="cyberbot-investigation-") as state:
                result=run([str(ROOT/"src-tauri/target/debug/cyberbot"),("--auto-budget-smoke" if options.budget_stop else "--auto-smoke" if options.auto else "--agent-smoke"),options.agent,state],cwd=ROOT,env=env,capture_output=True)
                report=json.loads(result.stdout)
                if not options.budget_stop:
                    assert any(a['tool']=='get_server' and a['ok'] for a in report['audit']), report
                    if not options.auto:
                        assert any(a['tool']=='refresh_metrics' and a['ok'] for a in report['audit']), report
                if options.auto or options.budget_stop:
                    assert report['autoStatus']['runs']==1, report
                    if options.budget_stop:
                        assert report['autoStatus']['blockedReason'], report
                        assert report['autoStatus']['chargedTokens']>=1000, report
                (ROOT/'.runtime'/f'agent-ssh-{options.agent}{"-budget" if options.budget_stop else "-auto" if options.auto else ""}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
                print(json.dumps({'agent':options.agent,'status':report['status'],'audit':report['audit'],'usage':report['usage']},ensure_ascii=False))
    finally:
        subprocess.run(["docker", "stop", "--time", "2", cid], stdout=subprocess.DEVNULL, check=False)

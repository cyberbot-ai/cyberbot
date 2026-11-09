"""Disposable SSH fixture: two Redis + two PostgreSQL, independent incidents/AUTO, no model.

Build: DOCKER_BUILDKIT=0 docker build --build-arg 'EXTRA_PACKAGES=postgresql redis-server' -t cyberbot-multi-test:local tests/integration
Requires the debug binary built with scripts/cargo.sh.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collectors.bundle import source as collector_source


def run(args, **kw):
    p = subprocess.run(args, capture_output=True, text=True, timeout=120, **kw)
    if p.returncode:
        raise RuntimeError(p.stderr[-4000:])
    return p.stdout.strip()


with tempfile.TemporaryDirectory(prefix="cyberbot-instances-") as d:
    folder = pathlib.Path(d)
    run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(folder / "id_ed25519"),
        ]
    )
    (folder / "authorized_keys").write_text((folder / "id_ed25519.pub").read_text())
    cid = run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--memory",
            "768m",
            "-p",
            "127.0.0.1::22",
            "-v",
            f"{folder}:/fixture:ro",
            "cyberbot-multi-test:local",
        ]
    )
    reports = []
    try:

        def ex(*args):
            return run(["docker", "exec", cid, *args])

        # Own the process as the same unprivileged account used by the SSH fixture.
        address = run(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid])
        run(["docker", "exec", "-i", cid, "sh", "-c", "cat >/tmp/cyberbot-probe.py && chmod 644 /tmp/cyberbot-probe.py"], input=collector_source())
        ex("runuser", "-u", "ops", "--", "redis-server", "--bind", address,
           "--port", "16379", "--maxmemory", "32mb", "--dir", "/tmp", "--daemonize", "yes", "--save", "", "--protected-mode", "no")

        def redis_probe(config):
            request = {"kind": "service", "state": {"kind": "redis", "config": {"enabled": True, **config}}}
            return json.loads(run(["docker", "exec", "-i", "--user", "ops", cid, "python3", "/tmp/cyberbot-probe.py"], input=json.dumps(request)))["details"]

        for config in ({"autoEndpoint": True}, {"endpoint": address, "port": 16379}):
            summary = redis_probe(config)
            assert summary["connected"] and summary["metrics"]["maxMemory"] == 32 * 1024 * 1024, summary
        rejected = redis_probe({"endpoint": "192.0.2.1", "port": 16379})
        assert not rejected["connected"] and rejected["issues"] == ["endpoint_not_local"], rejected
        ex("redis-cli", "-h", address, "-p", "16379", "shutdown", "nosave")
        print("Redis discovery and explicit local IP verified on a nonstandard port", flush=True)

        ex("pg_ctlcluster", "15", "main", "start")
        ex("pg_createcluster", "15", "second", "--port", "5433", "--start")
        for port in [5432, 5433]:
            ex(
                "runuser",
                "-u",
                "postgres",
                "--",
                "psql",
                "-p",
                str(port),
                "-c",
                "CREATE ROLE ops LOGIN; GRANT pg_read_all_stats TO ops;",
            )
        for port, memory in [(6379, "8mb"), (6380, "16mb")]:
            ex(
                "redis-server",
                "--port",
                str(port),
                "--maxmemory",
                memory,
                "--daemonize",
                "yes",
                "--save",
                "",
                "--appendonly",
                "no",
            )
        ssh_port = run(["docker", "port", cid, "22/tcp"]).rsplit(":", 1)[1]
        (folder / "known_hosts").write_text(
            f"[127.0.0.1]:{ssh_port} {ex('cat', '/etc/ssh/ssh_host_ed25519_key.pub')}\n"
        )
        env = dict(os.environ, CYBERBOT_TEST_SSH_DIR=d, CYBERBOT_TEST_SSH_PORT=ssh_port)

        def traffic():
            return sum(
                int(ex("cat", f"/sys/class/net/eth0/statistics/{n}_bytes"))
                for n in ["rx", "tx"]
            )

        def collect(kind, name, port, expected):
            local_env = dict(
                env,
                CYBERBOT_TEST_INSTANCE=name,
                CYBERBOT_TEST_INSTANCE_PORT=str(port),
                CYBERBOT_TEST_SERVICE_PEERS=str(expected),
                CYBERBOT_TEST_PG_EXPECTED=str(expected),
            )
            before = traffic()
            v = json.loads(
                run(
                    [
                        str(ROOT / "src-tauri/target/debug/cyberbot"),
                        "--service-smoke",
                        kind,
                        str(folder / "state"),
                    ],
                    env=local_env,
                )
            )
            v.update(kind=kind, name=name, sshBytes=traffic() - before)
            reports.append(v)
            assert v["summary"]["data"][
                "coverage" if kind == "postgresql" else "complete"
            ], v
            assert v["autoStatus"]["runs"] == 0, v
            return v

        profiles = [
            ("redis", "cache", 6379, 1),
            ("redis", "sessions", 6380, 0),
            ("postgresql", "primary", 5432, 1),
            ("postgresql", "analytics", 5433, 0),
        ]
        for profile in profiles:
            first = collect(*profile)
            assert not first["incidents"], first
        unchanged = ex(
            "sh",
            "-c",
            "find /home/ops/.cache/cyberbot -name '*.py' -exec stat -c '%n %Y %s' {} +",
        )
        print(
            "Four instances collected; waiting for independent confirmation windows",
            flush=True,
        )
        time.sleep(61)
        for profile in profiles:
            confirmed = collect(*profile)
        assert (
            len(confirmed["incidents"]) == 2 and confirmed["autoStatus"]["queued"] == 2
        ), confirmed
        checks = {i["check"] for i in confirmed["incidents"]}
        assert any(c.startswith("service:redis@") for c in checks) and any(
            c.startswith("postgresql@") for c in checks
        ), checks
        repeat = collect(*profiles[0])
        assert (
            repeat["autoStatus"]["queued"] == 2
            and {i["check"] for i in repeat["incidents"]} == checks
        )
        assert unchanged == ex(
            "sh",
            "-c",
            "find /home/ops/.cache/cyberbot -name '*.py' -exec stat -c '%n %Y %s' {} +",
        )
        # Inspect exact saved instance associations, distinct numeric data, and UI/MCP source views.
        import sqlite3

        db = sqlite3.connect(folder / "state" / "cyberbot.sqlite")
        rows = db.execute(
            "SELECT kind,id,name FROM service_instances WHERE id!='default'"
        ).fetchall()
        assert len(rows) == 4, rows
        names = {name: iid for _, iid, name in rows}
        assert any(names["cache"] in c for c in checks) and any(
            names["primary"] in c for c in checks
        )
        assert not any(
            names["sessions"] in c or names["analytics"] in c for c in checks
        )
        redis = [v["summary"]["data"]["metrics"] for v in reports[:2]]
        assert redis[0]["maxMemory"] != redis[1]["maxMemory"], redis
        print(
            json.dumps(
                [
                    dict(
                        kind=v["kind"],
                        name=v["name"],
                        applicationBytes=v["summary"]["bytesReceived"],
                        sshBytes=v["sshBytes"],
                        queued=v["autoStatus"]["queued"],
                    )
                    for v in reports
                ]
            )
        )
    finally:
        (ROOT / ".runtime").mkdir(exist_ok=True)
        (ROOT / ".runtime/instances-ssh.json").write_text(
            json.dumps(reports, ensure_ascii=False, indent=2)
        )
        subprocess.run(
            ["docker", "stop", "-t", "1", cid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )

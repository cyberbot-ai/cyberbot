"""Actual SSH/rsync → two services → SQLite → independent incidents/AUTO; no model."""

import json, os, pathlib, subprocess, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(args, **kw):
    p = subprocess.run(args, capture_output=True, text=True, **kw)
    if p.returncode:
        raise RuntimeError(p.stderr[-4000:])
    return p


with tempfile.TemporaryDirectory(prefix="cyberbot-services-") as d:
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
            "cyberbot-services-test:local",
        ]
    ).stdout.strip()
    report = []
    try:

        def ex(*args):
            return run(["docker", "exec", cid, *args])

        ex("service", "mariadb", "start")
        ex(
            "mariadb",
            "-e",
            "CREATE USER ops@localhost IDENTIFIED VIA unix_socket; GRANT PROCESS, REPLICA MONITOR ON *.* TO ops@localhost;",
        )
        ex("redis-server", "--daemonize", "yes", "--save", "", "--appendonly", "no")
        port = run(["docker", "port", cid, "22/tcp"]).stdout.strip().rsplit(":", 1)[1]
        key = ex("cat", "/etc/ssh/ssh_host_ed25519_key.pub").stdout.strip()
        (folder / "known_hosts").write_text(f"[127.0.0.1]:{port} {key}\n")
        env = dict(
            os.environ,
            CYBERBOT_TEST_SSH_DIR=d,
            CYBERBOT_TEST_SSH_PORT=port,
            CYBERBOT_TEST_SERVICE_PEERS="1",
        )

        def traffic():
            return sum(
                int(ex("cat", f"/sys/class/net/eth0/statistics/{n}_bytes").stdout)
                for n in ["rx", "tx"]
            )

        def collect(kind):
            before = traffic()
            p = run(
                [
                    str(ROOT / "src-tauri/target/debug/cyberbot"),
                    "--service-smoke",
                    kind,
                    str(folder / "state"),
                ],
                env=env,
            )
            v = json.loads(p.stdout)
            v["sshNetworkBytes"] = traffic() - before
            v["kind"] = kind
            report.append(v)
            assert v["autoStatus"]["runs"] == 0
            return v

        first = collect("mysql")
        collect("redis")
        assert not first["incidents"]
        before_files = ex(
            "sh",
            "-c",
            "find /home/ops/.cache/cyberbot -name '*.py' -exec stat -c '%n %Y %s' {} +",
        ).stdout
        print("Waiting for independent confirmation windows", flush=True)
        time.sleep(61)
        collect("mysql")
        confirmed = collect("redis")
        assert confirmed["autoStatus"]["queued"] == 2, confirmed
        repeat = collect("mysql")
        assert repeat["autoStatus"]["queued"] == 2, repeat
        after_files = ex(
            "sh",
            "-c",
            "find /home/ops/.cache/cyberbot -name '*.py' -exec stat -c '%n %Y %s' {} +",
        ).stdout
        assert before_files and before_files == after_files
        assert {i["check"] for i in repeat["incidents"]} == {
            "service:mysql:missingPeers",
            "service:redis:missingPeers",
        }
        print(
            json.dumps(
                [
                    {
                        "kind": v["kind"],
                        "applicationBytes": v["summary"]["bytesReceived"],
                        "sshBytes": v["sshNetworkBytes"],
                        "durationMs": v["summary"]["data"]["durationMs"],
                        "queued": v["autoStatus"]["queued"],
                    }
                    for v in report
                ]
            )
        )
    finally:
        (ROOT / ".runtime/services-ssh.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2)
        )
        subprocess.run(
            ["docker", "stop", "-t", "1", cid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

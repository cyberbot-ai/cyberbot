"""Actual MySQL 8.4, including PROCESS denial. Disposable fixture only."""

import json, pathlib, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collectors.bundle import source

containers = []
report = {}


def run(args, **kw):
    p = subprocess.run(args, capture_output=True, text=True, **kw)
    if p.returncode:
        raise RuntimeError(p.stderr[-2000:])
    return p


def start(image, *args, options=[]):
    cid = run(["docker", "run", "--rm", "-d", *options, image, *args]).stdout.strip()
    containers.append(cid)
    return cid


try:
    db = start(
        "mysql:8.4",
        options=["--memory", "1g", "-e", "MYSQL_ROOT_PASSWORD=SECRET_CANARY"],
    )
    for _ in range(90):
        try:
            run(
                [
                    "docker",
                    "exec",
                    db,
                    "mysql",
                    "-uroot",
                    "-pSECRET_CANARY",
                    "-e",
                    "SELECT 1",
                ]
            )
            break
        except RuntimeError:
            time.sleep(0.5)
    sql = "CREATE USER 'observer'@'127.0.0.1' IDENTIFIED BY 'SECRET_CANARY'; GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'observer'@'127.0.0.1'; CREATE USER 'limited'@'127.0.0.1' IDENTIFIED BY 'SECRET_CANARY';"
    run(["docker", "exec", db, "mysql", "-uroot", "-pSECRET_CANARY", "-e", sql])
    probe = start(
        "cyberbot-services-test:local",
        "600",
        options=["--entrypoint", "sleep", "--network", "container:" + db],
    )
    for user in ["observer", "limited"]:
        run(
            [
                "docker",
                "exec",
                probe,
                "sh",
                "-c",
                "printf '[client]\\nuser="
                + user
                + "\\npassword=SECRET_CANARY\\n' > /home/ops/.my.cnf; chown ops:ops /home/ops/.my.cnf; chmod 600 /home/ops/.my.cnf",
            ]
        )
        p = run(
            ["docker", "exec", "-i", "--user", "ops", probe, "python3", "-c", source()],
            input=json.dumps(
                {
                    "kind": "service",
                    "state": {
                        "kind": "mysql",
                        "config": {"enabled": True, "endpoint": "127.0.0.1"},
                    },
                }
            ),
        )
        report[user] = json.loads(p.stdout)["details"]
        assert "SECRET_CANARY" not in p.stdout
    assert (
        report["observer"]["connected"]
        and report["observer"]["metrics"]["longQueries"] == 0
    ), report["observer"]
    assert (
        report["limited"]["connected"]
        and report["limited"]["metrics"]["longQueries"] is None
        and not report["limited"]["complete"]
    ), report["limited"]
    print(json.dumps(report))
finally:
    (ROOT / ".runtime/mysql-real.json").write_text(json.dumps(report, indent=2))
    for cid in reversed(containers):
        subprocess.run(
            ["docker", "stop", "-t", "1", cid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

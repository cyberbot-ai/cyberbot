"""Disposable real-service acceptance. Provisions only containers created by this script.
Requires cyberbot-services-test:local and mongo:8.0 images.
"""

import json, pathlib, subprocess, sys, time, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collectors.bundle import source


def run(args, **kw):
    p = subprocess.run(args, capture_output=True, text=True, **kw)
    if p.returncode:
        raise RuntimeError(p.stderr[-4000:])
    return p


containers = []
report = {}


def start(image, *args, **kw):
    cid = run(
        ["docker", "run", "--rm", "-d", *kw.get("options", []), image, *args]
    ).stdout.strip()
    containers.append(cid)
    return cid


def ex(cid, *args, **kw):
    return run(["docker", "exec", cid, *args], **kw)


def collect(cid, kind, config=None, user="ops"):
    p = run(
        ["docker", "exec", "-i", "--user", user, cid, "python3", "-c", source()],
        input=json.dumps(
            {
                "kind": "service",
                "state": {"kind": kind, "config": {"enabled": True, **(config or {})}},
            }
        ),
    )
    v = json.loads(p.stdout)["details"]
    assert len(p.stdout.encode()) <= 32768
    assert "SECRET_CANARY" not in p.stdout
    return v


try:
    cid = start(
        "cyberbot-services-test:local",
        "600",
        options=["--entrypoint", "sleep", "--memory", "768m"],
    )
    ex(cid, "service", "mariadb", "start")
    ex(
        cid,
        "mariadb",
        "-e",
        "CREATE USER ops@localhost IDENTIFIED VIA unix_socket; GRANT PROCESS, REPLICA MONITOR ON *.* TO ops@localhost; CREATE USER limited@localhost IDENTIFIED BY 'SECRET_CANARY';",
    )
    report["mariadb"] = collect(cid, "mysql", {"user": "ops"})
    assert report["mariadb"]["complete"], report["mariadb"]
    # Credentials never enter argv or local app state; ignored option cannot execute SQL.
    ex(
        cid,
        "sh",
        "-c",
        "printf '[client]\\nuser=limited\\npassword=SECRET_CANARY\\ninit-command=CREATE DATABASE unsafe_canary\\n' > /home/ops/.my.cnf; chown ops:ops /home/ops/.my.cnf; chmod 600 /home/ops/.my.cnf",
    )
    report["mariadbLimited"] = collect(cid, "mysql")
    assert (
        report["mariadbLimited"]["connected"]
        and not report["mariadbLimited"]["complete"]
    )
    assert report["mariadbLimited"]["metrics"]["longQueries"] is None
    assert (
        "unsafe_canary" not in ex(cid, "mariadb", "-N", "-e", "SHOW DATABASES").stdout
    )
    ex(
        cid,
        "redis-server",
        "--daemonize",
        "yes",
        "--save",
        "",
        "--appendonly",
        "no",
        "--requirepass",
        "SECRET_CANARY",
    )
    report["redisDenied"] = collect(cid, "redis")
    assert not report["redisDenied"]["connected"]
    ex(
        cid,
        "sh",
        "-c",
        "mkdir -p /home/ops/.cache/cyberbot/credentials; printf '%s' '{\"password\":\"SECRET_CANARY\"}' > /home/ops/.cache/cyberbot/credentials/redis.json; chown -R ops:ops /home/ops/.cache; chmod 600 /home/ops/.cache/cyberbot/credentials/redis.json",
    )
    report["redis"] = collect(cid, "redis")
    assert report["redis"]["complete"], report["redis"]
    # nginx/postgresql collectors remain in the same delivered bundle alongside these services.
    # Real MongoDB with authenticated clusterMonitor, shared loopback namespace for Python.
    mongo = start(
        "mongo:8.0",
        options=[
            "--memory",
            "768m",
            "-e",
            "MONGO_INITDB_ROOT_USERNAME=fixture",
            "-e",
            "MONGO_INITDB_ROOT_PASSWORD=SECRET_CANARY",
        ],
    )
    for _ in range(60):
        try:
            ex(
                mongo,
                "mongosh",
                "--quiet",
                "-u",
                "fixture",
                "-p",
                "SECRET_CANARY",
                "--authenticationDatabase",
                "admin",
                "--eval",
                "db.adminCommand({ping:1})",
            )
            break
        except RuntimeError:
            time.sleep(0.5)
    ex(
        mongo,
        "mongosh",
        "--quiet",
        "-u",
        "fixture",
        "-p",
        "SECRET_CANARY",
        "--authenticationDatabase",
        "admin",
        "--eval",
        "db.getSiblingDB('admin').createUser({user:'observer',pwd:'SECRET_CANARY',roles:[{role:'clusterMonitor',db:'admin'}]})",
    )
    probe = start(
        "cyberbot-services-test:local",
        "600",
        options=["--entrypoint", "sleep", "--network", "container:" + mongo],
    )
    ex(
        probe,
        "sh",
        "-c",
        'mkdir -p /home/ops/.cache/cyberbot/credentials; printf \'%s\' \'{"user":"observer","password":"SECRET_CANARY"}\' > /home/ops/.cache/cyberbot/credentials/mongodb.json; chown -R ops:ops /home/ops/.cache; chmod 600 /home/ops/.cache/cyberbot/credentials/mongodb.json',
    )
    report["mongodb"] = collect(probe, "mongodb")
    assert report["mongodb"]["complete"], report["mongodb"]
    assert report["mongodb"]["metrics"]["connections"] is not None, report["mongodb"]
    # Docker GET operations against existing local daemon, no container mutation by collector.
    dock = start(
        "cyberbot-services-test:local",
        "600",
        options=[
            "--entrypoint",
            "sleep",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock:ro",
        ],
    )
    report["docker"] = collect(dock, "docker", user="root")
    assert report["docker"]["complete"], report["docker"]
    print(
        json.dumps(
            {
                k: {
                    "complete": v["complete"],
                    "bytes": len(json.dumps(v)),
                    "durationMs": v["durationMs"],
                    "issues": v["issues"],
                }
                for k, v in report.items()
            },
            ensure_ascii=False,
        )
    )
finally:
    (ROOT / ".runtime").mkdir(exist_ok=True)
    (ROOT / ".runtime/connectors-real.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2)
    )
    for cid in reversed(containers):
        subprocess.run(
            ["docker", "stop", "-t", "1", cid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

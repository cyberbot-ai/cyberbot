"""Disposable ClickHouse and CockroachDB integration, no external infrastructure."""

import json, pathlib, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collectors.bundle import source

containers = []
report = {}


def run(args, **kw):
    p = subprocess.run(args, capture_output=True, text=True, **kw)
    if p.returncode:
        raise RuntimeError(p.stderr[-4000:])
    return p


def start(image, *args, options=[]):
    cid = run(["docker", "run", "-d", *options, image, *args]).stdout.strip()
    containers.append(cid)
    return cid


def ex(cid, *args, **kw):
    return run(["docker", "exec", cid, *args], **kw)


def collect(cid, kind, **config):
    r = run(
        ["docker", "exec", "-i", "--user", "ops", cid, "python3", "-c", source()],
        input=json.dumps(
            {
                "kind": "service",
                "state": {"kind": kind, "config": {"enabled": True, **config}},
            }
        ),
    )
    return json.loads(r.stdout)["details"]


try:
    cr = start(
        "cockroachdb/cockroach:v24.3.0",
        "start-single-node",
        "--insecure",
        "--listen-addr=127.0.0.1:26257",
        "--store=type=mem,size=640MiB",
        "--cache=64MiB",
        "--max-sql-memory=64MiB",
        options=["--memory", "2g"],
    )
    for _ in range(60):
        try:
            ex(cr, "cockroach", "sql", "--insecure", "-e", "SELECT 1")
            break
        except RuntimeError:
            time.sleep(0.5)
    else:
        p = run(["docker", "logs", "--tail", "25", cr])
        raise RuntimeError(p.stdout + p.stderr)
    probe = start(
        "cyberbot-services-test:local",
        "600",
        options=["--entrypoint", "sleep", "--network", "container:" + cr],
    )
    report["cockroach"] = collect(probe, "cockroach", user="root")
    assert report["cockroach"]["complete"], report["cockroach"]
    ex(cr, "cockroach", "sql", "--insecure", "-e", "CREATE USER limited;")
    report["cockroachLimited"] = collect(probe, "cockroach", user="limited")
    ch = start("clickhouse/clickhouse-server:24.8", options=["--memory", "1500m"])
    for _ in range(60):
        try:
            ex(ch, "clickhouse-client", "-q", "SELECT 1")
            break
        except RuntimeError:
            time.sleep(0.5)
    probe2 = start(
        "cyberbot-services-test:local",
        "600",
        options=["--entrypoint", "sleep", "--network", "container:" + ch],
    )
    report["clickhouse"] = collect(probe2, "clickhouse")
    assert report["clickhouse"]["complete"], report["clickhouse"]
    ex(
        ch,
        "clickhouse-client",
        "--multiquery",
        "-q",
        "CREATE USER limited; GRANT SELECT ON system.processes TO limited; GRANT SELECT ON system.replicas TO limited; GRANT SELECT ON system.mutations TO limited;",
    )
    report["clickhouseLimited"] = collect(probe2, "clickhouse", user="limited")
    assert (
        not report["clickhouseLimited"]["complete"]
        and report["clickhouseLimited"]["metrics"]["replicationErrors"] is None
    ), report["clickhouseLimited"]
    print(json.dumps(report, ensure_ascii=False))
finally:
    (ROOT / ".runtime/database-connectors-real.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2)
    )
    for cid in reversed(containers):
        subprocess.run(
            ["docker", "rm", "-f", cid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

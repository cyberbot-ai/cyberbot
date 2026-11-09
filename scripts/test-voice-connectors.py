"""Actual PHP-FPM + Nginx HTTP status and Asterisk in a disposable Ubuntu container.
Changes below provision the fixture only. Collector configuration hashes must stay unchanged.
"""

import json, pathlib, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collectors.bundle import source


def run(args, **kw):
    p = subprocess.run(args, capture_output=True, text=True, **kw)
    if p.returncode:
        raise RuntimeError(p.stderr[-4000:])
    return p


cid = run(
    [
        "docker",
        "run",
        "--rm",
        "-d",
        "--entrypoint",
        "sleep",
        "--memory",
        "768m",
        "cyberbot-voice-test:local",
        "600",
    ]
).stdout.strip()
report = {}
try:

    def ex(*args, **kw):
        return run(["docker", "exec", cid, *args], **kw)

    ex(
        "sh",
        "-c",
        "printf '\n[www]\npm.status_path = /fpm-status\n' > /etc/php/8.3/fpm/pool.d/zz-cyberbot.conf; printf 'server { listen 80; location = /fpm-status { include fastcgi_params; fastcgi_param SCRIPT_FILENAME /fpm-status; fastcgi_pass unix:/run/php/php8.3-fpm.sock; } }' > /etc/nginx/sites-enabled/default",
    )
    ex("service", "php8.3-fpm", "start")
    ex("service", "nginx", "start")
    ex("usermod", "-aG", "asterisk", "ops")
    ex("service", "asterisk", "start")
    for _ in range(40):
        try:
            ready = run(
                [
                    "docker",
                    "exec",
                    "--user",
                    "ops",
                    cid,
                    "/usr/sbin/asterisk",
                    "-rx",
                    "core show channels count",
                ]
            )
            if "active channel" in ready.stdout:
                break
        except RuntimeError:
            pass
        time.sleep(0.5)
    before = ex(
        "sh",
        "-c",
        "find /etc/php /etc/nginx /etc/asterisk -type f -exec sha256sum {} +",
    ).stdout
    for kind in ["php-fpm", "asterisk"]:
        p = run(
            ["docker", "exec", "-i", "--user", "ops", cid, "python3", "-c", source()],
            input=json.dumps(
                {
                    "kind": "service",
                    "state": {"kind": kind, "config": {"enabled": True}},
                }
            ),
        )
        report[kind] = json.loads(p.stdout)["details"]
        assert report[kind]["complete"], (
            report[kind],
            run(
                [
                    "docker",
                    "exec",
                    "--user",
                    "ops",
                    cid,
                    "/usr/sbin/asterisk",
                    "-rx",
                    "core show channels count",
                ]
            ).stdout,
        )
    assert (
        before
        == ex(
            "sh",
            "-c",
            "find /etc/php /etc/nginx /etc/asterisk -type f -exec sha256sum {} +",
        ).stdout
    )
    print(json.dumps(report, ensure_ascii=False))
finally:
    (ROOT / ".runtime/voice-connectors-real.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2)
    )
    subprocess.run(
        ["docker", "stop", "-t", "1", cid],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

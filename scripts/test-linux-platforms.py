"""Real Debian + Alpine capability/kernel-metric smoke, disposable containers only.

Alpine's Python is installed ONLY in this temporary fixture; Cyberbot never installs it.
No production connections or model calls. No claim of full Alpine package/OpenRC support.
"""

import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collectors.bundle import source


def run(args, **kwargs):
    return subprocess.run(
        args, check=True, capture_output=True, text=True, timeout=180, **kwargs
    ).stdout


reports = []
with tempfile.TemporaryDirectory(prefix="cyberbot-linux-") as temp:
    bundle = pathlib.Path(temp) / "collector.py"
    bundle.write_text(source())
    for image, distro, setup in [
        ("cyberbot-multi-test:local", "debian", "python3 /fixture/collector.py"),
        (
            "alpine:3.21",
            "alpine",
            "apk add --no-cache python3 >/dev/null && python3 /fixture/collector.py",
        ),
    ]:
        # Override Debian fixture's SSH entrypoint: this test only measures local collection.
        out = run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--memory",
                "256m",
                "--cpus",
                "1",
                "--entrypoint",
                "/bin/sh",
                "-v",
                f"{temp}:/fixture:ro",
                image,
                "-c",
                setup,
            ],
            input=json.dumps({"kind": "metrics"}),
        )
        data = json.loads(out)
        p = data["platform"]
        assert p["distro"] == distro and p["procfs"], data
        assert (
            data["cpuPercent"] is not None
            and data["memoryPercent"] is not None
            and data["disks"]
        ), data
        assert len(out.encode()) <= 8192
        assert p["packageAdapter"] == (
            "dpkg" if distro == "debian" else "unsupported"
        ), p
        if distro == "alpine":
            assert (
                p["packageManager"] == "apk" and p["advisoryProvider"] == "unsupported"
            ), p
        # Containers do not run an init daemon. Do not mistake installed systemctl for systemd.
        assert (
            p["serviceAdapter"] == "unsupported"
            and "services_adapter_unsupported" in data["missing"]
        ), data
        reports.append(
            {"distro": distro, "applicationBytes": len(out.encode()), "platform": p}
        )
    # Extracted dpkg adapter still produces the bounded pagination manifest on real Debian.
    out = run(
        [
            "docker",
            "run",
            "--rm",
            "-i",
            "--memory",
            "192m",
            "--entrypoint",
            "python3",
            "-v",
            f"{temp}:/fixture:ro",
            "cyberbot-multi-test:local",
            "/fixture/collector.py",
        ],
        input=json.dumps({"kind": "packages"}),
    )
    packages = json.loads(out)
    assert (
        packages["kind"] == "manifest"
        and packages["count"] > 0
        and len(out.encode()) <= 32768
    ), packages
    reports.append(
        {"packages": packages["count"], "applicationBytes": len(out.encode())}
    )
    arch = run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "dpkg",
            "cyberbot-multi-test:local",
            "--print-architecture",
        ]
    ).strip()
    apt = json.loads(
        run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--memory",
                "192m",
                "--entrypoint",
                "/bin/sh",
                "-v",
                f"{temp}:/fixture:ro",
                "cyberbot-multi-test:local",
                "-c",
                """set -e
apt-get update -qq >/dev/null
cat >/etc/apt/apt.conf.d/99cyberbot-fixture <<'APT_CONFIG'
Dir::Cache::pkgcache "/var/cache/apt/cyberbot-fixture-pkgcache.bin";
Dir::Cache::srcpkgcache "/var/cache/apt/cyberbot-fixture-srcpkgcache.bin";
APT_CONFIG
python3 /fixture/collector.py
test ! -e /var/cache/apt/cyberbot-fixture-pkgcache.bin
test ! -e /var/cache/apt/cyberbot-fixture-srcpkgcache.bin""",
            ],
            input=json.dumps(
                {
                    "kind": "packages",
                    "state": {"root": packages["root"], "apt": ["python3:" + arch]},
                }
            ),
        )
    )
    assert (
        apt["kind"] == "apt"
        and len(apt["candidates"]) == 1
        and apt["candidates"][0]["version"]
        and apt["candidates"][0]["sourceVersion"]
        and apt["cacheAt"] is not None
    ), apt
    reports.append({"aptCandidates": len(apt["candidates"]), "cacheAt": apt["cacheAt"]})
(ROOT / ".runtime").mkdir(exist_ok=True)
(ROOT / ".runtime/linux-platforms.json").write_text(json.dumps(reports, indent=2))
print(json.dumps(reports))

"""Linux platform contract v1: trusted profiles, data-only detection, independent capabilities.

No remote input can select a profile, command or path. A family is a layout hint,
not a claim of package/advisory compatibility or sufficient diagnostic rights.
"""

import contextlib
import json
import os
import re
import shlex
import subprocess
import sys

LINUX_PROFILES = {
    "debian": {
        "ids": ("debian", "ubuntu"),
        "managers": ("dpkg",),
        "auth": ("auth.log",),
        "system": ("syslog",),
    },
    "rhel": {
        "ids": ("rhel", "fedora", "centos", "rocky", "almalinux", "ol"),
        "managers": ("rpm",),
        "auth": ("secure",),
        "system": ("messages",),
    },
    "suse": {
        "ids": (
            "suse",
            "opensuse",
            "opensuse-leap",
            "opensuse-tumbleweed",
            "sles",
            "sled",
        ),
        "managers": ("rpm",),
        "auth": ("auth.log", "secure"),
        "system": ("messages",),
    },
    "arch": {
        "ids": ("arch", "manjaro"),
        "managers": ("pacman",),
        "auth": ("auth.log",),
        "system": ("syslog.log", "messages.log"),
    },
    "alpine": {
        "ids": ("alpine",),
        "managers": ("apk",),
        "auth": ("auth.log",),
        "system": ("messages",),
    },
    "generic": {
        "ids": (),
        "managers": (),
        "auth": ("auth.log", "secure"),
        "system": ("syslog", "messages"),
    },
}
LINUX_PACKAGE_DATABASES = {
    "dpkg": ("dpkg-query", ("/var/lib/dpkg/status",)),
    "rpm": ("rpm", ("/var/lib/rpm", "/usr/lib/sysimage/rpm")),
    "apk": ("apk", ("/lib/apk/db/installed",)),
    "pacman": ("pacman", ("/var/lib/pacman/local",)),
}
LINUX_PACKAGE_ADAPTERS = {}  # Registered by the bundled, trusted adapter modules.
LINUX_SERVICE_ADAPTERS = {}


def load_collector_json(data):
    # Python 3.5's JSON decoder requires text.
    if sys.version_info < (3, 6) and isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8-sig")
    return json.loads(data)


@contextlib.contextmanager
def scan_directory(path):
    # Keep descriptor-based reads anchored on Python versions without scandir(fd).
    if isinstance(path, int) and sys.version_info < (3, 7):
        path = "/proc/self/fd/{}".format(path)
    entries = os.scandir(path)
    if sys.version_info < (3, 6):
        yield entries
    else:
        with entries as directory:
            yield directory


def linux_command(name):
    # Never consult the SSH user's PATH or execute os-release values.
    for directory in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        path = directory + "/" + name
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def linux_os_release():
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, encoding="utf-8", errors="replace") as stream:
                raw = stream.read(16385)
            if len(raw) > 16384:
                return {}
            fields = {}
            for line in raw.splitlines():
                if "=" not in line or line.lstrip().startswith("#"):
                    continue
                key, value = line.split("=", 1)
                if key not in ("ID", "ID_LIKE", "VERSION_ID", "VERSION_CODENAME"):
                    continue
                try:
                    parts = shlex.split(value)
                except ValueError:
                    continue
                if len(parts) == 1:
                    fields[key] = parts[0]
            return fields
        except FileNotFoundError:
            continue
        except OSError:
            return {}
    return {}


def linux_token(value, limit=64):
    return (
        value
        if isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9._-]{1," + str(limit) + "}", value)
        else "unknown"
    )


def linux_platform():
    fields = linux_os_release()
    distro = linux_token(fields.get("ID"))
    like = [
        v for v in fields.get("ID_LIKE", "").split()[:8] if linux_token(v) != "unknown"
    ]
    family = "generic"
    # Exact identity takes precedence; ID_LIKE is ordered closest-first.
    for identity in [distro, *like]:
        match = next(
            (key for key, p in LINUX_PROFILES.items() if identity in p["ids"]), None
        )
        if match:
            family = match
            break
    preferred = LINUX_PROFILES[family]["managers"]
    detected = [
        key
        for key, (command, paths) in LINUX_PACKAGE_DATABASES.items()
        if any(os.path.exists(path) for path in paths)
    ]
    manager = next((key for key in preferred if key in detected), None)
    if manager is None:
        manager = detected[0] if len(detected) == 1 else "unknown"
    if os.path.isdir("/run/systemd/system") and linux_command("systemctl"):
        init = "systemd"
    elif os.path.isdir("/run/openrc") and linux_command("rc-status"):
        init = "openrc"
    else:
        init = "unknown"
    package_adapter = (
        manager
        if manager in LINUX_PACKAGE_ADAPTERS
        and linux_command(LINUX_PACKAGE_DATABASES[manager][0])
        else "unsupported"
    )
    uname = os.uname()
    return {
        "version": 1,
        "distro": distro,
        "release": linux_token(fields.get("VERSION_CODENAME")),
        "versionId": linux_token(fields.get("VERSION_ID")),
        "idLike": like,
        "family": family,
        "architecture": linux_token(uname.machine),
        "kernel": linux_token(uname.release, 128),
        "procfs": os.path.isfile("/proc/stat") and os.path.isfile("/proc/meminfo"),
        "initSystem": init,
        "serviceAdapter": init if init in LINUX_SERVICE_ADAPTERS else "unsupported",
        "journalAvailable": linux_command("journalctl") is not None,
        "packageManager": manager,
        "packageAdapter": package_adapter,
        # Never inherit vulnerability coverage via ID_LIKE or package-manager presence.
        "advisoryProvider": (
            distro
            if distro in ("ubuntu", "debian") and package_adapter == "dpkg"
            else "unsupported"
        ),
    }


def linux_log_paths(platform=None):
    profile = LINUX_PROFILES[(platform or linux_platform())["family"]]
    choices = {
        "auth": profile["auth"],
        "syslog": profile["system"],
        "kern": ("kern.log",),
        "fail2ban": ("fail2ban.log",),
    }
    result = {}
    for category, names in choices.items():
        paths = ["/var/log/" + name for name in names]
        result[category] = next((p for p in paths if os.path.isfile(p)), paths[0])
    return result


def linux_services(platform=None):
    platform = platform or linux_platform()
    adapter = LINUX_SERVICE_ADAPTERS.get(platform["serviceAdapter"])
    if adapter is None:
        return [], ["services_adapter_unsupported"]
    return adapter(platform)


class PackageError(ValueError):
    """A fixed diagnostic code safe to return without remote command output."""


def linux_package_adapter():
    platform = linux_platform()
    adapter = LINUX_PACKAGE_ADAPTERS.get(platform["packageAdapter"])
    if adapter is None:
        raise PackageError("package_adapter_unsupported")
    return adapter

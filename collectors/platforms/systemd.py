"""Read-only systemd implementation of the Linux service contract."""

OS_SERVICE_UNITS = ('apache2', 'httpd', 'haproxy', 'rabbitmq-server')


def linux_systemd_services(platform):
    units = {
        unit + '.service': spec.get('ignoreExitedUnit', False)
        for spec in CONNECTOR_CATALOG.values() for unit in spec.get('units', ())
    }
    units.update({unit + '.service': False for unit in OS_SERVICE_UNITS})
    try:
        binary = linux_command("systemctl")
        if binary is None:
            return [], ["services_unavailable"]
        proc = subprocess.run(
            [
                binary,
                "show",
                "--no-pager",
                "--property=Id,LoadState,ActiveState,SubState",
                *(unit[:-8] for unit in units),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=4,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        if len(proc.stdout) > 16384:
            return [], ["services_output_limit"]
        services = {}
        loaded = False
        for block in proc.stdout.decode("utf-8", "replace").strip().split("\n\n"):
            values = dict(
                line.split("=", 1) for line in block.splitlines() if "=" in line
            )
            name, state = values.get("Id", ""), values.get("ActiveState", "unknown")
            if values.get("LoadState") == "loaded" and name in units:
                loaded = True
                if units[name] and values.get("SubState") == "exited":
                    continue
                services[name] = {
                    "name": name,
                    "state": (
                        state
                        if state
                        in (
                            "active",
                            "inactive",
                            "failed",
                            "activating",
                            "deactivating",
                            "reloading",
                        )
                        else "unknown"
                    ),
                }
        return list(services.values()), (
            ["services"] if proc.returncode and not loaded else []
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], ["services"]


LINUX_SERVICE_ADAPTERS["systemd"] = linux_systemd_services

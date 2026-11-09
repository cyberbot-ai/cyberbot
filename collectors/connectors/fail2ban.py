"""Read only aggregate Fail2ban status through its root-owned control socket."""

FAIL2BAN_SOCKET = "/run/fail2ban/fail2ban.sock"
FAIL2BAN_STATS_ROW = re.compile(
    rb"^\s*[^|]+\|\s*[^|]+\|\s*[0-9]+\s*\|\s*[0-9]+\s*\|\s*([0-9]+)\s*\|\s*([0-9]+)\s*$"
)


def fail2ban_interpreter(executable, path):
    if not re.fullmatch(r"python3(?:\.[0-9]+)?", executable):
        return False
    process = os.path.dirname(path)
    if os.stat(process).st_uid != 0:
        return False
    args = service_read_file(process + "/cmdline", 4096).split(b"\0")
    return len(args) > 1 and args[1] == b"/usr/bin/fail2ban-server"


def fail2ban_connector(config, result):
    binary = "/usr/bin/fail2ban-client"
    if not os.path.isfile(binary):
        raise ValueError("client_missing")
    directory = os.lstat(os.path.dirname(FAIL2BAN_SOCKET))
    control = os.lstat(FAIL2BAN_SOCKET)
    # The client deserializes its peer's response. Accept only the system daemon's socket.
    if not (stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and not directory.st_mode & 0o022
            and stat.S_ISSOCK(control.st_mode) and control.st_uid == 0):
        raise ValueError("endpoint_not_local")
    args = [binary, "-s", FAIL2BAN_SOCKET]
    body = service_process([*args, "status"], limit=8192, timeout=2)
    jails = re.search(rb"\bNumber of jail:\s*([0-9]+)\s*$", body, re.M)
    if jails is None:
        raise ValueError("unsupported_version")
    count = int(jails.group(1))
    result["metrics"]["jails"] = service_number(count)
    result.update(connected=True, availability="running")
    if count == 0:
        result["metrics"].update(currentlyBanned=0, totalBanned=0)
    else:
        try:
            # Check the running daemon. The client package may have been upgraded independently.
            version = service_process([*args, "version"], limit=256, timeout=1)
            release = re.match(rb"([0-9]{1,4})\.([0-9]{1,4})\.", version.strip())
            if release and tuple(map(int, release.groups())) >= (1, 1):
                data = service_process([*args, "stats"], limit=16384, timeout=2)
                data = data.replace("║".encode(), b"|").replace("│".encode(), b"|")
                rows = []
                for line in data.splitlines():
                    match = FAIL2BAN_STATS_ROW.fullmatch(line)
                    if match is not None:
                        rows.append(match.groups())
                if len(rows) == count:
                    result["metrics"]["currentlyBanned"] = service_number(sum(int(row[0]) for row in rows))
                    result["metrics"]["totalBanned"] = service_number(sum(int(row[1]) for row in rows))
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass  # Older releases still expose the count of jails.
    service_finish(result)


FAIL2BAN_ADAPTER = observed_service(
    IdentityPolicy("fail2ban-server", "f2b/server", verify_alias=fail2ban_interpreter,
                   sockets=(FAIL2BAN_SOCKET,), tcp_endpoint=False),
    fail2ban_connector, process_only=True, installed=("/usr/bin/fail2ban-server",),
)

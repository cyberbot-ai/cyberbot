"""PgBouncer's read-only console, independently verified from PostgreSQL."""

PGBOUNCER_SOCKET = r'/(?:var/run/(?:postgresql|pgbouncer)|run/(?:postgresql|pgbouncer)|tmp)/\.s\.PGSQL\.[0-9]{1,5}'
PGBOUNCER_POOLS = {
    "activeClients": "cl_active",
    "waitingClients": "cl_waiting",
    "activeServers": "sv_active",
    "idleServers": "sv_idle",
}


def pgbouncer_targets(record, config):
    targets = service_tcp_targets(record, config)
    for path in record["sockets"]:
        if not re.fullmatch(PGBOUNCER_SOCKET, path):
            continue
        directory, port = path.rsplit("/.s.PGSQL.", 1)
        if directory in ("/run/postgresql", "/run/pgbouncer"):
            directory = "/var" + directory
        if 0 < int(port) <= 65535:
            targets.add((directory, int(port)))
    return targets


def pgbouncer_peer(config):
    target = (config["endpoint"], config["port"])
    suffix = "/.s.PGSQL." + str(config["port"])
    for record in config["_observed_processes"]:
        if not record["complete"] or target not in pgbouncer_targets(record, config):
            continue
        proc = '/proc/{}'.format(record["pid"])
        for path in record["sockets"]:
            if not path.endswith(suffix) or not re.fullmatch(PGBOUNCER_SOCKET, path):
                continue
            try:
                status = service_read_file(proc + "/status", 16384)
                ids = dict(re.findall(rb"^([UG]id):[ \t]+[0-9]+[ \t]+([0-9]+)[ \t]", status, re.M))
                uid, gid = int(ids[b"Uid"]), int(ids[b"Gid"])
                socket_stat = os.lstat(path)
                if not uid or not gid or socket_stat.st_uid != uid or not stat.S_ISSOCK(socket_stat.st_mode):
                    continue
                peer = pwd.getpwuid(uid).pw_name
                started = process_stat(service_read_file(proc + "/stat", 2048).decode("ascii"))[1]
                if started == record["started"]:
                    return os.path.dirname(path), peer, uid, gid
            except (OSError, ValueError, KeyError, IndexError):
                continue
    return None


def pgbouncer_error(stderr):
    if (b"fe_sendauth: no password supplied" in stderr
            or re.search(rb"FATAL:[ \t]+password authentication failed\b", stderr)):
        return "credentials_unavailable"
    if (re.search(rb"(?:FATAL|ERROR):[ \t]+(?:not allowed|access denied|permission denied)\b", stderr)
            or b": Permission denied" in stderr or b"requirepeer parameter" in stderr):
        return "connection_denied"
    return "source_unavailable"


def pgbouncer_query(config):
    binary = "/usr/bin/psql"
    if not os.path.isfile(binary):
        raise ValueError("client_missing")
    args = [
        binary, "-X", "-w", "--csv", "-P", "footer=off", "-P", "pager=off",
        "--set=ON_ERROR_STOP=1", "--dbname=pgbouncer", "--port=" + str(config["port"]),
    ]
    end = time.monotonic() + 3

    def query(endpoint, user, env, preexec_fn=None):
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise ValueError("query_timeout")
        command = args + ["--host=" + endpoint]
        if user:
            command.append("--username=" + user)
        return service_process(
            command, b"SHOW POOLS;\n", env={"PGCONNECT_TIMEOUT": "2", **env},
            timeout=remaining, classify_error=pgbouncer_error, preexec_fn=preexec_fn,
        )

    if config["autoEndpoint"] and not config["user"] and os.geteuid() == 0:
        peer = pgbouncer_peer(config)
        if peer is not None:
            endpoint, peer_name, uid, gid = peer

            def drop_privileges():
                os.setgroups([])
                os.setresgid(gid, gid, gid)
                os.setresuid(uid, uid, uid)

            try:
                return query(endpoint, "pgbouncer", {
                    "PGPASSFILE": "/dev/null", "PGREQUIREPEER": peer_name,
                }, drop_privileges)
            except ValueError as exc:
                if str(exc) not in ("connection_denied", "credentials_unavailable"):
                    raise
            except (OSError, subprocess.SubprocessError):
                # The peer subprocess could not start with the selected identity.
                pass

    home = pwd.getpwuid(os.getuid()).pw_dir
    return query(config["endpoint"], config["user"], {"PGPASSFILE": os.path.join(home, ".pgpass")})


def pgbouncer_connector(config, result):
    import csv
    import io

    body = pgbouncer_query(config)
    rows = csv.DictReader(io.StringIO(body.decode("utf-8")))
    if rows.fieldnames is None or not set(PGBOUNCER_POOLS.values()) <= set(rows.fieldnames):
        raise ValueError("unsupported_version")
    pools = list(rows)
    if len(pools) > 128 or any(None in row for row in pools):
        raise ValueError("response_limit")
    for metric, column in PGBOUNCER_POOLS.items():
        values = [service_number(pool[column]) for pool in pools]
        if all(value is not None for value in values):
            result["metrics"][metric] = service_number(sum(values))
    result["connected"] = True
    service_finish(result)


PGBOUNCER_ADAPTER = observed_service(
    IdentityPolicy("pgbouncer", socket_pattern=PGBOUNCER_SOCKET, stream_tcp=True),
    pgbouncer_connector, targets=pgbouncer_targets, installed=("/usr/sbin/pgbouncer", "/usr/bin/pgbouncer"),
)

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


def pgbouncer_connector(config, result):
    import csv
    import io

    binary = "/usr/bin/psql"
    if not os.path.isfile(binary):
        raise ValueError("client_missing")
    home = pwd.getpwuid(os.getuid()).pw_dir
    args = [
        binary, "-X", "-w", "--csv", "-P", "footer=off", "-P", "pager=off",
        "--set=ON_ERROR_STOP=1", "--dbname=pgbouncer", "--host=" + config["endpoint"],
        "--port=" + str(config["port"]),
    ]
    if config["user"]:
        args.append("--username=" + config["user"])
    env = {"PGCONNECT_TIMEOUT": "2", "PGPASSFILE": os.path.join(home, ".pgpass")}
    body = service_process(args, b"SHOW POOLS;\n", env=env)
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

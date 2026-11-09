"""CockroachDB node metrics from the local DB Console or an existing SQL role."""

import ssl

COCKROACH_METRICS = {
    "sql.conns": "connections",
    "sql.statements.active": "active",
    "sql.query.count": "queries",
    "sql.failure.count": "errors",
    "ranges.unavailable": "unavailableRanges",
    "ranges.underreplicated": "underreplicatedRanges",
    "sys.uptime": "uptime",
}


def cockroach_options(record):
    root = f'/proc/{record["pid"]}'
    fields = {
        b'--http-addr': b'COCKROACH_HTTP_ADDR',
        b'--sql-addr': b'COCKROACH_SQL_ADDR',
        b'--listen-addr': b'COCKROACH_LISTEN_ADDR',
        b'--certs-dir': b'COCKROACH_CERTS_DIR',
        b'--insecure': b'COCKROACH_INSECURE',
        b'--unencrypted-localhost-http': b'COCKROACH_UNENCRYPTED_LOCALHOST_HTTP',
    }
    try:
        env = dict(
            field.split(b'=', 1) for field in service_read_file(root + '/environ', 32768).split(b'\0')
            if field.split(b'=', 1)[0] in fields.values() and b'=' in field
        )
    except (OSError, ValueError):
        env = {}
    options = {key: env[name] for key, name in fields.items() if name in env}
    args = service_read_file(root + '/cmdline', 32768).rstrip(b'\0').split(b'\0')
    for index, arg in enumerate(args[1:], 1):
        flag, sep, value = arg.partition(b'=')
        if flag in fields:
            if not sep:
                if flag in (b'--insecure', b'--unencrypted-localhost-http'):
                    value = b'true'
                elif index + 1 < len(args) and not args[index + 1].startswith(b'--'):
                    value = args[index + 1]
                else:
                    continue
            options[flag] = value
    if process_stat(service_read_file(root + '/stat', 2048).decode('ascii'))[1] != record['started']:
        raise ValueError('source_unavailable')
    return {os.fsdecode(k[2:]): os.fsdecode(v) for k, v in options.items() if len(v) <= 1024}


def cockroach_bind(options, *, sql=False):
    if sql:
        return options.get('sql-addr', options.get('listen-addr', ':26257')), 26257
    return options.get('http-addr', ':8080'), 8080


def cockroach_tcp_binds(record, *, sql=False):
    bind = cockroach_bind(cockroach_options(record), sql=sql)
    try:
        return (listener_address(*bind),)
    except ValueError:
        return ()


def cockroach_samples(body):
    names = {k.replace('.', '_').encode('ascii'): v for k, v in COCKROACH_METRICS.items()}
    values = {}
    for line in body.splitlines():
        name = re.split(rb'[{\s]', line, maxsplit=1)[0]
        if name not in names:
            continue
        key = names[name]
        # Prometheus labels may contain spaces and escaped quotes. Do not forward them.
        sample = re.fullmatch(rb'[^\s{]+(?:\{(?:[^"{}]|"(?:[^"\\]|\\.)*")*\})?[ \t]+([^\s]+)(?:[ \t]+-?\d+)?[ \t]*', line)
        values[key] = service_number(sample[1]) if key not in values and sample else None
    return values


def cockroach_scrape(record, options, target):
    host, port = target
    plaintext = options.get('insecure', '').lower() in ('1', 'true') or (
        ipaddress.ip_address(host).is_loopback
        and options.get('unencrypted-localhost-http', '').lower() in ('1', 'true')
    )
    tls = None if plaintext else ssl.create_default_context()
    if tls is not None:
        certs = options.get('certs-dir', 'certs')
        if certs.startswith('~/'):
            certs = os.path.join(pwd.getpwuid(os.stat(f'/proc/{record["pid"]}').st_uid).pw_dir, certs[2:])
        elif not os.path.isabs(certs):
            certs = os.path.join(f'/proc/{record["pid"]}/cwd', certs)
        try:
            ca = service_read_file(os.path.join(certs, 'ca.crt'), 131072)
            tls.load_verify_locations(cadata=ca.decode('ascii'))
        except (OSError, ValueError):
            pass  # The system trust store is still available.
    return cockroach_samples(service_http(
        {"endpoint": host, "port": port}, "/_status/vars", limit=4 * 1024 * 1024, tls=tls
    ))


def cockroach_sources(records, *, sql=False):
    sources = []
    for record in records:
        if not record['complete']:
            continue
        try:
            options = cockroach_options(record)
        except (OSError, ValueError):
            continue
        targets = bind_targets(record, *cockroach_bind(options, sql=sql))
        if targets:
            sources.append((record, options, min(targets, key=lambda t: (not ipaddress.ip_address(t[0]).is_loopback, t))))
    if len(sources) > 1:
        raise ValueError('endpoint_ambiguous')
    return sources


def cockroach_automatic(c, r):
    sources = cockroach_sources(c['_runtime'])
    if sources:
        try:
            values = cockroach_scrape(*sources[0])
        except (OSError, ValueError, http.client.HTTPException):
            values = {}
        if any(v is not None for k, v in values.items() if k != 'uptime'):
            r.update(detected=True, connected=True, uptime=values.pop('uptime', None))
            r["metrics"].update(values)
            service_finish(r)
            return
    records, _ = service_runtime(
        kind_filter='cockroach', details=True,
        tcp_binds=lambda record: cockroach_tcp_binds(record, sql=True),
    )
    sql = cockroach_sources(records, sql=True)
    if not sql:
        raise ValueError('source_unavailable')
    c["endpoint"], c["port"] = sql[0][2]
    cockroach_sql(c, r)

def cockroach_connector(c, r):
    if not service_begin(
        c, r, ["/etc/cockroach", "/var/lib/cockroach", "/usr/local/bin/cockroach"]
    ):
        return
    if c["autoEndpoint"]:
        cockroach_automatic(c, r)
    else:
        cockroach_sql(c, r)


def cockroach_sql(c, r):
    if not os.path.isfile("/usr/bin/psql"):
        raise ValueError("client_missing")
    home = pwd.getpwuid(os.getuid()).pw_dir
    env = {
        "PGCONNECT_TIMEOUT": "2",
        "PGOPTIONS": "-c default_transaction_read_only=on -c statement_timeout=1500",
        "PGPASSFILE": os.path.join(home, ".pgpass"),
        "PGSSLMODE": "prefer",
        "PGAPPNAME": "cyberbot",
    }
    sql = (
        "SELECT name,value FROM crdb_internal.node_metrics WHERE name IN ("
        + ",".join("'" + x + "'" for x in COCKROACH_METRICS)
        + ")"
    )
    args = [
        "/usr/bin/psql",
        "-X",
        "-w",
        "-A",
        "-t",
        "-F",
        "\t",
        "-h",
        c["endpoint"],
        "-p",
        str(c["port"]),
        "-d",
        "defaultdb",
    ]
    if c["user"]:
        args += ["-U", c["user"]]
    data = service_process(args + ["-c", sql], limit=16384, env=env)
    for row in data.decode("ascii", "replace").splitlines():
        p = row.split("\t")
        if len(p) == 2 and p[0] == "sys.uptime":
            r["uptime"] = service_number(p[1])
        elif len(p) == 2 and p[0] in COCKROACH_METRICS:
            r["metrics"][COCKROACH_METRICS[p[0]]] = service_number(p[1])
    r.update(detected=True, connected=True)
    service_finish(r)


def prepare_cockroach_endpoint(kind, config, result):
    binds = (
        cockroach_tcp_binds if config['autoEndpoint']
        else lambda _: ((config['endpoint'], config['port']),)
    )
    prepare_service_endpoint(kind, config, result, detailed=True, tcp_binds=binds)


COCKROACH_ADAPTER = ServiceAdapter(
    IdentityPolicy('cockroach'),
    cockroach_connector,
    prepare=prepare_cockroach_endpoint,
)

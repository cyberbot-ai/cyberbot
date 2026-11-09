"""Read the bounded stats JSON sent by Twemproxy's monitoring listener."""


def twemproxy_binds(record):
    root = f'/proc/{record["pid"]}'
    args = service_read_file(root + "/cmdline", 32768).decode("ascii").rstrip("\0").split("\0")
    if process_stat(service_read_file(root + "/stat", 2048).decode("ascii"))[1] != record["started"]:
        raise ValueError("source_unavailable")
    options = {"--stats-addr": "", "--stats-port": "22222"}
    aliases = {"-a": "--stats-addr", "-s": "--stats-port"}
    index = 1
    while index < len(args):
        option, separator, value = args[index].partition("=")
        if not separator and option[:2] in aliases and len(option) > 2:
            option, separator, value = option[:2], "=", option[2:]
        option = aliases.get(option, option)
        if option in options:
            if not separator:
                index += 1
                if index >= len(args):
                    raise ValueError("source_unavailable")
                value = args[index]
            options[option] = value
        index += 1
    host, port = options["--stats-addr"], options["--stats-port"]
    if not port.isdecimal() or not 0 < int(port) <= 65535:
        raise ValueError("source_unavailable")
    if host not in ("", "localhost", "0.0.0.0", "::") and not literal_ip(host):
        raise ValueError("source_unavailable")
    return ((host, int(port)),)


def twemproxy_values(config):
    limit = 262144
    with socket.create_connection((config["endpoint"], config["port"]), timeout=2) as stream:
        deadline = time.monotonic() + 2
        data = bytearray()
        while len(data) <= limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("query_timeout")
            stream.settimeout(remaining)
            part = stream.recv(min(4096, limit + 1 - len(data)))
            if not part:
                return json.loads(data)
            data.extend(part)
        raise ValueError("response_limit")


def twemproxy_total(rows, field):
    values = [service_number(row.get(field)) for row in rows]
    if rows and all(value is not None for value in values):
        return service_number(sum(values))
    return None


def twemproxy_connector(config, result):
    data = twemproxy_values(config)
    if not isinstance(data, dict) or data.get("service") != "nutcracker":
        raise ValueError("unsupported_version")
    pools = [pool for pool in data.values() if isinstance(pool, dict)]
    servers = [server for pool in pools for server in pool.values() if isinstance(server, dict)]
    result["metrics"].update(
        clientConnections=twemproxy_total(pools, "client_connections"),
        forwardErrors=twemproxy_total(pools, "forward_error"),
        requests=twemproxy_total(servers, "requests"),
        timeouts=twemproxy_total(servers, "server_timedout"),
    )
    result["uptime"] = service_number(data.get("uptime"))
    result["connected"] = True
    service_finish(result)


TWEMPROXY_ADAPTER = observed_service(
    IdentityPolicy("nutcracker", "twemproxy", stream_tcp=True), twemproxy_connector,
    binds=twemproxy_binds, targets=service_tcp_targets,
    installed=("/usr/bin/nutcracker", "/usr/sbin/nutcracker", "/usr/bin/twemproxy", "/usr/local/bin/twemproxy"),
)

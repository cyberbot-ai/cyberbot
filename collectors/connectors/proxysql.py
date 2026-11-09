"""ProxySQL diagnostics on the verified administration port."""

PROXYSQL_STATS = {
    "Client_Connections_connected": "clientConnections",
    "Server_Connections_connected": "serverConnections",
    "Questions": "queries",
    "Slow_queries": "slowQueries",
}


def proxysql_connector(config, result):
    if not any(os.path.isfile(path) for path in ("/usr/bin/mysql", "/usr/bin/mariadb")):
        raise ValueError("client_missing")
    credentials = service_credentials("proxysql")
    if not credentials.get("password") or not (config["user"] or credentials.get("user")):
        raise ValueError("credentials_unavailable")
    options = ["[client]"]
    for key, value in credentials.items():
        if any(char in value for char in "\r\n"):
            raise ValueError("credentials_unavailable")
        quoted = value.replace("\\", "\\\\").replace('"', '\\"')
        options.append(f'{key}="{quoted}"')
    names = ", ".join("'" + name + "'" for name in PROXYSQL_STATS)
    query = "SELECT Variable_Name, Variable_Value FROM stats_mysql_global WHERE Variable_Name IN (" + names + ")"
    client = {"host": config["endpoint"], "port": config["port"], "user": config["user"]}
    try:
        rows = mysql_query(client, query, None, time.monotonic() + 3,
                           credential=("\n".join(options) + "\n").encode())
    except ValueError as error:
        if str(error) == "query_denied":
            raise ValueError("connection_denied") from None
        if str(error) == "query_output_limit":
            raise ValueError("response_limit") from None
        raise
    for row in rows:
        metric = PROXYSQL_STATS.get(row.get("Variable_Name"))
        if metric is not None:
            result["metrics"][metric] = service_number(row.get("Variable_Value"))
    result["connected"] = True
    service_finish(result)


PROXYSQL_ADAPTER = observed_service(
    IdentityPolicy("proxysql", stream_tcp=True, group_processes=False), proxysql_connector,
    binds=lambda _: (("", 6032),), targets=lambda record, config: service_tcp_targets(record, config, 6032),
    installed=("/usr/bin/proxysql", "/usr/sbin/proxysql"),
)

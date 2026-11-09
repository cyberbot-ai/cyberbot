"""Process metrics for the local Nebula daemon, independent of tunnel configuration."""


def nebula_connector(config, result):
    records = config["_observed_processes"]
    if not records or any(not record["complete"] for record in records):
        raise ValueError("source_unavailable")
    if len(records) != 1:
        raise ValueError("endpoint_ambiguous")
    record = records[0]
    raw = service_read_file('/proc/{}/stat'.format(record["pid"]), 2048).decode("ascii")
    if process_stat(raw)[1] != record["started"]:
        raise ValueError("source_unavailable")
    fields = raw[raw.rfind(")") + 2:].split()
    uptime = float(service_read_file("/proc/uptime", 128).split()[0])
    elapsed = service_number(uptime - record["started"] / os.sysconf("SC_CLK_TCK"))
    result["metrics"]["processUptime"] = elapsed
    result["metrics"]["rss"] = service_number(int(fields[21]) * os.sysconf("SC_PAGE_SIZE"))
    result.update(connected=True, uptime=elapsed)
    service_finish(result)


NEBULA_ADAPTER = observed_service(
    IdentityPolicy("nebula", tcp_endpoint=False), nebula_connector, process_only=True,
    installed=("/usr/bin/nebula", "/usr/local/bin/nebula", "/opt/nebula/nebula"),
)

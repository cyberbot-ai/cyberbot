"""Daemon socket remains remote. Only fixed GET operations; no container commands."""

def docker_connector(c, r):
    if not service_begin(c, r, ["/run/docker.sock", "/var/run/docker.sock"]):
        return
    info = load_collector_json(service_http(c, "/info", limit=131072))
    r.update(
        detected=True,
        connected=True,
        identity=hashlib.sha256(str(info.get("ID", "")).encode()).hexdigest(),
    )
    m = r["metrics"]
    for k, v in [
        ("running", "ContainersRunning"),
        ("stopped", "ContainersStopped"),
        ("paused", "ContainersPaused"),
        ("containers", "Containers"),
    ]:
        m[k] = service_number(info.get(v))
    rows = load_collector_json(service_http(c, "/containers/json?all=1&limit=129", limit=262144))
    if not isinstance(rows, list):
        raise ValueError("source_unavailable")
    if len(rows) > 128 or m["containers"] is None or len(rows) != m["containers"]:
        r["issues"].append("partial_coverage")
    # List statuses expose health/restarting without inspecting environment or mounts.
    m["unhealthy"] = sum("(unhealthy)" in str(x.get("Status", "")) for x in rows)
    m["restarting"] = sum(x.get("State") == "restarting" for x in rows)
    m["dead"] = sum(x.get("State") == "dead" for x in rows)
    if r["issues"]:
        for k in ["unhealthy", "restarting", "dead"]:
            m[k] = None
    service_finish(r)


DOCKER_ADAPTER = ServiceAdapter(
    IdentityPolicy('dockerd', sockets=('/var/run/docker.sock', '/run/docker.sock'), tcp_endpoint=False),
    docker_connector,
)

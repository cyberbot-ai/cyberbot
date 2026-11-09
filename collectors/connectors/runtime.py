"""Connector host: closed profiles, local transport, bounded output, no shell tools."""

import os, time, hashlib, re, selectors, subprocess, socket, struct, stat, pwd, http.client, base64

SERVICE_ISSUES = (
    "endpoint_ambiguous",
    "endpoint_not_local",
    "profile_disabled",
    "not_detected",
    "client_missing",
    "unsupported_version",
    "credentials_unavailable",
    "connection_denied",
    "source_unavailable",
    "partial_coverage",
    "query_timeout",
    "response_limit",
    "counter_warmup",
    "replication_lag_unknown",
)


class ServiceAdapter:
    def __init__(self, identity, collect, *, prepare=None, structured=False, coverage=None, actions=()):
        self.identity = identity
        self.collect = collect
        self.prepare = prepare or prepare_service_endpoint
        self.structured = structured
        self.coverage = coverage
        self.actions = actions


def register_service_actions(adapters):
    for adapter in adapters.values():
        for action in adapter.actions:
            if action.name in ACTION_HANDLERS:
                raise ValueError('Duplicate action: {}'.format(action.name))
            ACTION_HANDLERS[action.name] = action


def dispatch_service(request):
    state = request.get('state')
    if not isinstance(state, dict) or set(state) - {'kind', 'instanceId', 'config', 'checkpoint'}:
        raise ValueError('Invalid service request')
    kind = state.get('kind')
    if not isinstance(kind, str) or kind not in SERVICE_ADAPTERS:
        raise ValueError('Invalid service kind')
    instance = service_instance_id(state.get('instanceId', 'default'))
    spec = CONNECTOR_CATALOG[kind]
    if instance != 'default' and not spec['multiple']:
        raise ValueError('Invalid service instance')
    adapter = SERVICE_ADAPTERS[kind]
    if adapter.structured:
        details = adapter.collect(state)
        complete = adapter.coverage(details)
    else:
        if state.get('checkpoint') is not None:
            raise ValueError('Invalid service checkpoint')
        details = collect_service(request)
        complete = details['complete']
    return {
        'version': 2, 'kind': kind, 'instanceId': instance,
        'detected': details['detected'], 'complete': complete,
        'durationMs': details['durationMs'], 'details': details,
    }


def prepare_service_endpoint(kind, config, result, *, detailed=False, local_only=False, tcp_binds=None):
    spec = CONNECTOR_CATALOG[kind]
    custom = config['endpoint'] not in spec['endpoints']
    scan_options = {'tcp_binds': tcp_binds} if tcp_binds is not None else {}
    if config['autoEndpoint'] and detailed:
        records, _ = service_runtime(kind_filter=kind, details=True, **scan_options)
        config['_runtime'] = records
        result['detected'] = bool(records)
        return
    if custom and local_only:
        if config['enabled'] and not local_interface_address(config['endpoint']):
            raise ValueError('endpoint_not_local')
        return
    if config['autoEndpoint'] or custom:
        records, _ = service_runtime(kind_filter=kind, **scan_options)
        result['detected'] = bool(records)
        if config['enabled'] and config['autoEndpoint']:
            config['endpoint'], config['port'] = discovered_endpoint(
                kind, spec['endpoint'], spec['port'], spec['endpoints'], records
            )
        elif config['enabled'] and not owned_listener(kind, config['endpoint'], config['port'], records):
            raise ValueError('endpoint_not_local')


def service_profile(kind, raw):
    spec = CONNECTOR_CATALOG[kind]
    c = dict(
        enabled=False,
        autoEndpoint=False,
        endpoint=spec["endpoint"],
        port=spec["port"],
        user="",
        intervalSeconds=180,
        expectedPeers=0,
        expectReplica=False,
    )
    if not isinstance(raw, dict) or set(raw) - set(c):
        raise ValueError("Invalid profile")
    c.update(raw)
    if (
        not (c["endpoint"] in spec["endpoints"] or "127.0.0.1" in spec["endpoints"] and literal_ip(c["endpoint"]))
        or type(c["enabled"]) != bool
        or type(c["autoEndpoint"]) != bool
        or type(c["expectReplica"]) != bool
    ):
        raise ValueError("Invalid endpoint")
    for k, lo, hi in [
        ("port", 1, 65535),
        ("intervalSeconds", 60, 86400),
        ("expectedPeers", 0, 64),
    ]:
        if type(c[k]) != int or not lo <= c[k] <= hi:
            raise ValueError("Invalid limit")
    if (
        not isinstance(c["user"], str)
        or c["user"]
        and not re.fullmatch("[A-Za-z_][A-Za-z0-9_.-]{0,62}", c["user"])
    ):
        raise ValueError("Invalid user")
    return c


def service_instance_id(value):
    if not isinstance(value, str) or (
        value != "default"
        and not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value)
    ):
        raise ValueError("Invalid instance identity")
    return value


def service_credentials(kind, instance="default"):
    service_instance_id(instance)
    # Optional credentials are provisioned by the operator on the remote server only.
    path = os.path.join(
        pwd.getpwuid(os.getuid()).pw_dir,
        ".cache/cyberbot/credentials",
        (
            kind + ".json"
            if instance == "default"
            else os.path.join(kind, instance + ".json")
        ),
    )
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or st.st_mode & 0o077
            or st.st_size > 8192
        ):
            raise ValueError("credentials_unavailable")
        v = load_collector_json(f.read(8193))
    if (
        not isinstance(v, dict)
        or set(v) - {"user", "password"}
        or any(
            not isinstance(x, str) or len(x) > 2048 or "\x00" in x for x in v.values()
        )
    ):
        raise ValueError("credentials_unavailable")
    return v


def service_process(args, data=b"", limit=32768, timeout=3, env=None, *,
                    statuses=(0,), classify_error=None, preexec_fn=None):
    clean = {"PATH": "/usr/bin:/bin:/usr/sbin", "HOME": "/nonexistent", "LC_ALL": "C"}
    if env:
        clean.update(env)
    end = time.monotonic() + timeout
    p = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=clean,
        preexec_fn=preexec_fn,
    )
    out = bytearray()
    errors = bytearray()
    try:
        p.stdin.write(data)
        p.stdin.close()
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout, selectors.EVENT_READ, out)
            sel.register(p.stderr, selectors.EVENT_READ, errors)
            while sel.get_map():
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise ValueError("query_timeout")
                for key, _ in sel.select(min(0.05, remaining)):
                    b = os.read(key.fd, 4096)
                    if not b:
                        sel.unregister(key.fileobj)
                        continue
                    key.data.extend(b)
                    if len(out) > limit or len(errors) > 4096:
                        raise ValueError("response_limit")
        try:
            status = p.wait(timeout=max(0, end - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise ValueError("query_timeout") from None
        if status not in statuses:
            raise ValueError(classify_error(errors) if classify_error else "source_unavailable")
        return bytes(out)
    finally:
        if p.poll() is None:
            p.kill()
        p.wait(timeout=1)
        p.stdout.close()
        p.stderr.close()
        if not p.stdin.closed:
            p.stdin.close()


def service_read_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("source_unavailable")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("response_limit")
    return data


def service_http_response(c, path, body=None, headers=None, limit=262144, *, tls=None, statuses=(200,)):
    if c["endpoint"].startswith("/"):

        class UnixHTTP(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(2)
                self.sock.connect(c["endpoint"])

        conn = UnixHTTP("localhost", timeout=2)
    elif tls is not None:
        conn = http.client.HTTPSConnection(c["endpoint"], c["port"], timeout=2, context=tls)
    else:
        conn = http.client.HTTPConnection(c["endpoint"], c["port"], timeout=2)
    try:
        conn.request(
            "POST" if body is not None else "GET",
            path,
            body=body,
            headers=headers or {},
        )
        r = conn.getresponse()
        if r.status not in statuses:
            raise ValueError("source_unavailable")
        data = r.read(limit + 1)
        if len(data) > limit:
            raise ValueError("response_limit")
        return r.status, data
    finally:
        conn.close()


def service_http(c, path, body=None, headers=None, limit=262144, *, tls=None):
    return service_http_response(c, path, body, headers, limit, tls=tls)[1]


def service_unit_state(kind):
    units = CONNECTOR_CATALOG[kind].get("units", ())
    if not units or not os.path.isdir("/run/systemd/system"):
        return "unknown", False, True
    binary = linux_command("systemctl")
    if binary is None:
        return "unknown", False, False
    names = {unit + ".service" for unit in units}
    try:
        data = service_process(
            [binary, "show", "--no-pager", "--property=Id,LoadState,ActiveState", *sorted(names)],
            limit=4096, timeout=1, statuses=(0, 1, 4),
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return "unknown", False, False
    seen = set()
    states = []
    for row in data.decode("ascii", errors="replace").strip().split("\n\n"):
        fields = dict(line.split("=", 1) for line in row.splitlines() if "=" in line)
        name, loaded = fields.get("Id"), fields.get("LoadState")
        if name not in names or loaded not in ("loaded", "masked", "not-found"):
            continue
        seen.add(name)
        if loaded != "not-found":
            states.append(fields.get("ActiveState"))
    if "active" in states:
        return "running", True, True
    if states and seen == names and all(state in ("inactive", "failed") for state in states):
        return "stopped", True, True
    return "unknown", bool(states), seen == names


def service_image_repository(reference):
    if not isinstance(reference, str):
        return ""
    repository = reference.split("@", 1)[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    for registry in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        if repository.startswith(registry):
            return repository[len(registry):]
    return repository


def service_container_targets(image, internal_port):
    # Same fixed local read as Docker diagnostics. No inspect, exec or private container IP.
    socket_path = next((path for path in ("/run/docker.sock", "/var/run/docker.sock")
                        if os.path.exists(path)), None)
    if socket_path is None:
        return [], False, False, True
    try:
        rows = load_collector_json(service_http({"endpoint": socket_path}, "/containers/json?all=1&limit=129"))
    except (OSError, ValueError, http.client.HTTPException):
        return [], False, False, False
    if not isinstance(rows, list) or len(rows) > 128 or any(not isinstance(row, dict) for row in rows):
        return [], False, False, False
    candidates = []
    states = []
    for index, row in enumerate(rows):
        if service_image_repository(row.get("Image")) != image:
            continue
        state = row.get("State")
        states.append(state)
        if state != "running":
            continue
        container_id = row.get("Id")
        owner = container_id if isinstance(container_id, str) and re.fullmatch(r"[0-9a-f]{64}", container_id) else index
        ports = row.get("Ports", [])
        if not isinstance(ports, list):
            return [], True, False, False
        for port in ports:
            if not isinstance(port, dict) or port.get("Type") != "tcp" or port.get("PrivatePort") != internal_port:
                continue
            host = port.get("IP")
            if host == "0.0.0.0":
                host = "127.0.0.1"
            elif host == "::":
                host = "::1"
            published = port.get("PublicPort")
            if host in ("127.0.0.1", "::1") and type(published) is int and 0 < published <= 65535:
                candidates.append((("container", owner), (host, published)))
    stopped = bool(states) and all(state in ("exited", "dead", "created") for state in states)
    return candidates, bool(states), "running" in states, stopped or not states or "running" in states


def service_observation(kind, config, result, *, process_only=False, binds=None, targets=None,
                        image=None, installed=()):
    records, complete = service_runtime(kind_filter=kind, details=True, process_only=process_only,
                                        tcp_binds=binds)
    live = [record for record in records if record["verified"]]
    config["_observed_processes"] = live if complete else []
    unit_state, unit_found, unit_complete = ("unknown", False, True)
    process_running = complete and any(record["complete"] for record in live)
    if not process_running:
        unit_state, unit_found, unit_complete = service_unit_state(kind)
    candidates = []
    container_found, container_running, container_complete = False, False, True
    if image is not None:
        candidates, container_found, container_running, container_complete = service_container_targets(
            image, CONNECTOR_CATALOG[kind]["port"]
        )
    detected = bool(records or unit_found or container_found or any(os.path.isfile(path) for path in installed))
    running = process_running or unit_state == "running" or container_running
    covered = complete and unit_complete and container_complete and all(record["complete"] for record in records)
    stopped = covered and not running and not live and (unit_state == "stopped" or container_found)
    result["detected"] = detected
    result["availability"] = "running" if running else "stopped" if stopped else "unknown"
    if not detected:
        result["issues"].append("not_detected" if covered else "source_unavailable")
        return False
    if not config["enabled"]:
        result["issues"].append("profile_disabled")
        return False
    if stopped:
        result["issues"].append("source_unavailable")
        return False
    if targets is None:
        return True
    if complete and all(record["complete"] for record in live):
        for record in live:
            owner = ("process", record["pid"], record["started"])
            candidates.extend((owner, target) for target in targets(record, config))
    requested = (config["endpoint"], config["port"])
    if not config["autoEndpoint"]:
        candidates = [candidate for candidate in candidates if candidate[1] == requested]
    if not candidates:
        raise ValueError("source_unavailable" if config["autoEndpoint"] else "endpoint_not_local")
    owners = {(owner, target[1]) for owner, target in candidates}
    if len(owners) != 1:
        raise ValueError("endpoint_ambiguous")
    owner, _ = next(iter(owners))
    if owner[0] == "process" or isinstance(owner[1], str):
        result["identity"] = hashlib.sha256(repr(owner).encode("ascii")).hexdigest()
    choices = {target for _, target in candidates}
    config["endpoint"], config["port"] = requested if requested in choices else min(
        choices, key=lambda target: (not target[0].startswith("/"), target[0] != "127.0.0.1", target)
    )
    return True


def observed_service(identity, read, **observation):
    def prepare(kind, config, result):
        config["_read_observation"] = service_observation(kind, config, result, **observation)

    def collect(config, result):
        if config["_read_observation"]:
            read(config, result)

    return ServiceAdapter(identity, collect, prepare=prepare)


def service_tcp_targets(record, config, port=None):
    targets = local_listeners(record, port)
    endpoint = config["endpoint"]
    chosen_port = config["port"]
    if (not config["autoEndpoint"] and (port is None or chosen_port == port)
            and literal_ip(endpoint) and owned_listener(record["kind"], endpoint, chosen_port, [record])):
        targets.add((endpoint, chosen_port))
    return targets


def service_prometheus(body, names):
    """Return only allowlisted numbers and aggregate distinct labeled series."""
    series = {}
    for line in body.splitlines():
        name = re.split(rb"[{\s]", line, maxsplit=1)[0]
        if name not in names:
            continue
        sample = re.fullmatch(
            rb'[^\s{]+(\{(?:[^"{}\\]|"[^"\\]*(?:\\.[^"\\]*)*")*\})?[ \t]+([^\s]+)(?:[ \t]+-?\d+)?[ \t]*',
            line,
        )
        key = names[name]
        labels = (sample.group(1) or b"") if sample else b""
        value = service_number(sample.group(2)) if sample else None
        values = series.setdefault(key, {})
        values[labels] = None if labels in values else value
    return {
        key: service_number(sum(values.values())) if all(value is not None for value in values.values()) else None
        for key, values in series.items()
    }


def collect_service(request):
    state = request.get("state", {})
    if not isinstance(state, dict) or (
        set(state) - {"kind", "config", "instanceId", "checkpoint"}
        or not {"kind", "config"} <= set(state)
    ):
        raise ValueError("Invalid service request")
    kind = state["kind"]
    if kind not in SERVICE_ADAPTERS:
        raise ValueError("Invalid service kind")
    spec = CONNECTOR_CATALOG[kind]
    config = service_profile(kind, state["config"])
    config["_instanceId"] = service_instance_id(state.get("instanceId", "default"))
    started = time.monotonic()
    result = {
        "version": 1,
        "detected": False,
        "connected": False,
        "complete": False,
        "issues": [],
        "metrics": {m["key"]: None for m in spec["metrics"]},
        "identity": None,
        "uptime": None,
        "durationMs": 0,
    }
    try:
        adapter = SERVICE_ADAPTERS[kind]
        adapter.prepare(kind, config, result)
        adapter.collect(config, result)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        subprocess.TimeoutExpired,
        http.client.HTTPException,
    ) as e:
        issue = str(e) if str(e) in SERVICE_ISSUES else "source_unavailable"
        result["issues"].append(issue)
        result["complete"] = False
    result["issues"] = list(dict.fromkeys(result["issues"]))[:16]
    result["durationMs"] = int((time.monotonic() - started) * 1000)
    return result


def service_begin(c, r, paths):
    r["detected"] = r["detected"] or any(os.path.exists(p) for p in paths)
    if not c["enabled"]:
        r["issues"].append("profile_disabled" if r["detected"] else "not_detected")
        return False
    if c.get("autoEndpoint") and not r["detected"]:
        r["issues"].append("not_detected")
        return False
    return True


def service_number(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        n = float(value)
    except (ValueError, TypeError):
        return None
    return n if 0 <= n <= 1e18 else None


def service_finish(r):
    if any(v is None for v in r["metrics"].values()):
        r["issues"].append("partial_coverage")
    r["complete"] = not r["issues"]

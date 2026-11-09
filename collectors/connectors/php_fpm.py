"""Read short FPM status over FastCGI, with bounded process-level fallback."""

import fnmatch


def fpm_pools(main):
    pools = {}
    files_read = 0
    remaining = 256 * 1024

    def visit(path, section, depth):
        nonlocal files_read, remaining
        if files_read >= 32 or depth > 4:
            raise ValueError('response_limit')
        data = service_read_file(path, min(remaining, 65536))
        files_read += 1
        remaining -= len(data)
        for raw in data.decode('utf-8', 'replace').splitlines():
            line = raw.split(';', 1)[0].strip()
            if line.startswith('[') and line.endswith(']'):
                section = line[1:-1].strip()
                continue
            key, sep, value = line.partition('=')
            if not sep:
                continue
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key == 'include' and value:
                directory, pattern = os.path.split(os.path.join(os.path.dirname(path), value))
                if any(char in directory for char in '*?['):
                    continue
                matches = []
                with os.scandir(directory) as entries:
                    for i, entry in enumerate(entries):
                        if i >= 256:
                            raise ValueError('response_limit')
                        if (not entry.name.startswith('.') or pattern.startswith('.')) and fnmatch.fnmatchcase(entry.name, pattern):
                            matches.append(entry.path)
                for included in sorted(matches):
                    section = visit(included, section, depth + 1)
            elif section and section != 'global' and key in ('listen', 'pm.status_path', 'pm.status_listen'):
                pools.setdefault(section, {})[key] = value.replace('$pool', section)
        return section

    visit(main, '', 0)
    return list(pools.values())


def fpm_targets(record, address):
    if not record['complete'] or not address:
        return set()
    if address.startswith('/'):
        path = os.path.realpath(address)
        return {(sock, 0) for sock in record['sockets'] if os.path.realpath(sock) == path}
    return bind_targets(record, address, 9000)


def fpm_status_sources(record):
    root = f'/proc/{record["pid"]}'
    title = service_read_file(root + '/cmdline', 4096).split(b'\0', 1)[0]
    match = re.fullmatch(rb'php-fpm: master process \((/[^()\r\n]{1,1024})\)', title)
    if not match:
        return []
    pools = fpm_pools(os.fsdecode(match[1]))
    sources = []
    for pool in pools:
        path = pool.get('pm.status_path', '')
        if not re.fullmatch(r'/[A-Za-z0-9_./~-]{0,126}', path):
            continue
        targets = []
        for key in ('pm.status_listen', 'listen'):
            matches = fpm_targets(record, pool.get(key))
            if not matches:
                continue
            target = min(matches, key=lambda t: (
                not t[0].startswith('/') and not ipaddress.ip_address(t[0]).is_loopback, t
            ))
            if target not in targets:
                targets.append(target)
        if targets:
            sources.append((targets, path))
    return sources


def fpm_fastcgi_status(target, path):
    def frame(kind, data=b''):
        return struct.pack('!BBHHBB', 1, kind, 1, len(data), 0, 0) + data

    # PHP-FPM requires a translated path to dispatch status. "/" cannot be a PHP script.
    fields = {
        b'REQUEST_METHOD': b'GET',
        b'SCRIPT_NAME': path.encode('ascii'),
        b'SCRIPT_FILENAME': b'/',
        b'QUERY_STRING': b'json',
    }
    params = b''.join(bytes((len(k), len(v))) + k + v for k, v in fields.items())
    request = frame(1, b'\0\1' + bytes(6)) + frame(4, params) + frame(4) + frame(5)
    host, port = target
    deadline = time.monotonic() + 2
    with socket.socket(
        socket.AF_UNIX if host.startswith('/') else socket.AF_INET6 if ':' in host else socket.AF_INET,
        socket.SOCK_STREAM,
    ) as sock:
        def timeout():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('query_timeout')
            sock.settimeout(remaining)

        def receive(size):
            data = bytearray()
            while len(data) < size:
                timeout()
                chunk = sock.recv(size - len(data))
                if not chunk:
                    raise ValueError('source_unavailable')
                data.extend(chunk)
            return data

        timeout()
        sock.connect(host if host.startswith('/') else target)
        timeout()
        sock.sendall(request)
        stdout, received = bytearray(), 0
        for _ in range(64):
            version, kind, request_id, size, padding, _ = struct.unpack('!BBHHBB', receive(8))
            if version != 1 or request_id != 1 or kind not in (3, 6, 7):
                raise ValueError('source_unavailable')
            received += size + padding
            if received > 16384:
                raise ValueError('response_limit')
            data = receive(size)
            receive(padding)
            if kind == 3:
                if size != 8 or any(data[:5]):
                    raise ValueError('source_unavailable')
                break
            if kind == 6:
                stdout.extend(data)
        else:
            raise ValueError('response_limit')

    headers, sep, body = bytes(stdout).partition(b'\r\n\r\n')
    fields = {}
    for line in headers.splitlines():
        key, colon, value = line.partition(b':')
        if colon:
            fields[key.lower()] = value.strip().lower()
    if (not sep or fields.get(b'content-type', b'').split(b';', 1)[0] != b'application/json'
            or fields.get(b'status', b'200').split(b' ', 1)[0] != b'200'):
        raise ValueError('source_unavailable')
    return json.loads(body)


def fpm_live_master(record):
    path = f'/proc/{record["pid"]}/stat'
    return process_stat(service_read_file(path, 2048).decode('ascii'))[1] == record['started']


def fpm_workers(record):
    if record['children'] is None:
        return None
    master = record['pid']
    count = 0
    try:
        for pid in record['children']:
            try:
                parent, _ = process_stat(service_read_file(f'/proc/{pid}/stat', 2048).decode('ascii'))
                if parent == master and os.path.samefile(f'/proc/{pid}/exe', f'/proc/{master}/exe'):
                    count += 1
            except FileNotFoundError:
                continue
        return count if fpm_live_master(record) else None
    except (OSError, ValueError, IndexError):
        return None


def fpm_queue(record):
    if not record['complete'] or len(record['inodes']) != 1:
        return None
    binary = linux_command('ss')
    if binary is None:
        return None
    inode, target = next(iter(record['inodes'].items()))
    unix = isinstance(target, str)
    try:
        data = service_process(
            [binary, '-H', '-O', '-l', '-n', '-e', '-x' if unix else '-t'], limit=131072, timeout=1
        ).decode('ascii', 'replace')
        for line in data.splitlines():
            fields = line.split()
            if unix and len(fields) >= 8 and fields[1] == 'LISTEN' and fields[5] == inode:
                return service_number(fields[2])
            if not unix and len(fields) >= 6 and fields[0] == 'LISTEN' and 'ino:' + inode in fields[5:]:
                return service_number(fields[1])
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return None


def fpm_status_result(d, r):
    if not isinstance(d, dict) or service_number(d.get('accepted conn')) is None or service_number(d.get('start since')) is None:
        return False
    r.update(
        detected=True,
        connected=True,
        uptime=service_number(d.get("start since")),
        identity=hashlib.sha256(str(d.get("start time", "")).encode()).hexdigest(),
    )
    for dest, src in {
        "queue": "listen queue",
        "active": "active processes",
        "idle": "idle processes",
        "total": "total processes",
        "requests": "accepted conn",
        "maxChildren": "max children reached",
        "slowRequests": "slow requests",
    }.items():
        r["metrics"][dest] = service_number(d.get(src))
    service_finish(r)
    return True


def fpm_automatic(c, r):
    records = [record for record in c['_runtime'] if record['verified']]
    if len(records) > 1:
        raise ValueError('endpoint_ambiguous')
    if not records:
        raise ValueError('source_unavailable')
    record = records[0]
    try:
        sources = fpm_status_sources(record) if record['complete'] else []
    except (OSError, ValueError):
        sources = []
    if len(sources) > 1:
        raise ValueError('endpoint_ambiguous')
    if sources:
        targets, path = sources[0]
        for target in targets:
            if not fpm_live_master(record):
                break
            try:
                if fpm_status_result(fpm_fastcgi_status(target, path), r):
                    return
            except (OSError, ValueError):
                continue
    total, queue = fpm_workers(record), fpm_queue(record)
    if (total is None and queue is None) or not fpm_live_master(record):
        raise ValueError('source_unavailable')
    r.update(detected=True, connected=True)
    r['metrics'].update(total=total, queue=queue)
    service_finish(r)


def php_fpm_connector(c, r):
    if not service_begin(c, r, ["/etc/php", "/run/php"]):
        return
    if c["autoEndpoint"]:
        fpm_automatic(c, r)
        return
    for path in ["/fpm-status?json", "/status?json"]:
        try:
            if fpm_status_result(json.loads(service_http(c, path, limit=16384)), r):
                return
        except (ValueError, OSError, http.client.HTTPException):
            pass
    raise ValueError("source_unavailable")


def prepare_fpm_endpoint(kind, config, result):
    prepare_service_endpoint(kind, config, result, detailed=True, local_only=True)


PHP_FPM_ADAPTER = ServiceAdapter(
    IdentityPolicy(process_pattern=r'php-fpm(?:[0-9]+(?:\.[0-9]+)?)?', diagnostic_paths=True, process_limit=1024, children=True),
    php_fpm_connector,
    prepare=prepare_fpm_endpoint,
)

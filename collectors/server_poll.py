"""Run independent read-only collector operations within one SSH command."""

POLL_INPUT_LIMIT = 2 * 1024 * 1024
POLL_FRAME_LIMIT = 40 * 1024
POLL_WORKERS = 4
POLL_TIMEOUT = 45
POLL_TASK_TIMEOUT = 15


def poll_frame(out, task, event, payload=None):
    data = json.dumps({'id': task, 'event': event, 'payload': payload},
                      separators=(',', ':'), allow_nan=False).encode()
    if len(data) >= POLL_FRAME_LIMIT:
        raise ValueError('Poll frame limit')
    out.write(data + b'\n')
    out.flush()


def poll_packages(state, send):
    if not isinstance(state, dict) or set(state) != {'root', 'hashes', 'resume', 'apt'}:
        raise ValueError('Invalid package inventory request')
    old_hashes = state['hashes']
    if not isinstance(old_hashes, list) or len(old_hashes) != 128 or any(
        h is not None and (not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h))
        for h in old_hashes
    ):
        raise ValueError('Invalid package hashes')
    resume = state['resume']
    if resume is not None and (not isinstance(resume, dict) or set(resume) != {'root', 'buckets', 'offset'}):
        raise ValueError('Invalid package resume state')
    apt = state['apt']
    if not isinstance(apt, list) or len(apt) > 8:
        raise ValueError('Invalid APT targets')
    inventory = package_inventory()
    result, hashes, _, _ = inventory
    root = result['root']
    if resume is not None and resume['root'] == root:
        page = {'buckets': resume['buckets'], 'offset': resume['offset']}
    elif resume is None and state['root'] == root:
        send('data', package_reply({'root': root}, inventory))
        page = None
    else:
        send('data', package_reply({}, inventory))
        wanted = [index for index, digest in enumerate(hashes) if digest != old_hashes[index]]
        page = {'buckets': wanted, 'offset': 0} if wanted else None
    while page is not None:
        reply = package_reply(dict(page, root=root), inventory)
        send('data', reply)
        page = reply['next']
    if apt and state['root'] == root:
        try:
            send('apt', package_reply({'root': root, 'apt': apt}, inventory))
        except PackageError as error:
            send('apt_error', str(error))


def poll_worker(out, task, request):
    def send(event, payload=None):
        poll_frame(out, task, event, payload)

    kind = request['kind']
    try:
        if kind == 'packages' and request['state']['apt']:
            apt_temp_file_limit(writable=False)
        else:
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        if kind == 'packages':
            poll_packages(request['state'], send)
        else:
            handler = {'metrics': lambda _: metrics(), 'logs': analyze_logs, 'service': dispatch_service}
            result = handler[kind](request)
            limit = 8192 if kind == 'metrics' else 32768
            if len(json.dumps(result, separators=(',', ':'), allow_nan=False).encode()) > limit:
                raise ValueError('Poll result limit')
            send('data', result)
        send('done')
    except PackageError as error:
        send('error', str(error))
    except Exception:
        send('error', 'collection_failed')


def poll_stop_worker(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)


def server_poll(request):
    if (not isinstance(request, dict) or set(request) != {'version', 'tasks'}
            or type(request['version']) is not int or request['version'] != 1
            or not isinstance(request['tasks'], list) or not 1 <= len(request['tasks']) <= 67):
        raise ValueError('Invalid server poll')
    pending = collections.deque()
    kinds = set()
    for task, operation in enumerate(request['tasks']):
        if not isinstance(operation, dict) or not isinstance(operation.get('kind'), str):
            raise ValueError('Invalid poll operation')
        kind = operation['kind']
        allowed = {
            'metrics': {'kind'}, 'logs': {'kind', 'state', 'salt', 'interval', 'thresholds'},
            'packages': {'kind', 'state'}, 'service': {'kind', 'state'},
        }
        if (kind not in allowed or set(operation) != allowed[kind]
                or len(json.dumps(operation, separators=(',', ':')).encode()) > 32768
                or (kind != 'service' and kind in kinds) or (kind == 'metrics' and task != 0)):
            raise ValueError('Invalid poll operation')
        pending.append((task, operation))
        kinds.add(kind)

    out = sys.stdout.buffer
    deadline = time.monotonic() + POLL_TIMEOUT
    active = {}
    with selectors.DefaultSelector() as selector:
        def start(task, operation):
            read_end, write_end = os.pipe()
            try:
                pid = os.fork()
            except OSError:
                os.close(read_end)
                os.close(write_end)
                poll_frame(out, task, 'error', 'worker_unavailable')
                return
            if pid == 0:
                try:
                    os.setpgid(0, 0)
                    os.close(read_end)
                    for fd in active:
                        os.close(fd)
                    selector.close()
                    with os.fdopen(write_end, 'wb') as pipe:
                        poll_worker(pipe, task, operation)
                finally:
                    os._exit(0)
            os.close(write_end)
            try:
                os.setpgid(pid, pid)
            except ProcessLookupError:
                pass
            selector.register(read_end, selectors.EVENT_READ)
            active[read_end] = [pid, task, time.monotonic() + POLL_TASK_TIMEOUT, bytearray(), False]

        def finish(fd, reason, event='error'):
            pid, task, _, _, terminal = active.pop(fd)
            selector.unregister(fd)
            os.close(fd)
            poll_stop_worker(pid)
            if reason and not terminal:
                poll_frame(out, task, event, reason)

        try:
            # The first result is usable even when another operation stalls.
            if 'metrics' in kinds:
                start(*pending.popleft())
            while active or pending:
                now = time.monotonic()
                if now >= deadline:
                    for fd in list(active):
                        finish(fd, 'poll_timeout', 'deferred')
                    for task, _ in pending:
                        poll_frame(out, task, 'deferred')
                    break
                metrics_running = 'metrics' in kinds and any(w[1] == 0 for w in active.values())
                while pending and len(active) < POLL_WORKERS and not metrics_running:
                    start(*pending.popleft())
                if not active:
                    continue
                wake = min(deadline, min(worker[2] for worker in active.values()))
                for key, _ in selector.select(max(0, wake - time.monotonic())):
                    fd = key.fd
                    worker = active[fd]
                    data = os.read(fd, 4096)
                    if not data:
                        finish(fd, 'worker_exited')
                        continue
                    worker[3].extend(data)
                    while b'\n' in worker[3]:
                        end = worker[3].index(b'\n') + 1
                        line = bytes(worker[3][:end])
                        del worker[3][:end]
                        event = load_collector_json(line)['event']
                        out.write(line)
                        out.flush()
                        if event in ('done', 'error'):
                            worker[4] = True
                    if len(worker[3]) >= POLL_FRAME_LIMIT:
                        finish(fd, 'response_limit')
                for fd in list(active):
                    if time.monotonic() >= active[fd][2]:
                        finish(fd, 'check_timeout')
        finally:
            for fd in list(active):
                finish(fd, None)

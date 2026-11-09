"""Broker for desktop-approved actions and their durable execution receipts."""
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import itertools
import os
import platform as action_platform
import pwd
import re
import resource
import select
import signal
import stat
import statistics
import subprocess
import sys
import tempfile
import time

class ActionError(ValueError):
    pass


ACTION_RULES = 'actions-v1'
ACTION_INPUT_LIMIT = 49152
ACTION_OUTPUT_LIMIT = 16384


def _action_filter():
    # The worker is already initialized. No path, network, process creation, IPC,
    # privilege, namespace, tracing, kernel control or descriptor creation syscall.
    arch = action_platform.machine()
    if arch == 'x86_64':
        audit_arch = 0xc000003e
        allowed = [0, 1, 3, 5, 9, 10, 11, 12, 13, 14, 15, 24, 25, 28,
                   39, 60, 98, 102, 104, 107, 108, 186, 202, 228, 231, 318]
    elif arch in ('aarch64', 'arm64'):
        audit_arch = 0xc00000b7
        allowed = [57, 63, 64, 80, 93, 94, 98, 113, 124, 134, 135, 139,
                   165, 172, 174, 175, 176, 177, 178, 214, 215, 216, 222, 226, 233, 278]
    else:
        raise ActionError('isolation_arch_unsupported')

    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]

    class Program(ctypes.Structure):
        _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]

    # Wrong ABI kills; unlisted syscalls return EPERM. x32 is never in the list.
    instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, audit_arch),
                    (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    for nr in allowed:
        instructions.extend([(0x15, 0, 1, nr), (0x06, 0, 0, 0x7fff0000)])
    instructions.append((0x06, 0, 0, 0x00050000 | errno.EPERM))
    bpf = (Filter * len(instructions))(*(Filter(*i) for i in instructions))
    program = Program(len(instructions), bpf)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise ActionError('isolation_seccomp_unavailable')


def action_worker():
    # Separate exec with empty environment/closed descriptors: no broker memory,
    # SSH secrets, config buffers, receipt descriptors or capabilities are inherited.
    try:
        payload = json.loads(sys.stdin.buffer.read(ACTION_INPUT_LIMIT + 1))
        code = payload['code']
        if not isinstance(code, str) or len(code.encode()) > 16384:
            raise ActionError('script_limit')
        compiled = compile(code, '<approved-python>', 'exec')
        inputs = payload['inputs']
        null = os.open('/dev/null', os.O_RDONLY)
        os.dup2(null, 0)
        if null > 2:
            os.close(null)
        os.closerange(3, 65536)
        if os.geteuid() == 0:
            os.setgroups([])
            os.setresgid(65534, 65534, 65534)
            os.setresuid(65534, 65534, 65534)
        os.environ.clear()
        resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
        resource.setrlimit(resource.RLIMIT_AS, (96 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (3, 3))
        namespace = {'inputs': inputs, 'json': json, 'math': math, 're': re,
                     'statistics': statistics, '__name__': '__approved__'}
        _action_filter()
        exec(compiled, namespace, namespace)
        result = json.dumps({'ok': True, 'result': namespace.get('result')},
                            separators=(',', ':'), allow_nan=False)
        if len(result.encode()) > ACTION_OUTPUT_LIMIT:
            os._exit(3)
        sys.stdout.write(result)
        sys.stdout.flush()
        os._exit(0)
    except BaseException:
        # Never echo exception contents: script strings and host metadata are untrusted.
        os.write(2, b'action_worker_rejected')
        os._exit(2)


def run_action_python(code, inputs):
    payload = json.dumps({'code': code, 'inputs': inputs}, separators=(',', ':'), allow_nan=False).encode()
    if len(payload) > ACTION_INPUT_LIMIT:
        raise ActionError('input_limit')
    started = time.monotonic()
    proc = subprocess.Popen([sys.executable, '-I', '-B', os.path.realpath(__file__), '--action-worker'],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            close_fds=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                            start_new_session=True)
    output = bytearray()
    try:
        proc.stdin.write(payload)
        proc.stdin.close()
        while True:
            if time.monotonic() - started > 8:
                raise ActionError('script_timeout')
            ready, _, _ = select.select([proc.stdout], [], [], .1)
            if ready:
                chunk = os.read(proc.stdout.fileno(), min(4096, ACTION_OUTPUT_LIMIT + 1 - len(output)))
                output.extend(chunk)
                if len(output) > ACTION_OUTPUT_LIMIT:
                    raise ActionError('script_output_limit')
                if not chunk:
                    break
        if proc.wait(timeout=1) != 0:
            raise ActionError('script_failed_or_isolation_unavailable')
        result = json.loads(output)
        if not isinstance(result, dict) or set(result) != {'ok', 'result'} or result['ok'] is not True:
            raise ActionError('invalid_script_result')
        return result['result']
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=1)
        proc.stdout.close()


def action_probe():
    code = '''
import os, socket
blocked = []
for op in (lambda: open('/etc/passwd').read(), lambda: open('/tmp/cyberbot-escape', 'w'),
           lambda: socket.socket(), lambda: os.fork(), lambda: os.execve('/bin/true', ['true'], {})):
    try:
        op()
        blocked.append(False)
    except (OSError, PermissionError):
        blocked.append(True)
result = {'blocked': blocked, 'value': sum(inputs['numbers'])}
'''
    # Import socket before filtering, but importing it inside the worker then needs
    # path access and fails. Preload only for this probe through the worker module.
    result = run_action_python(code, {'numbers': [2, 3]})
    if result != {'blocked': [True] * 5, 'value': 5}:
        raise ActionError('isolation_probe_failed')
    return {'available': True, 'engine': 'python-seccomp-v1', 'rules': ACTION_RULES,
            'cpuSeconds': 4, 'wallSeconds': 8, 'memoryBytes': 100663296,
            'outputBytes': ACTION_OUTPUT_LIMIT, 'files': False, 'network': False, 'processes': False}


if __name__ == '__main__' and sys.argv[1:] == ['--action-worker']:
    # The only entry into arbitrary Python. The broker process never evals code.
    import socket  # loaded before filtering; all socket syscalls remain denied
    action_worker()


def _action_hash(data):
    return hashlib.sha256(data).hexdigest()


def _action_private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    current = path
    # Reject symlinks and foreign ownership throughout the app-owned subtree.
    for _ in range(3):
        meta = os.lstat(current)
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o022:
            raise ActionError('unsafe_action_directory')
        current = os.path.dirname(current)
    return path


def _action_read(path, cap=131072):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > cap:
            raise ActionError('action_file_limit')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(cap + 1)
        if len(data) > cap:
            raise ActionError('action_file_limit')
        return data, meta
    finally:
        os.close(fd)


def _action_write(path, data, mode=0o600, uid=None, gid=None):
    # Only internal fixed filenames or the fixed Nginx config reach this function.
    temporary = path + '.cyberbot-tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fchmod(fd, mode)
        if uid is not None:
            os.fchown(fd, uid, gid)
        os.fsync(fd)
        os.replace(temporary, path)
        directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _action_fixed(args, seconds=3):
    # No interpolated command string, shell, inherited environment or unbounded output.
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, close_fds=True,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'},
                            start_new_session=True)
    try:
        return proc.wait(timeout=seconds) == 0
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=1)


def _action_capture(args):
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, close_fds=True,
                            env={'PATH':'/usr/bin:/bin','LANG':'C'}, start_new_session=True)
    output = bytearray()
    started = time.monotonic()
    try:
        while time.monotonic() - started < 3:
            if select.select([proc.stdout],[],[],.1)[0]:
                chunk = os.read(proc.stdout.fileno(),1024)
                output.extend(chunk)
                if len(output)>8192: raise ActionError('service_metadata_limit')
                if not chunk:
                    if proc.wait(timeout=1)!=0: raise ActionError('systemd_unavailable')
                    return output.decode('utf-8',errors='strict')
        raise ActionError('service_metadata_timeout')
    finally:
        if proc.poll() is None: os.killpg(proc.pid,signal.SIGKILL)
        proc.wait(timeout=1)
        proc.stdout.close()


class DiagnosticAction:
    name = 'diagnostic'

    def validate(self, action):
        if action != {'kind': self.name}:
            raise ActionError('unsupported_diagnostic_manifest')

    def validate_result(self, action, result):
        pass

    def prepare(self, action):
        self.validate(action)
        return {'kind': self.name, 'writes': [], 'rollback': 'No host changes',
                'limits': action_probe()}

    def apply(self, action, prepared, directory):
        self.validate(action)
        if prepared != self.prepare(action):
            raise ActionError('prepared_action_changed')
        return {'changed': False, 'verified': True}


SHELL_SECONDS = 15
SHELL_STREAM_BYTES = 4096


class ShellAction:
    def validate(self, action):
        if action != {'kind': 'shell'}:
            raise ActionError('invalid_shell_action')

    def prepare(self, action):
        uid = os.geteuid()
        return {'kind': 'shell', 'uid': uid, 'user': pwd.getpwuid(uid).pw_name}

    def rollback(self, action, prepared, directory):
        raise ActionError('rollback_not_available')


def _shell_stream(data):
    text = data.decode('utf-8', errors='replace')
    # Bound the serialized representation as well as the raw byte stream.
    if len(json.dumps(text)) <= SHELL_STREAM_BYTES:
        return text, False
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if len(json.dumps(text[:middle])) <= SHELL_STREAM_BYTES:
            low = middle
        else:
            high = middle - 1
    return text[:low], True


def run_action_shell(code, watch_fd):
    if not isinstance(code, str) or not code.strip() or '\0' in code or len(code.encode()) > 16384:
        raise ActionError('invalid_shell_script')
    with tempfile.TemporaryFile() as script:
        script.write(code.encode())
        script.seek(0)
        if watch_fd is not None and select.select([watch_fd], [], [], 0)[0]:
            return 'unknown', {'reason': 'disconnected_before_launch'}
        deadline = time.monotonic() + SHELL_SECONDS
        process = subprocess.Popen(['/bin/sh', '-s'], stdin=script, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        streams = {process.stdout.fileno(): bytearray(), process.stderr.fileno(): bytearray()}
        pending = list(streams)
        if watch_fd is not None:
            pending.append(watch_fd)
        truncated = False
        reason = None
        exit_code = None
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = 'timeout'
                    break
                # Keep the shell leader unreaped until cleanup of the process group.
                if not any(fd in streams for fd in pending) and os.waitid(
                        os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                    break
                for fd in select.select(pending, [], [], min(0.1, remaining))[0]:
                    if fd == watch_fd:
                        reason = 'connection_closed'
                        break
                    chunk = os.read(fd, 4096)
                    if not chunk:
                        pending.remove(fd)
                        continue
                    room = SHELL_STREAM_BYTES - len(streams[fd])
                    truncated |= len(chunk) > room
                    streams[fd].extend(chunk[:room])
                if reason:
                    break
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                exit_code = process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                reason = 'process_exit_unconfirmed'
            process.stdout.close()
            process.stderr.close()
        (stdout, out_cut), (stderr, err_cut) = [_shell_stream(data) for data in streams.values()]
        result = {'exitCode': exit_code if not reason else None, 'stdout': stdout,
                  'stderr': stderr, 'truncated': truncated or out_cut or err_cut}
        if reason:
            result['reason'] = reason
        return ('unknown' if reason else 'succeeded' if exit_code == 0 else 'failed'), result


ACTION_HANDLERS = {'diagnostic': DiagnosticAction(), 'shell': ShellAction()}


def _action_main_locked(request, watch_fd):
    if not isinstance(request, dict) or set(request) - {'operation', 'requestId', 'artifactHash', 'code', 'inputs', 'action', 'prepared'}:
        raise ActionError('unsupported_action_request')
    operation = request.get('operation')
    action = request.get('action')
    if not isinstance(action, dict) or action.get('kind') not in ACTION_HANDLERS:
        raise ActionError('unsupported_action')
    handler = ACTION_HANDLERS[action['kind']]
    handler.validate(action)
    shell = action['kind'] == 'shell'
    if operation == 'prepare':
        limits = ({'engine': 'ssh-shell-v1', 'rules': ACTION_RULES,
                   'wallSeconds': SHELL_SECONDS, 'outputBytes': SHELL_STREAM_BYTES * 2}
                  if shell else action_probe())
        return {'rules': ACTION_RULES, 'isolation': limits, 'prepared': handler.prepare(action)}
    request_id = request.get('requestId', '')
    artifact_hash = request.get('artifactHash', '')
    if not re.fullmatch(r'[0-9a-f-]{36}', request_id) or not re.fullmatch(r'[0-9a-f]{64}', artifact_hash):
        raise ActionError('invalid_action_identity')
    root = _action_private_dir(os.path.join(os.path.expanduser('~'), '.cache', 'cyberbot', 'actions'))
    action_trim(root)
    directory = os.path.join(root, request_id)
    receipt_path = os.path.join(directory, 'receipt.json')
    if operation in ('result', 'rollback') or os.path.lexists(directory):
        previous, _ = _action_read(receipt_path, 32768)
        receipt = json.loads(previous)
        if receipt.get('hash') != artifact_hash:
            raise ActionError('action_identity_conflict')
        if operation != 'rollback':
            return receipt if receipt['state'] != 'running' else {'state': 'unknown', 'hash': artifact_hash}
        if shell:
            raise ActionError('rollback_not_available')
        if receipt['state'] != 'succeeded' or receipt['action'] != action or receipt['prepared'] != request.get('prepared'):
            raise ActionError('rollback_not_available')
        # Durable rollback intent precedes the side effect; never retry unknown work.
        receipt['state'] = 'rollbackRunning'
        _action_write(receipt_path, json.dumps(receipt, separators=(',', ':')).encode())
        try:
            result = handler.rollback(action, receipt['prepared'], directory)
            receipt.update(state='rolledBack' if result['verified'] else 'rollbackUnknown', result=result)
        except Exception:
            receipt.update(state='rollbackUnknown', error='rollback_failed_or_changed')
        _action_write(receipt_path, json.dumps(receipt, separators=(',', ':')).encode())
        return receipt
    if operation != 'execute':
        raise ActionError('unsupported_action_operation')
    if sum(1 for _ in os.scandir(root)) >= 1000:
        raise ActionError('remote_receipt_limit')
    prepared = request.get('prepared')
    if handler.prepare(action) != prepared:
        raise ActionError('prepared_action_changed')
    os.mkdir(directory, 0o700)  # O_EXCL directory is the remote idempotency fence.
    receipt = {'hash': artifact_hash, 'state': 'running', 'action': action, 'prepared': prepared}
    _action_write(receipt_path, json.dumps(receipt, separators=(',', ':')).encode())
    try:
        if shell:
            status, result = run_action_shell(request['code'], watch_fd)
            receipt.update(state=status, result=result)
        else:
            result = run_action_python(request['code'], request['inputs'])
            handler.validate_result(action, result)
            applied = handler.apply(action, prepared, directory)
            receipt.update(state='succeeded' if applied['verified'] else 'failed' if applied.get('rollbackVerified') else 'unknown', result=result, effect=applied)
    except Exception:
        # If a host operation was entered, do not infer that no side effect happened.
        receipt.update(state='failed' if action['kind'] == 'diagnostic' else 'unknown', error='execution_failed')
    _action_write(receipt_path, json.dumps(receipt, separators=(',', ':')).encode())
    return receipt


def action_main(request, watch_fd=None):
    if isinstance(request,dict) and request.get('operation')=='prepare':
        return _action_main_locked(request, watch_fd)
    root=_action_private_dir(os.path.join(os.path.expanduser('~'),'.cache','cyberbot','actions'))
    lock=os.path.join(os.path.dirname(root),'action.lock')
    fd=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode & 0o077:
            raise ActionError('unsafe_action_lock')
        started=time.monotonic()
        while True:
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic()-started>2: raise ActionError('action_lock_busy')
                time.sleep(.05)
        return _action_main_locked(request, watch_fd)
    finally:
        os.close(fd)


def action_trim(root):
    # Only broker-owned regular artifacts are removed. No recursive filesystem delete.
    entries = []
    total = 0
    for entry in itertools.islice(os.scandir(root),1001):
        if not re.fullmatch(r'[0-9a-f-]{36}', entry.name) or not entry.is_dir(follow_symlinks=False):
            raise ActionError('foreign_action_artifact')
        if entry.stat(follow_symlinks=False).st_uid != os.getuid():
            raise ActionError('foreign_action_artifact')
        files = []
        for child in os.scandir(entry.path):
            if child.name not in ('receipt.json', 'before.conf', 'receipt.json.cyberbot-tmp') or not child.is_file(follow_symlinks=False) or child.stat(follow_symlinks=False).st_uid != os.getuid():
                raise ActionError('foreign_action_artifact')
            total += child.stat().st_size
            files.append(child.path)
        receipt, _ = _action_read(os.path.join(entry.path, 'receipt.json'), 32768)
        state = json.loads(receipt).get('state')
        if state in ('running', 'rollbackRunning') and entry.stat().st_mtime < time.time() - 60:
            state = 'unknown'
        # Unknown side effects retain their evidence until the 7-day policy expires.
        entries.append((entry.stat().st_mtime, entry.path, files, state not in ('running', 'rollbackRunning')))
    entries.sort()
    for at, directory, files, terminal in entries:
        if terminal and (at < time.time() - 7 * 86400 or total > 32 * 1024 * 1024 - 262144):
            for path in files:
                total -= os.lstat(path).st_size
                os.unlink(path)
            os.rmdir(directory)
    if total > 32 * 1024 * 1024 - 262144:
        raise ActionError('remote_artifact_limit')

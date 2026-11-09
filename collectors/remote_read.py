"""Bounded remote reads. Paths are walked through directory descriptors, never a shell."""

import contextlib
import json
import os
import stat
import time


READ_ROOTS = ('/home', '/srv', '/opt', '/var/www')
READ_LIMIT = 16 * 1024 * 1024
READ_FILE_LIMIT = 1024 * 1024
READ_ENTRY_LIMIT = 12000
READ_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _read_public_name(name):
    name = name.lower()
    return (not name.startswith(('.', 'id_', 'credential', 'secret', 'password'))
            and name not in ('authorized_keys', 'known_hosts', 'shadow', 'passwd', 'kubeconfig')
            and not name.endswith(('.key', '.pem', '.p12', '.pfx', '.kdbx')))


def _read_path(path):
    if not isinstance(path, str) or len(path.encode()) > 1024:
        raise ValueError('invalid_path')
    parts = path.split('/')[1:]
    if (not any(path == root or path.startswith(root + '/') for root in READ_ROOTS)
            or any(not name or not _read_public_name(name) or not name.isprintable() for name in parts)):
        raise ValueError('path_outside_read_policy')
    return parts


@contextlib.contextmanager
def _read_open(parent, name, directory):
    if directory:
        fd = os.open(name, READ_DIR, dir_fd=parent)
        try:
            yield fd
        finally:
            os.close(fd)
        return
    # O_PATH pins an inode without opening a device or FIFO that replaces it during traversal.
    reference = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
    try:
        info = os.fstat(reference)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('not_a_regular_file')
        fd = os.open('/proc/self/fd/{}'.format(reference), os.O_RDONLY | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or (
                    opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('file_changed')
            yield fd
        finally:
            os.close(fd)
    finally:
        os.close(reference)


class RemoteRead:
    def __init__(self):
        self.deadline = time.monotonic() + 8
        self.entries = 0
        self.bytes = 0
        self.allocated = 0
        self.rows = []
        self.output_bytes = 0
        self.gaps = set()

    def add(self, row):
        size = len(json.dumps(row, separators=(',', ':'))) + 1
        if self.output_bytes + size > 12288:
            self.gaps.add('output_limit')
            return False
        self.rows.append(row)
        self.output_bytes += size
        return True

    def read(self, fd):
        cap = min(READ_FILE_LIMIT, READ_LIMIT - self.bytes)
        data = bytearray()
        while len(data) < cap:
            chunk = os.read(fd, min(65536, cap - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        self.bytes += len(data)
        if len(data) == cap and os.fstat(fd).st_size > len(data):
            self.gaps.add('read_limit')
        return bytes(data)

    def walk(self, fd, path, operation, needle, depth=0):
        if depth >= 32:
            self.gaps.add('depth_limit')
            return
        if operation == 'du':
            self.allocated += os.fstat(fd).st_blocks * 512
        with scan_directory(fd) as directory:
            for entry in directory:
                if (time.monotonic() >= self.deadline or self.entries >= READ_ENTRY_LIMIT
                        or self.bytes >= READ_LIMIT or 'output_limit' in self.gaps):
                    self.gaps.add('scan_limit')
                    return
                self.entries += 1
                name = entry.name
                if not _read_public_name(name) or not name.isprintable():
                    self.gaps.add('excluded_paths')
                    continue
                child = path + '/' + name
                try:
                    info = entry.stat(follow_symlinks=False)
                    is_dir = stat.S_ISDIR(info.st_mode)
                    if not is_dir and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                        self.gaps.add('excluded_paths')
                        continue
                    if operation == 'ls':
                        if not self.add({'name': name, 'directory': is_dir, 'bytes': info.st_size}):
                            return
                    elif is_dir:
                        with _read_open(fd, name, True) as nested:
                            self.walk(nested, child, operation, needle, depth + 1)
                    elif operation == 'du':
                        self.allocated += info.st_blocks * 512
                    else:
                        with _read_open(fd, name, False) as file:
                            self.search(file, child, needle)
                except (OSError, ValueError):
                    self.gaps.add('unreadable_entries')

    def search(self, fd, path, needle):
        data = self.read(fd)
        if b'\0' not in data and needle in data:
            self.add(path)


def remote_read(request):
    operation = request.get('operation')
    options = {'ls': set(), 'du': set(), 'grep': {'pattern'},
               'cat': {'startLine', 'lineCount'}, 'sed': {'startLine', 'lineCount'},
               'awk': {'startLine', 'lineCount', 'fields', 'separator'}}
    if operation not in options or set(request) - ({'operation', 'path'} | options[operation]):
        raise ValueError('invalid_read_operation')
    path = request.get('path')
    parts = _read_path(path)
    start = request.get('startLine', 1)
    count = request.get('lineCount', 100)
    fields = request.get('fields', [])
    separator = request.get('separator')
    pattern = request.get('pattern', '')
    if (type(start) is not int or not 1 <= start <= 100000 or type(count) is not int or not 1 <= count <= 200
            or not isinstance(fields, list) or len(fields) > 16
            or any(type(field) is not int or not 1 <= field <= 256 for field in fields)
            or operation == 'awk' and not fields
            or separator is not None and (not isinstance(separator, str) or len(separator) != 1)
            or operation == 'grep' and (not isinstance(pattern, str) or not 0 < len(pattern.encode()) <= 256)):
        raise ValueError('invalid_read_parameters')
    result = RemoteRead()
    next_line = None
    with contextlib.ExitStack() as stack:
        parent = os.open('/', READ_DIR)
        stack.callback(os.close, parent)
        for name in parts[:-1]:
            parent = stack.enter_context(_read_open(parent, name, True))
        directory = operation in ('ls', 'du') or operation == 'grep' and stat.S_ISDIR(
            os.stat(parts[-1], dir_fd=parent, follow_symlinks=False).st_mode)
        fd = stack.enter_context(_read_open(parent, parts[-1], directory))
        if directory:
            result.walk(fd, path, operation, pattern.encode())
        elif operation == 'grep':
            result.search(fd, path, pattern.encode())
        else:
            data = result.read(fd)
            if b'\0' in data:
                raise ValueError('binary_file')
            lines = data.decode('utf-8', errors='replace').split('\n')
            if lines and not lines[-1]:
                lines.pop()
            if start + count <= len(lines):
                next_line = start + count
            for number, line in enumerate(lines[start - 1:start - 1 + count], start):
                if operation == 'awk':
                    values = line.split(separator, max(fields))
                    line = ' '.join(values[field - 1] if field <= len(values) else '' for field in fields)
                if not result.add({'line': number, 'text': line}):
                    next_line = number if result.rows else None
                    break
    response = {'operation': operation, 'path': path, 'complete': not result.gaps,
                'gaps': sorted(result.gaps), 'entriesScanned': result.entries, 'bytesRead': result.bytes}
    if operation == 'du':
        response['allocatedBytes'] = result.allocated
    else:
        response[{'grep': 'paths', 'ls': 'entries'}.get(operation, 'lines')] = result.rows
    if next_line is not None:
        response['nextStartLine'] = next_line
    return response

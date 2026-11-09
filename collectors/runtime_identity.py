"""Bounded local process/socket identity. Diagnostic details stay on the server."""
import ipaddress
import os
import re
import sys
import time


class IdentityPolicy:
    def __init__(self, *process_names, process_pattern=None, executable_aliases=(),
                 verify_alias=None, sockets=(), socket_pattern=None, diagnostic_paths=False,
                 process_limit=128, stream_tcp=False, children=False,
                 unix_endpoint=None, discover=True, tcp_endpoint=True, group_processes=True):
        self.process_names = process_names
        self.process_pattern = re.compile(process_pattern) if process_pattern else None
        self.executable_aliases = executable_aliases
        self.verify_alias = verify_alias
        self.sockets = sockets
        self.socket_pattern = re.compile(socket_pattern) if socket_pattern else None
        self.diagnostic_paths = diagnostic_paths
        self.process_limit = process_limit
        self.stream_tcp = stream_tcp
        self.children = children
        self.unix_endpoint = unix_endpoint or fixed_unix_endpoint
        self.discover = discover
        self.tcp_endpoint = tcp_endpoint
        self.group_processes = group_processes

    def matches_executable(self, name, path):
        return (
            name in self.process_names
            or name in self.executable_aliases
            or self.process_pattern is not None and self.process_pattern.fullmatch(name) is not None
            or self.verify_alias is not None and self.verify_alias(name, path)
        )


class RuntimeIdentityRegistry:
    def __init__(self, policies):
        self.policies = policies
        self.by_name = {}
        self.process_patterns = []
        self.sockets = set()
        self.socket_patterns = []
        for kind, policy in policies.items():
            for name in policy.process_names:
                if name in self.by_name:
                    raise ValueError('Duplicate process name: {}'.format(name))
                self.by_name[name] = kind
            if policy.process_pattern is not None:
                self.process_patterns.append((policy.process_pattern, kind))
            self.sockets.update(policy.sockets)
            if policy.socket_pattern is not None:
                self.socket_patterns.append(policy.socket_pattern)

    def kind(self, name):
        kind = self.by_name.get(name)
        if kind is not None:
            return kind
        return next((kind for pattern, kind in self.process_patterns if pattern.fullmatch(name)), None)

    def accepts_socket(self, path, policy):
        return (
            path in self.sockets
            or any(pattern.fullmatch(path) for pattern in self.socket_patterns)
            or policy is not None and policy.diagnostic_paths and path.startswith('/') and len(path) <= 107
        )


def fixed_unix_endpoint(path, port, allowed):
    return (path, port) if path in allowed else None


def process_stat(raw):
    fields = raw[raw.rfind(')') + 2:].split()
    return int(fields[1]), int(fields[19])  # ppid, starttime; comm may contain spaces


def service_runtime(proc='/proc', kind_filter=None, details=False, *, tcp_binds=None, process_only=False):
    """Discover service processes. tcp_binds supplies the (host, port) pairs to verify per process."""
    # Diagnostic discovery also runs on busy servers with thousands of open client sockets.
    diagnostic = kind_filter is not None
    policy = RUNTIME_IDENTITIES.policies.get(kind_filter)
    process_limit = policy.process_limit if policy is not None else 128
    deadline = time.monotonic() + (.75 if diagnostic else .25)
    remaining = (3 * 1024 if diagnostic else 512) * 1024
    table_limit = (1024 if diagnostic else 128) * 1024
    fd_limit = 4096 if diagnostic else 256
    complete = True

    def read(path, cap):
        nonlocal remaining
        if time.monotonic() >= deadline or remaining <= 0:
            raise ValueError('identity_budget')
        with open(path, 'rb') as stream:
            data = stream.read(min(cap, remaining) + 1)
        if len(data) > cap or len(data) > remaining:
            raise ValueError('identity_budget')
        remaining -= len(data)
        return data.decode('ascii', errors='replace')

    def tcp_listener_rows(path):
        nonlocal remaining
        # Linux lists listening sockets before established connections.
        available = min(table_limit, remaining)
        with open(path, 'rb') as stream:
            for index, line in enumerate(iter(lambda: stream.readline(1025), b'')):
                if len(line) > min(1024, available) or time.monotonic() >= deadline:
                    raise ValueError('identity_budget')
                available -= len(line)
                remaining -= len(line)
                if index == 0:
                    continue
                fields = line.decode('ascii').split()
                if len(fields) < 4:
                    raise ValueError('invalid_socket_table')
                if fields[3] != '0A':
                    break
                if len(fields) < 10:
                    raise ValueError('invalid_socket_table')
                yield fields

    def stat(pid):
        return process_stat(read('{}/{}/stat'.format(proc, pid), 2048))

    try:
        namespace = os.readlink('{}/self/ns/net'.format(proc))
        processes = {}
        with scan_directory(proc) as entries:
            for index, entry in enumerate(entries):
                if index >= 4096:
                    complete = False
                    break
                if not entry.name.isdecimal():
                    continue
                try:
                    kind = RUNTIME_IDENTITIES.kind(read(entry.path + '/comm', 64).strip())
                    if not kind or kind_filter is not None and kind != kind_filter:
                        continue
                    process_namespace = os.readlink(entry.path + '/ns/net')
                    if not process_namespace and details:
                        complete = False  # Some procfs implementations hide inaccessible targets.
                    if process_namespace != namespace:
                        continue  # Container namespace ports are not host endpoints.
                    pid = int(entry.name)
                    parent, started = stat(pid)
                    processes[pid] = (kind, parent, started)
                    if len(processes) >= process_limit:
                        complete = False
                        break
                except FileNotFoundError:
                    continue
                except OSError:
                    complete = False
        # Group workers/backends under their same-software master.
        roots = {}
        for pid, (kind, parent, started) in processes.items():
            root, visited = pid, set()
            while (RUNTIME_IDENTITIES.policies[kind].group_processes and parent in processes
                   and processes[parent][0] == kind and parent not in visited):
                visited.add(parent)
                root, parent = parent, processes[parent][1]
            roots[root] = processes[root]
        sockets, unix = {}, {}
        network_complete = True
        tables = ('tcp', 'tcp6', 'udp', 'udp6') if kind_filter is None else ('tcp', 'tcp6')
        for table in (() if process_only else tables):
            try:
                path = '{}/net/{}'.format(proc, table)
                if tcp_binds is not None or policy is not None and policy.stream_tcp:
                    rows = tcp_listener_rows(path)
                else:
                    rows = (row.split() for row in read(path, table_limit).splitlines()[1:])
                for fields in rows:
                    if len(fields) >= 10 and fields[3] == ('0A' if table.startswith('tcp') else '07'):
                        port = int(fields[1].rsplit(':', 1)[1], 16)
                        if 0 < port <= 65535:
                            if kind_filter is None:
                                sockets[fields[9]] = port
                            elif table.startswith('tcp'):
                                raw = bytes.fromhex(fields[1].split(':', 1)[0])
                                if sys.byteorder == 'little':
                                    raw = b''.join(raw[i:i+4][::-1] for i in range(0, len(raw), 4))
                                address = ipaddress.ip_address(raw)
                                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                                    address = address.ipv4_mapped
                                sockets[fields[9]] = (str(address), port)
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                network_complete = False
        if not process_only and tcp_binds is None:
            try:
                for row in read('{}/net/unix'.format(proc), table_limit).splitlines()[1:]:
                    fields = row.split(maxsplit=7)
                    if (len(fields) == 8 and fields[3:6] == ['00010000', '0001', '01']
                            and RUNTIME_IDENTITIES.accepts_socket(fields[7], policy)):
                        unix[fields[6]] = fields[7]
            except (OSError, ValueError):
                network_complete = False
        result = []
        for pid, (kind, parent, started) in sorted(roots.items()):
            if len(result) >= 64 or time.monotonic() >= deadline:
                complete = False
                break
            ports, paths, covered = set(), set(), network_complete
            verified, inodes = False, {}
            try:
                if kind_filter is not None:
                    exe_path = '{}/{}/exe'.format(proc, pid)
                    executable = os.path.basename(os.readlink(exe_path)).split(' (deleted)', 1)[0]
                    if not policy.matches_executable(executable, exe_path):
                        continue
                    verified = True
                if tcp_binds is not None:
                    binds = tcp_binds({'pid': pid, 'started': started})
                    candidates = {
                        inode: address for inode, address in sockets.items()
                        if any(tcp_bind_matches(address, bind) for bind in binds)
                    }
                    inodes, scanned = owned_tcp_listeners('{}/{}/fd'.format(proc, pid), candidates, deadline)
                    ports.update(inodes.values())
                    covered = covered and scanned
                elif not process_only:
                    with scan_directory('{}/{}/fd'.format(proc, pid)) as descriptors:
                        for index, fd in enumerate(descriptors):
                            if index >= fd_limit or time.monotonic() >= deadline:
                                covered = False
                                break
                            try:
                                link = os.readlink(fd.path)
                                match = re.fullmatch(r'socket:\[([0-9]+)\]', link)
                                if match:
                                    inode = match.group(1)
                                    if inode in sockets:
                                        ports.add(sockets[inode])
                                        if details:
                                            inodes[inode] = sockets[inode]
                                    if inode in unix:
                                        paths.add(unix[inode])
                                        if details:
                                            inodes[inode] = unix[inode]
                            except FileNotFoundError:
                                continue
                if stat(pid)[1] != started:
                    continue
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                covered = False
            if len(ports) > 16 or len(paths) > 4:
                covered = False
            record = {'kind': kind, 'pid': pid, 'sockets': sorted(paths)[:4], 'complete': covered}
            record['ports' if kind_filter is None else 'listeners'] = sorted(ports)[:16]
            if details:
                record.update(verified=verified, started=started, inodes=inodes)
                if RUNTIME_IDENTITIES.policies[kind].children:
                    record['children'] = [p for p, (k, parent, _) in processes.items() if k == kind and parent == pid] if complete else None
            result.append(record)
        return result, complete
    except (OSError, ValueError, IndexError):
        return [], False


def literal_ip(value):
    if not isinstance(value, str) or '%' in value:
        return False
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_unspecified or ip.is_multicast or ip.is_link_local or str(ip) == '255.255.255.255')
    except ValueError:
        return False


def local_interface_address(address, proc='/proc'):
    ip = ipaddress.ip_address(address)
    if ip.is_loopback:
        return True
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return False
    try:
        table = 'if_inet6' if ip.version == 6 else 'fib_trie'
        with open('{}/net/{}'.format(proc, table), encoding='ascii') as stream:
            rows = stream.read(131073)
        if len(rows) > 131072:
            return False
        if ip.version == 6:
            return any(row.split()[0] == ip.packed.hex() for row in rows.splitlines() if row.split())
        previous = ''
        for line in rows.splitlines():
            fields = line.split()
            if fields == ['/32', 'host', 'LOCAL'] and previous == str(ip):
                return True
            previous = fields[-1] if fields else ''
    except (OSError, UnicodeError):
        pass
    return False


def owned_listener(kind, endpoint, port, records):
    ip = ipaddress.ip_address(endpoint)
    endpoint = str(ip)
    wildcard = '::' if ip.version == 6 else '0.0.0.0'
    return local_interface_address(endpoint) and any(
        r['complete'] and ((endpoint, port) in r['listeners'] or (wildcard, port) in r['listeners'])
        for r in records if r['kind'] == kind
    )


def local_listeners(record, port=None):
    """Connectable addresses of a proven listener, with wildcards mapped to loopback."""
    if not record['complete']:
        return set()
    return {
        (host, number) for address, number in record['listeners']
        if port is None or number == port
        for host in [{'0.0.0.0': '127.0.0.1', '::': '::1'}.get(address, address)]
        if local_interface_address(host)
    }


def listener_address(value, default_port):
    """Split service bind syntax; an empty host means any local interface."""
    if literal_ip(value) or value == '::':
        return value, default_port
    host, sep, number = value.rpartition(':')
    if not sep:
        if value.isdecimal():
            return '', int(value)
        return value, default_port
    if not number.isdecimal():
        raise ValueError('source_unavailable')
    return host.strip('[]'), int(number)


def tcp_bind_matches(listener, bind):
    address, port = listener
    host, bind_port = bind
    if port != bind_port:
        return False
    ip = ipaddress.ip_address(address)
    if literal_ip(host):
        expected = ipaddress.ip_address(host)
        return ip == expected or ip.is_unspecified and ip.version == expected.version
    if host == 'localhost':
        return ip.is_loopback or ip.is_unspecified
    if host in ('0.0.0.0', '::'):
        return ip.version == ipaddress.ip_address(host).version
    return True


def owned_tcp_listeners(path, candidates, deadline):
    """Match socket inodes without inspecting descriptors past the last match."""
    found = {}
    pending = {'socket:[{}]'.format(inode): inode for inode in candidates}
    if not pending:
        return found, True
    with scan_directory(path) as descriptors:
        for fd in descriptors:
            if time.monotonic() >= deadline:
                return found, False
            try:
                inode = pending.pop(os.readlink(fd.path), None)
            except FileNotFoundError:
                continue
            if inode is not None:
                found[inode] = candidates[inode]
                if not pending:
                    break
    return found, True


def bind_targets(record, value, default_port):
    host, port = listener_address(value, default_port)
    if literal_ip(host):
        host = str(ipaddress.ip_address(host))
        return {(host, port)} if owned_listener(record['kind'], host, port, [record]) else set()
    targets = local_listeners(record, port)
    if host == 'localhost':
        return {target for target in targets if ipaddress.ip_address(target[0]).is_loopback}
    if host in ('0.0.0.0', '::'):
        family = ipaddress.ip_address(host).version
        return {target for target in targets if ipaddress.ip_address(target[0]).version == family}
    return targets


def discovered_endpoint(kind, endpoint, port, allowed, records):
    policy = RUNTIME_IDENTITIES.policies[kind]
    if not policy.discover:
        return endpoint, port
    candidates = {}
    for record in records:
        if not record['complete']:
            continue
        targets = set()
        for path in record['sockets']:
            target = policy.unix_endpoint(path, port, allowed)
            if target is not None:
                targets.add(target)
        if policy.tcp_endpoint:
            targets.update(local_listeners(record))
        for target in targets:
            candidates.setdefault(target, set()).add(record['pid'])
    if not candidates:
        return endpoint, port
    if len(candidates.get((endpoint, port), ())) == 1:
        return endpoint, port
    preferred = {target for target in candidates if target[1] == port} or candidates.keys()
    owners = {pid for target in preferred for pid in candidates[target]}
    if len(owners) > 1 or len({number for _, number in preferred}) > 1:
        raise ValueError('endpoint_ambiguous')
    return min(preferred, key=lambda target: (not target[0].startswith('/'), target[0] not in ('127.0.0.1', '::1'), target))

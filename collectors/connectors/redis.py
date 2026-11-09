"""Fixed Redis INFO commands; RESP parsing is byte/depth bounded."""


class RedisRead:
    def __init__(self, c):
        self.sock = socket.socket(
            (
                socket.AF_UNIX
                if c["endpoint"].startswith("/")
                else socket.AF_INET6 if ':' in c["endpoint"] else socket.AF_INET
            ),
            socket.SOCK_STREAM,
        )
        self.sock.settimeout(2)
        self.sock.connect(
            c["endpoint"]
            if c["endpoint"].startswith("/")
            else (c["endpoint"], c["port"])
        )
        self.f = self.sock.makefile("rb")
        self.left = 262144

    def read(self, n):
        if n > self.left:
            raise ValueError("response_limit")
        b = self.f.read(n)
        self.left -= len(b)
        if len(b) != n:
            raise ValueError("source_unavailable")
        return b

    def line(self):
        b = self.f.readline(min(self.left + 1, 16385))
        self.left -= len(b)
        if self.left < 0 or not b.endswith(b"\r\n"):
            raise ValueError("response_limit")
        return b[:-2]

    def command(self, *args):
        args = [str(x).encode() for x in args]
        self.sock.sendall(
            b"*"
            + str(len(args)).encode()
            + b"\r\n"
            + b"".join(
                b"$" + str(len(x)).encode() + b"\r\n" + x + b"\r\n" for x in args
            )
        )
        t = self.read(1)
        if t == b"-":
            self.line()
            raise ValueError("connection_denied")
        if t == b"+":
            return self.line()
        if t == b"$":
            n = int(self.line())
            if n < 0:
                raise ValueError("source_unavailable")
            b = self.read(n)
            if self.read(2) != b"\r\n":
                raise ValueError("source_unavailable")
            return b
        raise ValueError("source_unavailable")

    def close(self):
        self.f.close()
        self.sock.close()


def redis_connector(c, r):
    if not service_begin(c, r, ["/etc/redis", "/run/redis/redis-server.pid"]):
        return
    client = RedisRead(c)
    try:
        cred = service_credentials("redis", c.get("_instanceId", "default"))
        if cred.get("password"):
            client.command(
                "AUTH",
                *(
                    [cred.get("user") or c["user"], cred["password"]]
                    if cred.get("user") or c["user"]
                    else [cred["password"]]
                ),
            )
        d = {}
        for section in [
            "server",
            "clients",
            "memory",
            "stats",
            "persistence",
            "replication",
        ]:
            try:
                for line in (
                    client.command("INFO", section)
                    .decode("ascii", "replace")
                    .splitlines()
                ):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        d[k] = v
            except ValueError:
                r["issues"].append("partial_coverage")
        if "redis_version" not in d:
            raise ValueError("connection_denied")
        r.update(
            detected=True,
            connected=True,
            identity=hashlib.sha256(
                d.get("run_id", d["redis_version"]).encode()
            ).hexdigest(),
            uptime=service_number(d.get("uptime_in_seconds")),
        )
        m = r["metrics"]
        for dest, src in {
            "connections": "connected_clients",
            "blocked": "blocked_clients",
            "memory": "used_memory",
            "maxMemory": "maxmemory",
            "evictions": "evicted_keys",
            "rejected": "rejected_connections",
            "commands": "total_commands_processed",
            "replicas": "connected_slaves",
        }.items():
            m[dest] = service_number(d.get(src))
        m["memoryUsage"] = (
            m["memory"] / m["maxMemory"] * 100
            if m["memory"] is not None and m["maxMemory"]
            else None
        )
        m["persistenceErrors"] = (
            sum(
                d[k] != "ok"
                for k in [
                    "rdb_last_bgsave_status",
                    "aof_last_write_status",
                    "aof_last_bgrewrite_status",
                ]
                if k in d
            )
            if "rdb_last_bgsave_status" in d
            else None
        )
        replica = d.get("role") in ("slave", "replica")
        m["replicationStopped"] = (
            int(d.get("master_link_status") != "up")
            if replica
            else int(c["expectReplica"])
        )
        m["missingPeers"] = (
            max(0, c["expectedPeers"] - m["replicas"])
            if m["replicas"] is not None
            else None
        )
        r["complete"] = not r["issues"] and all(
            m[k] is not None
            for k in [
                "connections",
                "blocked",
                "memory",
                "evictions",
                "persistenceErrors",
                "replicationStopped",
            ]
        )
    finally:
        client.close()


def redis_executable_alias(name, path):
    # Some packages hardlink the server and these utilities to one executable.
    return name in ('redis-check-rdb', 'redis-check-aof') and os.path.samefile(path, '/usr/bin/redis-server')


REDIS_ADAPTER = ServiceAdapter(
    IdentityPolicy('redis-server', sockets=('/run/redis/redis-server.sock',), stream_tcp=True, verify_alias=redis_executable_alias),
    redis_connector,
)

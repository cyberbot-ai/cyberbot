"""Bounded MongoDB OP_MSG diagnostics and SCRAM-SHA-256, stdlib only."""

import hmac, unicodedata, stringprep


def mongo_bson(d):
    out = bytearray()
    for k, v in d.items():
        key = k.encode() + b"\0"
        if isinstance(v, bool):
            out += b"\x08" + key + bytes([v])
        elif isinstance(v, int):
            out += b"\x10" + key + struct.pack("<i", v)
        elif isinstance(v, str):
            b = v.encode()
            out += b"\x02" + key + struct.pack("<i", len(b) + 1) + b + b"\0"
        elif isinstance(v, bytes):
            out += b"\x05" + key + struct.pack("<i", len(v)) + b"\0" + v
        elif isinstance(v, dict):
            out += b"\x03" + key + mongo_bson(v)
        else:
            raise ValueError("source_unavailable")
    return struct.pack("<i", len(out) + 5) + out + b"\0"


def mongo_decode(data, depth=0):
    if depth > 16 or len(data) < 5:
        raise ValueError("response_limit")
    size = struct.unpack_from("<i", data)[0]
    if size != len(data) or data[-1] != 0:
        raise ValueError("source_unavailable")
    pos = 4
    out = {}

    def take(n):
        nonlocal pos
        if n < 0 or pos + n > size - 1:
            raise ValueError("source_unavailable")
        b = data[pos : pos + n]
        pos += n
        return b

    def num(fmt):
        return struct.unpack(fmt, take(struct.calcsize(fmt)))[0]

    def cstr():
        nonlocal pos
        end = data.find(b"\0", pos, size - 1)
        if end < 0:
            raise ValueError("source_unavailable")
        b = take(end - pos)
        take(1)
        return b.decode("utf8", "replace")

    while pos < size - 1:
        t = num("B")
        key = cstr()
        if t == 1:
            v = num("<d")
        elif t in (2, 13, 14):
            n = num("<i")
            b = take(n)
            if not b or b[-1]:
                raise ValueError("source_unavailable")
            v = b[:-1].decode("utf8", "replace")
        elif t in (3, 4):
            n = struct.unpack_from("<i", data, pos)[0]
            v = mongo_decode(take(n), depth + 1)
            if t == 4:
                v = list(v.values())
        elif t == 5:
            n = num("<i")
            take(1)
            v = take(n)
        elif t in (6, 10, 127, 255):
            v = None
        elif t == 7:
            v = take(12)
        elif t == 8:
            v = bool(num("B"))
        elif t in (9, 17, 18):
            v = num("<q")
        elif t == 16:
            v = num("<i")
        elif t == 19:
            take(16)
            v = None
        elif t == 11:
            cstr()
            cstr()
            v = None
        else:
            raise ValueError("unsupported_version")
        out[key] = v
        if len(out) > 8192:
            raise ValueError("response_limit")
    return out


class MongoRead:
    def __init__(self, c):
        self.sock = socket.create_connection((c["endpoint"], c["port"]), 2)
        self.seq = 0
        self.total = 0

    def read(self, n):
        if n < 0 or n > 524288 or self.total + n > 1572864:
            raise ValueError("response_limit")
        out = bytearray()
        while len(out) < n:
            b = self.sock.recv(n - len(out))
            if not b:
                raise ValueError("source_unavailable")
            out += b
        self.total += n
        return bytes(out)

    def command(self, d):
        self.seq += 1
        d = {**d, "$db": "admin"}
        body = b"\0" * 5 + mongo_bson(d)
        self.sock.sendall(
            struct.pack("<iiii", len(body) + 16, self.seq, 0, 2013) + body
        )
        size, _, response, op = struct.unpack("<iiii", self.read(16))
        if response != self.seq or op != 2013 or not 21 <= size <= 524288:
            raise ValueError("source_unavailable")
        body = self.read(size - 16)
        if struct.unpack_from("<I", body)[0] != 0 or body[4] != 0:
            raise ValueError("unsupported_version")
        v = mongo_decode(body[5:])
        if v.get("ok") != 1:
            raise ValueError("connection_denied")
        return v

    def auth(self, user, password):
        # ASCII identities only; apply RFC 4013 SASLprep to passwords.
        if any(ord(char) > 127 for char in user):
            raise ValueError("credentials_unavailable")
        password = "".join(
            " " if stringprep.in_table_c12(x) else x
            for x in password
            if not stringprep.in_table_b1(x)
        )
        password = unicodedata.ucd_3_2_0.normalize("NFKC", password)
        if any(
            any(
                fn(ch)
                for fn in (
                    stringprep.in_table_a1,
                    stringprep.in_table_c12,
                    stringprep.in_table_c21,
                    stringprep.in_table_c22,
                    stringprep.in_table_c3,
                    stringprep.in_table_c4,
                    stringprep.in_table_c5,
                    stringprep.in_table_c6,
                    stringprep.in_table_c7,
                    stringprep.in_table_c8,
                    stringprep.in_table_c9,
                )
            )
            for ch in password
        ):
            raise ValueError("credentials_unavailable")
        if any(stringprep.in_table_d1(ch) for ch in password) and (
            any(stringprep.in_table_d2(ch) for ch in password)
            or not stringprep.in_table_d1(password[0])
            or not stringprep.in_table_d1(password[-1])
        ):
            raise ValueError("credentials_unavailable")
        nonce = base64.b64encode(os.urandom(24)).decode()
        first = "n=" + user.replace("=", "=3D").replace(",", "=2C") + ",r=" + nonce
        a = self.command(
            {
                "saslStart": 1,
                "mechanism": "SCRAM-SHA-256",
                "payload": ("n,," + first).encode(),
                "autoAuthorize": 1,
            }
        )
        server = a["payload"].decode("ascii")
        fields = dict(x.split("=", 1) for x in server.split(","))
        rounds = int(fields["i"])
        if (
            not fields["r"].startswith(nonce)
            or len(fields["r"]) <= len(nonce)
            or not 4096 <= rounds <= 200000
        ):
            raise ValueError("connection_denied")
        salted = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            base64.b64decode(fields["s"], validate=True),
            rounds,
        )
        client = hmac.new(salted, b"Client Key", "sha256").digest()
        final = "c=biws,r=" + fields["r"]
        auth = (first + "," + server + "," + final).encode()
        signature = hmac.new(hashlib.sha256(client).digest(), auth, "sha256").digest()
        proof = bytes(x ^ y for x, y in zip(client, signature))
        b = self.command(
            {
                "saslContinue": 1,
                "conversationId": a["conversationId"],
                "payload": (final + ",p=" + base64.b64encode(proof).decode()).encode(),
            }
        )
        verify = dict(x.split("=", 1) for x in b["payload"].decode().split(","))
        expected = hmac.new(
            hmac.new(salted, b"Server Key", "sha256").digest(), auth, "sha256"
        ).digest()
        if not hmac.compare_digest(
            base64.b64decode(verify.get("v", ""), validate=True), expected
        ):
            raise ValueError("connection_denied")
        if not b.get("done"):
            b = self.command(
                {
                    "saslContinue": 1,
                    "conversationId": a["conversationId"],
                    "payload": b"",
                }
            )
            if not b.get("done"):
                raise ValueError("connection_denied")


def mongodb_connector(c, r):
    if not service_begin(c, r, ["/etc/mongod.conf", "/var/lib/mongodb", "/data/db"]):
        return
    client = MongoRead(c)
    try:
        cred = service_credentials("mongodb", c.get("_instanceId", "default"))
        if cred.get("password") is not None:
            client.auth(cred.get("user") or c["user"], cred["password"])
        hello = client.command({"hello": 1})
        r.update(detected=True, connected=True)
        if hello.get("msg") == "isdbgrid":
            raise ValueError("unsupported_version")
        # MongoDB 8 also removes mem when metrics=0; retain bounded metrics locally.
        d = client.command(
            {
                "serverStatus": 1,
                "mem": 1,
                "tcmalloc": 0,
                "wiredTiger": 0,
                "locks": 0,
                "network": 0,
                "opLatencies": 0,
                "opcountersRepl": 0,
                "repl": 0,
                "maxTimeMS": 1500,
            }
        )
        r["uptime"] = service_number(d.get("uptime"))
        r["identity"] = hashlib.sha256(str(d.get("pid", "")).encode()).hexdigest()
        m = r["metrics"]
        con = d.get("connections", {})
        for dest, src in [
            ("connections", "current"),
            ("available", "available"),
            ("active", "active"),
            ("rejected", "rejected"),
        ]:
            m[dest] = service_number(con.get(src))
        m["connectionUsage"] = (
            m["connections"] / (m["connections"] + m["available"]) * 100
            if m["connections"] is not None
            and m["available"] is not None
            and m["connections"] + m["available"]
            else None
        )
        m["residentMemory"] = service_number(d.get("mem", {}).get("resident"))
        m["queued"] = service_number(
            d.get("globalLock", {}).get("currentQueue", {}).get("total")
        )
        if "setName" not in hello:
            m["replicationErrors"] = int(c["expectReplica"])
            m["replicationLag"] = 0
            m["missingPeers"] = c["expectedPeers"]
        else:
            try:
                repl = client.command({"replSetGetStatus": 1, "maxTimeMS": 1500})
                members = repl.get("members", [])
                if not isinstance(members, list) or len(members) > 64:
                    raise ValueError("response_limit")
                m["replicationErrors"] = sum(
                    x.get("health") != 1 or x.get("state") not in (1, 2, 7)
                    for x in members
                ) + int(c["expectReplica"] and hello.get("isWritablePrimary", False))
                m["missingPeers"] = max(
                    0,
                    c["expectedPeers"]
                    - sum(x.get("health") == 1 and not x.get("self") for x in members),
                )
                primary = next(
                    (
                        x.get("optimeDate")
                        for x in members
                        if x.get("state") == 1 and x.get("health") == 1
                    ),
                    None,
                )
                times = [x.get("optimeDate") for x in members if x.get("state") == 2]
                m["replicationLag"] = (
                    max([0] + [(primary - x) / 1000 for x in times])
                    if isinstance(primary, (int, float))
                    and all(isinstance(x, (int, float)) for x in times)
                    else None
                )
            except ValueError:
                r["issues"].append("partial_coverage")
        # Older releases lack rejected connection counters; they remain explicitly unknown.
        service_finish(r)
    finally:
        client.sock.close()


MONGODB_ADAPTER = ServiceAdapter(
    IdentityPolicy('mongod'),
    mongodb_connector,
)

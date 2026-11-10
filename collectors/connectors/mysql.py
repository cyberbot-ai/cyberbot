# MySQL / MariaDB: fixed catalog operations, no query text or raw log transfer.
MY_META = "SELECT VERSION() AS version,@@server_id AS serverId,@@global.max_connections AS maxConnections,@@global.long_query_time AS slowThresholdSeconds,@@global.slow_query_log AS slowLogEnabled"
MY_STATUS_NAMES = (
    "Uptime",
    "Uptime_since_flush_status",
    "Threads_connected",
    "Threads_running",
    "Slow_queries",
    "Questions",
    "Connections",
    "Aborted_connects",
    "Connection_errors_max_connections",
    "Innodb_buffer_pool_pages_total",
    "Innodb_buffer_pool_pages_free",
    "Innodb_buffer_pool_pages_dirty",
    "Innodb_buffer_pool_reads",
    "Innodb_buffer_pool_read_requests",
    "Innodb_buffer_pool_wait_free",
    "Innodb_row_lock_waits",
    "Innodb_row_lock_time",
    "Innodb_deadlocks",
)
MY_STATUS = (
    "SHOW GLOBAL STATUS WHERE Variable_name IN ("
    + ",".join("'" + v + "'" for v in MY_STATUS_NAMES)
    + ")"
)
# Successful access to INNODB_TRX proves effective PROCESS, including inherited roles.
MY_LOCKS = """SELECT COUNT(CASE WHEN trx_state='LOCK WAIT' THEN 1 END) AS blocked,
 COUNT(CASE WHEN trx_state='LOCK WAIT' AND trx_wait_started IS NULL THEN 1 END) AS unknownWaits,
 COALESCE(MAX(CASE WHEN trx_state='LOCK WAIT' THEN GREATEST(0,TIMESTAMPDIFF(SECOND,trx_wait_started,NOW())) END),0) AS maxWaitSeconds,
 COUNT(CASE WHEN trx_started<NOW()-INTERVAL {longTransactionSeconds} SECOND THEN 1 END) AS longTransactions,
 COALESCE(MAX(GREATEST(0,TIMESTAMPDIFF(SECOND,trx_started,NOW()))),0) AS oldestTransactionSeconds
 FROM information_schema.INNODB_TRX WHERE trx_mysql_thread_id<>CONNECTION_ID()"""
MY_ACTIVITY = """SELECT COUNT(CASE WHEN COMMAND IN ('Query','Execute') THEN 1 END) AS active,
 COUNT(CASE WHEN COMMAND IN ('Query','Execute') AND TIME>={longQuerySeconds} THEN 1 END) AS longQueries,
 COALESCE(MAX(CASE WHEN COMMAND IN ('Query','Execute') THEN TIME END),0) AS longestQuerySeconds,
 COUNT(CASE WHEN COMMAND IN ('Binlog Dump','Binlog Dump GTID') THEN 1 END) AS replicaSenders
 FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID()"""


def mysql_config(raw):
    defaults = {
        "enabled": False,
        "host": "/run/mysqld/mysqld.sock",
        "port": 3306,
        "user": "",
        "intervalSeconds": 180,
        "expectedReplicas": 0,
        "instanceId": "default",
        "expectReplica": False,
    }
    if not isinstance(raw, dict) or set(raw) - set(defaults):
        raise ValueError("mysql_profile")
    c = dict(defaults, **raw)
    if (
        type(c["enabled"]) != bool
        or type(c["expectReplica"]) != bool
        or c["host"]
        not in (
            "/run/mysqld/mysqld.sock",
            "/var/run/mysqld/mysqld.sock",
            "/tmp/mysql.sock",
            "127.0.0.1",
            "::1",
        ) and not literal_ip(c["host"])
    ):
        raise ValueError("mysql_endpoint")
    for key, low, high in [
        ("port", 1, 65535),
        ("intervalSeconds", 60, 86400),
        ("expectedReplicas", 0, 64),
    ]:
        if type(c[key]) != int or not low <= c[key] <= high:
            raise ValueError("mysql_limit")
    if (
        not isinstance(c["user"], str)
        or c["user"]
        and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,62}", c["user"])
    ):
        raise ValueError("mysql_user")
    service_instance_id(c["instanceId"])
    return c


def mysql_credentials(instance="default"):
    service_instance_id(instance)
    import pwd, configparser, stat

    # Read only credential keys. Never let the client execute init-command, source,
    # plugin paths or !include directives from existing option files.
    path = os.path.join(
        pwd.getpwuid(os.getuid()).pw_dir,
        (
            ".my.cnf"
            if instance == "default"
            else ".cache/cyberbot/credentials/mysql/" + instance + ".cnf"
        ),
    )
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return b"[client]\n"
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or st.st_mode & 0o077
            or st.st_size > 16384
        ):
            raise ValueError("credentials_unavailable")
        raw = f.read(16385).decode("utf-8")
    if len(raw) > 16384:
        raise ValueError("credentials_unavailable")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(raw)
    except configparser.Error:
        raise ValueError("credentials_unavailable") from None
    out = "[client]\n"
    for key in ("user", "password"):
        if parser.has_option("client", key):
            value = parser.get("client", key).strip()
            # Preserve MySQL's own quoting/escapes, but never inject another option.
            if len(value) > 2048 or any(ch in value for ch in "\r\n\x00"):
                raise ValueError("credentials_unavailable")
            out += key + "=" + value + "\n"
    return out.encode()


def mysql_query(config, sql, family, deadline, *, credential=None):
    import csv, io

    binary = (
        "/usr/bin/mariadb" if os.path.isfile("/usr/bin/mariadb") else "/usr/bin/mysql"
    )
    if credential is None:
        credential = mysql_credentials(config.get("instanceId", "default"))
    r, w = os.pipe()
    try:
        os.write(w, credential)
        os.close(w)
        w = -1
        # A pipe carries sanitized credentials only on the server, never argv/env/disk.
        args = [binary, "--defaults-file=/dev/fd/" + str(r)]
        if binary.endswith("/mysql"):
            args += ["--no-login-paths"]
        args += [
            "--batch",
            "--raw",
            "--connect-timeout=2",
            "--skip-reconnect",
            "--local-infile=0",
            "--default-character-set=utf8mb4",
            "--binary-mode",
        ]
        if config["host"].startswith("/"):
            args += ["--protocol=SOCKET", "--socket=" + config["host"]]
        else:
            args += [
                "--protocol=TCP",
                "--host=" + config["host"],
                "--port=" + str(config["port"]),
            ]
        if config["user"]:
            args += ["--user=" + config["user"]]
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LC_ALL": "C",
            "MYSQL_HISTFILE": "/dev/null",
        }
        setup = (
            ""
            if family is None
            else (
                "SET SESSION max_statement_time=1.2; SET SESSION tx_read_only=ON;"
                if family == "mariadb"
                else "SET SESSION max_execution_time=1200; SET SESSION transaction_read_only=ON;"
            )
            + " SET SESSION lock_wait_timeout=1;"
        )
        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            pass_fds=(r,),
        )
    finally:
        os.close(r)
        if w != -1:
            os.close(w)
    out = bytearray()
    errors = bytearray()
    end = min(deadline, time.monotonic() + 2.5)
    try:
        proc.stdin.write((setup + "\n" + sql + ";\n").encode())
        proc.stdin.close()
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout, selectors.EVENT_READ, out)
            sel.register(proc.stderr, selectors.EVENT_READ, errors)
            while sel.get_map():
                if time.monotonic() > end:
                    raise ValueError("query_timeout")
                for key, _ in sel.select(0.05):
                    b = os.read(key.fd, 4096)
                    if not b:
                        sel.unregister(key.fileobj)
                        continue
                    key.data.extend(b)
                    if len(out) > 16384 or len(errors) > 4096:
                        raise ValueError("query_output_limit")
        if proc.wait(timeout=0.5) != 0:
            raise ValueError("query_denied")
        rows = list(
            csv.DictReader(
                io.StringIO(out.decode("utf-8")), delimiter="\t", quoting=csv.QUOTE_NONE
            )
        )
        if len(rows) > 128 or any(
            None in row or any(v is None for v in row.values()) for row in rows
        ):
            raise ValueError("invalid_result")
        return rows
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=1)
        proc.stdout.close()
        proc.stderr.close()
        if not proc.stdin.closed:
            proc.stdin.close()


def mysql_replication(rows):
    if len(rows) > 64:
        raise ValueError("replication_limit")
    result = {
        "channels": len(rows),
        "running": 0,
        "stopped": 0,
        "connecting": 0,
        "errors": 0,
        "unknownLag": 0,
        "maxLagSeconds": None,
        "delayed": 0,
        "examples": [],
    }
    for i, row in enumerate(rows):
        io = row.get("Replica_IO_Running", row.get("Slave_IO_Running"))
        applier = row.get("Replica_SQL_Running", row.get("Slave_SQL_Running"))
        if io not in ("Yes", "No", "Connecting") or applier not in ("Yes", "No"):
            raise ValueError("invalid_result")
        lag = row.get("Seconds_Behind_Source", row.get("Seconds_Behind_Master"))
        lag = None if lag in (None, "NULL", "") else int(lag)
        ie = int(row.get("Last_IO_Errno", "0"))
        se = int(row.get("Last_SQL_Errno", "0"))
        delay = int(row.get("SQL_Delay", "0"))
        if any(v < 0 for v in (ie, se, delay)) or lag is not None and lag < 0:
            raise ValueError("invalid_result")
        running = io == "Yes" and applier == "Yes"
        result["running"] += int(running)
        result["stopped"] += int(io == "No" or applier == "No")
        result["connecting"] += int(io == "Connecting")
        result["errors"] += int(ie != 0 or se != 0)
        result["delayed"] += int(delay > 0)
        # Delay is intentional configuration; lag alone cannot distinguish it from failure.
        if lag is None or not running or delay > 0:
            result["unknownLag"] += 1
        else:
            result["maxLagSeconds"] = max(result["maxLagSeconds"] or 0, lag)
        if len(result["examples"]) < 8:
            result["examples"].append(
                {
                    "slot": i + 1,
                    "receiver": {
                        "Yes": "running",
                        "No": "stopped",
                        "Connecting": "connecting",
                    }[io],
                    "applier": "running" if applier == "Yes" else "stopped",
                    "lagSeconds": lag,
                    "ioError": ie,
                    "sqlError": se,
                    "delaySeconds": delay,
                }
            )
    return result


def analyze_mysql(request, detected_process=False, automatic=False):
    started = time.monotonic()
    deadline = started + 12
    config = mysql_config(request.get("state", {}))
    limits = collector_thresholds("mysql", request.get("thresholds", {}))
    detected = detected_process or os.path.isdir("/etc/mysql") or any(
        os.path.exists(p) for p in ("/run/mysqld/mysqld.sock", "/tmp/mysql.sock")
    )
    result = {
        "version": 1,
        "detected": detected,
        "connected": False,
        "coverage": False,
        "issues": [],
        "meta": None,
        "metrics": None,
        "durationMs": 0,
    }
    if not config["enabled"]:
        result["issues"] = ["profile_disabled"] if detected else []
        return result
    if automatic and not detected:
        return result
    if not any(os.path.isfile(p) for p in ("/usr/bin/mysql", "/usr/bin/mariadb")):
        result["issues"] = ["client_missing"]
        return result
    try:
        meta = mysql_query(config, MY_META, None, deadline)[0]
        version = meta["version"]
        family = "mariadb" if "MariaDB" in version else "mysql"
        match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
        if not match:
            raise ValueError("invalid_result")
        major, minor, patch = map(int, match.groups())
        version_number = major * 10000 + minor * 100 + patch
        result["connected"] = True
        result["detected"] = True
        result["meta"] = {
            "family": family,
            "version": version_number,
            "instance": hashlib.sha256(
                (family + version + meta["serverId"]).encode()
            ).hexdigest(),
            "maxConnections": int(meta["maxConnections"]),
            "slowThresholdSeconds": float(meta["slowThresholdSeconds"]),
            "slowLogEnabled": bool(int(meta["slowLogEnabled"])),
        }
        supported = (
            family == "mysql"
            and (major, minor) in ((8, 0), (8, 4))
            and version_number >= 80022
        ) or (family == "mariadb" and (major == 10 and minor >= 6 or major == 11))
        if not supported:
            result["issues"] = ["unsupported_version"]
            return result
        metrics = {"status": None, "locks": None, "activity": None, "replication": None}
        result["metrics"] = metrics

        def group(key, sql, parse, reason):
            try:
                if time.monotonic() >= deadline:
                    raise ValueError("query_timeout")
                metrics[key] = parse(mysql_query(config, sql, family, deadline))
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                IndexError,
                subprocess.TimeoutExpired,
            ):
                result["issues"].append(reason)

        def status(rows):
            d = {
                r["Variable_name"].lower(): int(r["Value"])
                for r in rows
                if r["Variable_name"] in MY_STATUS_NAMES
            }
            for k in (
                "uptime",
                "uptime_since_flush_status",
                "threads_connected",
                "threads_running",
                "slow_queries",
                "questions",
            ):
                if k not in d:
                    raise ValueError("missing_status")
            if any(v < 0 for v in d.values()):
                raise ValueError("invalid_result")
            return {k.lower(): d.get(k.lower()) for k in MY_STATUS_NAMES}

        group("status", MY_STATUS, status, "status_unavailable")
        group(
            "locks",
            MY_LOCKS.format(**limits),
            lambda rows: {k: int(v) for k, v in rows[0].items()},
            "process_or_innodb_unavailable",
        )
        if (
            metrics["locks"] is not None
            and metrics["status"] is not None
            and metrics["status"]["innodb_deadlocks"] is None
        ):
            try:
                rows = mysql_query(
                    config,
                    "SELECT COUNT AS value FROM information_schema.INNODB_METRICS WHERE NAME='lock_deadlocks' AND STATUS='enabled'",
                    family,
                    deadline,
                )
                if len(rows) == 1:
                    metrics["status"]["innodb_deadlocks"] = int(rows[0]["value"])
            except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
                pass
        if metrics["locks"] is not None:
            group(
                "activity",
                MY_ACTIVITY.format(**limits),
                lambda rows: {k: int(v) for k, v in rows[0].items()},
                "activity_unavailable",
            )
        group(
            "replication",
            "SHOW ALL SLAVES STATUS" if family == "mariadb" else "SHOW REPLICA STATUS",
            mysql_replication,
            "replication_unavailable",
        )
        if metrics["replication"] and metrics["replication"]["unknownLag"]:
            result["issues"].append("replication_lag_unknown")
        if metrics["locks"] and metrics["locks"]["unknownWaits"]:
            result["issues"].append("lock_wait_age_unknown")
        if metrics["status"] and any(
            metrics["status"][k] is None
            for k in (
                "innodb_buffer_pool_pages_total",
                "innodb_buffer_pool_pages_free",
                "innodb_buffer_pool_wait_free",
            )
        ):
            result["issues"].append("engine_partial")
        result["coverage"] = not result["issues"] and all(
            v is not None for v in metrics.values()
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        subprocess.TimeoutExpired,
    ) as e:
        result["issues"] = [
            (
                str(e)
                if str(e)
                in ("credentials_unavailable", "query_timeout", "query_output_limit")
                else "connection_or_query_denied"
            )
        ]
        result["metrics"] = None
    finally:
        result["durationMs"] = int((time.monotonic() - started) * 1000)
    return result


def mysql_connector(c, r):
    config = {
        "enabled": c["enabled"],
        "host": c["endpoint"],
        "port": c["port"],
        "user": c["user"],
        "intervalSeconds": c["intervalSeconds"],
        "expectedReplicas": c["expectedPeers"],
        "instanceId": c.get("_instanceId", "default"),
        "expectReplica": c["expectReplica"],
    }
    v = analyze_mysql({"state": config, "thresholds": c["_thresholds"]}, r["detected"], c.get("autoEndpoint", False))
    r.update(detected=v["detected"], connected=v["connected"], complete=v["coverage"])
    mapping = {
        "profile_disabled": "profile_disabled",
        "client_missing": "client_missing",
        "unsupported_version": "unsupported_version",
        "credentials_unavailable": "credentials_unavailable",
        "query_timeout": "query_timeout",
        "query_output_limit": "response_limit",
        "connection_or_query_denied": "connection_denied",
        "replication_lag_unknown": "replication_lag_unknown",
    }
    r["issues"] = [mapping.get(x, "partial_coverage") for x in v["issues"]]
    if not v["metrics"]:
        return
    meta = v["meta"]
    r["identity"] = meta["instance"]
    m = r["metrics"]
    m["slowThreshold"] = meta["slowThresholdSeconds"]
    m["slowLog"] = int(meta["slowLogEnabled"])
    status = v["metrics"]["status"]
    locks = v["metrics"]["locks"]
    activity = v["metrics"]["activity"]
    replica = v["metrics"]["replication"]
    if status:
        r["uptime"] = status["uptime"]
        m["uptimeFlush"] = status["uptime_since_flush_status"]
        m["connections"] = max(0, status["threads_connected"] - 1)
        m["connectionUsage"] = 100 * m["connections"] / meta["maxConnections"]
        m["slowQueries"] = status["slow_queries"]
        m["bufferPoolWaits"] = status["innodb_buffer_pool_wait_free"]
        m["deadlocks"] = status["innodb_deadlocks"]
        total = status["innodb_buffer_pool_pages_total"]
        free = status["innodb_buffer_pool_pages_free"]
        dirty = status["innodb_buffer_pool_pages_dirty"]
        if total and free is not None:
            m["bufferPoolUsed"] = 100 * (total - free) / total
        if total and dirty is not None:
            m["bufferPoolDirty"] = 100 * dirty / total
    if locks:
        m["blocked"] = locks["blocked"]
        m["lockWait"] = locks["maxWaitSeconds"] if not locks["unknownWaits"] else None
        m["longTransactions"] = locks["longTransactions"]
    if activity:
        m["active"] = activity["active"]
        m["longQueries"] = activity["longQueries"]
        m["longestQuery"] = activity["longestQuerySeconds"]
        m["replicaSenders"] = activity["replicaSenders"]
        m["missingPeers"] = max(0, c["expectedPeers"] - activity["replicaSenders"])
    if replica:
        m["channels"] = replica["channels"]
        m["replicationStopped"] = (
            replica["stopped"]
            + replica["connecting"]
            + int(c["expectReplica"] and not replica["channels"])
        )
        m["replicationErrors"] = replica["errors"]
        m["replicationUnknown"] = replica["unknownLag"]
        m["replicationLag"] = (
            None if replica["unknownLag"] else (replica["maxLagSeconds"] or 0)
        )

    service_finish(r)


MYSQL_ADAPTER = ServiceAdapter(
    IdentityPolicy('mysqld', 'mariadbd', sockets=('/run/mysqld/mysqld.sock', '/var/run/mysqld/mysqld.sock', '/tmp/mysql.sock')),
    mysql_connector,
)

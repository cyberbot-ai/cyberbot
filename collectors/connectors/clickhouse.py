"""Numeric system table aggregates, bounded read-only HTTP queries."""

def clickhouse_connector(c, r):
    if not service_begin(c, r, ["/etc/clickhouse-server", "/var/lib/clickhouse"]):
        return
    cred = service_credentials("clickhouse", c.get("_instanceId", "default"))
    headers = {}
    if cred or c["user"]:
        headers["Authorization"] = (
            "Basic "
            + base64.b64encode(
                (
                    (cred.get("user") or c["user"] or "default")
                    + ":"
                    + cred.get("password", "")
                ).encode()
            ).decode()
        )
    # system.replicas/mutations silently filter tables without SHOW TABLES.
    # Prove global visibility through effective grants before accepting their zeros.
    visibility = False
    try:
        sql = "SELECT (countIf(access_type IN ('SHOW TABLES','SHOW','ALL') AND database IS NULL AND table IS NULL AND is_partial_revoke=0)>0 AND countIf(is_partial_revoke=1 AND access_type IN ('SHOW TABLES','SHOW','ALL'))=0) AS visible FROM system.grants WHERE user_name=currentUser() OR role_name IN (SELECT role_name FROM system.enabled_roles)"
        rows = load_collector_json(
            service_http(
                c,
                "/?readonly=1&max_execution_time=1&max_result_bytes=16384&result_overflow_mode=throw",
                (sql + " FORMAT JSON").encode(),
                headers,
                32768,
            )
        )["data"]
        visibility = len(rows) == 1 and service_number(rows[0].get("visible")) == 1
    except (OSError, ValueError, KeyError):
        pass
    if not visibility:
        r["issues"].append("partial_coverage")
    queries = [
        (
            "SELECT count() AS queries, countIf(elapsed>60) AS longQueries, sum(memory_usage) AS queryMemory FROM system.processes WHERE query_id != initialQueryID()",
            ["queries", "longQueries", "queryMemory"],
        ),
        (
            "SELECT count() AS replicaTables, countIf(is_readonly OR is_session_expired) AS replicationErrors, max(absolute_delay) AS replicationLag, sum(queue_size) AS replicationQueue FROM system.replicas",
            [
                "replicaTables",
                "replicationErrors",
                "replicationLag",
                "replicationQueue",
            ],
        ),
        (
            "SELECT countIf(NOT is_done) AS pendingMutations, countIf(NOT is_done AND latest_fail_reason!='') AS failedMutations FROM system.mutations",
            ["pendingMutations", "failedMutations"],
        ),
    ]
    for sql, keys in queries:
        if not visibility and "system.processes" not in sql:
            continue
        try:
            rows = load_collector_json(
                service_http(
                    c,
                    "/?readonly=1&max_execution_time=1&max_result_bytes=16384&result_overflow_mode=throw",
                    (sql + " FORMAT JSON").encode(),
                    headers,
                    32768,
                )
            )["data"]
            if len(rows) != 1:
                raise ValueError("source_unavailable")
            for k in keys:
                r["metrics"][k] = service_number(rows[0].get(k))
            r.update(detected=True, connected=True)
        except (OSError, ValueError, KeyError):
            r["issues"].append("partial_coverage")
    service_finish(r)


CLICKHOUSE_ADAPTER = ServiceAdapter(
    IdentityPolicy('clickhouse-serv', executable_aliases=('clickhouse',)),
    clickhouse_connector,
)

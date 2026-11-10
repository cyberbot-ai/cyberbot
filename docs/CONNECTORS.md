# Service connector contract

A server can expose several services simultaneously. Observations use the tuple `(server_id, kind, instance_id)`. Each instance owns its profile, counters, history, and incidents. Each enabled connector runs in the shared server poll.

## Lifecycle

| Operation | Responsibility |
| --- | --- |
| Discover | Detect known processes, units, sockets, or standard endpoints. Discovery establishes presence only. |
| Configure | Validate the local endpoint, diagnostic role and any supported replication expectations. The service itself is configured by its administrator. |
| Collect | Execute bounded, fixed read operations on the monitored host and return permitted measurements. |
| Snapshot | Read the stored observation, including freshness, evidence, and missing fields. |
| Evaluate | Apply deterministic rules and update episodes from the stored observations. |

The shared catalog lives in `collectors/connectors/catalog.json`. Service results in the server poll use version 2 of the connector response envelope. Adapter data goes in `details`. Rust validates the payload and verifies the endpoint and profile revision before persistence. The scheduler limits collection to one active operation per server. All components treat an unavailable field as unknown.

`list_service_instances` provides stable IDs and labels. `get_service_summary` reads a saved summary in the investigation's scope and defaults to the main instance when no ID is supplied. Connection settings and credentials stay outside the MCP response.

## Supported services

| Service | Typical source or requirement | Multiple configured instances |
| --- | --- | --- |
| Nginx | Local `stub_status` when available and readable access or error logs | No |
| PostgreSQL | A local client with diagnostic access to statistics and replication views | Yes |
| MySQL or MariaDB | Local SQL client and access to global status and diagnostic counters | Yes |
| MongoDB | Local OP_MSG and cluster monitor permissions for server and replica status | Yes |
| CockroachDB | `psql` and access to local node metrics | Yes |
| ClickHouse | Local HTTP endpoint and read access to supported system tables | Yes |
| Redis | Local RESP with access to supported `INFO` sections | Yes |
| Docker | Docker Engine API through the rootful Unix socket | No |
| PHP-FPM | Local access to the configured FPM status endpoint | Yes |
| Asterisk | Local CLI access to channel counts, uptime, and PJSIP registration status | No |
| PgBouncer | `psql` and permission to run `SHOW POOLS` on a local listener | No |
| ProxySQL | Local admin listener and a statistics account | No |
| Twemproxy | Local statistics listener | No |
| Envoy | Readiness and statistics from the local admin endpoint | No |
| Qdrant | Local readiness, collection, and metrics endpoints | No |
| Nebula | Process uptime and RSS through `/proc` | No |
| Fail2ban | Local `fail2ban-client status` and `stats` where supported | No |
| Caddy | Process status and metrics from the local admin endpoint when available | No |

For exact metrics, endpoints, and permission requirements, consult the in-app monitoring library or the catalog. Service diagnostics use local endpoints and existing server-side credentials. Treat access to the Docker socket as privileged.

Where supported, a default Redis, MongoDB, ClickHouse, ProxySQL, or Qdrant profile reads credentials from `~/.cache/cyberbot/credentials/<kind>.json` on the monitored server. Use a regular file owned by the SSH user with mode `0600`. The JSON fields are `user` and `password`. Qdrant uses `password` for its read-only API key. Additional Redis, MongoDB, and ClickHouse instances use `credentials/<kind>/<instance-id>.json` and have separate credentials. PostgreSQL and CockroachDB can use the remote user's `.pgpass`.

PgBouncer diagnostics use `psql` to run `SHOW POOLS`. With automatic address detection and an empty diagnostic role, a collector running as root can connect without a password through a verified Unix socket. The query runs as the operating-system account that owns the PgBouncer process, using the built-in `pgbouncer` console login. For a manual address or a password-based connection, set **Diagnostic role** to an existing `stats_users` role and put any required password in the SSH user's `~/.pgpass` on the monitored server. Use `pgbouncer` in the database field and set the file mode to `0600`.

## Adding a connector

1. Register its stable ID, Python module, operations, metrics, endpoint rules, and requirements in the catalog.
2. Add a `ServiceAdapter` under `collectors/connectors/` with its `IdentityPolicy` and collection function. Use fixed commands, bounded transports, sanitized aggregates, and a timeout for the entire collection cycle. Keep row data, secrets, and full command output out of observations.
3. Update typed validation and persistence in Rust and expose the measurements through the shared service panel or an appropriate scoped Vue component.
4. Test discovery, simultaneous connectors, missing clients and permissions, stale data, instance isolation, and recovery. Run the Linux collector checks and test real service fixtures when available.

Service configuration affects future samples. Changing an endpoint or disabling collection must not make older samples look fresh. Keep migration and retention compatible with the shared SQLite limits.

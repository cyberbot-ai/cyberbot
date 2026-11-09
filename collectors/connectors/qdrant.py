"""Local Qdrant REST readiness and aggregate metrics."""


def qdrant_connector(config, result):
    credentials = service_credentials("qdrant")
    key = credentials.get("password")
    if key and (not ipaddress.ip_address(config["endpoint"]).is_loopback
                or any(not 32 <= ord(char) < 127 for char in key)):
        raise ValueError("credentials_unavailable")
    status, _ = service_http_response(config, "/readyz", limit=4096, statuses=(200, 404, 503))
    if status in (200, 503):
        result["connected"] = True
        result["metrics"]["ready"] = int(status == 200)
    status, body = service_http_response(
        config, "/metrics", headers={"api-key": key} if key else None,
        limit=524288, statuses=(200, 401, 403),
    )
    if status != 200:
        raise ValueError("connection_denied" if key else "credentials_unavailable")
    result["connected"] = True
    result["metrics"].update(service_prometheus(body, {
        b"collections_total": "collections",
        b"rest_responses_total": "restResponses",
        b"rest_responses_fail_total": "restFailures",
    }))
    service_finish(result)


QDRANT_ADAPTER = observed_service(
    IdentityPolicy("qdrant", stream_tcp=True), qdrant_connector,
    targets=lambda record, config: service_tcp_targets(record, config, config["port"]),
    image="qdrant/qdrant", installed=("/usr/bin/qdrant", "/usr/local/bin/qdrant"),
)

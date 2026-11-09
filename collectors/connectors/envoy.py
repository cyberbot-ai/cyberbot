"""Envoy readiness and bounded Prometheus aggregates."""


def envoy_connector(config, result):
    status, _ = service_http_response(config, "/ready", limit=4096, statuses=(200, 404, 503))
    if status in (200, 503):
        result["connected"] = True
        result["metrics"]["ready"] = int(status == 200)
    body = service_http(config, "/stats/prometheus", limit=524288)
    result["connected"] = True
    result["metrics"].update(service_prometheus(body, {
        b"envoy_cluster_upstream_cx_active": "upstreamConnections",
        b"envoy_server_memory_allocated": "memory",
    }))
    service_finish(result)


ENVOY_ADAPTER = observed_service(
    IdentityPolicy("envoy", stream_tcp=True), envoy_connector,
    targets=lambda record, config: service_tcp_targets(record, config, config["port"]),
    image="envoyproxy/envoy", installed=("/usr/bin/envoy", "/usr/local/bin/envoy"),
)

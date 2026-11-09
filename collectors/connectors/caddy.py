"""Local Caddy runtime metrics without reading its configuration."""


def caddy_connector(config, result):
    body = service_http(config, "/metrics", limit=524288)
    samples = service_prometheus(body, {
        b"process_resident_memory_bytes": "rss",
        b"go_goroutines": "goroutines",
    })
    if not any(value is not None for value in samples.values()):
        raise ValueError("source_unavailable")
    result["metrics"].update(samples)
    result["connected"] = True
    service_finish(result)


CADDY_ADAPTER = observed_service(
    IdentityPolicy("caddy", stream_tcp=True), caddy_connector,
    targets=lambda record, config: service_tcp_targets(record, config, config["port"]),
    installed=("/usr/bin/caddy", "/usr/local/bin/caddy"),
)

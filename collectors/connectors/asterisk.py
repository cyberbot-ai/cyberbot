"""Fixed local CLI diagnostics. No calls, reloads, configuration or media access."""

def asterisk_connector(c, r):
    if not service_begin(c, r, ["/etc/asterisk", "/run/asterisk/asterisk.ctl"]):
        return
    if not os.path.isfile("/usr/sbin/asterisk"):
        raise ValueError("client_missing")
    text = service_process(
        ["/usr/sbin/asterisk", "-rx", "core show channels count"], limit=4096
    ).decode("ascii", "replace")
    for key, pattern in [
        ("channels", r"(\d+) active channels?"),
        ("calls", r"(\d+) active calls?"),
        ("processed", r"(\d+) calls? processed"),
    ]:
        hit = re.search(pattern, text)
        r["metrics"][key] = int(hit.group(1)) if hit else None
    if r["metrics"]["channels"] is None:
        raise ValueError("source_unavailable")
    r.update(detected=True, connected=True)
    try:
        up = service_process(
            ["/usr/sbin/asterisk", "-rx", "core show uptime seconds"], limit=4096
        ).decode("ascii", "replace")
        hit = re.search(r"System uptime:\s*(\d+)", up)
        r["uptime"] = int(hit.group(1)) if hit else None
        text = service_process(
            ["/usr/sbin/asterisk", "-rx", "pjsip show registrations"], limit=32768
        ).decode("ascii", "replace")
        if "objects found" in text.lower():
            rows = [
                line
                for line in text.splitlines()
                if re.search(r"\b(Registered|Unregistered|Rejected|Stopped)\b", line)
            ]
            r["metrics"]["registrationErrors"] = sum(
                bool(re.search(r"\b(Unregistered|Rejected|Stopped)\b", x)) for x in rows
            )
    except ValueError:
        r["issues"].append("partial_coverage")
    service_finish(r)


ASTERISK_ADAPTER = ServiceAdapter(
    IdentityPolicy('asterisk', sockets=('/run/asterisk/asterisk.ctl',), discover=False),
    asterisk_connector,
)

# Package inventory v1: stateless hashed buckets and bounded pages, no remote writes.
PACKAGE_FORMAT = "${Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Status}\n"
PACKAGE_NAME = r"[a-z0-9][a-z0-9+.-]{0,199}"
PACKAGE_VERSION = r"[A-Za-z0-9.+:~_-]{1,256}"
APT_TEMP_FILE_LIMIT = 8 * 1024 * 1024


def dpkg_package_rows():
    # Check metadata before/after dpkg-query so an in-progress transaction is not accepted.
    def stamp():
        s = os.stat("/var/lib/dpkg/status")
        updates = []
        with scan_directory("/var/lib/dpkg/updates") as it:
            for entry in __import__("itertools").islice(it, 128):
                if entry.name.isdigit():
                    updates.append(entry.name)
        return (s.st_ino, s.st_size, s.st_mtime_ns, tuple(sorted(updates)))

    before = stamp()
    if before[-1]:
        raise PackageError("package_database_busy")
    proc = subprocess.Popen(
        ["dpkg-query", "--show", "--showformat=" + PACKAGE_FORMAT],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    rows = []
    consumed = 0
    try:
        for raw in proc.stdout:
            consumed += len(raw)
            if consumed > 16 * 1024 * 1024 or len(raw) > 2048 or len(rows) >= 20000:
                raise PackageError("package_limit")
            parts = raw.decode("utf-8", "strict").rstrip("\n").split("\t")
            if len(parts) != 6:
                raise PackageError("package_format")
            name, arch, version, source, source_version, status = parts
            if status in ("not-installed", "config-files"):
                continue
            if (
                not re.fullmatch(PACKAGE_NAME, name)
                or not re.fullmatch(PACKAGE_NAME, source)
                or not re.fullmatch(r"[a-z0-9-]{1,32}", arch)
            ):
                raise PackageError("package_format")
            if not re.fullmatch(PACKAGE_VERSION, version) or not re.fullmatch(
                PACKAGE_VERSION, source_version
            ):
                raise PackageError("package_format")
            if status not in (
                "installed",
                "unpacked",
                "half-configured",
                "half-installed",
                "triggers-awaited",
                "triggers-pending",
            ):
                raise PackageError("package_format")
            rows.append(
                {
                    "name": name,
                    "arch": arch,
                    "version": version,
                    "source": source,
                    "sourceVersion": source_version,
                    "status": status,
                }
            )
        if proc.wait(timeout=1) != 0:
            raise PackageError("package_read_failed")
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=1)
        proc.stdout.close()
    if stamp() != before:
        raise PackageError("package_database_changed")
    return sorted(rows, key=lambda p: (p["name"], p["arch"]))


def apt_temp_file_limit(writable=True):
    _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = APT_TEMP_FILE_LIMIT if hard == resource.RLIM_INFINITY else min(hard, APT_TEMP_FILE_LIMIT)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit if writable else 0, limit))


def apt_cache(args, timeout):
    # APT uses temporary files to unpack InRelease, even for a cache-only query.
    # Disable its persistent caches and grant the temporary file limit only to the child.
    result = subprocess.run(
        ["apt-cache", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        preexec_fn=apt_temp_file_limit,
    )
    if result.returncode == -signal.SIGXFSZ:
        raise PackageError("apt_temp_file_limit")
    return result


def dpkg_candidates(state, result, rows):
    requested = state["apt"]
    if state.get("root") != result["root"]:
        return dict(result, kind="changed")
    known = {r["name"] + ":" + r["arch"] for r in rows}
    if (
        not isinstance(requested, list)
        or len(requested) > 32
        or any(not isinstance(s, str) or s not in known for s in requested)
    ):
        raise PackageError("apt_scope_changed")
    result["kind"] = "apt"
    result["candidates"] = []
    if not requested:
        return result
    try:
        p = apt_cache(["policy", *requested], timeout=4)
    except FileNotFoundError:
        raise PackageError("apt_missing") from None
    except subprocess.TimeoutExpired:
        raise PackageError("apt_timeout") from None
    except PermissionError:
        raise PackageError("apt_permission_denied") from None
    if p.returncode:
        if b"Cannot allocate memory" in p.stderr or b"Dynamic MMap ran out of room" in p.stderr:
            raise PackageError("apt_memory_limit")
        raise PackageError("apt_read_failed")
    if len(p.stdout) > 262144:
        raise PackageError("apt_output_limit")
    current = None
    candidate = None
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        if line and not line[0].isspace() and line.endswith(":"):
            current = line[:-1]
            candidate = None
            if current not in known:
                current = next(
                    (key for key in requested if key.split(":")[0] == current), None
                )
        elif current in requested and line.strip().startswith("Candidate:"):
            candidate = line.strip().split(":", 1)[1].strip()
            result["candidates"].append(
                {
                    "package": current,
                    "version": (
                        candidate if re.fullmatch(PACKAGE_VERSION, candidate) else None
                    ),
                }
            )
    # Read candidate source metadata only from the existing local APT cache.
    # No refresh, downloads or package installation.
    for candidate in result["candidates"]:
        candidate.update(source=None, sourceVersion=None)
        if not candidate["version"]:
            continue
        show = apt_cache(
            [
                "show",
                "--no-all-versions",
                candidate["package"] + "=" + candidate["version"],
            ],
            timeout=2,
        )
        if show.returncode or len(show.stdout) > 262144:
            continue
        fields = {}
        for line in show.stdout.decode("utf-8", "replace").splitlines():
            if not line:
                break
            if line and not line[0].isspace() and ": " in line:
                key, value = line.split(": ", 1)
                if key in ("Package", "Version", "Source"):
                    fields[key] = value
        if (
            fields.get("Package") != candidate["package"].split(":")[0]
            or fields.get("Version") != candidate["version"]
        ):
            continue
        source = re.fullmatch(
            r"([a-z0-9][a-z0-9+.-]*)(?: \(([^)]+)\))?",
            fields.get("Source", fields["Package"]),
        )
        if source and re.fullmatch(
            PACKAGE_VERSION, source.group(2) or fields["Version"]
        ):
            candidate["source"] = source.group(1)
            candidate["sourceVersion"] = source.group(2) or fields["Version"]
    stamps = []
    try:
        with scan_directory("/var/lib/apt/lists") as files:
            for f in __import__("itertools").islice(files, 1024):
                if f.name.endswith(("InRelease", "_Release")):
                    stamps.append(int(f.stat(follow_symlinks=False).st_mtime))
    except OSError:
        pass
    result["cacheAt"] = min(stamps) if stamps else None
    return result


LINUX_PACKAGE_ADAPTERS["dpkg"] = {
    "rows": dpkg_package_rows,
    "candidates": dpkg_candidates,
}

#!/usr/bin/env python3
"""Versioned collector and dispatch for broker-approved actions.

Installed only in Cyberbot's versioned cache. No dependencies outside Python stdlib.
stdout is one bounded JSON document; errors/partial coverage are explicit.
"""
import datetime
import hashlib
import hmac
import ipaddress
import selectors
import signal
import collections
import json
import os
import pwd
import re
import resource
import socket
import struct
import subprocess
import sys
import time

MAX_LOG_READ = 2 * 1024 * 1024
MAX_LINE = 16384


def text(path, limit=65536):
    with open(path, "r", encoding="utf-8", errors="replace") as stream:
        return stream.read(limit)


def cpu_ticks():
    values = [int(v) for v in text("/proc/stat").splitlines()[0].split()[1:9]]
    return sum(values), values[3] + values[4]


def metrics():
    ignored_mounts = tuple(
        prefix for spec in CONNECTOR_CATALOG.values() for prefix in spec.get('ignoredMountPrefixes', ())
    )
    missing = []
    platform = linux_platform()
    result = {"platform": platform, "at": int(time.time()), "cpuPercent": None, "memoryPercent": None,
              "swapPercent": None, "load": None, "uptime": None,
              "disks": [], "services": [], "missing": missing,
              "bytesReceived": 0, "durationMs": 0}
    try:
        a, idle_a = cpu_ticks()
        time.sleep(0.15)
        b, idle_b = cpu_ticks()
        result["cpuPercent"] = round(100 * (1 - (idle_b-idle_a)/(b-a)), 2) if b > a else None
    except (OSError, ValueError, IndexError):
        missing.append("cpu")
    try:
        mem = {line.split(":")[0]: int(line.split()[1]) for line in text("/proc/meminfo").splitlines()}
        result["memoryPercent"] = round(100 * (1-mem["MemAvailable"]/mem["MemTotal"]), 2)
        result["swapPercent"] = round(100 * (1-mem["SwapFree"]/mem["SwapTotal"]), 2) if mem["SwapTotal"] else 0
    except (OSError, ValueError, KeyError, ZeroDivisionError):
        missing.append("memory")
    try:
        result["load"] = os.getloadavg()[0]
        result["uptime"] = float(text("/proc/uptime").split()[0])
    except (OSError, ValueError, IndexError):
        missing.append("uptime/load")
    try:
        mounts = []
        for line in text("/proc/mounts").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] in ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "overlay"):
                mount = parts[1].replace("\\040", " ")
                if mount.startswith(ignored_mounts):
                    continue
                mounts.append(mount)
        if len(mounts) > 16:
            missing.append("mounts_truncated")
        for mount in dict.fromkeys(mounts[:16]):
            try:
                stat = os.statvfs(mount)
                result["disks"].append({"mount": mount,
                    "usedPercent": round(100 * (1-stat.f_bavail/stat.f_blocks), 2) if stat.f_blocks else 0,
                    "inodePercent": round(100 * (1-stat.f_favail/stat.f_files), 2) if stat.f_files else None})
            except OSError:
                missing.append("disk:"+mount)
    except OSError:
        missing.append("disks")
    result["services"], unavailable = linux_services(platform)
    missing.extend(unavailable)
    if not platform["procfs"]:
        missing.append("procfs_unavailable")
    result["serviceRuntime"], result["serviceRuntimeComplete"] = service_runtime()
    # Identity is supplementary; preserve the existing 8-KiB metrics limit.
    while result["serviceRuntime"] and len(json.dumps(result, separators=(",", ":")).encode()) > 8000:
        result["serviceRuntime"].pop()
        result["serviceRuntimeComplete"] = False
    return result


def aggregate_file(path, cursor=None, status_parser=None):
    """Read only appended bytes; cap work, cardinality, and individual lines."""
    counts = collections.Counter()
    statuses = collections.Counter()
    skipped = False
    malformed = 0
    with open(path, "rb") as stream:
        stat = os.fstat(stream.fileno())
        offset = cursor.get("offset", 0) if isinstance(cursor, dict) else 0
        if not isinstance(offset, int) or offset < 0:
            offset = 0
        same = isinstance(cursor, dict) and cursor.get("inode") == stat.st_ino and offset <= stat.st_size
        discarding = bool(cursor.get("discarding", False)) if same else False
        if not same:
            offset = max(0, stat.st_size - MAX_LOG_READ)
            skipped = offset > 0 or cursor is not None
        stream.seek(offset)
        if offset > 0 and not same:
            stream.readline(MAX_LINE)
        start = stream.tell()
        while stream.tell()-start < MAX_LOG_READ:
            line_start = stream.tell()
            line = stream.readline(min(MAX_LINE, MAX_LOG_READ-(line_start-start)))
            if not line:
                break
            if discarding:
                skipped = True
                discarding = not line.endswith(b"\n")
                continue
            if not line.endswith(b"\n"):
                if len(line) >= MAX_LINE or stream.tell()-start >= MAX_LOG_READ:
                    skipped = True
                    discarding = True
                else:
                    stream.seek(line_start)
                break
            line = line.decode("utf-8", "replace")
            if status_parser is not None:
                status = status_parser(line)
                if status is None:
                    malformed += 1
                else:
                    statuses[status] += 1
            else:
                lower = line.lower()
                for label, needles in {
                    "ssh_failed": ("failed password", "invalid user", "authentication failure"),
                    "ssh_accepted": ("accepted publickey", "accepted password"),
                    "oom": ("out of memory", "oom-kill", "killed process"),
                    "disk_error": ("i/o error", "filesystem error", "read-only file system"),
                    "service_failure": ("failed to start", "segfault", "core dumped"),
                }.items():
                    if any(needle in lower for needle in needles):
                        counts[label] += 1
        end = stream.tell()
        return {"counts": dict(counts), "statuses": dict(statuses), "malformed": malformed,
                "bytesRead": end-start, "partial": skipped or end < stat.st_size,
                "cursor": {"inode": stat.st_ino, "offset": end, "discarding": discarding}, "size": stat.st_size}


# Log profile v1: fixed source paths and classifiers. Raw messages never leave here.
CATEGORIES = ("oom", "disk_io", "service_crash", "protection_failure", "ssh_suspicious_success")
TEMPLATES = {"oom": "Memory exhaustion", "disk_io": "Storage or filesystem error", "service_crash": "Process or service failure", "protection_failure": "SSH protection failure", "ssh_suspicious_success": "Successful SSH login after repeated failures"}
UNSUPPORTED_FAIL2BAN_STATS = re.compile(r"\bCommand \['stats'\] has failed\. Received Exception\('Invalid command'\)\s*$")


def iso_log_time(stamp):
    stamp = stamp.replace("Z", "+00:00")
    if sys.version_info >= (3, 7):
        return datetime.datetime.fromisoformat(stamp)
    pattern = "%Y-%m-%d" + stamp[10:11] + "%H:%M:%S"
    if stamp[19:20] == ".":
        pattern += ".%f"
    offset = re.search(r"[+-]\d{2}:?\d{2}$", stamp[19:])
    if offset:
        stamp = stamp[:19 + offset.start()] + offset.group().replace(":", "")
        pattern += "%z"
    return datetime.datetime.strptime(stamp, pattern)


def event_time(line, fallback):
    try:
        stamp = line.split()[0]
        if re.match(r"\d{4}-\d\d-\d\dT", stamp):
            return int(iso_log_time(stamp).timestamp())
        if re.match(r"\d{4}-\d\d-\d\d$", stamp):
            return int(iso_log_time(line[:19]).timestamp())
        stamp = datetime.datetime.strptime(line[:15], "%b %d %H:%M:%S").replace(year=datetime.datetime.fromtimestamp(fallback).year)
        value = int(stamp.timestamp())
        if value > fallback + 86400:
            value = int(stamp.replace(year=stamp.year-1).timestamp())
        return value
    except (ValueError, IndexError, OverflowError):
        return None


class LogAnalysis:
    def __init__(self, request, clock=None):
        self.now = int(time.time()) if clock is None else clock
        self.thresholds = collector_thresholds("logs", request.get("thresholds", {}))
        self.started = time.monotonic()
        self.state = request.get("state", {})
        if not isinstance(self.state, dict):
            raise ValueError("Invalid log state")
        salt = request.get("salt", "")
        if not isinstance(salt, str) or not re.fullmatch(r"[0-9a-f]{64}", salt):
            raise ValueError("Invalid salt")
        self.salt = bytes.fromhex(salt)
        self.previous = self.state.get("at", self.now-600)
        if not isinstance(self.previous, int):
            raise ValueError("Invalid timestamp")
        self.cutoff = self.now-600 if self.now-self.previous > 3600 else self.previous
        self.initial = "at" not in self.state
        self.counts = collections.Counter()
        self.patterns = collections.Counter()
        self.examples = []
        self.gaps = []
        self.bytes_read = 0
        self.sources = []
        self.files = {}
        self.seen = {}
        self.recent = {}
        limited_until = self.state.get("sshLimitedUntil", 0)
        self.ssh_limited_until = limited_until if isinstance(limited_until, int) and self.now < limited_until <= self.now + 1800 else 0
        self.banned = set()
        self.failures_by_ip = collections.Counter()
        self.next = {"at": self.now, "files": self.files}
        for key, value in list(self.state.get("recent", {}).items())[:32]:
            if re.fullmatch(r"[0-9a-f]{24}:[0-9a-f]{24}", key) and isinstance(value, list):
                bins = [[int(t), min(int(n), 1000000)] for t, n in value[:7] if self.now-1800 <= int(t) <= self.now]
                if bins:
                    self.recent[key] = bins
        if self.now-self.previous > 3600:
            self.gap("backlog_skipped", "all", fromTime=self.previous, toTime=self.cutoff)
        if self.previous > self.now:
            self.gap("clock_changed", "all")
            self.cutoff = self.now-600

    def gap(self, reason, source, **bounds):
        item = {"reason": reason, "source": source, **bounds}
        if item not in self.gaps and len(self.gaps) < 16:
            self.gaps.append(item)

    def pseudonym(self, text):
        return hmac.new(self.salt, text.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:24]

    def room(self):
        return self.bytes_read < MAX_LOG_READ-2048 and time.monotonic()-self.started < 14

    def event(self, line, source, at=None, priority=None, identity=""):
        # Deduplicate file copies only when a timestamp exists, not repeated same-file events.
        when = event_time(line, self.now) if at is None else at
        timestamp_known = when is not None
        if when is None:
            self.gap("unknown_timestamp", source)
            return
        if when < self.cutoff:
            return
        if when > self.now+300:
            self.gap("clock_changed", source)
            return
        if source != "journal":
            normalized = re.sub(r"^.{15,32}?\s+\S+\s+", "", line)
            key = (when, hashlib.sha256(normalized.encode()).digest())
            if key in self.seen and self.seen[key] != source:
                return
            # Dedup between syslog/kernel; other streams have exclusive classifiers.
            if source == "syslog" and len(self.seen) < 4096:
                self.seen[key] = source
            elif source == "syslog" and len(self.seen) >= 4096:
                self.gap("dedupe_limit", source)
        lower = line.lower()
        is_ssh = identity in ("sshd", "sshd-session") or bool(re.search(r"\bsshd(?:-session)?(?:\[\d+\])?:", line))
        is_protection = identity.startswith("fail2ban") or "fail2ban" in lower or source == "fail2ban"
        is_firewall = bool(re.search(r"(?:\bDROP\b|\bREJECT\b|\[UFW BLOCK\]).*\bDPT=22\b", line))
        if source == "syslog" and is_ssh and "auth" in self.sources:
            return
        if source == "syslog" and is_protection and "fail2ban" in self.sources:
            return
        if is_firewall:
            self.counts["ssh_blocked"] += 1
            m = re.search(r"\bSRC=(\S+)", line)
            if m: self.banned.add(self.pseudonym(m.group(1)))
            return
        if is_protection:
            if UNSUPPORTED_FAIL2BAN_STATS.search(line):
                return
            ban = re.search(r"\bBan\s+(\S+)", line)
            if ban:
                self.counts["ssh_banned"] += 1
                self.banned.add(self.pseudonym(ban.group(1)))
            # Found/Ignore/Unban and error-looking rejected login messages are noise.
            if (re.search(r"\b(ERROR|CRITICAL)\b", line) or "failed to start" in lower or "failed with result" in lower) and not re.search(r"\b(?:Found|Ban|Unban|Ignore)\b", line):
                template = None
                if "have not found any log file" in lower:
                    template = "Fail2ban log source missing"
                elif "failed to start" in lower or "failed with result" in lower:
                    template = "Fail2ban startup failed"
                elif "failed to execute ban" in lower or "failed to execute unban" in lower:
                    template = "Fail2ban blocking action failed"
                self.finding("protection_failure", when, template=template)
            return
        if is_ssh:
            # Failures/blocks and every other sshd message are excluded from generic novelty.
            failure = re.search(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)", line)
            success = re.search(r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for (\S+) from (\S+)", line)
            if failure:
                user, addr = failure.groups()
                self.counts["ssh_failed"] += 1
                ip = self.pseudonym(addr); key = ip+":"+self.pseudonym(user)
                self.failures_by_ip[ip] += 1
                if key not in self.recent and len(self.recent) >= 32:
                    # Preserve recent identities instead of unbounded attacker-controlled state.
                    oldest = min(self.recent, key=lambda k: max((b[0] for b in self.recent[k]), default=0))
                    del self.recent[oldest]
                    self.ssh_limited_until = self.now + 1800
                bins = self.recent.setdefault(key, [])
                bucket = (when//300)*300
                old = next((b for b in bins if b[0] == bucket), None)
                if old: old[1] = min(old[1]+1, 1000000)
                else: bins.append([bucket, 1])
            elif success:
                self.counts["ssh_accepted"] += 1
                user, addr = success.groups()
                ip = self.pseudonym(addr); account = self.pseudonym(user)
                bins = self.recent.get(ip+":"+account, [])
                # Conservative bucket inclusion avoids claiming failures older than the window.
                n = sum(n for t, n in bins if when-self.thresholds["sshLookbackSeconds"] <= t <= when)
                if n >= self.thresholds["sshFailedAttempts"] and timestamp_known:
                    self.finding("ssh_suspicious_success", when, ip, account)
            elif any(s in lower for s in ("invalid user", "authentication failure", "preauth", "connection closed", "connection reset", "unable to negotiate", "disconnect")):
                self.counts["ssh_noise"] += 1
            return
        category = None
        for name, needles in (
            ("oom", ("out of memory", "oom-kill", "killed process")),
            ("disk_io", ("i/o error", "filesystem error", "read-only file system", "ext4-fs error")),
            ("service_crash", ("failed to start", "segfault", "core dumped")),
        ):
            if any(n in lower for n in needles): category = name; break
        if category: self.finding(category, when)
        if category or (priority is not None and priority <= 3) or re.search(r"\b(error|fatal|critical|panic)\b", lower):
            self.counts["system_error"] += 1
            normalized = re.sub(r"\b[0-9a-f]{8,}\b|\b\d+(?:[.:]\d+)*\b|(?<=\s)/\S+|https?://\S+", "<value>", lower)
            normalized = re.sub(r"^.{15}\s+\S+\s+", "", normalized)
            fingerprint = self.pseudonym(normalized)
            if fingerprint in self.patterns or len(self.patterns) < 64:
                self.patterns[fingerprint] += 1
            else: self.gap("pattern_limit", source)

    def finding(self, category, at, peer=None, account=None, *, template=None):
        self.counts[category] += 1
        if len(self.examples) < 10:
            e = {"at": at, "category": category, "template": template or TEMPLATES[category]}
            if peer: e["peer"] = peer
            if account: e["account"] = account
            self.examples.append(e)

    def file(self, source, path):
        saved = self.state.get("files", {}).get(source)
        try:
            # Read only regular files; symlinks/devices cannot redirect fixed sources.
            import stat
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
            stream = os.fdopen(fd, "rb")
            with stream:
                st = os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode): raise OSError("not regular")
                if saved and (saved.get("inode"), saved.get("device")) != (st.st_ino, st.st_dev):
                    found = False
                    # Never scan the whole directory or decompress archives.
                    for suffix in (".1", ".2", ".3", ".4", ".5", ".6", ".7", ".8"):
                        try:
                            oldfd = os.open(str(path)+suffix, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
                            with os.fdopen(oldfd, "rb") as old:
                                oldst = os.fstat(old.fileno())
                                if stat.S_ISREG(oldst.st_mode) and (oldst.st_ino, oldst.st_dev) == (saved.get("inode"), saved.get("device")):
                                    self.read_file(old, source, saved, oldst)
                                    found = True
                                    if old.tell() < oldst.st_size: self.gap("rotation_tail_lost", source)
                                    break
                        except OSError: pass
                    if not found: self.gap("rotation_tail_lost", source)
                    saved = None
                self.files[source] = self.read_file(stream, source, saved, st)
                self.sources.append(source)
        except OSError:
            if source not in ("fail2ban", "kern"):
                self.gap("source_unavailable", source)
            if saved: self.files[source] = saved

    def read_file(self, stream, source, saved, st):
        offset = saved.get("offset", 0) if isinstance(saved, dict) else 0
        if not isinstance(offset, int) or offset < 0: offset = 0
        if saved and offset <= st.st_size:
            stream.seek(max(0, offset-64)); anchor = stream.read(min(64, offset))
            self.bytes_read += len(anchor)
            if hashlib.sha256(anchor).hexdigest() != saved.get("anchor"):
                self.gap("file_rewritten", source); saved = None; offset = 0
        elif saved:
            self.gap("file_truncated", source); saved = None; offset = 0
        available = max(0, MAX_LOG_READ-self.bytes_read)
        discarding = bool(saved and saved.get("discarding"))
        if st.st_size-offset > available or self.now-self.previous > 3600:
            previous_offset = offset
            offset = max(0, st.st_size-min(available, MAX_LOG_READ//4))
            discarding = offset > 0
            self.gap("backlog_skipped", source, fromOffset=previous_offset, toOffset=max(previous_offset, offset))
        stream.seek(offset)
        while self.room():
            start = stream.tell()
            line = stream.readline(min(MAX_LINE, MAX_LOG_READ-2048-self.bytes_read))
            self.bytes_read += len(line)
            if not line: break
            if discarding:
                discarding = not line.endswith(b"\n")
                continue
            if not line.endswith(b"\n"):
                if len(line) >= MAX_LINE:
                    discarding = True; self.gap("long_line", source)
                else:
                    stream.seek(start); self.gap("incomplete_line", source)
                break
            decoded = line.decode("utf-8", "replace")
            if "\ufffd" in decoded: self.gap("invalid_encoding", source)
            self.event(decoded, source)
        end = stream.tell()
        if end < st.st_size: self.gap("read_limit", source)
        stream.seek(max(0, end-64)); anchor = stream.read(min(64, end))
        # Anchor reads count toward the total; reserve room before payload reads.
        self.bytes_read += len(anchor)
        return {"device": st.st_dev, "inode": st.st_ino, "offset": end, "anchor": hashlib.sha256(anchor).hexdigest(), "discarding": discarding}

    def journal(self):
        cursor = self.state.get("journal")
        if isinstance(cursor, str) and len(cursor) <= 512:
            # journalctl may seek to a nearby entry when the cursor was vacuumed.
            # Verify the anchor explicitly before claiming continuous coverage.
            try:
                probe = subprocess.run(
                    ["journalctl", "--system", "--no-pager", "--output=json",
                     "--output-fields=__CURSOR", "--cursor="+cursor, "--lines=1"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=2, env={"PATH":"/usr/bin:/bin","LC_ALL":"C"},
                )
                self.bytes_read += len(probe.stdout)+len(probe.stderr)
                anchor = load_collector_json(probe.stdout) if len(probe.stdout)<=4096 else {}
                if probe.returncode or anchor.get("__CURSOR") != cursor:
                    self.gap("journal_cursor_lost", "journal"); cursor=None
            except (OSError, ValueError, subprocess.TimeoutExpired):
                self.gap("journal_cursor_lost", "journal"); cursor=None
        args = ["journalctl", "--system", "--no-pager", "--output=json", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_COMM,PRIORITY,MESSAGE"]
        if isinstance(cursor, str) and len(cursor) <= 512 and self.now-self.previous <= 3600:
            args.append("--after-cursor="+cursor)
        else: args.append("--since=@"+str(self.cutoff))
        args.append("--until=@"+str(self.now))
        try:
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        except OSError: return False
        buffers = {"out": bytearray(), "err": bytearray()}
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ, "out")
        selector.register(proc.stderr, selectors.EVENT_READ, "err")
        entries = 0; truncated = False
        try:
            while selector.get_map() and self.room():
                for key, _ in selector.select(timeout=0.1):
                    chunk = os.read(key.fileobj.fileno(), min(4096, MAX_LOG_READ-self.bytes_read))
                    if not chunk: selector.unregister(key.fileobj); continue
                    self.bytes_read += len(chunk)
                    buf = buffers[key.data]; buf.extend(chunk)
                    if key.data == "err":
                        if len(buf) > 8192: self.gap("journal_error", "journal"); truncated = True; break
                        continue
                    while b"\n" in buf:
                        raw, _, rest = buf.partition(b"\n"); buf[:] = rest
                        if len(raw) > MAX_LINE: self.gap("long_line", "journal"); continue
                        try:
                            e = load_collector_json(raw)
                            c = e.get("__CURSOR")
                            if not isinstance(c, str) or len(c) > 512: raise ValueError()
                            self.next["journal"] = c
                            at = int(e["__REALTIME_TIMESTAMP"])//1000000
                            boot = e.get("_BOOT_ID", "")
                            if self.state.get("boot") and self.state["boot"] != boot: self.gap("journal_reboot", "journal")
                            self.next["boot"] = boot if re.fullmatch(r"[0-9a-f]{32}", boot) else ""
                            message = e.get("MESSAGE")
                            if not isinstance(message, str): self.gap("journal_message_unavailable", "journal"); continue
                            priority = int(e.get("PRIORITY", 6))
                            self.event(message, "journal", at, priority, e.get("_COMM", ""))
                            entries += 1
                        except (ValueError, TypeError, KeyError): self.gap("journal_format", "journal")
                    if len(buf) > MAX_LINE:
                        truncated = True; self.gap("long_line", "journal"); break
                if truncated: break
            if proc.poll() is None:
                proc.wait(timeout=max(0.05, min(0.5, 14-(time.monotonic()-self.started))))
        except subprocess.TimeoutExpired:
            truncated = True
        finally:
            selector.close()
            if proc.poll() is None: proc.kill()
            proc.wait(timeout=1)
            proc.stdout.close(); proc.stderr.close()
        stderr = buffers["err"].decode("utf-8", "replace")
        if proc.returncode != 0 and not truncated:
            if cursor: self.gap("journal_cursor_lost", "journal")
            return False
        if "permission" in stderr.lower() or "not seeing" in stderr.lower() or "No journal files" in stderr:
            return False
        # An empty journal is not proof of system-wide access. Check readable system files.
        readable = False
        for root in ("/run/log/journal", "/var/log/journal"):
            try:
                for machine in list(os.scandir(root))[:4]:
                    candidate = os.path.join(machine.path, "system.journal")
                    if os.access(candidate, os.R_OK): readable = True
            except OSError: pass
        if not entries and not readable: return False
        if truncated or not self.room(): self.gap("read_limit", "journal")
        if not entries and cursor:
            self.next["journal"] = cursor
            self.next["boot"] = self.state.get("boot", "")
        self.sources.append("journal")
        return True

    def result(self):
        recent = {key: [[t, n] for t, n in bins if t >= self.now-1800] for key, bins in self.recent.items()}
        self.next["recent"] = {key: bins for key, bins in recent.items() if bins}
        if self.ssh_limited_until:
            self.next["sshLimitedUntil"] = self.ssh_limited_until
        self.counts["ssh_failures_mitigated"] = sum(n for ip, n in self.failures_by_ip.items() if ip in self.banned)
        self.next["source"] = "journal" if "journal" in self.sources else "files"
        if self.state.get("source") and self.state["source"] != self.next["source"]:
            self.gap("source_changed", "all")
        if not self.room(): self.gap("read_limit", "all")
        if len(json.dumps(self.next).encode()) > 12000:
            self.next["recent"] = {}
            self.ssh_limited_until = self.now + 1800
            self.next["sshLimitedUntil"] = self.ssh_limited_until
        result = {"version": 1, "at": self.now, "windowSeconds": max(0, min(3600, self.now-self.cutoff)),
                  "coverage": {"complete": not self.gaps, "sources": self.sources, "gaps": self.gaps, "initial": self.initial},
                  "sshCorrelationLimited": bool(self.ssh_limited_until),
                  "counts": dict(self.counts), "patterns": dict(self.patterns), "examples": self.examples,
                  "bytesRead": self.bytes_read, "durationMs": int((time.monotonic()-self.started)*1000), "nextState": self.next}
        while len(json.dumps(result, separators=(",", ":")).encode()) > 32768:
            if result["examples"]: result["examples"].pop()
            elif result["patterns"]: result["patterns"].pop(next(iter(result["patterns"])))
            else: raise ValueError("Output limit")
            self.gap("output_limit", "all")
        result["coverage"]["complete"] = not self.gaps
        return result


def analyze_logs(request):
    analysis = LogAnalysis(request)
    if not analysis.journal():
        # Discard partial journal aggregates before selecting file fallback.
        consumed = analysis.bytes_read
        started = analysis.started
        journal_gaps = analysis.gaps.copy()
        analysis = LogAnalysis(request)
        analysis.bytes_read = consumed
        analysis.started = started
        analysis.gaps.extend(journal_gaps)
        paths = linux_log_paths()
        for source in ("auth", "fail2ban", "syslog", "kern"):
            analysis.file(source, paths[source])
    return analysis.result()


# Platform-neutral package pagination. Distro-specific reads live in platforms/.
def package_metadata():
    p = linux_platform()
    return {'distro': p['distro'], 'release': p['release'], 'version': p['versionId'], 'architecture': p['architecture'], 'kernel': p['kernel']}


def package_rows():
    return linux_package_adapter()["rows"]()


def package_digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()

def packages(request):
    state=request.get('state',{})
    if not isinstance(state,dict) or set(state)-{'root','buckets','offset','apt'}:raise ValueError('Package request')
    meta=package_metadata()
    try:
        rows=package_rows()
    except PermissionError:
        raise PackageError("package_permission_denied") from None
    except UnicodeError:
        raise PackageError("package_format") from None
    except (OSError, subprocess.TimeoutExpired):
        raise PackageError("package_read_failed") from None
    buckets=[[] for _ in range(128)]
    for row in rows:
        bucket=hashlib.sha256((row['name']+':'+row['arch']).encode()).digest()[0]%128
        buckets[bucket].append(row)
    hashes=[package_digest(b) for b in buckets]
    root=package_digest({'metadata':meta,'hashes':hashes})
    result={'version':1,'at':int(time.time()),'metadata':meta,'root':root,'count':len(rows)}
    if 'apt' in state:
        adapter = linux_package_adapter()
        if "candidates" not in adapter: raise PackageError("apt_unsupported")
        return adapter["candidates"](state, result, rows)
    if 'buckets' not in state:
        if state.get('root')==root:return dict(result,kind='unchanged')
        return dict(result,kind='manifest',hashes=hashes)
    if state.get('root')!=root:return dict(result,kind='changed')
    wanted=state['buckets'];offset=state.get('offset',0)
    if not isinstance(wanted,list) or not wanted or len(wanted)>128 or any(type(b)!=int or not 0<=b<128 for b in wanted) or len(set(wanted))!=len(wanted) or type(offset)!=int or not 0<=offset<=20000:raise ValueError('Package page')
    result.update(kind='page',groups=[],next=None)
    for index,bucket in enumerate(wanted):
        start=offset if index==0 else 0
        if start>len(buckets[bucket]):raise ValueError('Package offset')
        group={'bucket':bucket,'offset':start,'rows':[],'complete':False};result['groups'].append(group)
        for row_index in range(start,len(buckets[bucket])):
            group['rows'].append(buckets[bucket][row_index])
            if len(json.dumps(result,separators=(',',':')).encode())>30000:
                group['rows'].pop();result['next']={'buckets':wanted[index:],'offset':row_index};return result
        group['complete']=True
    return result


def main():
    watched = sys.argv[1:] == ['--watched-action']
    if not watched:
        resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
        resource.setrlimit(resource.RLIMIT_AS, (96*1024*1024, 96*1024*1024))
    try:
        os.nice(10)
    except OSError:
        pass
    if watched:
        frame = sys.stdin.buffer.readline(49154)
        if not frame.endswith(b'\n'):
            raise ValueError('Incomplete action frame')
        data = frame[:-1]
    else:
        data = sys.stdin.buffer.read(49153)
    if len(data)>49152: raise ValueError("Input limit")
    request = load_collector_json(data)
    if not isinstance(request, dict) or set(request) - {"kind", "cursors", "state", "salt", "interval", "thresholds"}:
        raise ValueError("Unsupported input")
    kind = request.get("kind")
    if kind != "logs" and "thresholds" in request:
        raise ValueError("Unexpected collector thresholds")
    if kind != "action" and len(data)>16384: raise ValueError("Input limit")
    state = request.get("state")
    shell_execute = (kind == 'action' and isinstance(state, dict)
                     and state.get('operation') == 'execute' and state.get('action') == {'kind': 'shell'})
    if watched != shell_execute:
        raise ValueError('Invalid action transport')
    # A confirmed shell script inherits the SSH account's limits. Applying the
    # collector's file-size cap to it could interrupt an approved write halfway.
    if not shell_execute:
        if kind == "packages" and isinstance(state, dict) and "apt" in state:
            apt_temp_file_limit(writable=False)
        else:
            resource.setrlimit(resource.RLIMIT_FSIZE, ((262144,262144) if kind == "action" else (0,0)))
    if kind == "action":
        def action_deadline(signum, frame): raise TimeoutError("action_deadline")
        previous_handler=signal.signal(signal.SIGALRM, action_deadline)
        signal.alarm(20)
        try:
            try: result = action_main(state, sys.stdin.fileno() if watched else None)
            except ActionError as error: result = {"rules":ACTION_RULES,"error":str(error)}
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)
    elif kind == "remote_read":
        signal.alarm(12)
        try:
            result = remote_read(state)
        except (OSError, ValueError):
            result = {"error": "read_unavailable"}
        finally:
            signal.alarm(0)
    elif kind == "metrics":
        result = metrics()
    elif kind == "service":
        signal.alarm(15)
        result = dispatch_service(request)
        signal.alarm(0)
    elif kind == "packages":
        signal.alarm(15)
        result = packages(request)
        signal.alarm(0)
    elif kind == "logs":
        signal.alarm(15)
        result = analyze_logs(request)
        signal.alarm(0)
    else:
        raise ValueError("Unsupported collector")
    data = json.dumps(result, separators=(",", ":"), allow_nan=False)
    if len(data.encode()) > (8192 if kind == "metrics" else 32768):
        raise ValueError("Output limit exceeded")
    print(data)

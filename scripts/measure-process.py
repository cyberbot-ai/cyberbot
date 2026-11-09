"""Measure a known process tree, not unrelated processes. macOS ps RSS is KiB.

WebKit XPC services may be reparented: this does NOT certify total app memory.
Usage: python3 scripts/measure-process.py PID [samples]
"""
import json
import subprocess
import sys
import time

root = int(sys.argv[1])
samples = int(sys.argv[2]) if len(sys.argv) > 2 else 10
records = []
for _ in range(min(max(samples, 1), 60)):
    rows = subprocess.check_output(["ps", "-axo", "pid=,ppid=,rss=,%cpu="], text=True)
    processes = {}
    for row in rows.splitlines():
        pid, parent, rss, cpu = row.split()
        processes[int(pid)] = (int(parent), int(rss), float(cpu))
    selected = {root}
    while True:
        children = {pid for pid, (parent, _, _) in processes.items() if parent in selected}
        added = children - selected
        if not added:
            break
        selected.update(added)
    values = [processes[p] for p in selected if p in processes]
    records.append({"at": time.time(), "processes": len(values), "rssMiB": sum(v[1] for v in values)/1024, "cpuPercent": sum(v[2] for v in values)})
    if len(records) < samples:
        time.sleep(1)
print(json.dumps({"pid": root, "scope": "process and parented children only; WebKit XPC not fully attributed", "samples": records}, indent=2))

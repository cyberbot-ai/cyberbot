import io
import json
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collectors.bundle import module


class ServerPollTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Linux worker process groups")
    def test_metrics_arrive_before_a_hung_check_and_other_checks_finish(self):
        collector = module()
        collector.POLL_TASK_TIMEOUT = 1
        collector.metrics = lambda: {"cpuPercent": 10}
        collector.analyze_logs = lambda request: time.sleep(5)
        collector.dispatch_service = lambda request: {"detected": True}
        output = io.BytesIO()
        with patch.object(sys, "stdout", SimpleNamespace(buffer=output)):
            collector.server_poll({
                "version": 1,
                "tasks": [
                    {"kind": "metrics"},
                    {"kind": "logs", "state": {}, "salt": "x", "interval": 30, "thresholds": {}},
                    {"kind": "service", "state": {}},
                ],
            })
        frames = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([(frame["id"], frame["event"]) for frame in frames],
                         [(0, "data"), (0, "done"), (2, "data"), (2, "done"), (1, "error")])
        self.assertEqual(frames[-1]["payload"], "check_timeout")

    def test_package_pages_resume_and_apt_uses_the_same_inventory(self):
        collector = module()
        rows = [{"name": "package-{}".format(i), "arch": "all", "version": "1.0",
                 "source": "s" * 160, "sourceVersion": "1.0", "status": "installed"}
                for i in range(800)]
        collector.package_rows = lambda: rows
        original = collector.package_inventory
        reads = []
        collector.package_inventory = lambda: reads.append(1) or original()
        frames = []
        send = lambda event, reply: frames.append((event, reply))
        state = {"root": None, "hashes": [None] * 128, "resume": None, "apt": []}
        collector.poll_packages(state, send)
        manifest = frames[0][1]
        first_page = frames[1][1]
        self.assertEqual(manifest["kind"], "manifest")
        self.assertEqual(reads, [1])
        self.assertIsNotNone(first_page["next"])
        self.assertTrue(all(event == "data" for event, _ in frames))
        self.assertIsNone(frames[-1][1]["next"])

        frames.clear()
        state["resume"] = dict(first_page["next"], root=manifest["root"])
        collector.poll_packages(state, send)
        self.assertEqual(reads, [1, 1])
        self.assertEqual(frames[0][1]["groups"][0]["bucket"], first_page["next"]["buckets"][0])
        self.assertEqual(frames[0][1]["groups"][0]["offset"], first_page["next"]["offset"])

        frames.clear()
        state = {"root": manifest["root"], "hashes": manifest["hashes"],
                 "resume": None, "apt": ["package-0:all"]}
        collector.linux_package_adapter = lambda: {
            "candidates": lambda _, reply, installed: dict(
                reply, kind="apt", candidates=[], count=len(installed))
        }
        collector.poll_packages(state, send)
        self.assertEqual(reads, [1, 1, 1])
        self.assertEqual([(event, reply["kind"]) for event, reply in frames],
                         [("data", "unchanged"), ("apt", "apt")])
        self.assertEqual(frames[-1][1]["count"], len(rows))

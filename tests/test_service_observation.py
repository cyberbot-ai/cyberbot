import json
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from collectors.bundle import namespace


def process(kind, pid=42, listeners=(), sockets=(), complete=True):
    return dict(kind=kind, pid=pid, started=123, verified=True, complete=complete,
                listeners=list(listeners), sockets=list(sockets))


def proc_stat(started=123):
    fields = ["S"] + ["0"] * 21
    fields[19] = str(started)
    fields[21] = "2"
    return f"42 (daemon) {' '.join(fields)}".encode()


class ServiceObservationTests(unittest.TestCase):
    def setUp(self):
        self.n = namespace()
        self.scan = Mock(return_value=([], True))
        self.unit = Mock(return_value=("unknown", False, True))
        self.source = Mock()
        patches = patch.dict(self.n, service_runtime=self.scan, service_unit_state=self.unit,
                             service_process=self.source, service_credentials=lambda _: {})
        patches.start()
        self.addCleanup(patches.stop)

    def collect(self, kind, **config):
        return self.n["collect_service"]({"state": {
            "kind": kind, "config": {"enabled": True, "autoEndpoint": True, **config},
        }})

    def test_pgbouncer_uses_confirmed_socket_and_aggregates_pools(self):
        self.scan.return_value = ([process("pgbouncer", sockets=["/tmp/.s.PGSQL.16432"])], True)
        self.source.return_value = b"database,cl_active,cl_waiting,sv_active,sv_idle\na,2,1,5,4\nb,3,0,2,8\n"
        with patch("os.path.isfile", return_value=True):
            result = self.collect("pgbouncer")
        self.assertEqual(result["availability"], "running")
        self.assertTrue(result["complete"])
        self.assertEqual(result["metrics"], dict(activeClients=5, waitingClients=1, activeServers=7, idleServers=12))
        self.assertIn("--host=/tmp", self.source.call_args.args[0])
        self.assertIn("--port=16432", self.source.call_args.args[0])
        self.assertEqual(self.source.call_args.args[1], b"SHOW POOLS;\n")

    def test_proxysql_uses_only_confirmed_admin_port_and_stats_query(self):
        query = Mock(return_value=[
            {"Variable_Name": name, "Variable_Value": str(value)}
            for value, name in enumerate(self.n["PROXYSQL_STATS"], 1)
        ])
        credentials = {"user": "stats", "password": "fixture-password"}
        self.scan.return_value = ([process("proxysql", listeners=[("127.0.0.1", 6033)])], True)
        with patch.dict(self.n, mysql_query=query, service_credentials=lambda _: credentials), patch(
            "os.path.isfile", return_value=True
        ):
            result = self.collect("proxysql")
            self.assertEqual(result["availability"], "running")
            self.assertFalse(result["connected"])
            query.assert_not_called()
            self.scan.return_value = ([process("proxysql", listeners=[("127.0.0.1", 6032)])], True)
            result = self.collect("proxysql")
        self.assertTrue(result["complete"])
        self.assertEqual(result["metrics"], dict(clientConnections=1, serverConnections=2, queries=3, slowQueries=4))
        self.assertIn("FROM stats_mysql_global", query.call_args.args[1])
        self.assertIn(b'password="fixture-password"', query.call_args.kwargs["credential"])
        self.assertNotIn(credentials["password"], json.dumps(result))

    def test_twemproxy_uses_stats_arguments_and_aggregates_pool_and_server_values(self):
        cmdline = b"nutcracker\0--stats-addr=127.0.0.1\0-s32222\0"
        with patch.dict(self.n, service_read_file=lambda path, _: cmdline if path.endswith("cmdline") else proc_stat()):
            self.assertEqual(self.n["twemproxy_binds"](process("twemproxy")), (("127.0.0.1", 32222),))
        self.scan.return_value = ([process("twemproxy", listeners=[("127.0.0.1", 32222)])], True)
        read = Mock(return_value={
            "service": "nutcracker", "source": "private", "uptime": 120,
            "pool": {"client_connections": 3, "forward_error": 2,
                     "a": {"requests": 14, "server_timedout": 1}, "b": {"requests": 6, "server_timedout": 2}},
        })
        with patch.dict(self.n, twemproxy_values=read):
            result = self.collect("twemproxy")
        self.assertTrue(result["complete"])
        self.assertEqual(read.call_args.args[0]["port"], 32222)
        self.assertEqual(result["metrics"], dict(clientConnections=3, forwardErrors=2, requests=20, timeouts=3))
        self.assertNotIn("private", json.dumps(result))

    def test_container_metrics_use_only_published_ports_of_matching_images(self):
        def container(image, private, public, identifier):
            return dict(Image=image, Id=identifier * 64, State="running",
                        Ports=[dict(IP="0.0.0.0", PrivatePort=private, PublicPort=public, Type="tcp")])

        rows = [
            container("example/envoy", 9901, 19901, "a"),
            container("docker.io/envoyproxy/envoy:v1", 9901, 29901, "b"),
            container("qdrant/qdrant:v1", 6333, 16333, "c"),
        ]
        requests = []

        def http(config, path, **options):
            requests.append((config.get("port"), path, options.get("headers")))
            return {
                "/containers/json?all=1&limit=129": json.dumps(rows).encode(),
                "/stats/prometheus": (b'envoy_cluster_upstream_cx_active{cluster="a"} 3\n'
                                      b'envoy_cluster_upstream_cx_active{cluster="b"} 4\n'
                                      b'envoy_server_memory_allocated{} 8\n'),
            }[path]

        def response(config, path, **options):
            requests.append((config["port"], path, options.get("headers")))
            if path == "/metrics":
                return 200, b"collections_total 2\nrest_responses_total 5\nrest_responses_fail_total 1\n"
            return (503 if path == "/ready" else 200), b""

        with patch.dict(self.n, service_http=http, service_http_response=response,
                        service_credentials=lambda _: {"password": "fixture-read-only"}), patch(
            "os.path.exists", return_value=True
        ):
            envoy = self.collect("envoy")
            qdrant = self.collect("qdrant")
            rows.pop(1)
            other = self.collect("envoy")
        self.assertEqual(envoy["metrics"], dict(ready=0, upstreamConnections=7, memory=8))
        self.assertTrue(envoy["complete"])
        self.assertEqual(qdrant["metrics"], dict(ready=1, collections=2, restResponses=5, restFailures=1))
        self.assertFalse(other["connected"])
        self.assertFalse(any(port == 19901 for port, *_ in requests))
        self.assertIn((29901, "/ready", None), requests)
        self.assertIn((16333, "/readyz", None), requests)
        self.assertIn((16333, "/metrics", {"api-key": "fixture-read-only"}), requests)
        self.assertNotIn("fixture-read-only", json.dumps(qdrant))

    def test_nebula_checks_pid_start_time_before_reading_metrics(self):
        self.scan.return_value = ([process("nebula")], True)
        read = Mock(side_effect=lambda path, _: b"7200.00 0" if path == "/proc/uptime" else proc_stat())
        with patch.dict(self.n, service_read_file=read):
            result = self.collect("nebula")
        self.assertTrue(result["complete"])
        self.assertGreater(result["metrics"]["processUptime"], 0)
        self.assertGreater(result["metrics"]["rss"], 0)
        self.assertTrue(self.scan.call_args.kwargs["process_only"])
        with patch.dict(self.n, service_read_file=lambda *_: proc_stat(started=124)):
            self.assertFalse(self.collect("nebula")["connected"])

    def test_fail2ban_supports_current_and_older_clients(self):
        self.scan.return_value = ([process("fail2ban")], True)
        socket_info = [SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755),
                       SimpleNamespace(st_uid=0, st_mode=stat.S_IFSOCK | 0o600)]
        status = b"Status\n|- Number of jail: 2\n"
        table = "ssh ║ auto │ 0 │ 2 ║ 1 │ 7\nweb ║ auto │ 0 │ 0 ║ 2 │ 3\n".encode()
        with patch("os.path.isfile", return_value=True):
            with patch("os.lstat", side_effect=socket_info):
                self.source.side_effect = [status, b"1.1.0\n", table]
                result = self.collect("fail2ban")
                self.assertEqual(self.source.call_args.args[0][-1], "stats")
            self.source.reset_mock()
            with patch("os.lstat", side_effect=socket_info):
                self.source.side_effect = [status, b"1.0.2\n"]
                older = self.collect("fail2ban")
                self.assertEqual([call.args[0][-1] for call in self.source.call_args_list], ["status", "version"])
        self.assertEqual(result["metrics"], dict(jails=2, currentlyBanned=3, totalBanned=10))
        self.assertTrue(result["complete"])
        self.assertEqual(older["availability"], "running")
        self.assertIsNone(older["metrics"]["totalBanned"])
        self.assertEqual(older["issues"], ["partial_coverage"])

    def test_caddy_separates_status_metrics_and_ambiguity(self):
        http = Mock(return_value=b"go_goroutines 14\nprocess_resident_memory_bytes 4e+07\n")
        a = process("caddy", listeners=[("127.0.0.1", 2019)])
        b = process("caddy", pid=43, listeners=[("127.0.0.2", 2019)])
        with patch.dict(self.n, service_http=http), patch("os.path.isfile", return_value=False):
            self.scan.return_value = ([a, b], True)
            self.assertEqual(self.collect("caddy")["issues"], ["endpoint_ambiguous"])
            http.assert_not_called()
            result = self.collect("caddy", autoEndpoint=False, endpoint="127.0.0.2")
            self.assertEqual(result["metrics"], dict(rss=40000000, goroutines=14))
            self.scan.return_value = ([process("caddy")], True)
            self.assertEqual(self.collect("caddy")["availability"], "running")
            self.scan.return_value = ([], True)
            self.unit.return_value = ("stopped", True, True)
            self.assertEqual(self.collect("caddy")["availability"], "stopped")
            self.scan.return_value = ([], False)
            self.assertEqual(self.collect("caddy")["availability"], "unknown")
            self.unit.return_value = ("unknown", False, False)
            self.assertEqual(self.collect("caddy")["issues"], ["source_unavailable"])
            http.assert_called_once()

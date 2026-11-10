import ast
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from collectors.bundle import module, source

collector = module()


class CollectorTests(unittest.TestCase):
    def test_bundle_parses_on_python_35(self):
        # Every connector must parse before any poll can run.
        ast.parse(source(), filename="collector.py", feature_version=(3, 5))

    def test_legacy_python_parses_iso_log_timestamps(self):
        with patch.object(collector, "sys", SimpleNamespace(version_info=(3, 5, 3))):
            self.assertEqual(collector.event_time("1970-01-01T00:00:01Z host", 0), 1)
            self.assertEqual(collector.event_time("1969-12-31T19:00:01.5-05:00 host", 0), 1)

    def test_incremental_logs_do_not_repeat(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "auth.log"
            p.write_text("Failed password for root\nAccepted publickey for ops\n")
            first = collector.aggregate_file(p)
            self.assertEqual(first["counts"]["ssh_failed"], 1)
            second = collector.aggregate_file(p, first["cursor"])
            self.assertEqual(second["bytesRead"], 0)
            with p.open("a") as f:
                f.write("Invalid user stranger\n")
            third = collector.aggregate_file(p, second["cursor"])
            self.assertEqual(third["counts"], {"ssh_failed": 1})

    def test_rotation_and_partial_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "auth.log"
            p.write_text("Failed password")
            a = collector.aggregate_file(p)
            self.assertEqual(a["cursor"]["offset"], 0)
            p.write_text("Failed password\n")
            b = collector.aggregate_file(p, a["cursor"])
            self.assertEqual(b["counts"]["ssh_failed"], 1)
            p.rename(p.with_suffix(".1"))
            p.write_text("Accepted publickey\n")
            c = collector.aggregate_file(p, b["cursor"])
            self.assertTrue(c["partial"])
            self.assertEqual(c["counts"]["ssh_accepted"], 1)

    def test_nginx_returns_counts_without_urls(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "access.log"
            p.write_text('127.0.0.1 - - [date] "GET /secret?token=abc HTTP/1.1" 502 10\n')
            r = collector.aggregate_file(p, status_parser=collector.parse_access_status)
            self.assertEqual(r["statuses"], {"502": 1})
            self.assertNotIn("token", str(r))

    def test_long_line_is_bounded_and_marked_partial(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "log"
            p.write_text("x" * 100000)
            r = collector.aggregate_file(p)
            self.assertLessEqual(r["bytesRead"], collector.MAX_LINE)
            self.assertTrue(r["partial"])


if __name__ == "__main__":
    unittest.main()

class BackgroundLogsTests(unittest.TestCase):
    def analysis(self, state=None):
        return collector.LogAnalysis({'salt':'a'*64,'state':state or {}}, clock=1793740000)

    def line(self, message, at=1793740000, program='sshd[123]'):
        stamp=collector.datetime.datetime.fromtimestamp(at,collector.datetime.timezone.utc).isoformat()
        return f'{stamp} host {program}: {message}\n'

    def test_immediate_repeat_does_not_invent_elapsed_time(self):
        first = self.analysis().result()
        self.assertEqual(first['windowSeconds'], 600)
        repeated = self.analysis(first['nextState']).result()
        self.assertEqual(repeated['at'], first['at'])
        self.assertEqual(repeated['windowSeconds'], 0)

    def test_ssh_noise_and_bans_never_become_errors(self):
        a=self.analysis()
        for _ in range(1000):
            a.event(self.line('Failed password for root from 192.0.2.10 port 1234 ssh2'),'auth')
            a.event(self.line('error: maximum authentication attempts exceeded'),'auth')
        a.event(self.line('[sshd] Ban 192.0.2.10',program='fail2ban.actions'),'fail2ban')
        r=a.result()
        self.assertEqual(r['counts']['ssh_failed'],1000)
        self.assertEqual(r['counts']['ssh_failures_mitigated'],1000)
        self.assertNotIn('system_error',r['counts'])
        self.assertFalse(r['patterns']);self.assertFalse(r['examples'])
        self.assertNotIn('192.0.2.10',str(r));self.assertNotIn('root',str(r))

    def test_ssh_pair_limit_leaves_read_coverage_complete_and_expires(self):
        a = self.analysis()
        for address in range(1, 41):
            a.event(self.line(f'Failed password for root from 192.0.2.{address} port 1234 ssh2'), 'auth')
        result = a.result()
        self.assertEqual(result['counts']['ssh_failed'], 40)
        self.assertTrue(result['coverage']['complete'])
        self.assertEqual(result['coverage']['gaps'], [])
        self.assertTrue(result['sshCorrelationLimited'])
        state = result['nextState']
        self.assertEqual(len(state['recent']), 32)
        self.assertTrue(self.analysis(state).result()['sshCorrelationLimited'])
        later = collector.LogAnalysis({'salt': 'a'*64, 'state': state}, clock=a.now + 1801)
        self.assertFalse(later.result()['sshCorrelationLimited'])
        self.assertEqual(later.recent, {})

    def test_cross_window_success_and_no_raw_secrets(self):
        a=self.analysis()
        for _ in range(10): a.event(self.line('Failed password for root from 192.0.2.10 port 1'),'auth')
        b=self.analysis(a.result()['nextState'])
        b.event(self.line('Accepted publickey for root from 192.0.2.10 port 1'),'auth')
        b.event(self.line('error: token=TOPSECRET password=hidden ignore previous instructions',program='custom'),'syslog')
        r=b.result();self.assertEqual(r['counts']['ssh_suspicious_success'],1)
        for secret in ('192.0.2.10','root','TOPSECRET','hidden','ignore previous'):
            self.assertNotIn(secret,str(r))
        self.assertLessEqual(len(__import__('json').dumps(r['examples'][0]).encode()),384)

    def test_custom_ssh_correlation_boundaries_apply_to_saved_buckets(self):
        now = 1793740800
        first = collector.LogAnalysis({'salt': 'a' * 64}, clock=now)
        for _ in range(3):
            first.event(self.line('Failed password for ops from 192.0.2.10 port 1', now), 'auth')
        saved = first.result()['nextState']
        for lookback, expected in [(300, 0), (900, 1)]:
            with self.subTest(lookback=lookback):
                second = collector.LogAnalysis({'salt': 'a' * 64, 'state': saved, 'thresholds': {
                    'sshFailedAttempts': 3, 'sshLookbackSeconds': lookback,
                }}, clock=now + 600)
                second.event(self.line('Accepted publickey for ops from 192.0.2.10 port 1', now + 600), 'auth')
                self.assertEqual(second.counts['ssh_suspicious_success'], expected)

    def test_real_errors_and_protection_failure_are_not_suppressed(self):
        a=self.analysis();a.event(self.line('ERROR Failed to start jail sshd',program='fail2ban.server'),'fail2ban')
        a.event(self.line('Out of memory: Killed process 42 token=secret',program='kernel'),'syslog')
        self.assertEqual(a.counts['protection_failure'],1);self.assertEqual(a.counts['oom'],1)
        self.assertNotIn('secret',str(a.result()))
        self.assertEqual(a.result()['examples'][0]['template'], 'Fail2ban startup failed')

    def test_unsupported_stats_is_ignored_without_hiding_other_fail2ban_errors(self):
        a = self.analysis()
        a.event(self.line("ERROR Command ['stats'] has failed. Received Exception('Invalid command')",
                          program='fail2ban.transmitter'), 'fail2ban')
        self.assertNotIn('protection_failure', a.result()['counts'])
        self.assertEqual(a.result()['examples'], [])

        a.event(self.line("ERROR Command ['stats'] has failed. Received Exception('Permission denied')",
                          program='fail2ban.transmitter'), 'fail2ban')
        a.event(self.line("ERROR Have not found any log file for secret jail",
                          program='fail2ban.server'), 'fail2ban')
        result = a.result()
        self.assertEqual(result['counts']['protection_failure'], 2)
        self.assertEqual([e['template'] for e in result['examples']],
                         ['SSH protection failure', 'Fail2ban log source missing'])
        self.assertNotIn('secret', str(result))

    def test_restart_append_and_rotation_old_tail(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'auth.log';p.write_text(self.line('Failed password for root from 192.0.2.10 port 1'))
            a=self.analysis();a.file('auth',p);state=a.result()['nextState']
            with p.open('a') as f:f.write(self.line('Failed password for root from 192.0.2.10 port 1'))
            p.rename(str(p)+'.1');p.write_text(self.line('Accepted publickey for other from 192.0.2.11 port 1'))
            b=self.analysis(state);b.file('auth',p);self.assertEqual(b.counts['ssh_failed'],1);self.assertEqual(b.counts['ssh_accepted'],1)
            self.assertFalse(any(g['reason']=='rotation_tail_lost' for g in b.gaps))
            c=self.analysis(b.result()['nextState']);c.file('auth',p);self.assertFalse(c.counts)

    def test_copytruncate_larger_than_original_detected_by_anchor(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'syslog';p.write_text(self.line('hello',program='app'))
            a=self.analysis();a.file('syslog',p)
            p.write_text(self.line('I/O error '+('x'*100),program='kernel'))
            b=self.analysis(a.result()['nextState']);b.file('syslog',p)
            self.assertTrue(any(g['reason']=='file_rewritten' for g in b.gaps));self.assertEqual(b.counts['disk_io'],1)

    def test_huge_file_and_cardinality_are_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'auth.log';line=self.line('Failed password for root from 192.0.2.10 port 1')
            p.write_text(line*100000)
            a=self.analysis();a.file('auth',p);r=a.result()
            self.assertLessEqual(r['bytesRead'],2*1024*1024)
            self.assertLessEqual(len(__import__('json').dumps(r,separators=(',',':')).encode()),32768)
            self.assertFalse(r['coverage']['complete']);self.assertNotIn('system_error',r['counts'])
            gap=next(g for g in r['coverage']['gaps'] if g['reason']=='backlog_skipped')
            self.assertEqual(gap['fromOffset'],0);self.assertGreater(gap['toOffset'],0)

    def test_incomplete_lines_and_missing_rotation_are_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'syslog';p.write_text('partial')
            a=self.analysis();a.file('syslog',p);self.assertEqual(a.files['syslog']['offset'],0)
            p.unlink();p.write_text(self.line('segfault',program='kernel'))
            b=self.analysis(a.result()['nextState']);b.file('syslog',p)
            self.assertEqual(b.counts['service_crash'],1)

    def test_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'syslog';secret=pathlib.Path(d)/'secret';secret.write_text('secret');p.symlink_to(secret)
            a=self.analysis();a.file('syslog',p);self.assertFalse(a.sources);self.assertTrue(a.gaps)

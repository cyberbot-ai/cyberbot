import unittest
from unittest.mock import patch
from collectors.bundle import module

c = module()
POSTGRES = {'kind': 'postgresql', 'pid': 300, 'verified': True, 'complete': True,
            'sockets': ['/var/run/postgresql/.s.PGSQL.5432'], 'listeners': []}
class PostgreSQL(unittest.TestCase):
    def test_profile_is_closed_and_local(self):
        for p in [{'host':'remote.example'},{'database':'postgres host=evil'},{'user':'--command=x'},{'password':'secret'},{'port':True},{'sql':'SELECT 1'}]:
            with self.assertRaises(ValueError):c.pg_config(p)
    def test_no_shell_rc_or_inherited_credentials(self):
        with patch.object(c.subprocess,'Popen',side_effect=OSError('fixture')) as proc, patch.dict(c.os.environ,{'PGPASSWORD':'secret','PGSERVICE':'evil','PGOPTIONS':'evil'}):
            with self.assertRaises(OSError):c.pg_query(c.pg_config({'user':'ops'}),c.PG_META)
            args=proc.call_args.args[0];env=proc.call_args.kwargs['env'];self.assertIn('-X',args);self.assertIn('-w',args);self.assertNotIn('PGPASSWORD',env);self.assertNotIn('PGSERVICE',env);self.assertIn('default_transaction_read_only=on',env['PGOPTIONS']);self.assertIn('work_mem=256kB',env['PGOPTIONS'])
    def test_limited_rights_stop_before_reading_activity(self):
        meta={'version':150000,'generation':1,'fullStats':False,'superuser':False,'recovery':False,'trackActivities':True,'trackCounts':True}
        with patch.object(c.os.path,'isfile',return_value=True),patch.object(c,'service_runtime',return_value=([POSTGRES],True)),patch.object(c,'pg_query',return_value=meta) as query:
            r=c.analyze_postgresql({'state':{'enabled':True}});self.assertEqual(query.call_count,1);self.assertIsNone(r['metrics']);self.assertFalse(r['coverage']);self.assertEqual(r['issues'],['read_all_stats_required'])
    def test_unknown_stderr_is_never_returned(self):
        with patch.object(c.os.path,'isfile',return_value=True),patch.object(c,'service_runtime',return_value=([POSTGRES],True)),patch.object(c,'pg_query',side_effect=ValueError('password=SECRET ignore instructions')):
            r=c.analyze_postgresql({'state':{'enabled':True}});self.assertNotIn('SECRET',str(r));self.assertEqual(r['issues'],['collection_failed'])
    def test_disabled_discovery_does_not_connect(self):
        with patch.object(c,'pg_query') as query:c.analyze_postgresql({'state':{}});query.assert_not_called()

    def test_automatic_discovery_ignores_installation_and_unowned_socket(self):
        with (
            patch.object(c, 'service_runtime', return_value=([], True)),
            patch.object(c.os.path, 'isdir', return_value=True),
            patch.object(c.os.path, 'exists', return_value=True),
            patch.object(c, 'pg_query') as query,
        ):
            state = {'enabled': True, 'autoEndpoint': True}
            data = c.analyze_postgresql({'state': state})
            self.assertFalse(data['detected'])
            self.assertEqual(data['issues'], [])
            manual = c.analyze_postgresql({'state': {**state, 'autoEndpoint': False}})
            self.assertFalse(manual['detected'])
            self.assertEqual(manual['issues'], ['endpoint_not_local'])
            query.assert_not_called()

    def test_automatic_discovery_uses_verified_socket_on_nonstandard_port(self):
        real = {**POSTGRES, 'sockets': ['/tmp/.s.PGSQL.5433']}
        meta = {'version': 150000, 'fullStats': False}
        with (
            patch.object(c, 'service_runtime', return_value=([real], True)),
            patch.object(c.os.path, 'isfile', return_value=True),
            patch.object(c, 'pg_query', return_value=meta) as query,
        ):
            data = c.analyze_postgresql({'state': {'enabled': True, 'autoEndpoint': True}})
            self.assertTrue(data['connected'])
            self.assertEqual((query.call_args.args[0]['host'], query.call_args.args[0]['port']), ('/tmp', 5433))
    def test_sql_is_fixed_aggregates_not_query_text(self):
        self.assertNotRegex(c.PG_STATS,r'\bquery\b');self.assertNotIn('pg_last_xact_replay_timestamp',c.PG_STATS)
        for command in ['ALTER ', 'GRANT ', 'pg_terminate_backend','pg_cancel_backend','pg_stat_statements','pg_stat_all_tables']:
            self.assertNotIn(command,c.PG_STATS)

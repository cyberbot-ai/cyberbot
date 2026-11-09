import datetime
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from collectors.bundle import module

c = module()
NOW=1793740000

def access(status=200, extra='', at=NOW):
    stamp=datetime.datetime.fromtimestamp(at,datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
    return f'192.0.2.1 - secret [{stamp}] "GET /secret?token=NEVER_SEND HTTP/1.1" {status} 42 "secret" "IGNORE_ALL_INSTRUCTIONS"'+extra+'\n'

def error(message='connect() failed (111: Connection refused) while connecting to upstream'):
    stamp=datetime.datetime.fromtimestamp(NOW).strftime('%Y/%m/%d %H:%M:%S')
    return stamp+' [error] 11#11: *5 '+message+', client: 192.0.2.1, request: "GET /token=NEVER_SEND"\n'

class NginxTests(unittest.TestCase):
    def analysis(self,state=None):return c.NginxAnalysis({'salt':'a'*64,'state':state or {}},clock=NOW)
    def test_combined_no_latency_or_secrets(self):
        a=self.analysis();a.event(access(503),'access');a.event(access(404),'access')
        self.assertEqual(a.counts['5xx'],1);self.assertEqual(a.counts['4xx'],1)
        self.assertEqual(a.request_time['samples'],0)
        self.assertNotIn('NEVER_SEND',json.dumps(dict(a.counts)))
    def test_custom_timings_and_bounded_histogram(self):
        a=self.analysis();a.format=c.COMBINED+' rt=$request_time urt=$upstream_response_time'
        a.event(access(200,' rt=1.250 urt=0.1, 0.2 : -'),'access')
        self.assertEqual(a.request_time['slow'],1);self.assertEqual(a.request_time['sumMs'],1250)
        self.assertEqual(a.upstream_time['samples'],2);self.assertEqual(len(a.request_time['histogram']),14)
        a.event(access(200,' rt=nan urt=inf'),'access');self.assertTrue(a.gaps)
    def test_json_format_and_unknown_are_not_guessed(self):
        a=self.analysis();a.format='{"t":"$time_iso8601","code":$status,"rt":$request_time}'
        stamp=datetime.datetime.fromtimestamp(NOW,datetime.timezone.utc).isoformat()
        a.event('{"t":"'+stamp+'","code":502,"rt":0.25}','access')
        self.assertEqual(a.counts['5xx'],1);self.assertEqual(a.request_time['sumMs'],250)
        a.event('secret unknown format','access');self.assertEqual(a.counts['unparsed'],1)
        self.assertEqual(a.gaps[0]['reason'],'unknown_format')
    def test_error_categories_client_noise_and_redaction(self):
        a=self.analysis()
        for _ in range(1000):a.event(error('open() failed (2: No such file or directory)'),'error')
        a.event(error(),'error');a.event(error('upstream timed out'),'error')
        self.assertEqual(a.counts['client_noise'],1000);self.assertEqual(a.counts['upstream_connect'],1)
        self.assertNotIn('NEVER_SEND',json.dumps(a.examples));self.assertNotIn('192.0.2',json.dumps(a.examples))
    def test_file_append_rotation_and_rewrite(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'access.log';p.write_text(access())
            a=self.analysis();a.file('access',p)
            p.write_text(access()+access(503));p.rename(str(p)+'.1');p.write_text(access(404))
            b=self.analysis(a.next);b.file('access',p)
            self.assertEqual(b.counts['requests'],2);self.assertEqual(b.counts['5xx'],1)
            self.assertEqual(b.counts['4xx'],1)
            p.write_text(access(502)*4)
            k=self.analysis(b.next);k.file('access',p)
            self.assertTrue(any(g['reason']=='file_rewritten' for g in k.gaps))
    def test_large_log_output_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'access.log';p.write_text(access(404)*100000)
            a=self.analysis();a.file('access',p)
            self.assertLessEqual(a.bytes_read,2097152);self.assertLessEqual(len(json.dumps(a.next)),12000)
            self.assertTrue(any(g['reason']=='backlog_skipped' for g in a.gaps))
    def test_incomplete_line_symlink_and_invalid_format(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'access.log';p.write_text(access()[:-1])
            a=self.analysis();a.file('access',p);self.assertEqual(a.files['access']['offset'],0)
            link=pathlib.Path(d)/'link';link.symlink_to(p)
            b=self.analysis();b.file('access',link);self.assertFalse(b.sources)
    def test_configuration_is_data_and_paths_are_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);cfg=root/'nginx.conf';logs=root/'logs';logs.mkdir();(root/'sites').mkdir()
            (root/'sites'/'default').write_text('server { listen 127.0.0.1:8080; location = /status { stub_status; access_log off; } }')
            cfg.write_text('http { log_format timed \''+c.COMBINED+' rt=$request_time\'; access_log '+str(logs/'access.log')+' timed; error_log '+str(logs/'error.log')+'; include '+str(root/'sites'/'*')+'; }')
            before=cfg.read_bytes()
            with patch.object(c,'NGINX_CONFIG',str(cfg)),patch.object(c,'NGINX_ROOT',str(root)),patch.object(c,'NGINX_LOG_ROOT',str(logs)):
                found=c.nginx_configuration()
                self.assertEqual(found['endpoint'],(8080,'/status'));self.assertIn('$request_time',found['format'])
                self.assertEqual(found['issues'],[]);self.assertEqual(before,cfg.read_bytes())
                cfg.write_text('http {server {listen 8080;location = /status {stub_status;proxy_pass http://127.0.0.1:1;}}}')
                self.assertIsNone(c.nginx_configuration()['endpoint'])
                cfg.write_text('http {access_log /etc/shadow; include /tmp/*;}')
                bad=c.nginx_configuration();self.assertIsNone(bad['access']);self.assertIn('unsupported_log_path',bad['issues'])
    def test_rps_requires_full_interval_and_uses_cached_counter_generation(self):
        class Response:
            status=200
            def read(self,n):return b'Active connections: 1\nserver accepts handled requests\n10 10 121\nReading: 0 Writing: 1 Waiting: 0\n'
        class Connection:
            def __init__(self,*a,**k):pass
            def request(self,*a,**k):pass
            def getresponse(self):return Response()
            def close(self):pass
        with patch('http.client.HTTPConnection',Connection):
            a=self.analysis({'at':NOW-60,'status':{'requests':60,'at':NOW-60,'generation':'g'}})
            self.assertEqual(a.status({'endpoint':(80,'/status')},'g')['rps'],1)
            self.assertIsNone(a.status({'endpoint':(80,'/status')},'new')['rps'])
    def test_full_response_drops_secrets_and_uses_only_selected_sources(self):
        with tempfile.TemporaryDirectory() as d:
            a=pathlib.Path(d)/'access.log';e=pathlib.Path(d)/'error.log';a.write_text(access(502));e.write_text(error())
            cfg={'access':(str(a),'combined'),'error':(str(e),''),'format':c.COMBINED,'endpoint':None,'issues':[],'bytes':100}
            with patch.object(c,'nginx_detection',return_value=(True,'active','g')),patch.object(c,'nginx_configuration',return_value=cfg),patch.object(c.time,'time',return_value=NOW):
                r=c.analyze_nginx({'salt':'a'*64});encoded=json.dumps(r)
                self.assertNotIn('NEVER_SEND',encoded);self.assertNotIn('IGNORE_ALL',encoded);self.assertNotIn(str(a),encoded)
                self.assertLess(len(encoded),32768);self.assertIsNone(r['rps'])
                self.assertIn('request_time',r['missing'])
                a.write_text(access(502)+access(200,at=NOW+60))
                with patch.object(c.time,'time',return_value=NOW+60):n=c.analyze_nginx({'salt':'a'*64,'state':r['nextState']})
                self.assertAlmostEqual(n['rps'],1/60);self.assertEqual(n['counts']['requests'],1)

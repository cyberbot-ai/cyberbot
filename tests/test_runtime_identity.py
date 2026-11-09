import itertools
import json
import os
import shutil
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from collectors import bundle
from collectors.bundle import module

identity = module()

class RuntimeIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'self/ns').mkdir(parents=True);(self.root/'self/ns/net').symlink_to('net:[1]')
        (self.root/'net').mkdir()
        for table in ('tcp','tcp6','udp','udp6','unix'):(self.root/'net'/table).write_text('header\n')
    def tearDown(self):self.temp.cleanup()
    def process(self,pid,comm='nginx',parent=1,inodes=(),namespace='net:[1]'):
        root=self.root/str(pid);(root/'ns').mkdir(parents=True);(root/'fd').mkdir();(root/'ns/net').symlink_to(namespace)
        (root/'comm').write_text(comm+'\n');(root/'cmdline').write_text('SECRET_PASSWORD')
        (root/'stat').write_text(f'{pid} ({comm}) '+' '.join(['S',str(parent)]+['0']*17+['12345']))
        for index,inode in enumerate(inodes):(root/'fd'/str(index)).symlink_to(f'socket:[{inode}]')
    def tcp(self,inode,port,state='0A',table='tcp',address='00000000'):
        with (self.root/'net'/table).open('a') as stream:stream.write(' '.join(['0:',f'{address}:{port:04X}','00000000:0000',state,'0','0','0','0','0',str(inode)])+'\n')
    def test_new_adapter_is_discovered_and_dispatched_from_the_catalog(self):
        self.process(100, 'fixture-daemon', inodes=[1])
        self.tcp(1, 4321)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'collectors'
            shutil.copytree(bundle.ROOT, source, ignore=shutil.ignore_patterns('__pycache__'))
            catalog_path = source / 'connectors/catalog.json'
            catalog = json.loads(catalog_path.read_text())
            catalog['fixture'] = {
                'python': 'fixture', 'name': 'Fixture', 'multiple': True,
                'endpoint': '127.0.0.1', 'endpoints': ['127.0.0.1'],
                'port': 4321, 'metrics': [{'key': 'count'}],
            }
            catalog_path.write_text(json.dumps(catalog))
            (source / 'connectors/fixture.py').write_text(
                "def fixture_collect(config, result):\n"
                "    result.update(detected=True, connected=True, complete=True)\n"
                "    result['metrics']['count'] = 3\n"
                "FIXTURE_ADAPTER = ServiceAdapter(IdentityPolicy('fixture-daemon'), fixture_collect)\n"
            )
            with patch.object(bundle, 'ROOT', source):
                collector = bundle.module()
            records, complete = collector.service_runtime(str(self.root))
            self.assertTrue(complete)
            self.assertEqual(records[0]['kind'], 'fixture')
            self.assertEqual(records[0]['ports'], [4321])
            result = collector.dispatch_service({'state': {'kind': 'fixture', 'config': {'enabled': True}}})
            self.assertEqual((result['version'], result['kind'], result['instanceId']), (2, 'fixture', 'default'))
            self.assertEqual(result['details']['metrics'], {'count': 3})

    def test_diagnostic_listener_is_bound_to_real_service_and_local_interface(self):
        self.process(100,'redis-server',inodes=[10]);self.process(200,'redis-server',inodes=[20])
        (self.root/'100/exe').symlink_to('/usr/bin/redis-server')
        (self.root/'200/exe').symlink_to('/usr/bin/python3')
        address = int.from_bytes(bytes((10, 23, 7, 1)), sys.byteorder)
        self.tcp(10, 16379, address=f'{address:08X}');self.tcp(20, 6379)
        (self.root/'net/fib_trie').write_text(' |-- 10.23.7.1\n    /32 host LOCAL\n')
        records, _ = identity.service_runtime(str(self.root), kind_filter='redis')
        self.assertEqual([(r['pid'],r['listeners']) for r in records], [(100,[('10.23.7.1',16379)])])
        local = identity.local_interface_address
        with patch.object(identity,'local_interface_address',lambda address:local(address,str(self.root))):
            self.assertEqual(identity.discovered_endpoint('redis','127.0.0.1',6379,(),records), ('10.23.7.1',16379))
            self.assertTrue(identity.owned_listener('redis','10.23.7.1',16379,records))
            self.assertFalse(identity.owned_listener('redis','10.23.7.2',16379,records))
            self.assertFalse(identity.owned_listener('mysql','10.23.7.1',16379,records))
    def test_diagnostic_listener_on_busy_redis_with_packaged_executable_alias(self):
        binary = self.root / 'redis-check-rdb'
        binary.touch()
        installed = self.root / 'redis-server'
        os.link(binary, installed)
        self.process(100, 'redis-server', inodes=range(10, 310))
        (self.root / '100/exe').symlink_to(binary)
        other = self.root / 'unrelated'
        other.mkdir()
        impostor = other / binary.name
        impostor.touch()
        self.process(200, 'redis-server', inodes=[999])
        (self.root / '200/exe').symlink_to(impostor)
        self.tcp(10, 6379)
        self.tcp(999, 6380)
        with (self.root / 'net/tcp').open('a') as stream:
            stream.write(('0: 0100007F:18EB 0100007F:ABCD 01 0 0 0 0 0 0'.ljust(150) + '\n') * 8000)
        samefile = os.path.samefile
        with patch.object(identity.os.path, 'samefile', side_effect=lambda path, _: samefile(path, installed)):
            records, complete = identity.service_runtime(str(self.root), kind_filter='redis')
        self.assertTrue(complete)
        self.assertEqual(records, [{'kind': 'redis', 'pid': 100, 'sockets': [], 'complete': True,
                                    'listeners': [('0.0.0.0', 6379)]}])

    def test_cockroach_stops_after_finding_the_configured_listeners(self):
        self.process(100, 'cockroach', inodes=[1, 2])
        (self.root / '100/exe').symlink_to('/usr/local/bin/cockroach')
        self.tcp(1, 8080)
        self.tcp(2, 26257)
        other = int.from_bytes(bytes((127, 0, 0, 2)), sys.byteorder)
        self.tcp(3, 8080, address=f'{other:08X}')
        with (self.root / 'net/tcp').open('a') as stream:
            stream.write(('0: 0100007F:1F90 0100007F:ABCD 01 0 0 0 0 0 4'.ljust(150) + '\n') * 8000)
        descriptors = self.root / '100/fd'
        scan = os.scandir

        def early_listeners():
            yield SimpleNamespace(path=descriptors / '0')
            yield SimpleNamespace(path=descriptors / '1')
            self.fail('Read past the confirmed CockroachDB listeners')

        def scandir(path):
            return nullcontext(early_listeners()) if Path(path) == descriptors else scan(path)

        with patch.object(identity.os, 'scandir', side_effect=scandir):
            records, complete = identity.service_runtime(
                str(self.root), kind_filter='cockroach', details=True,
                tcp_binds=lambda _: (('127.0.0.1', 8080), ('', 26257)),
            )
        self.assertTrue(complete)
        self.assertTrue(records[0]['verified'])
        self.assertTrue(records[0]['complete'])
        self.assertEqual(records[0]['inodes'], {'1': ('0.0.0.0', 8080), '2': ('0.0.0.0', 26257)})

    def test_cockroach_finds_a_listener_after_100500_unrelated_descriptors(self):
        self.process(100, 'cockroach', inodes=[1])
        descriptors = self.root / '100/fd'
        (descriptors / '1').symlink_to('/dev/null')

        def late_listener():
            yield from itertools.repeat(SimpleNamespace(path=descriptors / '1'), 100500)
            yield SimpleNamespace(path=descriptors / '0')

        with (
            patch.object(identity.os, 'scandir', return_value=nullcontext(late_listener())),
            patch.object(identity.time, 'monotonic', new=lambda: 0),
        ):
            found, complete = identity.owned_tcp_listeners(descriptors, {'1': ('0.0.0.0', 8080)}, 1)
        self.assertTrue(complete)
        self.assertEqual(found, {'1': ('0.0.0.0', 8080)})

    def test_cockroach_listener_search_respects_deadline(self):
        self.process(100, 'cockroach', inodes=[1])
        with patch.object(identity.time, 'monotonic', return_value=1):
            found, complete = identity.owned_tcp_listeners(self.root / '100/fd', {'1': ('0.0.0.0', 8080)}, 1)
        self.assertFalse(complete)
        self.assertEqual(found, {})

    def test_master_ports_are_minimal_workers_connections_and_secrets_are_excluded(self):
        self.process(100,inodes=[10,11,12]);self.process(101,parent=100,inodes=[10,11]);self.process(200,inodes=[20],namespace='net:[2]')
        self.tcp(10,443);self.tcp(11,80);self.tcp(12,22,state='01');self.tcp(20,81)
        rows,complete=identity.service_runtime(str(self.root));self.assertTrue(complete);self.assertEqual(rows,[{'kind':'nginx','pid':100,'ports':[80,443],'sockets':[],'complete':True}]);self.assertNotIn('SECRET',json.dumps(rows))
    def test_unix_only_servers_preserve_pid_without_inventing_a_port(self):
        self.process(300,'postgres',inodes=[30]);(self.root/'net/unix').write_text('header\n0: 2 0 00010000 0001 01 30 /tmp/.s.PGSQL.5433\n')
        rows,complete=identity.service_runtime(str(self.root));self.assertTrue(complete);self.assertEqual(rows[0]['ports'],[]);self.assertEqual(rows[0]['pid'],300);self.assertEqual(rows[0]['sockets'],['/tmp/.s.PGSQL.5433'])
    def test_denied_descriptors_are_unknown_not_proof_of_no_port(self):
        self.process(100,inodes=[10]);self.tcp(10,80)
        original=os.scandir
        def scan(path):
            if str(path).endswith('/100/fd'):raise PermissionError()
            return original(path)
        with patch.object(identity.os,'scandir',side_effect=scan):rows,_=identity.service_runtime(str(self.root))
        self.assertFalse(rows[0]['complete']);self.assertEqual(rows[0]['ports'],[])
    def test_cardinality_and_fd_work_are_bounded(self):
        for pid in range(100,170):self.process(pid)
        rows,complete=identity.service_runtime(str(self.root));self.assertLessEqual(len(rows),64);self.assertFalse(complete)
    def test_unsupported_proc_is_explicit(self):self.assertEqual(identity.service_runtime('/nonexistent-cyberbot-proc'),([],False))

    def test_postgresql_rejects_pgbouncer_on_default_tcp_port_and_socket(self):
        self.process(300, 'pgbouncer', inodes=[30, 31])
        self.process(301, 'postgres', inodes=[32])
        (self.root / '301/exe').symlink_to('/usr/bin/pgbouncer')
        self.tcp(30, 5432)
        self.tcp(32, 5433)
        (self.root / 'net/unix').write_text('header\n0: 2 0 00010000 0001 01 31 /tmp/.s.PGSQL.5432\n')
        self.assertEqual(identity.service_runtime(str(self.root), kind_filter='postgresql', details=True), ([], True))

    def test_hidden_namespace_does_not_confirm_postgresql_absence(self):
        self.process(300, 'postgres')
        readlink = os.readlink
        hidden = str(self.root / '300/ns/net')
        with patch.object(identity.os, 'readlink', side_effect=lambda path: '' if path == hidden else readlink(path)):
            self.assertEqual(identity.service_runtime(str(self.root), kind_filter='postgresql', details=True), ([], False))

    @unittest.skipUnless(sys.platform=='linux','real Linux sockets and process metadata')
    def test_real_socket_ownership_and_lowest_port(self):
        script="""import ctypes,json,os,socket,sys
ctypes.CDLL(None).prctl(15,b'redis-server',0,0,0)
sockets=[socket.socket(),socket.socket()]
for s in sockets:s.bind(('127.0.0.1',0));s.listen(1)
print(json.dumps({'pid':os.getpid(),'ports':sorted(s.getsockname()[1] for s in sockets)}),flush=True)
sys.stdin.read()
"""
        workers=[]
        try:
            expected=[]
            for _ in range(2):
                worker=subprocess.Popen([sys.executable,'-c',script],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);workers.append(worker);expected.append(json.loads(worker.stdout.readline()))
            rows,complete=identity.service_runtime();self.assertTrue(complete)
            for server in expected:
                row=next(row for row in rows if row['pid']==server['pid']);self.assertEqual(row['ports'],server['ports']);self.assertEqual(row['kind'],'redis');self.assertTrue(row['complete'])
        finally:
            for worker in workers:worker.communicate(timeout=2)

if __name__=='__main__':unittest.main()

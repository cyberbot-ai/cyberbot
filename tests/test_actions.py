from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from collectors.bundle import source


def setUpModule():
    global actions
    folder = tempfile.TemporaryDirectory()
    unittest.addModuleCleanup(folder.cleanup)
    # The broker starts its worker by executing the same collector file.
    path = Path(folder.name) / 'collector.py'
    path.write_text(source(), encoding='utf-8')
    spec = spec_from_file_location('collector_test', path)
    actions = module_from_spec(spec)
    spec.loader.exec_module(actions)


class ActionContracts(unittest.TestCase):
    def test_manifest_is_closed_and_does_not_accept_paths_or_commands(self):
        for action in ({'kind':'diagnostic','command':'rm -rf /'}, {'kind':'nginx_workers','workerProcesses':'1; rm -rf /','activation':'reload'}, {'kind':'nginx_workers','workerProcesses':'999','activation':'none'}, {'kind':'nginx_workers','workerProcesses':'auto','activation':'reload','path':'/etc/shadow'}):
            with self.assertRaises(ValueError):
                actions.ACTION_HANDLERS[action['kind']].validate(action)

    def test_nginx_lexer_only_changes_top_level_scalar(self):
        handler=actions.NginxWorkersAction()
        source=b'# worker_processes 50;\nworker_processes 2;\nhttp { server { listen 80; set $x "worker_processes 8;"; } }\n'
        candidate,before=handler._replace(source,'auto')
        self.assertEqual(before,'2')
        self.assertEqual(candidate,source.replace(b'\nworker_processes 2;',b'\nworker_processes auto;'))
        for invalid in (b'worker_processes 1;worker_processes 2;',b'http {worker_processes 1;}',b'worker_processes "2";',b'worker_processes 2 #comment\nextra;', b'worker_processes 2; }'):
            with self.assertRaises(ValueError): handler._replace(invalid,'auto')

    def test_read_refuses_symlink_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'secret';p.write_text('secret');(Path(root)/'link').symlink_to(p)
            with self.assertRaises(OSError):actions._action_read(str(Path(root)/'link'))
            with self.assertRaises(ValueError):actions._action_read(str(p),3)


@unittest.skipUnless(sys.platform=='linux','real Linux seccomp only')
class LinuxActionIsolation(unittest.TestCase):
    def test_shell_returns_exit_and_bounded_streams_and_reuses_receipt(self):
        with tempfile.TemporaryDirectory() as home, patch.dict(os.environ, {'HOME': home}):
            action = {'kind': 'shell'}
            target = Path(home) / 'marker'
            request = {'operation': 'execute', 'requestId': str(uuid.uuid4()), 'artifactHash': 'b' * 64,
                       'action': action, 'prepared': actions.ShellAction().prepare(action), 'inputs': [],
                       'code': f"echo once >> '{target}'; printf error >&2; exit 3"}
            first = actions.action_main(request)
            self.assertEqual(first['state'], 'failed')
            self.assertEqual(first['result'], {'exitCode': 3, 'stdout': '', 'stderr': 'error', 'truncated': False})
            self.assertEqual(actions.action_main(request), first)
            self.assertEqual(target.read_text(), 'once\n')
            status, output = actions.run_action_shell("head -c 10000 /dev/zero", None)
            self.assertEqual(status, 'succeeded')
            self.assertTrue(output['truncated'])
            self.assertLessEqual(len(json.dumps(output['stdout'])), 4096)

    def test_shell_cancellation_leaves_unknown_receipt_and_does_not_retry(self):
        import threading
        read_fd, write_fd = os.pipe()
        timer = threading.Timer(0.3, os.close, (write_fd,))
        with tempfile.TemporaryDirectory() as home, patch.dict(os.environ, {'HOME': home}):
            action = {'kind': 'shell'}
            request = {'operation': 'execute', 'requestId': str(uuid.uuid4()), 'artifactHash': 'c' * 64,
                       'action': action, 'prepared': actions.ShellAction().prepare(action), 'inputs': [],
                       'code': 'echo started; sleep 12'}
            timer.start()
            try:
                first = actions.action_main(request, read_fd)
            finally:
                os.close(read_fd)
                timer.join()
            self.assertEqual(first['state'], 'unknown')
            self.assertEqual(first['result']['reason'], 'connection_closed')
            with patch.object(actions, 'run_action_shell', side_effect=AssertionError('must not execute')):
                self.assertEqual(actions.action_main(request), first)

    def test_probe_denies_host_files_network_exec_and_fork(self):
        self.assertTrue(actions.action_probe()['available'])

    def test_computation_has_prepared_inputs_and_loaded_standard_modules(self):
        result=actions.run_action_python("result={'median':statistics.median(inputs['values']), 'sum':sum(inputs['values'])}",{'values':[2,8,2]})
        self.assertEqual(result,{'median':2,'sum':12})

    def test_missing_and_invalid_code_is_not_executed_in_broker(self):
        for code in ('result = open("/etc/passwd").read()', 'while True:\n pass', 'result="x"*20000', 'import subprocess\nsubprocess.run(["/bin/sh"])'):
            with self.subTest(code=code[:30]),self.assertRaises((ValueError,OSError)):
                actions.run_action_python(code,{})

    def test_duplicate_delivery_is_idempotent_and_unknown_is_not_retried(self):
        with tempfile.TemporaryDirectory() as home, patch.dict(os.environ,{'HOME':home}):
            request={'operation':'execute','requestId':str(uuid.uuid4()),'artifactHash':'a'*64,'action':{'kind':'diagnostic'},'code':'result={"sum":sum(inputs["values"])}','inputs':{'values':[2,3]}}
            request['prepared']=actions.ACTION_HANDLERS['diagnostic'].prepare(request['action'])
            first=actions.action_main(request);self.assertEqual(first['state'],'succeeded')
            with patch.object(actions,'run_action_python',side_effect=AssertionError('must not execute')):
                self.assertEqual(actions.action_main(request),first)
            receipt=Path(home)/'.cache/cyberbot/actions'/request['requestId']/'receipt.json'
            value=json.loads(receipt.read_text());value['state']='running';receipt.write_text(json.dumps(value))
            with patch.object(actions,'run_action_python',side_effect=AssertionError('must not retry')):
                self.assertEqual(actions.action_main(request)['state'],'unknown')
            request['artifactHash']='b'*64
            with self.assertRaises(ValueError):actions.action_main(request)

    @unittest.skipUnless(os.geteuid()==0,'root-owned config fixture')
    def test_nginx_apply_rollback_hash_fence_and_changed_backup(self):
        with tempfile.TemporaryDirectory() as root:
            h=actions.NginxWorkersAction();h.config=root+'/nginx.conf';h.binary='/usr/bin/true'
            source=b'worker_processes 2;\nevents {worker_connections 16;}\n';Path(h.config).write_bytes(source)
            manifest={'kind':'nginx_workers','workerProcesses':'auto','activation':'none'}
            prepared=h.prepare(manifest)
            effect=h.apply(manifest,prepared,root);self.assertTrue(effect['verified']);self.assertIn(b'worker_processes auto;',Path(h.config).read_bytes())
            self.assertTrue(h.rollback(manifest,prepared,root)['verified']);self.assertEqual(Path(h.config).read_bytes(),source)
            Path(h.config).write_bytes(source.replace(b'2;',b'3;'))
            with self.assertRaises(ValueError):h.apply(manifest,prepared,root)

    @unittest.skipUnless(os.path.isfile('/usr/sbin/nginx') and os.geteuid()==0,'real Nginx fixture image')
    def test_real_nginx_validation_and_rollback(self):
        with tempfile.TemporaryDirectory() as root:
            h=actions.NginxWorkersAction();h.config=root+'/nginx.conf'
            source=f'worker_processes 1;\npid {root}/nginx.pid;\nerror_log {root}/error.log;\nevents {{ worker_connections 16; }}\nhttp {{ access_log off; }}\n'.encode();Path(h.config).write_bytes(source)
            manifest={'kind':'nginx_workers','workerProcesses':'2','activation':'none'}
            prepared=h.prepare(manifest);effect=h.apply(manifest,prepared,root)
            self.assertTrue(effect['verified']);self.assertTrue(h.rollback(manifest,prepared,root)['verified']);self.assertEqual(Path(h.config).read_bytes(),source)


if __name__=='__main__':unittest.main()

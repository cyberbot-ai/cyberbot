import json
import pathlib
import unittest
from unittest.mock import patch
from collectors.bundle import module

c = module()
META={'distro':'debian','release':'bookworm','version':'12','architecture':'x86_64','kernel':'6.1.0'}
def package(n):return {'name':f'package-{n:05}','arch':'amd64','version':'1:2.0-1+deb12u1','source':f'source-{n:05}','sourceVersion':'1:2.0-1+deb12u1','status':'installed'}
class PackagesTests(unittest.TestCase):
 def test_paginated_inventory_digest_and_unchanged(self):
  rows=[package(n) for n in range(5000)]
  with patch.object(c,'package_metadata',return_value=META),patch.object(c,'package_rows',return_value=rows):
   m=c.packages({});self.assertEqual(m['kind'],'manifest');self.assertLess(len(json.dumps(m)),32768)
   cursor={'root':m['root'],'buckets':list(range(128)),'offset':0};received=[];pages=0
   while cursor:
    page=c.packages({'state':cursor});self.assertLess(len(json.dumps(page,separators=(',',':')).encode()),32768);received.extend(r for g in page['groups'] for r in g['rows']);cursor={'root':m['root'],**page['next']} if page['next'] else None;pages+=1
   self.assertEqual(sorted(received,key=lambda r:r['name']),rows);self.assertGreater(pages,1)
   unchanged=c.packages({'state':{'root':m['root']}});self.assertEqual(unchanged['kind'],'unchanged');self.assertLess(len(json.dumps(unchanged)),512)
   rows[1]['version']='3.0';changed=c.packages({'state':{'root':m['root'],'buckets':[0]}});self.assertEqual(changed['kind'],'changed')
 def test_rejects_paths_commands_and_uninstalled_apt_targets(self):
  with patch.object(c,'package_metadata',return_value=META),patch.object(c,'package_rows',return_value=[package(1)]):
   m=c.packages({})
   for state in [{'command':'rm -rf /'},{'path':'/etc/shadow'},{'root':m['root'],'apt':[';whoami']},{'root':m['root'],'buckets':[128]}]:
    with self.assertRaises(ValueError):c.packages({'state':state})
 def test_only_changed_buckets_differ(self):
  rows=[package(n) for n in range(100)]
  with patch.object(c,'package_metadata',return_value=META),patch.object(c,'package_rows',return_value=rows):
   a=c.packages({});rows[10]['version']='2.1';b=c.packages({})
   self.assertEqual(sum(x!=y for x,y in zip(a['hashes'],b['hashes'])),1)

 def test_apt_read_failure_reports_safe_code(self):
  rows = [package(1)]
  with patch.object(c.subprocess, 'run', return_value=c.subprocess.CompletedProcess(
      ['apt-cache'], 100, b'', b'E: Unable to parse https://private.example/repo')):
   with self.assertRaisesRegex(c.PackageError, '^apt_read_failed$'):
    c.dpkg_candidates({'root':'snapshot','apt':['package-00001:amd64']}, {'root':'snapshot'}, rows)

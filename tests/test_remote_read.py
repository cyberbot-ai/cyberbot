import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from collectors.bundle import module

reader = module()


@unittest.skipUnless(sys.platform == 'linux', 'Linux descriptor-based file reader')
class RemoteReadTests(unittest.TestCase):
    def test_recursive_grep_skips_secrets_links_and_special_files(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(reader, 'READ_ROOTS', (directory,)):
            root = Path(directory)
            (root / 'job.sh').write_text('ffmpeg -version\n')
            (root / '.env').write_text('ffmpeg secret\n')
            (root / 'credentials.txt').write_text('ffmpeg secret\n')
            (root / 'link').symlink_to(root / '.env')
            os.link(root / '.env', root / 'hardlink')
            os.mkfifo(root / 'fifo')
            result = reader.remote_read({'operation': 'grep', 'path': directory, 'pattern': 'ffmpeg'})
            self.assertEqual(result['paths'], [f'{directory}/job.sh'])
            self.assertFalse(result['complete'])
            self.assertIn('excluded_paths', result['gaps'])
            for name in ('.env', 'credentials.txt', 'link', 'hardlink', 'fifo', '../etc/passwd'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    reader.remote_read({'operation': 'cat', 'path': f'{directory}/{name}'})

    def test_read_tools_bound_lines_and_reject_write_arguments(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(reader, 'READ_ROOTS', (directory,)):
            path = Path(directory) / 'data.txt'
            path.write_text('a 1\nb 2\nc 3\n')
            base = {'path': str(path)}
            sed = reader.remote_read({**base, 'operation': 'sed', 'startLine': 2, 'lineCount': 1})
            self.assertEqual(sed['lines'], [{'line': 2, 'text': 'b 2'}])
            self.assertEqual(sed['nextStartLine'], 3)
            awk = reader.remote_read({**base, 'operation': 'awk', 'fields': [2]})
            self.assertEqual([line['text'] for line in awk['lines']], ['1', '2', '3'])
            self.assertEqual(reader.remote_read({**base, 'operation': 'cat'})['lines'][0]['text'], 'a 1')
            self.assertEqual(reader.remote_read({'operation': 'ls', 'path': directory})['entries'][0]['name'], path.name)
            self.assertGreaterEqual(reader.remote_read({'operation': 'du', 'path': directory})['allocatedBytes'], path.stat().st_blocks * 512)
            with self.assertRaises(ValueError):
                reader.remote_read({**base, 'operation': 'awk', 'script': 'system("rm -f data.txt")'})
            self.assertEqual(path.read_text(), 'a 1\nb 2\nc 3\n')

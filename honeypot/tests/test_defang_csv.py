"""Defanging of exported CSV cells."""
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import defang_csv
from defang_csv import defang


class DefangTests(unittest.TestCase):
    def test_urls(self):
        self.assertEqual(defang('http://evil.example.com/x.sh'), 'hxxp://evil[.]example[.]com/x.sh')
        self.assertEqual(defang('get HTTPS://a.b/c now'), 'get hxxps://a[.]b/c now')
        self.assertEqual(defang('ftp://files.example.net/p'), 'fxp://files[.]example[.]net/p')
        self.assertEqual(defang('tftp://10.0.0.1/b'), 'txftp://10.0.0[.]1/b')

    def test_ips(self):
        self.assertEqual(defang('192.0.2.10'), '192.0.2[.]10')
        self.assertEqual(defang('http://198.51.100.7:8080/a'), 'hxxp://198.51.100[.]7:8080/a')
        self.assertEqual(defang('from 203.0.113.5 and 203.0.113.6'), 'from 203.0.113[.]5 and 203.0.113[.]6')

    def test_leaves_lookalikes_alone(self):
        for text in ('Mozilla/5.0 Chrome/86.0.4240.183 Safari/537.36',
                     '2026-10-08T06:49:47.827178', 'OpenSSH_8.2p1', '1.2.3',
                     '999.1.1.1', 'application/x-www-form-urlencoded', ''):
            self.assertEqual(defang(text), text)

    def test_formula_guard(self):
        self.assertEqual(defang('=HYPERLINK("http://x.y")'), '\'=HYPERLINK("hxxp://x[.]y")')
        self.assertEqual(defang('-cmd'), "'-cmd")

    def test_whole_csv(self):
        source = io.StringIO('ip,url\n192.0.2.1,"http://a.b/c, d"\n')
        out = io.StringIO()
        with patch.object(sys, 'argv', ['defang_csv.py']), \
             patch.object(sys, 'stdin', source), patch.object(sys, 'stdout', out):
            defang_csv.main()
        self.assertEqual(out.getvalue().splitlines(),
                         ['ip,url', '192.0.2[.]1,"hxxp://a[.]b/c, d"'])


if __name__ == '__main__':
    unittest.main()

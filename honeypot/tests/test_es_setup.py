"""es-setup.sh installs the samples template because the honeypot's writer
role cannot; its mappings must stay identical to core/sample_index.py."""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.sample_index import MAPPINGS, SAMPLE_INDEX


def heredoc(script: str, path: str) -> dict:
    match = re.search(rf"es PUT {re.escape(path)} <<'EOF'\n(.*?)\nEOF", script, re.S)
    return json.loads(match.group(1))


class EsSetupTests(unittest.TestCase):
    def setUp(self):
        self.script = (ROOT / 'es-setup.sh').read_text()

    def test_samples_template_matches_code(self):
        template = heredoc(self.script, '/_index_template/honeypot_samples_template')
        self.assertEqual(template['index_patterns'], [SAMPLE_INDEX])
        self.assertEqual(template['priority'], 500)
        self.assertEqual(template['template']['mappings'], MAPPINGS)

    def test_writer_cannot_manage_templates(self):
        role = heredoc(self.script, '/_security/role/honeypot_writer')
        self.assertEqual(role['cluster'], [])


if __name__ == '__main__':
    unittest.main()

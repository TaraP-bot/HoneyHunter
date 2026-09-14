"""Offline sample extraction, routing, deduplication and backfill checks."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.sample_index import SampleIndexer, sample_document, TEXT_BYTE_LIMIT
from core.honeypot_manager import TelemetryCollector
from backfill_samples import document_from_file, backfill


class Conflict(Exception):
    status_code = 409


class SampleTests(unittest.IsolatedAsyncioTestCase):
    def test_text_and_binary(self):
        data = b'<?php eval(base64_decode("test")); ?>'
        doc = sample_document(data, {'filename': 'shell.php'})
        self.assertEqual(doc['content_text'], data.decode())
        self.assertEqual(doc['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(doc['extraction_method'], 'utf8')
        self.assertFalse(doc['text_truncated'])
        doc = sample_document(b'\x00\xffhello\x00https://example.test\x01', {})
        self.assertEqual(doc['content_text'], 'hello\nhttps://example.test')
        self.assertEqual(doc['extraction_method'], 'ascii_strings')

    def test_utf8_boundary_and_limit(self):
        data = b'a' * (TEXT_BYTE_LIMIT - 1) + 'é'.encode() + b'end'
        doc = sample_document(data, {})
        self.assertEqual(doc['extraction_method'], 'utf8')
        self.assertTrue(doc['text_truncated'])
        self.assertEqual(doc['bytes_examined'], TEXT_BYTE_LIMIT)
        self.assertEqual(len(doc['content_text']), TEXT_BYTE_LIMIT - 1)

    async def test_separate_index_and_deduplication(self):
        client = AsyncMock()
        client.indices.exists.return_value = False
        indexer = SampleIndexer(client)
        doc = sample_document(b'php code', {})
        self.assertTrue(await indexer.index_document(doc))
        client.index.assert_awaited_once_with(index='honeypot-samples', id=doc['sha256'], document=doc, op_type='create')
        self.assertEqual(client.indices.put_index_template.call_args.kwargs['priority'], 500)
        self.assertEqual(client.indices.put_index_template.call_args.kwargs['index_patterns'], ['honeypot-samples'])
        client.index.side_effect = Conflict()
        self.assertFalse(await indexer.index_document(doc))
        self.assertEqual(client.indices.put_index_template.await_count, 1)

    async def test_failure_preserves_local_sample_and_disabled_es(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = TelemetryCollector(Path(directory))
            digest = await collector.save_sample(b'php code', '192.0.2.1', 'http_upload', {})
            self.assertEqual((collector.samples_dir / (digest + '.bin')).read_bytes(), b'php code')
            collector.es_enabled = True
            collector.sample_indexer = AsyncMock()
            collector.sample_indexer.index_document.side_effect = RuntimeError('offline')
            with self.assertLogs(level='ERROR'):
                second = await collector.save_sample(b'another sample', '192.0.2.1', 'http_upload', {})
            self.assertTrue((collector.samples_dir / (second + '.bin')).exists())
            self.assertTrue((collector.samples_dir / (second + '.json')).exists())

    async def test_backfill_and_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b'<?php echo "proof"; ?>'
            path = root / (hashlib.sha256(data).hexdigest() + '.bin')
            path.write_bytes(data)
            path.with_suffix('.json').write_text(json.dumps({'filename': 'proof.php'}))
            self.assertEqual(document_from_file(path)['filename'], 'proof.php')
            indexer = AsyncMock()
            indexer.index_document.return_value = True
            self.assertEqual(await backfill(root, indexer), {'indexed': 1, 'existing': 0, 'failed': 0})
            indexer.index_document.return_value = False
            self.assertEqual((await backfill(root, indexer))['existing'], 1)
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                document_from_file(path)
            with self.assertLogs(level='ERROR'):
                self.assertEqual((await backfill(root, indexer))['failed'], 1)

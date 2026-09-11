"""Offline upload regressions with in-memory streams and temporary storage."""
import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_stream_capture import Writer, Reader, Telemetry
from http_service import HTTPHoneypot
from honeypot_manager import TelemetryCollector
from http_capture import collect_request


class UploadTests(unittest.IsolatedAsyncioTestCase):
    async def capture(self, chunks):
        with tempfile.TemporaryDirectory() as directory:
            collector = TelemetryCollector(Path(directory))
            writer = Writer()
            await HTTPHoneypot(8080, collector).handle_client(Reader(chunks), writer)
            samples = {p.stem: p.read_bytes() for p in collector.samples_dir.glob('*.bin')}
            events = [json.loads(line) for line in collector.event_log.read_text().splitlines()]
        return samples, [e for e in events if e['event_type'] == 'http_artifact'], writer

    async def test_fragmented_large_raw_php(self):
        body = b'<?php /* ' + b'x' * 70000 + b' */ ?>\x00\xff\r\n'
        head = b'POST /shell.php HTTP/1.1\r\ncontent-type: application/x-php\r\ncontent-length: ' + str(len(body)).encode() + b'\r\n\r\n'
        samples, events, _ = await self.capture([head[:15], head[15:], body[:30000], body[30000:]])
        self.assertEqual(samples[hashlib.sha256(body).hexdigest()], body)
        self.assertTrue(any(e['decoded_payload']['artifact_kind'] == 'http_body' and e['decoded_payload']['capture_status'] == 'complete' for e in events))

    async def test_multipart_quoted_boundary_filenames_and_empty_files(self):
        php = b'<?php echo "test"; ?>\x00\xff\r\n'
        body = (b'--abc\r\ncontent-disposition: form-data; name="file"; filename="../../shell.php"\r\n\r\n' + php + b'\r\n--abc\r\nContent-Disposition: form-data; name="empty"; filename="empty.php"\r\n\r\n\r\n--abc--\r\n')
        head = b'POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary="abc"\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
        samples, events, _ = await self.capture([head, body])
        self.assertEqual(samples[hashlib.sha256(php).hexdigest()], php)
        parts = [e['decoded_payload'] for e in events if e['decoded_payload']['artifact_kind'] == 'multipart_part']
        self.assertEqual([p['filename'] for p in parts], ['../../shell.php', 'empty.php'])
        self.assertIn(hashlib.sha256(b'').hexdigest(), samples)

    async def test_form_php_fields(self):
        body = b'code=%3C%3Fphp+echo+1%3B%3F%3E&code=%FF%00'
        head = b'POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
        samples, events, _ = await self.capture([head + body])
        self.assertIn(b'<?php echo 1;?>', samples.values())
        self.assertIn(b'\xff\x00', samples.values())
        self.assertEqual(len([e for e in events if e['decoded_payload']['artifact_kind'] == 'form_field']), 2)

    async def test_chunked_put_and_continue(self):
        head = b'PUT /a.php HTTP/1.1\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n'
        samples, events, writer = await self.capture([head, b'3\r', b'\nabc\r\n', b'2;ext=yes\r\n\xff\x00\r\n0\r\nX-Trailer: yes\r\n\r\n'])
        self.assertIn(b'abc\xff\x00', samples.values())
        self.assertTrue(writer.data.startswith(b'HTTP/1.1 100 Continue\r\n\r\n'))
        self.assertTrue(all(e['decoded_payload']['capture_status'] == 'complete' for e in events))

    async def test_truncated_and_malformed_preserve_evidence(self):
        for headers, data, status in [
            (b'Content-Length: 10', b'abc', 'peer_eof'),
            (b'Transfer-Encoding: chunked', b'3\r\nabc!!', 'invalid_chunk_terminator'),
        ]:
            samples, events, _ = await self.capture([b'PATCH / HTTP/1.1\r\n' + headers + b'\r\n\r\n', data])
            self.assertTrue(any(data in sample for sample in samples.values()))
            self.assertTrue(all(e['decoded_payload']['capture_status'] == status for e in events))

    async def test_size_limit_and_timeout(self):
        with patch('http_capture.BODY_LIMIT', 3):
            _, body, _, status = await collect_request(b'POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde', Reader([]), Writer())
        self.assertEqual((body, status), (b'abc', 'body_limit'))
        class TimedOutReader:
            async def read(self, n):
                raise asyncio.TimeoutError()
        _, body, _, status = await collect_request(b'POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab', TimedOutReader(), Writer())
        self.assertEqual((body, status), (b'ab', 'timeout'))

    async def test_json_and_encoded_bodies_preserved(self):
        for content_type, body in [(b'application/json', b'{"script":"<?php echo 1;?>"}'), (b'application/octet-stream', b'\x1f\x8b\x00\xff')]:
            head = b'POST / HTTP/1.1\r\nContent-Type: ' + content_type + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
            samples, _, _ = await self.capture([head, body])
            self.assertIn(body, samples.values())

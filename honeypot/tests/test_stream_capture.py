"""Offline tests: no listeners, network connections, or external services."""
import asyncio
import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'core'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services'))
from honeypot_manager import StreamCapture, CapturedWriter
from http_service import HTTPHoneypot


class Telemetry:
    def __init__(self):
        self.events = []

    def generate_session_id(self, *args):
        return 'test-session'

    async def log_event(self, event):
        self.events.append(event.to_dict())


class Writer:
    def __init__(self, fail=False):
        self.data = bytearray()
        self.fail = fail
        self.closed = False

    def get_extra_info(self, key):
        return {'peername': ('192.0.2.2', 49804), 'sockname': ('192.0.2.1', 8080)}[key]

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        if self.fail:
            raise ConnectionResetError()

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class Reader:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    async def read(self, n=-1):
        return next(self.chunks, b'')


class CaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_binary_split_and_coalesced_frames(self):
        telemetry, writer = Telemetry(), Writer()
        service = HTTPHoneypot(8080, telemetry)
        raw = (23).to_bytes(4, 'big') + bytes(range(23)) + (83).to_bytes(4, 'big') + bytes(range(173, 256))
        await service.handle_client(Reader([raw[:2], raw[2:19], raw[19:]]), writer)
        events = [e for e in telemetry.events if e['event_type'] == 'tcp_data']
        self.assertEqual(b''.join(base64.b64decode(e['payload_base64']) for e in events), raw)
        self.assertEqual([e['stream_offset'] for e in events], [0, 2, 19])
        self.assertEqual(sum(e['payload_size'] for e in events), 114)
        self.assertTrue(all(e['source_port'] == 49804 and e['dest_port'] == 8080 for e in events))
        self.assertEqual(writer.data, b'')
        self.assertTrue(writer.closed)
        self.assertEqual(telemetry.events[-1]['decoded_payload']['reason'], 'peer_eof')

    async def test_http_response_bytes_and_ports(self):
        telemetry, writer = Telemetry(), Writer()
        await HTTPHoneypot(8080, telemetry).handle_client(Reader([b'G', b'ET / HTTP/1.1\r\nHost: test\r\n\r\n']), writer)
        response = [e for e in telemetry.events if e['direction'] == 'outbound']
        self.assertEqual(len(response), 1)
        self.assertEqual(base64.b64decode(response[0]['payload_base64']), bytes(writer.data))
        self.assertEqual((response[0]['source_port'], response[0]['dest_port']), (8080, 49804))
        self.assertEqual(response[0]['capture_status'], 'drained')
        self.assertTrue(writer.data.startswith(b'HTTP/'))

    async def test_failed_drain_preserves_bytes(self):
        telemetry = Telemetry()
        service = HTTPHoneypot(8080, telemetry)
        writer = Writer(fail=True)
        captured = CapturedWriter(writer, StreamCapture(service, writer, 'test-session'))
        captured.write(b'\x00\xff\x80')
        with self.assertRaises(ConnectionResetError):
            await captured.drain()
        self.assertEqual(telemetry.events[0]['capture_status'], 'drain_failed')
        self.assertEqual(base64.b64decode(telemetry.events[0]['payload_base64']), b'\x00\xff\x80')


if __name__ == '__main__':
    unittest.main()

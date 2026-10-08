"""DNS over TCP framing. Offline: no listeners or network connections."""
import asyncio
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'core'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services'))
from dns_service import DNSHoneypot


class Telemetry:
    def __init__(self):
        self.events = []

    def generate_session_id(self, *args):
        return 'test-session'

    async def log_event(self, event):
        self.events.append(event.to_dict())


class Writer:
    def __init__(self):
        self.data = bytearray()

    def get_extra_info(self, key):
        return {'peername': ('192.0.2.2', 49804), 'sockname': ('192.0.2.1', 5353)}[key]

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


def query(name: str, txid: int = 0x1234) -> bytes:
    """Standard recursive A query"""
    labels = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    return struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', 1, 1)


class DNSTCPTests(unittest.IsolatedAsyncioTestCase):
    async def run_client(self, payload: bytes):
        telemetry = Telemetry()
        reader = asyncio.StreamReader()
        reader.feed_data(payload)
        reader.feed_eof()
        writer = Writer()
        await DNSHoneypot(5353, telemetry).handle_client(reader, writer)
        queries = [e for e in telemetry.events if e['event_type'] == 'dns_query']
        return bytes(writer.data), queries

    async def test_length_prefixed_query_is_parsed_and_answered_framed(self):
        msg = query('example.com')
        reply, queries = await self.run_client(struct.pack('!H', len(msg)) + msg)
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0]['decoded_payload']['domain'], 'example.com')
        self.assertEqual(queries[0]['decoded_payload']['query_type'], 'A')
        self.assertEqual(queries[0]['decoded_payload']['transaction_id'], 0x1234)
        # Reply carries its own length prefix and echoes the transaction ID
        (length,) = struct.unpack('!H', reply[:2])
        self.assertEqual(length, len(reply) - 2)
        self.assertEqual(struct.unpack('!H', reply[2:4])[0], 0x1234)

    async def test_query_split_across_reads(self):
        msg = query('example.com')
        framed = struct.pack('!H', len(msg)) + msg
        telemetry = Telemetry()
        reader = asyncio.StreamReader()
        writer = Writer()
        task = asyncio.create_task(DNSHoneypot(5353, telemetry).handle_client(reader, writer))
        for i in range(0, len(framed), 5):
            reader.feed_data(framed[i:i + 5])
            await asyncio.sleep(0)
        reader.feed_eof()
        await task
        names = [e['decoded_payload']['domain'] for e in telemetry.events
                 if e['event_type'] == 'dns_query']
        self.assertEqual(names, ['example.com'])

    async def test_non_dns_probe_is_not_logged_as_a_query(self):
        # A TLS ClientHello sent to port 53: its first bytes read as a
        # length of 0x1603, and the probe ends long before that
        reply, queries = await self.run_client(b'\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03')
        self.assertEqual(queries, [])
        self.assertEqual(reply, b'')

    async def test_too_short_for_a_header(self):
        reply, queries = await self.run_client(struct.pack('!H', 4) + b'\x00' * 4)
        self.assertEqual(queries, [])
        self.assertEqual(reply, b'')


if __name__ == '__main__':
    unittest.main()

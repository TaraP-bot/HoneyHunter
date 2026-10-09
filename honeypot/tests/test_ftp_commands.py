"""FTP replies match vsftpd 3.0.3. Offline: no listeners or network connections."""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'core'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services'))
from ftp_service import FTPHoneypot


class Telemetry:
    def __init__(self):
        self.events = []

    def generate_session_id(self, *args):
        return 'test-session'

    async def log_event(self, event):
        self.events.append(event.to_dict())

    async def save_sample(self, *args):
        pass


class Writer:
    def __init__(self, peer='192.0.2.2'):
        self.data = bytearray()
        self.peer = peer

    def get_extra_info(self, key):
        return {'peername': (self.peer, 49804), 'sockname': ('192.0.2.1', 2121)}[key]

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


class FTPCommandTests(unittest.IsolatedAsyncioTestCase):
    async def session(self, *commands, service=None, peer='192.0.2.2'):
        """Run one client through the commands; returns its reply lines"""
        service = service or FTPHoneypot(2121, Telemetry())
        reader = asyncio.StreamReader()
        reader.feed_data(''.join(f'{c}\r\n' for c in commands).encode())
        reader.feed_eof()
        writer = Writer(peer)
        await service.handle_client(reader, writer)
        return bytes(writer.data).decode().split('\r\n')[:-1]

    async def test_shodan_style_probe(self):
        lines = await self.session('USER anonymous', 'PASS x@', 'FEAT', 'HELP')
        self.assertEqual(lines[:3], ['220 (vsFTPd 3.0.3)', '331 Please specify the password.',
                                     '230 Login successful.'])
        self.assertEqual(lines[3:12], ['211-Features:', ' EPRT', ' EPSV', ' MDTM', ' PASV',
                                       ' REST STREAM', ' SIZE', ' TVFS', '211 End'])
        self.assertEqual(lines[12], '214-The following commands are recognized.')
        self.assertEqual(lines[-1], '214 Help OK.')
        self.assertNotIn('500 Unknown command.', lines)

    async def test_before_login(self):
        lines = await self.session('SYST', 'PASS x', 'FEAT', 'OPTS UTF8 ON', 'LIST')
        self.assertEqual(lines[1], '530 Please login with USER and PASS.')
        self.assertEqual(lines[2], '503 Login with USER first.')
        self.assertEqual(lines[3], '211-Features:')
        self.assertEqual(lines[-2], '200 Always in UTF8 mode.')
        self.assertEqual(lines[-1], '530 Please login with USER and PASS.')

    async def test_common_commands_after_login(self):
        lines = await self.session('USER anonymous', 'PASS x', 'NOOP', 'CWD /', 'CWD /etc',
                                   'SIZE readme.txt', 'SIZE nope', 'MDTM readme.txt',
                                   'MKD x', 'TYPE I', 'STAT', 'BOGUS')
        self.assertEqual(lines[3:11], [
            '200 NOOP ok.', '250 Directory successfully changed.',
            '550 Failed to change directory.', '213 1024', '550 Could not get file size.',
            '213 20260101120000', '550 Permission denied.', '200 Switching to Binary mode.'])
        self.assertIn('     Connected to 192.0.2.2', lines)
        self.assertIn('     Logged in as ftp', lines)
        self.assertIn('     TYPE: BINARY', lines)
        self.assertEqual(lines[-1], '500 Unknown command.')

    async def test_pasv_advertises_public_ip(self):
        with patch.dict('os.environ', {'PUBLIC_IP': '203.0.113.9'}):
            service = FTPHoneypot(2121, Telemetry())
        lines = await self.session('USER anonymous', 'PASS x', 'PASV', service=service)
        self.assertTrue(lines[-1].startswith('227 Entering Passive Mode (203,0,113,9,'))

    async def test_quit_closes_the_session(self):
        lines = await self.session('QUIT', 'NOOP')
        self.assertEqual(lines[-1], '221 Goodbye.')

    async def test_login_state_is_per_connection(self):
        service = FTPHoneypot(2121, Telemetry())
        await self.session('USER admin', 'PASS admin', service=service)
        lines = await self.session('LIST', service=service, peer='198.51.100.3')
        self.assertEqual(lines[-1], '530 Please login with USER and PASS.')


if __name__ == '__main__':
    unittest.main()

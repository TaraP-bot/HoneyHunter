"""FTP replies match vsftpd 3.0.3. Data-connection tests use loopback only."""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'core'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services'))
import ftp_service
from ftp_service import FTPHoneypot, fake_content


class Telemetry:
    def __init__(self):
        self.events = []
        self.samples = []

    def generate_session_id(self, *args):
        return 'test-session'

    async def log_event(self, event):
        self.events.append(event.to_dict())

    async def save_sample(self, data, source_ip, protocol, metadata):
        self.samples.append((data, metadata))


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
        with patch.dict('os.environ', {'PUBLIC_IP': '203.0.113.9', 'FTP_PASV_PORTS': '0'}):
            service = FTPHoneypot(2121, Telemetry())
        lines = await self.session('USER anonymous', 'PASS x', 'PASV', service=service)
        self.assertTrue(lines[-1].startswith('227 Entering Passive Mode (203,0,113,9,'))

    async def test_transfer_needs_pasv_or_port(self):
        lines = await self.session('USER anonymous', 'PASS x', 'LIST')
        self.assertEqual(lines[-1], '425 Use PORT or PASV first.')

    async def test_active_mode_never_connects_out(self):
        lines = await self.session('USER anonymous', 'PASS x', 'PORT 198,51,100,7,4,1',
                                   'PORT 192,0,2,2,4,1', 'LIST', 'EPRT |1|198.51.100.7|1025|')
        self.assertEqual(lines[3:], ['500 Illegal PORT command.',
                                     '200 PORT command successful. Consider using PASV.',
                                     '425 Failed to establish connection.',
                                     '500 Illegal EPRT command.'])

    async def test_quit_closes_the_session(self):
        lines = await self.session('QUIT', 'NOOP')
        self.assertEqual(lines[-1], '221 Goodbye.')

    async def test_login_state_is_per_connection(self):
        service = FTPHoneypot(2121, Telemetry())
        await self.session('USER admin', 'PASS admin', service=service)
        lines = await self.session('LIST', service=service, peer='198.51.100.3')
        self.assertEqual(lines[-1], '530 Please login with USER and PASS.')


class FTPDataTests(unittest.IsolatedAsyncioTestCase):
    """A live session over loopback: control via fakes, data via real sockets"""

    async def asyncSetUp(self):
        with patch.dict('os.environ', {'PUBLIC_IP': '127.0.0.1', 'FTP_PASV_PORTS': '0'}):
            self.telemetry = Telemetry()
            self.service = FTPHoneypot(2121, self.telemetry)
        self.reader = asyncio.StreamReader()
        self.writer = Writer('127.0.0.1')
        self.task = asyncio.create_task(self.service.handle_client(self.reader, self.writer))
        await self.command('USER anonymous', '331')
        await self.command('PASS x', '230')

    async def asyncTearDown(self):
        self.reader.feed_eof()
        await self.task

    async def command(self, line, expect):
        """Send a command; return the first new reply line starting with expect"""
        seen = len(bytes(self.writer.data).decode().split('\r\n'))
        self.reader.feed_data(f'{line}\r\n'.encode())
        for _ in range(200):
            await asyncio.sleep(0.01)
            lines = bytes(self.writer.data).decode().split('\r\n')
            for reply in lines[seen - 1:]:
                if reply.startswith(expect):
                    return reply
        self.fail(f'no {expect} reply to {line}: {lines[seen - 1:]}')

    async def open_passive(self):
        reply = await self.command('EPSV', '229')
        port = int(reply.split('|||')[1].rstrip('|)'))
        return await asyncio.open_connection('127.0.0.1', port)

    async def test_list_over_data_connection(self):
        data_reader, data_writer = await self.open_passive()
        await self.command('LIST', '226 Directory send OK.')
        listing = (await data_reader.read()).decode()
        data_writer.close()
        self.assertIn('-rw-r--r--    1 0        0            1024 Jan 01  2026 readme.txt\r\n',
                      listing)
        control = bytes(self.writer.data).decode()
        self.assertIn('150 Here comes the directory listing.', control)
        self.assertNotIn('readme.txt', control)

    async def test_retr_sends_listed_size(self):
        data_reader, data_writer = await self.open_passive()
        await self.command('TYPE I', '200')
        await self.command('RETR readme.txt', '226 Transfer complete.')
        body = await data_reader.read()
        data_writer.close()
        self.assertEqual(body, fake_content('readme.txt'))
        self.assertIn('150 Opening BINARY mode data connection for readme.txt (1024 bytes).',
                      bytes(self.writer.data).decode())

    async def test_stor_captures_upload(self):
        data_reader, data_writer = await self.open_passive()
        self.reader.feed_data(b'STOR drop.sh\r\n')
        await asyncio.sleep(0.05)
        data_writer.write(b'#!/bin/sh\necho hi\n')
        await data_writer.drain()
        data_writer.close()
        await self.command('NOOP', '226 Transfer complete.')
        self.assertEqual(self.telemetry.samples[0][0], b'#!/bin/sh\necho hi\n')
        self.assertEqual(self.telemetry.samples[0][1]['filename'], 'drop.sh')

    async def test_data_connection_from_other_ip_is_refused(self):
        self.writer.peer = '192.0.2.2'  # control client; the loopback connect won't match
        self.task.cancel()
        self.reader = asyncio.StreamReader()
        self.task = asyncio.create_task(self.service.handle_client(self.reader, self.writer))
        await self.command('USER anonymous', '331')
        await self.command('PASS x', '230')
        with patch.object(ftp_service, 'DATA_TIMEOUT', 0.3):
            data_reader, data_writer = await self.open_passive()
            await self.command('LIST', '425 Failed to establish connection.')
        self.assertEqual(await data_reader.read(), b'')
        data_writer.close()


if __name__ == '__main__':
    unittest.main()

"""HTTPS serving, certificate reload and ACME challenges. TLS tests use loopback only."""
import asyncio
import os
import shutil
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_stream_capture import Writer, Reader, Telemetry
import http_service
from http_service import HTTPHoneypot


def request(path):
    return [f'GET {path} HTTP/1.1\r\nHost: test\r\n\r\n'.encode()]


class ACMETests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.webroot = Path(self.tmp.name)
        challenges = self.webroot / '.well-known' / 'acme-challenge'
        challenges.mkdir(parents=True)
        (challenges / 'tok-EN_123').write_text('tok-EN_123.thumbprint')
        (self.webroot / 'secret').write_text('not served')

    async def asyncTearDown(self):
        self.tmp.cleanup()

    async def get(self, path, webroot=True):
        writer = Writer()
        service = HTTPHoneypot(8080, Telemetry(), acme_webroot=self.webroot if webroot else None)
        await service.handle_client(Reader(request(path)), writer)
        return bytes(writer.data).decode()

    async def test_serves_challenge(self):
        reply = await self.get('/.well-known/acme-challenge/tok-EN_123')
        self.assertTrue(reply.startswith('HTTP/1.1 200 OK'))
        self.assertTrue(reply.endswith('\r\n\r\ntok-EN_123.thumbprint'))

    async def test_unknown_or_unsafe_tokens_are_404(self):
        for path in ('/.well-known/acme-challenge/missing',
                     '/.well-known/acme-challenge/../../secret',
                     '/.well-known/acme-challenge/'):
            self.assertTrue((await self.get(path)).startswith('HTTP/1.1 404'), path)

    async def test_no_webroot_means_normal_pages(self):
        reply = await self.get('/.well-known/acme-challenge/tok-EN_123', webroot=False)
        self.assertNotIn('thumbprint', reply)


@unittest.skipUnless(shutil.which('openssl'), 'needs openssl')
class TLSTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.cert, self.key = self.dir / 'fullchain.pem', self.dir / 'privkey.pem'
        self.telemetry = Telemetry()
        self.service = HTTPHoneypot(0, self.telemetry, ssl_cert=self.cert, ssl_key=self.key)
        self.poll = patch.object(http_service, 'CERT_POLL_SECONDS', 0.05)
        self.poll.start()

    async def asyncTearDown(self):
        await self.service.stop()
        self.poll.stop()
        self.tmp.cleanup()

    def make_cert(self, name, mtime=None):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                        'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
                        '-subj', f'/CN={name}', '-keyout', str(self.key), '-out', str(self.cert)],
                       check=True, capture_output=True)
        if mtime:
            for path in (self.cert, self.key):
                os.utime(path, (mtime, mtime))

    async def wait_for(self, condition):
        for _ in range(100):
            if condition():
                return
            await asyncio.sleep(0.02)
        self.fail('condition not met')

    async def fetch(self):
        """GET / over TLS; returns (peer certificate subject CN, response)"""
        port = self.service.server.sockets[0].getsockname()[1]
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection('127.0.0.1', port, ssl=context)
        writer.write(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
        response = await reader.read()
        der = writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
        writer.close()
        subject = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-subject'],
                                 input=der, capture_output=True, check=True).stdout.decode()
        return subject.strip(), response.decode()

    async def test_waits_for_certificate_then_serves(self):
        self.assertEqual(self.service.name, 'HTTPS')
        await self.service.start()
        await asyncio.sleep(0.1)
        self.assertIsNone(self.service.server)  # nothing listening without a certificate
        self.make_cert('first')
        await self.wait_for(lambda: self.service.server is not None)
        subject, response = await self.fetch()
        self.assertIn('first', subject)
        self.assertTrue(response.startswith('HTTP/1.1 200 OK'))
        self.assertIn('Server: Apache/2.4.41 (Ubuntu)', response)
        await self.wait_for(lambda: any(e['event_type'] == 'http_request' for e in self.telemetry.events))
        request = next(e for e in self.telemetry.events if e['event_type'] == 'http_request')
        self.assertEqual(request['service'], 'HTTPS')

    async def test_renewed_certificate_is_picked_up_without_restart(self):
        self.make_cert('first', mtime=1_000_000)
        await self.service.start()
        await self.wait_for(lambda: self.service.server is not None)
        server = self.service.server
        self.make_cert('renewed', mtime=2_000_000)
        await self.wait_for(lambda: self.service._cert_mtime == 2_000_000)
        subject, _ = await self.fetch()
        self.assertIn('renewed', subject)
        self.assertIs(self.service.server, server)


if __name__ == '__main__':
    unittest.main()

"""Device personas: fingerprint strings and HTTPHoneypot wiring."""
import unittest

from test_stream_capture import Writer, Reader, Telemetry
from http_service import HTTPHoneypot
from personas import get_persona, SONICWALL_SERVER


def request(path, method='GET'):
    return [f'{method} {path} HTTP/1.1\r\nHost: test\r\n\r\n'.encode()]


class PersonaUnitTests(unittest.TestCase):
    def test_sonicwall_fingerprint(self):
        persona = get_persona('sonicwall')
        self.assertEqual(persona.server, 'SonicWALL SSL-VPN Web Server')
        status, _, body, ctype = persona.respond('GET', '/cgi-bin/welcome')
        self.assertEqual(status, 200)
        self.assertIn('<title>Virtual Office</title>', body)
        self.assertIn('text/html', ctype)

    def test_persona_responds_to_any_path(self):
        persona = get_persona('sonicwall')
        for path in ('/', '/cgi-bin/welcome', '/sslvpnclient', '/random'):
            self.assertIsNotNone(persona.respond('GET', path), path)

    def test_unknown_persona_rejected(self):
        with self.assertRaises(ValueError):
            get_persona('nope')


class PersonaServiceTests(unittest.IsolatedAsyncioTestCase):
    async def get(self, path):
        writer = Writer()
        # No cert, so the handler runs in plain mode for the test; the persona
        # logic is independent of TLS.
        service = HTTPHoneypot(8444, Telemetry(), name='SONICWALL',
                               persona='sonicwall')
        await service.handle_client(Reader(request(path)), writer)
        return bytes(writer.data).decode()

    async def test_service_name_and_header(self):
        service = HTTPHoneypot(8444, Telemetry(), name='SONICWALL',
                               persona='sonicwall')
        self.assertEqual(service.name, 'SONICWALL')
        self.assertEqual(service.server_header, SONICWALL_SERVER)

    async def test_serves_portal_with_banner(self):
        reply = await self.get('/cgi-bin/welcome')
        self.assertTrue(reply.startswith('HTTP/1.1 200 OK'))
        self.assertIn(f'Server: {SONICWALL_SERVER}', reply)
        self.assertIn('<title>Virtual Office</title>', reply)

    async def test_portal_served_for_arbitrary_path(self):
        reply = await self.get('/cgi-bin/sslvpnclient?launchplatform=')
        self.assertIn('<title>Virtual Office</title>', reply)


if __name__ == '__main__':
    unittest.main()

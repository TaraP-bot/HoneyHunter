#!/usr/bin/env python3
"""
Device personas for HTTP/HTTPS listeners.

A persona makes a listener look like a specific network appliance to
fingerprinting scanners (Shodan, Censys, nuclei and the like): it sets the
Server header and serves a login portal page carrying the title and markup
those scanners match on. The point is to be *identified* as the device so the
honeypot records who comes looking and what they send next.

Scope is deliberately the public, unauthenticated front door only - the login
portal. Personas do not emulate authenticated sessions, device internals, or
any post-authentication or exploit behaviour; a scanner that tries those paths
just gets the portal back, and the attempt is logged by the capture framework
like any other request.
"""

from typing import Callable, Dict, NamedTuple, Optional, Tuple

# (status_code, status_text, body, content_type)
Response = Tuple[int, str, str, str]


class Persona(NamedTuple):
    server: str
    respond: Callable[[str, str], Optional[Response]]


# --- SonicWall SSL-VPN (Virtual Office portal) --------------------------------
# Fingerprint, per public detection templates (e.g. nuclei
# exposed-panels/sonicwall-sslvpn-panel): the Server header
# "SonicWALL SSL-VPN Web Server" and a page titled "Virtual Office", typically
# on TCP 4433. The HTML below is an original, minimal portal written to carry
# those strings; it is not copied from any appliance.

SONICWALL_SERVER = "SonicWALL SSL-VPN Web Server"

_SONICWALL_LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Virtual Office</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, Helvetica, sans-serif; background: #f0f0f0; }
        #login { width: 340px; margin: 80px auto; background: #fff;
                 border: 1px solid #c0c0c0; padding: 24px; }
        h2 { font-size: 16px; color: #333; margin: 0 0 16px; }
        input { width: 100%; box-sizing: border-box; margin: 6px 0; padding: 8px; }
        input[type=submit] { background: #d87022; color: #fff; border: none;
                             cursor: pointer; }
        .foot { color: #888; font-size: 11px; margin-top: 16px; text-align: center; }
    </style>
</head>
<body>
    <div id="login">
        <h2>SonicWall - Virtual Office</h2>
        <form action="/cgi-bin/userLogin" method="post">
            <input type="text" name="username" placeholder="Username" autofocus>
            <input type="password" name="password" placeholder="Password">
            <input type="text" name="domain" value="LocalDomain">
            <input type="submit" value="Log In">
        </form>
        <div class="foot">SonicWall Secure Remote Access</div>
    </div>
</body>
</html>"""


def _sonicwall_respond(method: str, path: str) -> Optional[Response]:
    """Serve the Virtual Office portal for any request, so the listener is
    consistently fingerprinted as the appliance regardless of the path probed."""
    return (200, "OK", _SONICWALL_LOGIN_HTML, "text/html; charset=UTF-8")


PERSONAS: Dict[str, Persona] = {
    "sonicwall": Persona(server=SONICWALL_SERVER, respond=_sonicwall_respond),
}


def get_persona(name: str) -> Persona:
    try:
        return PERSONAS[name]
    except KeyError:
        raise ValueError(f"Unknown persona: {name!r}; "
                         f"known: {', '.join(sorted(PERSONAS))}")

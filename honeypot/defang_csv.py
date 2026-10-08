#!/usr/bin/env python3
"""
Defang every cell of a CSV before it is shared.

URLs get a non-clickable scheme (hxxp://, hxxps://, fxp://) and [.] in
their host, IPv4 addresses become 1.2.3[.]4, and cells that a spreadsheet
would run as a formula are prefixed with a quote. Works on any CSV: the
samples CSV from analyze_telemetry.py or files downloaded from Kibana.

Usage:
    python3 defang_csv.py export.csv > export-defanged.csv
    ... --samples-csv | python3 defang_csv.py > samples-defanged.csv
"""

import csv
import re
import sys

SCHEMES = {'http': 'hxxp', 'https': 'hxxps', 'ftp': 'fxp', 'tftp': 'txftp'}
URL_RE = re.compile(r'\b(https?|ftp|tftp)://([^/\s:?#\'"]+)', re.I)
IPV4_RE = re.compile(r'\b((?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.'
                     r'(?:25[0-5]|2[0-4]\d|1?\d?\d))\.(25[0-5]|2[0-4]\d|1?\d?\d)\b')


def defang(text: str) -> str:
    def url(match):
        scheme = SCHEMES[match.group(1).lower()]
        host = match.group(2)
        if not IPV4_RE.fullmatch(host):  # IPs are handled below
            host = host.replace('.', '[.]')
        return f'{scheme}://{host}'

    text = URL_RE.sub(url, text)
    text = IPV4_RE.sub(r'\1[.]\2', text)
    if text[:1] in ('=', '+', '-', '@', '\t', '\r'):
        text = "'" + text
    return text


def main():
    source = open(sys.argv[1], newline='', encoding='utf-8-sig') if len(sys.argv) > 1 else sys.stdin
    writer = csv.writer(sys.stdout)
    for row in csv.reader(source):
        writer.writerow([defang(cell) for cell in row])


if __name__ == '__main__':
    main()

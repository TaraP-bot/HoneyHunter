#!/usr/bin/env python3
"""
Print one CSV of honeypot data from Elasticsearch, using the read-only
honeypot_analyst account. Runs on the droplet host; export.sh calls it and
defangs the output on your PC.

Usage (from /opt/honeypot, with .env loaded into the environment):
    python3 es_export.py logins|ips|dns [--hours 24]

    logins  one row per successful SSH/FTP login
    ips     one row per attacker IP with country, network and activity
    dns     one row per DNS query

The sensor's own IP (HONEYPOT_BIND_IP) is always excluded.
"""

import argparse
import base64
import csv
import json
import os
import sys
import urllib.request

ES = 'http://127.0.0.1:9200/honeypot-2*/_search'
NOISE = ['tcp_connection_closed', 'tcp_data']
# DNS over TCP was misparsed before this fix went live; older rows are junk
DNS_FIXED_AT = '2026-10-08T08:00:00'


def search(body: dict) -> dict:
    auth = base64.b64encode(
        f"honeypot_analyst:{os.environ['HONEYPOT_ANALYST_PASSWORD']}".encode()).decode()
    req = urllib.request.Request(ES, data=json.dumps(body).encode(), method='POST',
                                 headers={'Authorization': f'Basic {auth}',
                                          'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def field(source: dict, path: str):
    for key in path.split('.'):
        source = source.get(key) if isinstance(source, dict) else None
    return source


def base_filter(hours: int) -> dict:
    return {'filter': [{'range': {'timestamp': {'gte': f'now-{hours}h'}}}],
            'must_not': [{'term': {'source_ip.keyword': os.environ['HONEYPOT_BIND_IP']}}]}


def rows_export(query: dict, columns: list, out):
    """One row per event, oldest first"""
    result = search({'size': 10000, 'sort': [{'timestamp': 'asc'}],
                     'query': {'bool': query}})
    writer = csv.writer(out)
    writer.writerow([c.rsplit('.', 1)[-1] for c in columns])
    for hit in result['hits']['hits']:
        writer.writerow([field(hit['_source'], c) for c in columns])
    if result['hits']['total']['value'] > 10000:
        print('warning: more than 10000 rows; use a shorter --hours', file=sys.stderr)


def logins(hours: int, out):
    query = base_filter(hours)
    query['filter'] += [
        {'terms': {'event_type.keyword': ['ssh_login_attempt', 'ftp_login_attempt']}},
        {'term': {'decoded_payload.success': True}}]
    rows_export(query, ['timestamp', 'source_ip', 'source_geo.country_iso_code',
                        'source_geo.country_name', 'source_as.asn',
                        'source_as.organization_name', 'event_type',
                        'decoded_payload.username', 'decoded_payload.password'], out)


def dns(hours: int, out):
    query = base_filter(hours)
    query['filter'] += [{'term': {'event_type.keyword': 'dns_query'}},
                        {'range': {'timestamp': {'gte': DNS_FIXED_AT}}}]
    rows_export(query, ['timestamp', 'source_ip', 'source_geo.country_iso_code',
                        'source_as.organization_name', 'decoded_payload.domain',
                        'decoded_payload.query_type'], out)


def ips(hours: int, out):
    query = base_filter(hours)
    query['must_not'].append({'terms': {'event_type.keyword': NOISE}})

    def top(field_name):
        return {'terms': {'field': field_name, 'size': 1}}

    result = search({'size': 0, 'query': {'bool': query}, 'aggs': {'ip': {
        'terms': {'field': 'source_ip.keyword', 'size': 10000},
        'aggs': {'cc': top('source_geo.country_iso_code.keyword'),
                 'country': top('source_geo.country_name.keyword'),
                 'asn': top('source_as.asn'),
                 'org': top('source_as.organization_name.keyword'),
                 'svc': {'terms': {'field': 'service.keyword', 'size': 5}},
                 'logins': {'filter': {'term': {'decoded_payload.success': True}}},
                 'first': {'min': {'field': 'timestamp'}},
                 'last': {'max': {'field': 'timestamp'}}}}}})

    def first_key(bucket, name):
        return (bucket[name]['buckets'] or [{'key': ''}])[0]['key']

    writer = csv.writer(out)
    writer.writerow(['source_ip', 'country_iso_code', 'country', 'asn', 'network', 'events',
                     'services', 'successful_logins', 'first_seen', 'last_seen'])
    for b in result['aggregations']['ip']['buckets']:
        writer.writerow([b['key'], first_key(b, 'cc'), first_key(b, 'country'),
                         first_key(b, 'asn'), first_key(b, 'org'), b['doc_count'],
                         ' '.join(s['key'] for s in b['svc']['buckets']),
                         b['logins']['doc_count'],
                         b['first']['value_as_string'], b['last']['value_as_string']])


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('kind', choices=['logins', 'ips', 'dns'])
    parser.add_argument('--hours', type=int, default=24)
    args = parser.parse_args()
    {'logins': logins, 'ips': ips, 'dns': dns}[args.kind](args.hours, sys.stdout)


if __name__ == '__main__':
    main()

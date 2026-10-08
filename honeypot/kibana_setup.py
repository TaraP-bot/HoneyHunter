#!/usr/bin/env python3
"""
Create the honeypot data view, visualizations, saved search and dashboard in
Kibana. Objects have fixed IDs and are overwritten, so re-running updates
them in place.

Run on the droplet from /opt/honeypot, on the compose network (only the two
variables it needs are passed, by name, so no secret is on the command line):
    set -a; . ./.env; set +a
    docker run --rm --network honeypot_honeypot_net \\
      -e ELASTIC_PASSWORD -e HONEYPOT_BIND_IP \\
      -v "$PWD/kibana_setup.py:/app/kibana_setup.py:ro" \\
      --entrypoint python honeypot-honeypot kibana_setup.py

Environment:
    KIBANA_URL         default http://kibana:5601
    ELASTIC_PASSWORD   Kibana admin login (elastic)
    HONEYPOT_BIND_IP   the sensor's public IP, filtered out of the dashboard
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request

KIBANA = os.environ.get('KIBANA_URL', 'http://kibana:5601')
DATA_VIEW = 'honeypot-events'
INDEX_REF = 'kibanaSavedObjectMeta.searchSourceJSON.index'

# Connection bookkeeping that would drown out attacker activity
NOT_NOISE = 'NOT event_type.keyword : ("tcp_connection_closed" or "tcp_data")'


def search_source(query: str) -> dict:
    return {'searchSourceJSON': json.dumps({
        'query': {'query': query, 'language': 'kuery'},
        'filter': [],
        'indexRefName': INDEX_REF,
    })}


def count_agg():
    return {'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {}}


def terms_agg(agg_id, field, size, schema='bucket', label=None):
    params = {'field': field, 'size': size, 'order': 'desc', 'orderBy': '1',
              'otherBucket': False, 'missingBucket': False}
    if label:
        params['customLabel'] = label
    return {'id': agg_id, 'enabled': True, 'type': 'terms', 'schema': schema,
            'params': params}


def visualization(vis_id, title, vis_type, params, aggs, query):
    return {
        'type': 'visualization', 'id': vis_id,
        'attributes': {
            'title': title,
            'visState': json.dumps({'title': title, 'type': vis_type,
                                    'params': params, 'aggs': aggs}),
            'uiStateJSON': '{}', 'description': '', 'version': 1,
            'kibanaSavedObjectMeta': search_source(query),
        },
        'references': [{'name': INDEX_REF, 'type': 'index-pattern', 'id': DATA_VIEW}],
    }


TABLE = {'perPage': 15, 'showPartialRows': False, 'showMetricsAtAllLevels': False,
         'showTotal': False, 'totalFunc': 'sum', 'percentageCol': ''}

PIE = {'type': 'pie', 'addTooltip': True, 'legendDisplay': 'show',
       'legendPosition': 'right', 'isDonut': True, 'nestedLegend': False,
       'distinctColors': False, 'truncateLegend': True, 'maxLegendLines': 1,
       'labels': {'show': True, 'values': True, 'last_level': True,
                  'truncate': 100, 'position': 'default'}}

HISTOGRAM = {
    'type': 'histogram', 'grid': {'categoryLines': False},
    'categoryAxes': [{'id': 'CategoryAxis-1', 'type': 'category', 'position': 'bottom',
                      'show': True, 'scale': {'type': 'linear'},
                      'labels': {'show': True, 'filter': True, 'truncate': 100},
                      'title': {}}],
    'valueAxes': [{'id': 'ValueAxis-1', 'name': 'LeftAxis-1', 'type': 'value',
                   'position': 'left', 'show': True,
                   'scale': {'type': 'linear', 'mode': 'normal'},
                   'labels': {'show': True, 'rotate': 0, 'filter': False, 'truncate': 100},
                   'title': {'text': 'Events'}}],
    'seriesParams': [{'show': True, 'type': 'histogram', 'mode': 'stacked',
                      'data': {'label': 'Events', 'id': '1'}, 'valueAxis': 'ValueAxis-1',
                      'drawLinesBetweenPoints': True, 'lineWidth': 2, 'showCircles': True}],
    'addTooltip': True, 'addLegend': True, 'legendPosition': 'right', 'times': [],
    'addTimeMarker': False, 'labels': {'show': False},
    'thresholdLine': {'show': False, 'value': 10, 'width': 1, 'style': 'full',
                      'color': '#E7664C'},
}

METRIC = {'addTooltip': True, 'addLegend': False, 'type': 'metric',
          'metric': {'percentageMode': False, 'useRanges': False,
                     'colorSchema': 'Green to Red', 'metricColorMode': 'None',
                     'colorsRange': [{'from': 0, 'to': 10000}],
                     'labels': {'show': True}, 'invertColors': False,
                     'style': {'bgFill': '#000', 'bgColor': False, 'labelColor': False,
                               'subText': '', 'fontSize': 48}}}


def objects(sensor_ip: str) -> list:
    hist_aggs = [
        count_agg(),
        {'id': '2', 'enabled': True, 'type': 'date_histogram', 'schema': 'segment',
         'params': {'field': 'timestamp', 'interval': 'auto', 'min_doc_count': 1,
                    'extended_bounds': {}}},
        terms_agg('3', 'event_type.keyword', 10, schema='group'),
    ]
    login = 'event_type.keyword : "ssh_login_attempt"'
    visualizations = [
        visualization('hp-events-total', 'Honeypot: attacker events', 'metric',
                      METRIC, [count_agg()], NOT_NOISE),
        visualization('hp-unique-ips', 'Honeypot: unique attacker IPs', 'metric',
                      METRIC, [{'id': '1', 'enabled': True, 'type': 'cardinality',
                                'schema': 'metric',
                                'params': {'field': 'source_ip.keyword'}}], NOT_NOISE),
        visualization('hp-over-time', 'Honeypot: activity over time', 'histogram',
                      HISTOGRAM, hist_aggs, NOT_NOISE),
        visualization('hp-top-ips', 'Honeypot: top attacker IPs', 'table', TABLE,
                      [count_agg(),
                       terms_agg('2', 'source_ip.keyword', 25, label='Source IP'),
                       terms_agg('3', 'source_geo.country_iso_code.keyword', 1, label='Country'),
                       terms_agg('4', 'source_as.organization_name.keyword', 1, label='Network (ASN)')],
                      NOT_NOISE),
        visualization('hp-countries', 'Honeypot: countries', 'pie', PIE,
                      [count_agg(),
                       terms_agg('2', 'source_geo.country_name.keyword', 15, schema='segment')],
                      NOT_NOISE),
        visualization('hp-asns', 'Honeypot: networks (ASN)', 'table', TABLE,
                      [count_agg(),
                       terms_agg('2', 'source_as.organization_name.keyword', 20, label='Network'),
                       {'id': '3', 'enabled': True, 'type': 'cardinality', 'schema': 'metric',
                        'params': {'field': 'source_ip.keyword', 'customLabel': 'IPs'}}],
                      NOT_NOISE),
        visualization('hp-ssh-users', 'Honeypot: SSH usernames tried', 'table', TABLE,
                      [count_agg(),
                       terms_agg('2', 'decoded_payload.username.keyword', 20, label='Username')],
                      login),
        visualization('hp-ssh-passwords', 'Honeypot: SSH passwords tried', 'table', TABLE,
                      [count_agg(),
                       terms_agg('2', 'decoded_payload.password.keyword', 20, label='Password')],
                      login),
        visualization('hp-http-paths', 'Honeypot: HTTP paths requested', 'table', TABLE,
                      [count_agg(),
                       terms_agg('2', 'decoded_payload.path.keyword', 25, label='Path'),
                       terms_agg('3', 'decoded_payload.method.keyword', 3, label='Method')],
                      'event_type.keyword : "http_request"'),
        visualization('hp-dns-names', 'Honeypot: DNS names queried', 'table', TABLE,
                      [count_agg(),
                       terms_agg('2', 'decoded_payload.domain.keyword', 20, label='Name'),
                       terms_agg('3', 'decoded_payload.query_type.keyword', 3, label='Type')],
                      'event_type.keyword : "dns_query"'),
    ]

    notable_query = (
        'event_type.keyword : ("ssh_command" or "ssh_request" or "http_artifact" '
        'or "ftp_upload" or "ftp_download") '
        'or (event_type.keyword : ("ssh_login_attempt" or "ftp_login_attempt") '
        'and decoded_payload.success : true)'
    )
    notable = {
        'type': 'search', 'id': 'hp-notable',
        'attributes': {
            'title': 'Honeypot: notable events',
            'description': 'Successful logins, commands, rejected SSH requests '
                           '(exec/sftp/tunnels) and captured artifacts',
            'columns': ['event_type', 'source_ip', 'source_geo.country_iso_code',
                        'decoded_payload.username', 'decoded_payload.password',
                        'decoded_payload.command', 'decoded_payload.request',
                        'decoded_payload.value', 'decoded_payload.path'],
            'sort': [['timestamp', 'desc']],
            'kibanaSavedObjectMeta': search_source(notable_query),
        },
        'references': [{'name': INDEX_REF, 'type': 'index-pattern', 'id': DATA_VIEW}],
    }

    # Dashboard layout on Kibana's 48-column grid: (object, x, y, w, h)
    layout = [
        ('hp-events-total', 0, 0, 12, 8), ('hp-unique-ips', 12, 0, 12, 8),
        ('hp-countries', 24, 0, 24, 16),
        ('hp-over-time', 0, 8, 24, 16),
        ('hp-notable', 0, 24, 48, 18),
        ('hp-top-ips', 0, 42, 24, 20), ('hp-asns', 24, 42, 24, 20),
        ('hp-ssh-users', 0, 62, 16, 18), ('hp-ssh-passwords', 16, 62, 16, 18),
        ('hp-dns-names', 32, 62, 16, 18),
        ('hp-http-paths', 0, 80, 48, 18),
    ]
    panels, references = [], []
    for i, (obj_id, x, y, w, h) in enumerate(layout, 1):
        obj_type = 'search' if obj_id == 'hp-notable' else 'visualization'
        panels.append({'version': '8.11.0', 'type': obj_type,
                       'gridData': {'x': x, 'y': y, 'w': w, 'h': h, 'i': str(i)},
                       'panelIndex': str(i), 'embeddableConfig': {},
                       'panelRefName': f'panel_{i}'})
        references.append({'name': f'panel_{i}', 'type': obj_type, 'id': obj_id})

    filters = []
    if sensor_ip:
        # Tests run from the droplet itself; keep them out of the picture
        filter_ref = 'kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index'
        filters.append({
            'meta': {'alias': 'exclude the sensor itself', 'negate': True,
                     'disabled': False, 'type': 'phrase', 'key': 'source_ip.keyword',
                     'params': {'query': sensor_ip}, 'indexRefName': filter_ref},
            'query': {'match_phrase': {'source_ip.keyword': sensor_ip}},
            '$state': {'store': 'appState'},
        })
        references.append({'name': filter_ref, 'type': 'index-pattern', 'id': DATA_VIEW})

    dashboard = {
        'type': 'dashboard', 'id': 'hp-overview',
        'attributes': {
            'title': 'Honeypot overview',
            'description': 'Attacker activity with GeoIP/ASN enrichment',
            'panelsJSON': json.dumps(panels),
            'optionsJSON': json.dumps({'useMargins': True, 'hidePanelTitles': False}),
            'timeRestore': True, 'timeFrom': 'now-24h', 'timeTo': 'now',
            'refreshInterval': {'pause': False, 'value': 300000},
            'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps({
                'query': {'query': '', 'language': 'kuery'}, 'filter': filters})},
        },
        'references': references,
    }

    data_view = {
        'type': 'index-pattern', 'id': DATA_VIEW,
        'attributes': {'title': 'honeypot-2*', 'name': 'Honeypot events',
                       'timeFieldName': 'timestamp'},
    }
    return [data_view, *visualizations, notable, dashboard, *export_objects(sensor_ip)]


def export_objects(sensor_ip: str) -> list:
    """Views meant for exporting to CSV, outside the dashboard. They exclude
    the sensor itself in their own query so they are clean when opened
    directly."""
    exclude = f' and not source_ip.keyword : "{sensor_ip}"' if sensor_ip else ''

    logins_query = ('event_type.keyword : ("ssh_login_attempt" or "ftp_login_attempt") '
                    'and decoded_payload.success : true' + exclude)
    logins = {
        'type': 'search', 'id': 'hp-export-logins',
        'attributes': {
            'title': 'Honeypot export: successful logins',
            'description': 'One row per successful login. Discover > Share > '
                           'CSV Reports > Generate CSV',
            'columns': ['source_ip', 'source_geo.country_iso_code',
                        'source_geo.country_name', 'source_as.asn',
                        'source_as.organization_name', 'event_type',
                        'decoded_payload.username', 'decoded_payload.password'],
            'sort': [['timestamp', 'desc']],
            'kibanaSavedObjectMeta': search_source(logins_query),
        },
        'references': [{'name': INDEX_REF, 'type': 'index-pattern', 'id': DATA_VIEW}],
    }

    def metric(agg_id, agg_type, field, label):
        return {'id': agg_id, 'enabled': True, 'type': agg_type, 'schema': 'metric',
                'params': {'field': field, 'customLabel': label}}

    attacker_ips = visualization(
        'hp-export-ips', 'Honeypot export: unique attacker IPs', 'table',
        {**TABLE, 'perPage': 50},
        [count_agg(),
         metric('5', 'min', 'timestamp', 'First seen'),
         metric('6', 'max', 'timestamp', 'Last seen'),
         metric('7', 'cardinality', 'service.keyword', 'Services'),
         terms_agg('2', 'source_ip.keyword', 2000, label='Source IP'),
         terms_agg('3', 'source_geo.country_iso_code.keyword', 1, label='Country'),
         terms_agg('4', 'source_as.organization_name.keyword', 1, label='Network'),
         terms_agg('8', 'source_as.asn', 1, label='ASN')],
        NOT_NOISE + exclude)
    return [logins, attacker_ips]


def main():
    password = os.environ.get('ELASTIC_PASSWORD')
    if not password:
        sys.exit('ELASTIC_PASSWORD is not set')
    auth = base64.b64encode(f'elastic:{password}'.encode()).decode()
    body = json.dumps(objects(os.environ.get('HONEYPOT_BIND_IP', ''))).encode()
    req = urllib.request.Request(
        f'{KIBANA}/api/saved_objects/_bulk_create?overwrite=true', data=body,
        method='POST', headers={'Authorization': f'Basic {auth}',
                                'Content-Type': 'application/json', 'kbn-xsrf': 'true'})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.load(resp)
    except urllib.error.HTTPError as exc:
        sys.exit(f'Kibana returned HTTP {exc.code}: {exc.read()[:300]!r}')
    failed = [o for o in result['saved_objects'] if 'error' in o]
    for obj in result['saved_objects']:
        status = obj['error']['message'] if 'error' in obj else 'ok'
        print(f"  {obj['type']:14} {obj['id']:18} {status}")
    if failed:
        sys.exit(f'{len(failed)} object(s) failed')
    print('Dashboard: Analytics > Dashboards > "Honeypot overview"')


if __name__ == '__main__':
    main()

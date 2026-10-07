#!/bin/bash
# One-shot setup for Elasticsearch security, run by the es-setup service.
# Sets the kibana_system password and creates a least-privilege
# honeypot_writer user, so the attacker-facing honeypot container never
# holds the elastic superuser password. Also creates a read-only
# honeypot_analyst user for reports, and the GeoIP/ASN enrichment pipeline
# applied to every honeypot-* index. Safe to re-run.
#
# Passwords come from .env via docker-compose. They are passed to curl
# through files, not arguments, so they never show up in `ps`.
set -euo pipefail

ES=http://elasticsearch:9200
umask 077
printf 'user = "elastic:%s"\n' "$ELASTIC_PASSWORD" > /tmp/es-auth

es() {
    curl -sS -f -K /tmp/es-auth -H 'Content-Type: application/json' \
        -X "$1" "$ES$2" --data-binary @- -o /dev/null
}

echo "Waiting for Elasticsearch..."
until curl -s -f -K /tmp/es-auth -o /dev/null \
        "$ES/_cluster/health?wait_for_status=yellow&timeout=5s"; do
    sleep 5
done

echo "Setting kibana_system password"
es POST /_security/user/kibana_system/_password <<EOF
{"password": "$KIBANA_SYSTEM_PASSWORD"}
EOF

echo "Creating honeypot_writer role"
# Only what core/honeypot_manager.py and core/sample_index.py call:
# put_index_template, indices.exists/create/put_mapping, and index with
# auto or create-only IDs. No read, update, or delete of collected data.
es PUT /_security/role/honeypot_writer <<'EOF'
{
  "cluster": ["manage_index_templates"],
  "indices": [{
    "names": ["honeypot-*"],
    "privileges": ["create_index", "create_doc", "view_index_metadata",
                   "indices:admin/mapping/put"]
  }]
}
EOF

echo "Creating honeypot_writer user"
es PUT /_security/user/honeypot_writer <<EOF
{"password": "$HONEYPOT_ES_PASSWORD", "roles": ["honeypot_writer"]}
EOF

echo "Creating honeypot_analyst role and user"
# Read-only access for reports and dashboards
es PUT /_security/role/honeypot_analyst <<'EOF'
{"indices": [{"names": ["honeypot-*"],
              "privileges": ["read", "view_index_metadata"]}]}
EOF
es PUT /_security/user/honeypot_analyst <<EOF
{"password": "$HONEYPOT_ANALYST_PASSWORD", "roles": ["honeypot_analyst"]}
EOF

echo "Creating honeypot-enrich ingest pipeline"
# Adds country/city/location and ASN for the attacker address. ES downloads
# the GeoLite2 databases itself once a geoip processor exists.
es PUT /_ingest/pipeline/honeypot-enrich <<'EOF'
{"description": "GeoIP and ASN enrichment of the attacker address",
 "processors": [
  {"geoip": {"field": "source_ip", "target_field": "source_geo",
             "ignore_missing": true, "ignore_failure": true}},
  {"geoip": {"field": "source_ip", "target_field": "source_as",
             "database_file": "GeoLite2-ASN.mmdb",
             "ignore_missing": true, "ignore_failure": true}}
 ]}
EOF

# Single node: replicas can never be assigned and leave the cluster yellow.
# Every honeypot-* index also gets the enrichment pipeline and a geo_point
# location for maps. This overwrites the template of the same name from
# setup_elasticsearch.py; rerun that afterwards only if you need its mappings
# and then re-add these settings.
echo "Installing honeypot_template"
es PUT /_index_template/honeypot_template <<'EOF'
{"index_patterns": ["honeypot-*"],
 "template": {
  "settings": {"number_of_shards": 1, "number_of_replicas": 0,
               "index.default_pipeline": "honeypot-enrich"},
  "mappings": {"properties": {
    "source_geo": {"properties": {"location": {"type": "geo_point"}}}}}}}
EOF

# Bring indices created before this template into line
es PUT "/honeypot-*/_settings?allow_no_indices=true&ignore_unavailable=true" <<'EOF'
{"index": {"number_of_replicas": 0}}
EOF
es PUT "/honeypot-2*/_settings?allow_no_indices=true&ignore_unavailable=true" <<'EOF'
{"index": {"default_pipeline": "honeypot-enrich"}}
EOF
es PUT "/honeypot-2*/_mapping?allow_no_indices=true&ignore_unavailable=true" <<'EOF'
{"properties": {"source_geo": {"properties": {"location": {"type": "geo_point"}}}}}
EOF

rm -f /tmp/es-auth
echo "Elasticsearch security setup complete"

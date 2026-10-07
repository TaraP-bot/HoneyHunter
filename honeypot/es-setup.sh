#!/bin/bash
# One-shot setup for Elasticsearch security, run by the es-setup service.
# Sets the kibana_system password and creates a least-privilege
# honeypot_writer user, so the attacker-facing honeypot container never
# holds the elastic superuser password. Safe to re-run.
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

rm -f /tmp/es-auth
echo "Elasticsearch security setup complete"

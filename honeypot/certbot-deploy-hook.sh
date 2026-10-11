#!/usr/bin/env bash
# Certbot deploy hook: copy a newly issued or renewed certificate to where
# the honeypot's HTTPS service reads it. Install on the droplet as
#   /etc/letsencrypt/renewal-hooks/deploy/honeypot.sh
# The service checks for new files every minute, so no restart is needed.
set -euo pipefail

DEST=/opt/honeypot/certs
install -d -o 1000 -g 1000 -m 700 "$DEST"

# Copy under temporary names, then rename, so the service never reads a
# partly written file. The private key is readable by the container's user only.
install -o 1000 -g 1000 -m 644 "$RENEWED_LINEAGE/fullchain.pem" "$DEST/.fullchain.pem"
install -o 1000 -g 1000 -m 600 "$RENEWED_LINEAGE/privkey.pem" "$DEST/.privkey.pem"
mv "$DEST/.privkey.pem" "$DEST/privkey.pem"
mv "$DEST/.fullchain.pem" "$DEST/fullchain.pem"

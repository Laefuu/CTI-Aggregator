#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Generate a self-signed TLS certificate for local development
# Usage: ./gen-dev-cert.sh [hostname]
# Default hostname: localhost
# ─────────────────────────────────────────────────────────────
set -euo pipefail

HOSTNAME="${1:-localhost}"
CERTS_DIR="$(dirname "$0")/certs"
mkdir -p "$CERTS_DIR"

echo "Generating self-signed cert for: $HOSTNAME"

openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout "$CERTS_DIR/cti.key" \
  -out    "$CERTS_DIR/cti.crt" \
  -subj   "/CN=$HOSTNAME/O=CTI Aggregator Dev/C=FR" \
  -addext "subjectAltName=DNS:$HOSTNAME,DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERTS_DIR/cti.key"
echo "Done: $CERTS_DIR/cti.crt + cti.key"
echo "Add cti.crt to your browser's trusted certificates for a clean HTTPS experience."

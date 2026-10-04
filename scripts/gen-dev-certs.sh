#!/usr/bin/env bash
# Generate self-signed PEMs for local/dev hub TLS into ./certs.
# Not for production. Point hub tls_cert_file / tls_key_file at these paths
# (Compose: mount ./certs → /etc/svc-peer/tls and enable the commented knobs).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${CERT_DIR:-${ROOT}/certs}"
DAYS="${DAYS:-365}"

mkdir -p "${CERT_DIR}"

CONF="$(mktemp)"
trap 'rm -f "${CONF}"' EXIT

cat >"${CONF}" <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = hub
IP.1 = 127.0.0.1
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${CERT_DIR}/key.pem" \
  -out "${CERT_DIR}/cert.pem" \
  -days "${DAYS}" \
  -config "${CONF}"

chmod 600 "${CERT_DIR}/key.pem" "${CERT_DIR}/cert.pem"
echo "Wrote ${CERT_DIR}/cert.pem and ${CERT_DIR}/key.pem (SAN: localhost, hub, 127.0.0.1)"

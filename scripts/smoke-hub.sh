#!/usr/bin/env bash
# Curl hub GET /health. Default: plain HTTP on compose/local hub.
# Agent local APIs (/local/health on :9100/:9101) need:
#   docker compose --profile agents up -d
# and are not checked here.
set -euo pipefail

HUB_URL="${HUB_URL:-http://127.0.0.1:8080}"
CURL_OPTS=(-fsS)

case "${HUB_URL}" in
https://*|HTTPS://*)
  # Dev self-signed PEMs from `make certs` are not in system trust.
  CURL_OPTS+=(-k)
  ;;
esac

echo "GET ${HUB_URL}/health"
curl "${CURL_OPTS[@]}" "${HUB_URL}/health"
echo

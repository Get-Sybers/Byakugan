#!/usr/bin/env bash
# Byakugan STANDALONE Elastic bootstrap — runs once per `docker compose up`
# from the Elasticsearch image (the compose `setup` service). Modelled on
# DX_DFIR's own docker/elastic/config/setup.sh, minus the certificate dance:
# this stack runs HTTP TLS off (see docker-compose.yml's header comment), so
# there is nothing to generate here.
#   1. refuse to run with the .env.example placeholders still in place;
#   2. wait for Elasticsearch to answer (security enforcing auth);
#   3. set the kibana_system password (idempotent).
# Kibana waits for this script to complete successfully.
set -euo pipefail

ES_URL=http://elasticsearch:9200

: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD must be set (elastic/.env)}"
: "${KIBANA_SYSTEM_PASSWORD:?KIBANA_SYSTEM_PASSWORD must be set (elastic/.env)}"
for v in ELASTIC_PASSWORD KIBANA_SYSTEM_PASSWORD; do
  case "${!v}" in
    *change-me*)
      echo "setup | ${v} still holds the .env.example placeholder — set a real value in elastic/.env" >&2
      exit 1 ;;
  esac
done

echo "setup | waiting for Elasticsearch at ${ES_URL}"
until curl -s "${ES_URL}" | grep -q "missing authentication credentials"; do
  sleep 5
done

echo "setup | setting the kibana_system password"
until curl -s -X POST \
      -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
      "${ES_URL}/_security/user/kibana_system/_password" \
      -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}" | grep -q "^{}"; do
  sleep 5
done

echo "setup | done"

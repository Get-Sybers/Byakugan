#!/usr/bin/env bash
# Byakugan STANDALONE Elastic bootstrap — runs once per `docker compose up`
# from the Elasticsearch image (the compose `setup` service). Modelled on
# DX_DFIR's own docker/elastic/config/setup.sh, minus the certificate dance:
# this stack runs HTTP TLS off (see docker-compose.yml's header comment), so
# there is nothing to generate here.
#   1. refuse to run with the .env.example placeholders still in place;
#   2. wait for Elasticsearch to answer (security enforcing auth);
#   3. set the kibana_system password (idempotent);
#   4. create the logs_car_writer role + byakugan_loader user (idempotent) —
#      parity with DX_DFIR's own docker/elastic/config/setup.sh: the same
#      least-privilege loader identity, minus --cacert (this stack is plain
#      HTTP — see the header comment above).
# Kibana waits for this script to complete successfully.
set -euo pipefail

ES_URL=http://elasticsearch:9200

: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD must be set (elastic/.env)}"
: "${KIBANA_SYSTEM_PASSWORD:?KIBANA_SYSTEM_PASSWORD must be set (elastic/.env)}"
: "${BYAKUGAN_LOADER_PASSWORD:?BYAKUGAN_LOADER_PASSWORD must be set (elastic/.env)}"
for v in ELASTIC_PASSWORD KIBANA_SYSTEM_PASSWORD BYAKUGAN_LOADER_PASSWORD; do
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

# The CAR loader's identity: least-privilege by construction, not by
# discipline. logs_car_writer can only create_doc/create_index/read/
# view_index_metadata on logs-car.* — no cluster privileges, so it cannot
# alter or drop what it writes (evidence immutability at the credential
# layer) and cannot manage index/component templates or Kibana either;
# `byakugan load --setup` authenticates as elastic for that (see
# elastic/README.md). byakugan_loader is every ROUTINE (non --setup) load's
# identity thereafter. Both calls are idempotent: a PUT role always replaces
# the definition in place, and re-creating an existing user updates it (same
# password, same role) rather than failing.
echo "setup | creating the logs_car_writer role (least-privilege CAR loader)"
until curl -s -X PUT \
      -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
      "${ES_URL}/_security/role/logs_car_writer" \
      -d '{"indices":[{"names":["logs-car.*"],"privileges":["create_doc","create_index","read","view_index_metadata"]}]}' \
      | grep -q '"role"'; do
  sleep 5
done

echo "setup | creating the byakugan_loader user"
until curl -s -X PUT \
      -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
      "${ES_URL}/_security/user/byakugan_loader" \
      -d "{\"password\":\"${BYAKUGAN_LOADER_PASSWORD}\",\"roles\":[\"logs_car_writer\"],\"full_name\":\"byakugan load (CAR to logs-car.*)\"}" \
      | grep -q '"created"'; do
  sleep 5
done

echo "setup | done"

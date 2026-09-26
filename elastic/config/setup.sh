#!/usr/bin/env bash
# The standalone stack's one-shot bootstrap (the compose `setup` service):
# refuse placeholders, wait for ES, set the kibana_system password, create
# the least-privilege loader identity — DX_DFIR parity minus the certificate
# dance (this stack is plain HTTP). Kibana waits on it.
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

_curl_grep() {
  # _curl_grep PATTERN CURL_ARGS... — runs curl, stores the response in
  # CURL_LAST_RESPONSE (exported for _retry's diagnostic), then greps it.
  # Returns grep's exit code so _retry treats a non-match as failure.
  local pattern=$1; shift
  CURL_LAST_RESPONSE=$(curl -s "$@" 2>&1)
  echo "${CURL_LAST_RESPONSE}" | grep -q "${pattern}"
}

_retry() {
  # _retry MAX_ATTEMPTS SLEEP_SECONDS DESCRIPTION -- COMMAND [ARGS...]
  # Runs COMMAND up to MAX_ATTEMPTS times, sleeping SLEEP_SECONDS between tries.
  # Succeeds as soon as COMMAND exits 0; on exhaustion prints the last response
  # to stderr and exits 1.
  local max=$1 delay=$2 desc=$3; shift 3
  # consume the '--' separator if present
  [ "${1-}" = "--" ] && shift
  local attempt=1
  while [ "$attempt" -le "$max" ]; do
    CURL_LAST_RESPONSE=
    "$@" && return 0
    if [ -n "${CURL_LAST_RESPONSE-}" ]; then
      echo "setup | ${desc}: last response: ${CURL_LAST_RESPONSE}" >&2
    fi
    if [ "$attempt" -lt "$max" ]; then
      echo "setup | ${desc}: attempt ${attempt}/${max} failed, retrying in ${delay}s" >&2
      sleep "$delay"
    fi
    attempt=$(( attempt + 1 ))
  done
  echo "setup | ${desc}: gave up after ${max} attempts" >&2
  exit 1
}

echo "setup | waiting for Elasticsearch at ${ES_URL}"
_retry 60 5 "wait for Elasticsearch" -- \
  _curl_grep "missing authentication credentials" "${ES_URL}"

echo "setup | setting the kibana_system password"
_retry 30 5 "set kibana_system password" -- \
  _curl_grep "^{}" -X POST \
    -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
    "${ES_URL}/_security/user/kibana_system/_password" \
    -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}"

# least-privilege loader: create_doc/create_index/read/view_index_metadata
# on logs-car.* only (evidence immutability at the credential layer);
# --setup runs authenticate as elastic instead. Both calls are idempotent: a PUT role always replaces
# the definition in place, and re-creating an existing user updates it (same
# password, same role) rather than failing.
echo "setup | creating the logs_car_writer role (least-privilege CAR loader)"
_retry 30 5 "create logs_car_writer role" -- \
  _curl_grep '"role"' -X PUT \
    -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
    "${ES_URL}/_security/role/logs_car_writer" \
    -d '{"indices":[{"names":["logs-car.*"],"privileges":["create_doc","create_index","read","view_index_metadata"]}]}'

echo "setup | creating the byakugan_loader user"
_retry 30 5 "create byakugan_loader user" -- \
  _curl_grep '"created":\(true\|false\)' -X PUT \
    -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
    "${ES_URL}/_security/user/byakugan_loader" \
    -d "{\"password\":\"${BYAKUGAN_LOADER_PASSWORD}\",\"roles\":[\"logs_car_writer\"],\"full_name\":\"byakugan load (CAR to logs-car.*)\"}"

echo "setup | done"

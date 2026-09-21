# Byakugan standalone Elastic stack

Byakugan's **own** Elasticsearch + Kibana — consumption mode 1 of the three
Byakugan supports as an individual component (see the top-level
[README.md](../README.md) "Three ways to run it"): point the engine at
processor output, stand this stack up, and `byakugan load` gives you a
queryable, timestamp-ordered `logs-car.*` tier with nothing else to deploy.

This is a **lab stack**: single node, security **on** (Basic licence), HTTP
TLS **off**, every port bound to `127.0.0.1`. It is not the DX_DFIR
repository's own `docker/elastic/` stack — see "Relationship to DX_DFIR's
stack" below.

## Bring it up

```sh
cd elastic
cp .env.example .env             # then replace every change-me value: the three passwords,
                                 # and the three Kibana encryption keys (`openssl rand -hex 32` each —
                                 # Kibana 9.x refuses to finish Fleet setup without them)
sudo sysctl -w vm.max_map_count=262144
docker compose up -d
docker compose ps                # setup exits 0; elasticsearch/kibana go (healthy)
```

- Elasticsearch -> `http://127.0.0.1:9201` (`elastic` / `ELASTIC_PASSWORD`)
- Kibana -> `http://127.0.0.1:5602` (log in as `elastic`)

`config/setup.sh` refuses to run while `ELASTIC_PASSWORD` / `KIBANA_SYSTEM_PASSWORD`
/ `BYAKUGAN_LOADER_PASSWORD` still hold the `.env.example` placeholders.
`.env` is gitignored — **never commit real secrets**.

## Load a materialised CAR tree — one command

Point `byakugan build` (or the container's `build` sub-tool) at your processor
output first, the way you always would; that gives you a car tree
(`car_<object>.jsonl` + `car_relationships.jsonl` per source — see the
top-level README's "Quickstart"). Then wire it straight into this stack:

```sh
set -a; source .env; set +a       # so $ELASTIC_PASSWORD below is the one you just set
python -m byakugan.elastic.load <car-tree> \
    --es-url http://127.0.0.1:9201 \
    --es-user elastic --es-password "$ELASTIC_PASSWORD" \
    --setup --kibana-url http://127.0.0.1:5602 \
    --namespace <case>
```

(Flags are `byakugan.elastic.load`'s own — `--es-url`, `--es-user`/`--es-password`
[or `--es-password-file`, or `--es-api-key`], `--es-ca-file` (not needed here:
no HTTP TLS), `--setup`, `--kibana-url`, `--namespace`; see
`byakugan/elastic/load.py`'s module docstring or
`python -m byakugan.elastic.load --help`. The container form is
`BYAKUGAN_LOAD_ES_URL=http://127.0.0.1:9201 BYAKUGAN_LOAD_ES_USER=elastic
BYAKUGAN_LOAD_ES_PASSWORD=... BYAKUGAN_LOAD_SETUP=1
BYAKUGAN_LOAD_KIBANA_URL=http://127.0.0.1:5602 BYAKUGAN_LOAD_NAMESPACE=<case>
byakugan load` — see `byakugan/cli.py`'s module docstring.)

This one command:

1. projects every `car_<object>.jsonl` / `car_relationships.jsonl` /
   `car_inferred.jsonl` under `<car-tree>` through the CAR->ECS contract
   (`elastic/projection/`) into `_bulk` NDJSON and POSTs it to
   `logs-car.<object>-<case>` / `logs-car.rel-<case>` / `logs-car.inferred-<case>`
   data streams, verifying per-stream document counts;
2. `--setup` PUTs the contract's rendered component templates then index
   templates (`elastic/projection/rendered/{component_templates,index_templates}/*.json`)
   first — skipping any already applied unchanged, so re-running `--setup` is
   safe;
3. `--kibana-url` additionally imports `elastic/projection/rendered/kibana/logs-car-views.ndjson`:
   a `logs-car.*` data view, a `car-timeline` saved search, a
   `car-timeline-histogram` Lens visualisation and a `car-timeline-dashboard`
   dashboard — open Kibana at `http://127.0.0.1:5602` and go to that
   dashboard once the load finishes.

### Two identities: the first load vs. every load after that

Like DX_DFIR's own integrated stack, this one has two loader identities.
**The first load** (above) authenticates as `elastic`: `--setup` manages
index/component templates and imports the Kibana bundle — privileges
`byakugan_loader` deliberately does not have. **Every load after that**
authenticates as `byakugan_loader` instead — created by `config/setup.sh`
with the least-privilege `logs_car_writer` role (`create_doc`/`create_index`/
`read`/`view_index_metadata` on `logs-car.*` only, no cluster privileges: it
cannot alter or delete what it has already written, and cannot touch
templates or Kibana at all):

```sh
python -m byakugan.elastic.load <car-tree> \
    --es-url http://127.0.0.1:9201 \
    --es-user byakugan_loader --es-password "$BYAKUGAN_LOADER_PASSWORD" \
    --namespace <case>
```

(`$BYAKUGAN_LOADER_PASSWORD` is set the same way as `$ELASTIC_PASSWORD` above
— `set -a; source .env; set +a`. The container form is the same
`BYAKUGAN_LOAD_*` block, `BYAKUGAN_LOAD_ES_USER=byakugan_loader` and no
`BYAKUGAN_LOAD_SETUP`/`BYAKUGAN_LOAD_KIBANA_URL`.)

A re-run of either command is a no-op (deterministic content-derived
document ids + a manifest) unless the car tree changed or you pass `--force`.

## Reading it back as a timeline

`byakugan.timeline`'s own `--elastic` source (the same flags) rebuilds the
merged, time-ordered `timeline.jsonl` from the data streams instead of from
the local materialised JSONL tree — useful once several sources/cases share
this one stack:

```sh
python -m byakugan.timeline <car-tree> --out timeline.jsonl \
    --elastic http://127.0.0.1:9201 --namespace <case> \
    --es-user elastic --es-password "$ELASTIC_PASSWORD"
```

`<car-tree>` here only supplies the default `--out` path — no local file is
read; every row comes from `logs-car.*-<case>`. Same output bytes either way
(see `byakugan/timeline.py`'s module docstring).

## Coexisting with DX_DFIR

Nothing here collides with a DX_DFIR-integrated stack running on the same
host: this compose project is named `byakugan-standalone` (DX_DFIR's is
`byakugan`), so containers, the network and named volumes are all
independently namespaced, and the published ports are offset (`9201`/`5602`
here vs. DX_DFIR's `9200`/`5601`) — override `BYAKUGAN_STANDALONE_ES_PORT`
/ `BYAKUGAN_STANDALONE_KIBANA_PORT` in `.env` if those also collide with
something else. Run both at once, or either alone.

## Relationship to DX_DFIR's stack

**This is the standalone lab stack** — everything Byakugan needs to be
queryable as its own component, nothing else. DX_DFIR's own `docker/elastic/`
(in the DX_DFIR repository — a separate checkout, typically alongside this
one) is **the integrated stack** — the same Elasticsearch + Kibana core plus
Fleet, a Fleet Server and Filebeat as the raw-evidence shipper, and
HTTP+transport TLS behind a generated CA — built for DX_DFIR's wider
multi-tool orchestration. Both are single-node, Basic-licence Elastic; **both
consume exactly the same rendered contract** (`elastic/projection/rendered/`)
through the exact same `byakugan.elastic.load` (bundle or push) and
`byakugan.timeline --elastic` this engine ships, and **both carry the same
least-privilege `byakugan_loader` identity** for routine loads — nothing
about the CAR->ECS projection, the data-stream names or the loader's identity
differs between them, only the TLS posture and the certificate dance it
requires. Pick this stack when Byakugan is the whole job; point at DX_DFIR's
when Byakugan is embedded in it.

## Teardown

```sh
docker compose down          # stop + remove containers; volumes (data) survive
docker compose down -v       # also delete esdata/kibanadata — full reset
```

## Validating this directory without a daemon

No Docker daemon is required to check the compose file and setup script are
well-formed:

```sh
docker compose config                  # resolves/validates docker-compose.yml (needs the CLI, not a daemon)
python3 -c "import yaml; yaml.safe_load(open('docker-compose.yml'))"   # or, with no compose CLI at hand
bash -n config/setup.sh                # shell syntax check
```

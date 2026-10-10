# `elastic/` — Byakugan's Elastic config tree

**Generated. Committed. Drift-gated.** Rendered from the hand-authored CAR → ECS
boundary contract in [`model/projection/`](../model/projection/README.md) by
`python model/projection/render_elastic.py`; never edited here. It is laid out
the way DX_DFIR's own `elastic/` tree is — *configuration as data*: templates by
kind, a Kibana space as a directory — so the same walk deploys either.

```
elastic/
├── templates/
│   ├── component/             # component templates, one logs-car@<model> each:
│   │                          #   logs-car@header (the common header every stream composes first),
│   │                          #   logs-car@<object> (13), logs-car@rel, logs-car@inferred, logs-car@content
│   └── index/                 # one index template per data stream (logs-car-<object> ×13, -rel, -inferred, -content):
│                              #   index_patterns logs-car.<stream>-*, data_stream: {}, priority 500,
│                              #   composed_of [logs-car@header, logs-car@<stream>, logs-car@custom]
└── dashboards/
    └── byakugan/              # the Byakugan Kibana SPACE: space.json + its saved objects
        ├── space.json         #   id byakugan, name Byakugan, initials By, steel blue (#4682B4), every feature enabled
        ├── 00-data-views.ndjson   # the logs-car.* data view (car-logs-all)
        └── car-timeline.ndjson    # the CAR timeline: saved search, Lens histogram by car.object, the dashboard
```

Template **names are the filenames** (minus `.json`): `logs-car@<model>` for a
component template (Elastic's own `<type>@<name>` convention, the one DX_DFIR's
`logs-dxdfir@<lane>` uses), `logs-car-<stream>` for an index template.
`logs-car@custom` is the one component *not* rendered here: the optional
operator-owned customization slot every index template composes last, with
`ignore_missing_component_templates` so the templates apply before it exists
(DX_DFIR's risk-gate remedy hook — retention, `lifecycle: {}`).

There are no ingest pipelines: the CAR → ECS projection happens engine-side
(`byakugan.elastic.projection`), so a `logs-car.*` document arrives already
shaped. There is no Filebeat config: `byakugan load` is the only writer.

## How it is deployed

`byakugan load` reads this tree out of the engine's own checkout — or, in the
`get-sybers/byakugan` image [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz/tree/main/byakugan)
builds from this repository, out of the baked `/opt/byakugan/elastic/` — and
applies it on a push-mode run with `--setup` (`BYAKUGAN_LOAD_SETUP=1`):

1. every `templates/component/*.json` is PUT as `_component_template/<name>`,
   then every `templates/index/*.json` as `_index_template/<name>` — each GET
   first and left alone when the stored body already matches, so a re-setup
   is a no-op;
2. with a Kibana URL (`--kibana-url` / `BYAKUGAN_LOAD_KIBANA_URL`): the
   `byakugan` space is created from `dashboards/byakugan/space.json` (or
   updated when a field differs), then that directory's `*.ndjson` are
   imported **into the space** (`/s/byakugan/api/saved_objects/_import`,
   `overwrite=true`) as one payload, in file order. Any `dashboards/*.ndjson`
   at the top level would go to the default space the same way (none are
   rendered today — the slot DX_DFIR's tree shape has).

The space is then at `<kibana>/s/byakugan/app/dashboards` — open the
**CAR timeline** dashboard once the load finishes. `byakugan timeline --elastic`
reads the same streams back into `timeline.jsonl`.

```sh
# from a checkout (any Elasticsearch + Kibana, http or https):
python -m byakugan.elastic.load <car-tree> \
    --es-url https://127.0.0.1:9200 --es-ca-file <ca.crt> \
    --es-user elastic --es-password "$ELASTIC_PASSWORD" \
    --setup --kibana-url http://127.0.0.1:5601 --namespace <case>

# the same run from the standalone image (the GoDFIR-toolz README has the full env contract):
docker run --rm --network <stack network> --read-only --tmpfs /tmp:rw,uid=2000,gid=2000 \
    -v "$PWD/car:/input:ro" -v "$PWD/elastic-out:/output" -v "$PWD/certs:/certs:ro" \
    -e BYAKUGAN_LOAD_ES_URL=https://elasticsearch:9200 -e BYAKUGAN_LOAD_ES_USER=elastic \
    -e BYAKUGAN_LOAD_ES_PASSWORD="$ELASTIC_PASSWORD" -e BYAKUGAN_LOAD_SETUP=1 \
    -e BYAKUGAN_LOAD_KIBANA_URL=http://kibana:5601 -e BYAKUGAN_LOAD_NAMESPACE=<case> \
    get-sybers/byakugan:latest load
```

**Two identities.** The `--setup` run needs cluster and Kibana privileges, so
it authenticates as `elastic`. Every load after that authenticates as the
least-privilege `byakugan_loader` (role `logs_car_writer`: `create_doc`,
`create_index`, `read`, `view_index_metadata` on `logs-car.*` only — it cannot
alter or delete what it has written, nor touch templates or Kibana) with no
`--setup`. The stack creates that identity: DX_DFIR's `dxdfir_stack` role does
on deploy, and the [`elastic-e2e`](../.github/workflows/elastic-e2e.yml)
workflow makes the same two `_security` calls against its throwaway cluster.

## Inside DX_DFIR

DX_DFIR's [`elastic/`](https://github.com/Get-Sybers/DX_DFIR/tree/main/elastic)
tree configures the `logs-dxdfir.*` raw-evidence family and the `malcolm`
space; `logs-car.*` is deliberately *not* configured there. This tree is how
the Byakugan family reaches that stack: `dx byakugan load` (the
`dxdfir_car_load` role) runs the `get-sybers/byakugan` image's `load` sub-tool
in push mode with `BYAKUGAN_LOAD_SETUP`, so the templates — and, with
`--kibana`, the `byakugan` space — land in the stack `dx deploy stack` brought
up, from the engine's own pinned copy of this tree. Nothing is copied into the
DX_DFIR checkout; the image imports it.

## Regenerating

```sh
python model/projection/validate.py                  # the contract is in step with the CAR model
python model/projection/render_elastic.py            # rewrite templates/ and dashboards/
python model/projection/render_elastic.py --check    # CI: byte-compare against a fresh render
pytest -q tests/test_projection_contract.py tests/test_kibana_assets.py
```

A projection decision changes in `model/projection/` (see its README); this
tree is re-rendered and committed with it. `--check` refuses a missing,
drifted or orphan file under `templates/` and `dashboards/` (this README is the
one hand-written file here). The live proof — real templates, the real space,
a real least-privilege re-push — is `scripts/e2e_elastic.py`, run by the
`elastic-e2e` workflow against a throwaway Elasticsearch + Kibana started with
plain `docker run`: this repository ships no compose file, Dockerfile or stack
of its own.

#!/usr/bin/env python3
"""Render the Elastic assets for the CAR->ECS projection contract.

conventions.yml + objects/<object>.yml (13) + relationships.yml + inferred.yml
+ ecs_types.yml decide the projection; this renders that DECISION into the
Elasticsearch/Kibana assets DX_DFIR's loader composes at index-template time —
component templates, index templates and a minimal Kibana data-view bundle —
under elastic/projection/rendered/ (committed output, like model/sql/*.sql):

    rendered/
      component_templates/logs-car-header.json         the shared header (every stream)
      component_templates/logs-car-<object>.json (13)   one CAR object's own fields
      component_templates/logs-car-rel.json             the relationship-timeline stream
      component_templates/logs-car-inferred.json        the inferred-node stream
      component_templates/logs-car-content.json         the content-node stream (the attribution layer)
      index_templates/logs-car-<object>.json (13)       index_patterns + composed_of
      index_templates/logs-car-rel.json
      index_templates/logs-car-inferred.json
      kibana/logs-car-views.ndjson                      one data view + one saved search

This is a RENDERER, not a decision-maker: every field, type and rationale
comes from the contract files above (validate.py is what keeps THOSE in step
with the CAR model — run it first). Nothing here talks to a live cluster;
DX_DFIR's loader is what PUTs these under _component_template / _index_template
and imports the ndjson.

Dependencies: pyyaml only.

    python elastic/projection/render_elastic.py            # write rendered/
    python elastic/projection/render_elastic.py --check     # verify rendered/ is in sync; write nothing
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CONVENTIONS_PATH = os.path.join(HERE, "conventions.yml")
OBJECTS_DIR = os.path.join(HERE, "objects")
RELATIONSHIPS_PATH = os.path.join(HERE, "relationships.yml")
INFERRED_PATH = os.path.join(HERE, "inferred.yml")
CONTENT_PATH = os.path.join(HERE, "content.yml")
ECS_TYPES_PATH = os.path.join(HERE, "ecs_types.yml")
RENDERED_DIR = os.path.join(HERE, "rendered")

# The optional DX_DFIR-owned customization slot every index template composes
# with last (Elastic's own `<type>@custom` convention for Fleet-managed data
# streams): empty until DX_DFIR creates it, so index templates must tolerate
# its absence — the riskgate remedy hook.
CUSTOM_COMPONENT = "logs-car@custom"


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _dump_json(obj) -> str:
    """Byte-deterministic rendering: stable key order, 2-space indent, trailing newline."""
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def _dump_ndjson_line(obj) -> str:
    return json.dumps(obj, sort_keys=True)


# --------------------------------------------------------------------------- #
# Path nesting: {"a.b.c": spec} -> the ES {"properties": {"a": {"properties":
# {"b": {"properties": {"c": spec}}}}}} tree every mapping in this file uses.
# --------------------------------------------------------------------------- #
def _nest(flat: dict[str, dict]) -> dict:
    root: dict = {}
    for path, spec in flat.items():
        parts = path.split(".")
        node = root
        for p in parts[:-1]:
            node = node.setdefault(p, {}).setdefault("properties", {})
        node[parts[-1]] = spec
    return root


def _ecs_type(path: str, ecs_types: dict) -> str:
    """A target path's mapping type: ecs_types.yml's override, else keyword
    (ECS's own default, and the honest fallback for anything this contract
    does not positively know to be a date/long/ip/float/boolean)."""
    return (ecs_types.get(path) or {}).get("type", "keyword")


def _component_meta(contract: dict, extra_sources: list[str]) -> dict:
    """The component/index-template-level `_meta` every rendered asset carries:
    provenance back to the hand-authored contract files that produced it."""
    return {
        "contract": contract.get("name"),
        "version": contract.get("version"),
        "source": ["elastic/projection/conventions.yml", *extra_sources],
        "generated_by": "python elastic/projection/render_elastic.py",
        "recompute_on": ("any projection change (conventions.yml, objects/*.yml, "
                         "ecs_types.yml, relationships.yml, inferred.yml)"),
    }


# --------------------------------------------------------------------------- #
# The common header — byakugan/store.py HEADER, conventions.yml common_header.
# Hardcoded (rather than derived) because the CAR-name aliases and the
# verbatim-timestamp companion (car.timestamp) are RENDERING conventions this
# phase introduces, not structured data conventions.yml itself carries; every
# path below traces to one common_header entry (see the comment on each).
# --------------------------------------------------------------------------- #
# path -> ES type. One entry per common_header field's PRIMARY target, plus
# link_confidence's `also:` (labels.link_confidence) and the verbatim-string
# evidence-timestamp companion (car.timestamp, matching the pattern
# relationships.yml/inferred.yml use for their own primary date field).
_HEADER_CONCRETE: dict[str, str] = {
    "@timestamp": "date",                    # timestamp
    "event.kind": "keyword",                 # constant (conventions.yml constants)
    "event.module": "keyword",               # constant
    "event.dataset": "keyword",              # constant (per-object value; keyword here, not
                                             # constant_keyword — it varies per object stream)
    "event.action": "keyword",               # car_action
    "event.provider": "keyword",             # source_artefact
    "event.id": "keyword",                   # guid
    "event.ingested": "date",                # loader-stamped (not a CAR field)
    "host.name": "keyword",                  # source_host
    "labels.link_confidence": "keyword",     # link_confidence also:
    "ecs.version": "keyword",                # constant
    "data_stream.type": "constant_keyword",  # constant
    "data_stream.dataset": "constant_keyword",  # constant
    "data_stream.namespace": "constant_keyword",  # loader-chosen, constant per index
    "car.object": "keyword",                 # constant (the CAR object name; absent on rel/inferred)
    "car.link_confidence": "float",          # link_confidence
    "car.volume_guid": "keyword",            # volume_guid
    "car.mac_address": "keyword",            # mac_address
    "car.device_serial": "keyword",          # device_serial
    "car.timestamp": "keyword",              # timestamp, verbatim (id-reproducibility companion)
    "car.native": "flattened",               # native
    # owning_guid's PRIMARY target (conventions.yml: "the owning process IS
    # process.entity_id"), for every object — not process-specific. Declared
    # here, in the header, so the car.owning_guid alias below has something
    # real to point at; objects/process.yml must not redeclare it (dedup, see
    # object_targets()).
    "process.entity_id": "keyword",
}

# car.<original-header-name> -> its ECS home, for every header field whose CAR
# name differs from its ECS/custom path. (volume_guid, mac_address,
# device_serial, link_confidence and native already share their CAR name with
# their car.* home, so they need no alias.)
_HEADER_ALIASES: dict[str, str] = {
    "car.guid": "event.id",
    "car.car_action": "event.action",
    "car.source_artefact": "event.provider",
    "car.source_host": "host.name",
    "car.owning_guid": "process.entity_id",
}


def render_header(contract: dict) -> tuple[dict, set[str]]:
    flat: dict[str, dict] = {p: {"type": t} for p, t in _HEADER_CONCRETE.items()}
    for alias_path, target in _HEADER_ALIASES.items():
        flat[alias_path] = {"type": "alias", "path": target}
    body = {
        "template": {
            "mappings": {
                "dynamic": False,
                "_meta": {
                    "note": ("evidence is never rejected for shape; drift is caught by the "
                            "verify counts and the contract tests, not by mapping strictness."),
                },
                "properties": _nest(flat),
            },
        },
        "_meta": _component_meta(contract, []),
    }
    header_paths = set(_HEADER_CONCRETE) | set(_HEADER_ALIASES)
    return body, header_paths


# --------------------------------------------------------------------------- #
# Per-object component templates (objects/<object>.yml).
# --------------------------------------------------------------------------- #
def object_targets(name: str, doc: dict, ecs_types: dict,
                   header_paths: set[str]) -> tuple[dict, dict, list[str]]:
    """(concrete {path: spec}, aliases {car.<object>.<field>: target ecs path},
    warnings) for one objects/<object>.yml — every mapped entry's primary home
    + also: copies + derived: targets (typed via ecs_types.yml), every native:
    true entry as its own concrete car.<object>.<field>, and a CAR-name alias
    for every mapped entry. Anything already concrete on the header is
    dropped (composed_of already supplies it — see logs-car-header.json)."""
    concrete: dict[str, dict] = {}
    mapped: list[tuple[str, str]] = []          # (car field name, primary ecs path)
    for e in doc.get("fields") or []:
        car_field = e["car"]
        if e.get("native") is True:
            concrete[f"car.{name}.{car_field}"] = {"type": e["type"]}
            continue
        primary = e["ecs"]
        if primary == "event.outcome":
            # excluded from the primary ECS mapping (byakugan/elastic/projection.py
            # _compile_object: event.outcome is DERIVED from event_defaults,
            # never a plain field copy — rules.event_action), but the raw
            # value that DRIVES the derivation (event_defaults.
            # outcome_from_field) is still captured verbatim, native-style
            # (_apply_event_defaults) — so it is concrete here too, exactly
            # like a native: true field. An alias to event.outcome would
            # collide with that real write (ES refuses to index a value at
            # an alias path).
            concrete[f"car.{name}.{car_field}"] = {"type": "keyword"}
            continue
        concrete.setdefault(primary, {"type": _ecs_type(primary, ecs_types)})
        for also in e.get("also") or []:
            concrete.setdefault(also, {"type": _ecs_type(also, ecs_types)})
        mapped.append((car_field, primary))
    for d in doc.get("derived") or []:
        concrete.setdefault(d["ecs"], {"type": _ecs_type(d["ecs"], ecs_types)})

    aliases: dict[str, str] = {}
    warnings: list[str] = []
    for car_field, primary in mapped:
        alias_path = f"car.{name}.{car_field}"
        if alias_path in concrete:
            warnings.append(f"{name}: alias {alias_path} -> {primary} collides with a concrete "
                            "field of this object's own template — skipped")
            continue
        aliases[alias_path] = primary

    for p in list(concrete):
        if p in header_paths:
            del concrete[p]
    return concrete, aliases, warnings


def render_object_component(name: str, doc: dict, ecs_types: dict, header_paths: set[str],
                            contract: dict, extra_sources: list[str]) -> tuple[dict, list[str]]:
    concrete, aliases, warnings = object_targets(name, doc, ecs_types, header_paths)
    flat = dict(concrete)
    for alias_path, target in aliases.items():
        flat[alias_path] = {"type": "alias", "path": target}
    body = {
        "template": {"mappings": {"properties": _nest(flat)}},
        "_meta": _component_meta(contract, extra_sources),
    }
    return body, warnings


# --------------------------------------------------------------------------- #
# relationships.yml / inferred.yml component templates — every field entry
# already carries its own explicit type: (no ecs_types.yml lookup needed).
# --------------------------------------------------------------------------- #
def render_edge_component(doc: dict, header_paths: set[str], contract: dict,
                          source_path: str) -> dict:
    concrete: dict[str, dict] = {}
    for e in doc.get("fields") or []:
        concrete.setdefault(e["ecs"], {"type": e["type"]})
        also = e.get("also")
        if also:
            concrete.setdefault(also, {"type": e["also_type"]})
    for p in list(concrete):
        if p in header_paths:
            del concrete[p]
    return {
        "template": {"mappings": {"properties": _nest(concrete)}},
        "_meta": _component_meta(contract, [source_path]),
    }


# --------------------------------------------------------------------------- #
# Index templates.
# --------------------------------------------------------------------------- #
def render_index_template(index_pattern: str, component_name: str, extra_sources: list[str],
                          contract: dict) -> dict:
    meta = _component_meta(contract, extra_sources)
    meta["notes"] = (f"{CUSTOM_COMPONENT} is the optional DX_DFIR-owned customization component; "
                     "ignore_missing_component_templates lets this template apply before "
                     "DX_DFIR creates it (the riskgate remedy hook).")
    return {
        "index_patterns": [index_pattern],
        "data_stream": {},
        "priority": 500,
        "composed_of": ["logs-car-header", component_name, CUSTOM_COMPONENT],
        "ignore_missing_component_templates": [CUSTOM_COMPONENT],
        "_meta": meta,
    }


# --------------------------------------------------------------------------- #
# Kibana assets: data view + saved search + Lens histogram + the dashboard,
# references LAST in the file (test_kibana_assets.py enforces it).
# typeMigrationVersion 8.9.0 + coreMigrationVersion 8.8.0 go on the LENS
# object only: without them Kibana 9.5.3 runs the legacy lens migration
# chain over this modern hand-authored state and the import 500s (falsified
# live, 2026-09-05); the other objects import fine unstamped.
# --------------------------------------------------------------------------- #
DATA_VIEW_ID = "car-logs-all"
SEARCH_ID = "car-timeline"
LENS_ID = "car-timeline-histogram"
DASHBOARD_ID = "car-timeline-dashboard"


def _render_lens_histogram() -> dict:
    return {
        "id": LENS_ID,
        "type": "lens",
        "managed": False,
        "coreMigrationVersion": "8.8.0",
        "typeMigrationVersion": "8.9.0",
        "attributes": {
            "title": "CAR events over time (by object)",
            "description": "Document count over @timestamp, split by car.object.",
            "visualizationType": "lnsXY",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "layer1": {
                                "columnOrder": ["colBreak", "colDate", "colCount"],
                                "columns": {
                                    "colBreak": {
                                        "dataType": "string", "isBucketed": True,
                                        "label": "car.object", "operationType": "terms",
                                        "params": {
                                            "missingBucket": False,
                                            "orderBy": {"columnId": "colCount", "type": "column"},
                                            "orderDirection": "desc", "otherBucket": True,
                                            "parentFormat": {"id": "terms"}, "size": 10,
                                        },
                                        "scale": "ordinal", "sourceField": "car.object",
                                    },
                                    "colCount": {
                                        "dataType": "number", "isBucketed": False,
                                        "label": "Count of records", "operationType": "count",
                                        "params": {"emptyAsNull": True},
                                        "scale": "ratio", "sourceField": "___records___",
                                    },
                                    "colDate": {
                                        "dataType": "date", "isBucketed": True,
                                        "label": "@timestamp", "operationType": "date_histogram",
                                        "params": {"dropPartials": False, "includeEmptyRows": True,
                                                  "interval": "auto"},
                                        "scale": "interval", "sourceField": "@timestamp",
                                    },
                                },
                                "incompleteColumns": {},
                            },
                        },
                    },
                },
                "filters": [],
                "query": {"language": "kuery", "query": ""},
                "visualization": {
                    "fittingFunction": "None",
                    "layers": [{
                        "accessors": ["colCount"], "layerId": "layer1", "layerType": "data",
                        "seriesType": "bar_stacked", "splitAccessor": "colBreak", "xAccessor": "colDate",
                    }],
                    "legend": {"isVisible": True, "position": "right"},
                    "preferredSeriesType": "bar_stacked", "valueLabels": "hide",
                },
            },
        },
        "references": [{"id": DATA_VIEW_ID, "name": "indexpattern-datasource-layer-layer1",
                        "type": "index-pattern"}],
    }


def _render_dashboard() -> dict:
    panels = [
        {"panelIndex": "1", "type": "lens", "gridData": {"x": 0, "y": 0, "w": 48, "h": 15, "i": "1"},
         "panelRefName": "panel_1", "embeddableConfig": {}},
        {"panelIndex": "2", "gridData": {"x": 0, "y": 15, "w": 48, "h": 20, "i": "2"},
         "panelRefName": "panel_2", "embeddableConfig": {}},
    ]
    return {
        "id": DASHBOARD_ID,
        "type": "dashboard",
        "managed": False,
        "attributes": {
            "title": "CAR timeline",
            "description": "The CAR event timeline: every logs-car.* document (the car-timeline "
                           "saved search) and its shape over time by object (the histogram).",
            "panelsJSON": json.dumps(panels, sort_keys=True),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}, sort_keys=True),
            },
        },
        "references": [
            {"id": LENS_ID, "name": "panel_1", "type": "lens"},
            {"id": SEARCH_ID, "name": "panel_2", "type": "search"},
        ],
    }


def render_kibana_ndjson() -> str:
    index_pattern = {
        "id": DATA_VIEW_ID,
        "type": "index-pattern",
        "managed": False,
        "attributes": {
            "title": "logs-car.*",
            "name": "CAR (logs-car.*)",
            "timeFieldName": "@timestamp",
        },
        "references": [],
    }
    search = {
        "id": SEARCH_ID,
        "type": "search",
        "managed": False,
        "attributes": {
            "title": "CAR timeline",
            "columns": ["car.object", "event.action", "event.provider", "host.name"],
            "sort": [["@timestamp", "asc"]],
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": [],
                     "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"},
                    sort_keys=True),
            },
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": DATA_VIEW_ID}],
    }
    # the dashboard references the search + lens objects above by id, and
    # must itself come LAST (test_kibana_assets.py, uSaid's own convention).
    objects = [index_pattern, search, _render_lens_histogram(), _render_dashboard()]
    return "\n".join(_dump_ndjson_line(o) for o in objects) + "\n"


# --------------------------------------------------------------------------- #
# Orchestration.
# --------------------------------------------------------------------------- #
def render_all() -> tuple[dict[str, str], list[str]]:
    """({published path under rendered/: file content}, alias-collision warnings)."""
    conventions = _load(CONVENTIONS_PATH)
    contract = conventions.get("contract") or {}
    objects: dict[str, dict] = {}
    for path in sorted(glob.glob(os.path.join(OBJECTS_DIR, "*.yml"))):
        objects[os.path.splitext(os.path.basename(path))[0]] = _load(path)
    relationships = _load(RELATIONSHIPS_PATH)
    inferred = _load(INFERRED_PATH)
    content = _load(CONTENT_PATH)
    ecs_types = (_load(ECS_TYPES_PATH) or {}).get("types") or {}

    files: dict[str, str] = {}
    warnings: list[str] = []

    header_body, header_paths = render_header(contract)
    files["component_templates/logs-car-header.json"] = _dump_json(header_body)

    for name, doc in objects.items():
        extra_sources = [f"elastic/projection/objects/{name}.yml", "elastic/projection/ecs_types.yml"]
        body, w = render_object_component(name, doc, ecs_types, header_paths, contract, extra_sources)
        warnings += w
        files[f"component_templates/logs-car-{name}.json"] = _dump_json(body)
        files[f"index_templates/logs-car-{name}.json"] = _dump_json(
            render_index_template(f"logs-car.{name}-*", f"logs-car-{name}", extra_sources, contract))

    files["component_templates/logs-car-rel.json"] = _dump_json(
        render_edge_component(relationships, header_paths, contract, "elastic/projection/relationships.yml"))
    files["index_templates/logs-car-rel.json"] = _dump_json(render_index_template(
        "logs-car.rel-*", "logs-car-rel", ["elastic/projection/relationships.yml"], contract))

    files["component_templates/logs-car-inferred.json"] = _dump_json(
        render_edge_component(inferred, header_paths, contract, "elastic/projection/inferred.yml"))
    files["index_templates/logs-car-inferred.json"] = _dump_json(render_index_template(
        "logs-car.inferred-*", "logs-car-inferred", ["elastic/projection/inferred.yml"], contract))

    files["component_templates/logs-car-content.json"] = _dump_json(
        render_edge_component(content, header_paths, contract, "elastic/projection/content.yml"))
    files["index_templates/logs-car-content.json"] = _dump_json(render_index_template(
        "logs-car.content-*", "logs-car-content", ["elastic/projection/content.yml"], contract))

    files["kibana/logs-car-views.ndjson"] = render_kibana_ndjson()

    return files, warnings


def write(out_dir: str = RENDERED_DIR) -> list[str]:
    files, warnings = render_all()
    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)
    for rel, content in files.items():
        path = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return sorted(files)


def check(out_dir: str = RENDERED_DIR) -> list[str]:
    """Every way rendered/ can be stale; [] means it matches a fresh render."""
    files, warnings = render_all()
    problems = [f"alias collision: {w}" for w in warnings]
    on_disk: dict[str, str] = {}
    for root, _dirs, names in os.walk(out_dir):
        for n in names:
            full = os.path.join(root, n)
            rel = os.path.relpath(full, out_dir).replace(os.sep, "/")
            on_disk[rel] = full
    for rel, content in sorted(files.items()):
        disk_path = on_disk.get(rel)
        if disk_path is None:
            problems.append(f"missing: {rel} (run: python elastic/projection/render_elastic.py)")
            continue
        with open(disk_path, encoding="utf-8") as fh:
            existing = fh.read()
        if existing != content:
            problems.append(f"drifted: {rel} (run: python elastic/projection/render_elastic.py)")
    for rel in sorted(set(on_disk) - set(files)):
        problems.append(f"orphan: {rel} (no longer generated by render_elastic.py; remove it)")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="elastic.projection.render_elastic",
        description="render the Elastic component/index templates + Kibana views from the "
                    "CAR->ECS projection contract")
    ap.add_argument("--check", action="store_true",
                    help="verify rendered/ matches a fresh render; write nothing")
    args = ap.parse_args(argv)

    if args.check:
        problems = check()
        if problems:
            print(f"car-ecs render DRIFT: {len(problems)} problem(s)", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            return 1
        print(f"OK: rendered/ in sync ({RENDERED_DIR})")
        return 0

    written = write()
    print(f"wrote {len(written)} files to {RENDERED_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

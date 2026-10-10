"""Structural checks for the rendered Kibana assets (elastic/dashboards/).

Mirrors the idea in /home/user/uSaid/tests/test_kibana_views.py: a saved-object
bundle is an import artifact, not code, so nothing catches a renamed/typo'd
field at import time -- a saved search just renders an empty column forever.
These checks hold the rendered bundle to the same contract render_elastic.py's
own decisions imply: every column/sort/timeField must actually be a field
(concrete or alias) of some stream the referenced data view's title pattern
matches, every reference must resolve within its IMPORT UNIT (a space
directory's *.ndjson are imported together as one payload, so a reference
may cross files inside a space; the default space's top-level *.ndjson are
another unit), every object id must be unique within its unit, and every
space.json is what Kibana's spaces API takes. render_elastic.py --check
(test_projection_contract.py) is what proves the tree on disk is what
render_elastic.py would write today; this file proves what it writes is
internally consistent.
"""
from __future__ import annotations

import fnmatch
import glob
import json
import os

import pytest

ELASTIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "elastic")
DASHBOARDS_DIR = os.path.join(ELASTIC, "dashboards")
COMPONENT_DIR = os.path.join(ELASTIC, "templates", "component")
INDEX_DIR = os.path.join(ELASTIC, "templates", "index")

BUNDLES = sorted(glob.glob(os.path.join(DASHBOARDS_DIR, "*.ndjson"))
                 + glob.glob(os.path.join(DASHBOARDS_DIR, "*", "*.ndjson")))
SPACE_FILES = sorted(glob.glob(os.path.join(DASHBOARDS_DIR, "*", "space.json")))


def _objects(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]


def _import_unit(path: str) -> list[str]:
    """The files imported together with `path` as one payload: a space
    directory's *.ndjson, or the default space's top-level *.ndjson."""
    d = os.path.dirname(path)
    if os.path.exists(os.path.join(d, "space.json")):
        return sorted(glob.glob(os.path.join(d, "*.ndjson")))
    return sorted(glob.glob(os.path.join(DASHBOARDS_DIR, "*.ndjson")))


def _unit_objects(path: str) -> list[dict]:
    objs: list[dict] = []
    for p in _import_unit(path):
        objs += _objects(p)
    return objs


def _load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _flatten(properties: dict, prefix: str = "") -> set[str]:
    """Every leaf field path (concrete or alias) in an ES properties tree.
    A `flattened` leaf also admits any subkey (car.native.<anything>)."""
    fields: set[str] = set()
    for name, spec in properties.items():
        full = f"{prefix}{name}"
        if "properties" in spec:
            fields |= _flatten(spec["properties"], full + ".")
        else:
            fields.add(full)
            if spec.get("type") == "flattened":
                fields.add(full + ".*")
    return fields


def _stream_fields(index_template_path: str) -> set[str]:
    """The full field set an index template's composed_of implies: the header
    + the stream's own component (logs-car@custom is DX_DFIR's, not rendered
    here, so it is skipped rather than required)."""
    idx = _load_json(index_template_path)
    fields: set[str] = set()
    for name in idx["composed_of"]:
        comp_path = os.path.join(COMPONENT_DIR, f"{name}.json")
        if not os.path.exists(comp_path):
            continue
        comp = _load_json(comp_path)
        fields |= _flatten(comp["template"]["mappings"].get("properties") or {})
    return fields


def _example_index_name(index_pattern: str) -> str:
    """One concrete data-stream name an index_patterns entry ('logs-car.foo-*')
    would match -- what a data view's own wildcard title is matched against."""
    assert index_pattern.endswith("*"), index_pattern
    return index_pattern[:-1] + "default"


def _matching_streams(title: str) -> list[str]:
    """Every index_templates/*.json whose index_patterns a data-view title
    (also a wildcard pattern, e.g. 'logs-car.*') would match."""
    matches = []
    for path in sorted(glob.glob(os.path.join(INDEX_DIR, "*.json"))):
        idx = _load_json(path)
        if any(fnmatch.fnmatch(_example_index_name(p), title) for p in idx["index_patterns"]):
            matches.append(path)
    return matches


def _fields_for_title(title: str) -> set[str]:
    fields: set[str] = set()
    for path in _matching_streams(title):
        fields |= _stream_fields(path)
    return fields


def _field_ok(field: str, fields: set[str]) -> bool:
    if field in fields:
        return True
    parts = field.split(".")
    return any(".".join(parts[:i]) + ".*" in fields for i in range(len(parts) - 1, 0, -1))


def test_rendered_kibana_bundle_exists():
    assert BUNDLES, f"no *.ndjson under {DASHBOARDS_DIR} -- run python model/projection/render_elastic.py"


def test_the_byakugan_space_is_rendered():
    assert os.path.join(DASHBOARDS_DIR, "byakugan", "space.json") in SPACE_FILES


@pytest.mark.parametrize("path", SPACE_FILES, ids=lambda p: os.path.basename(os.path.dirname(p)))
def test_space_json_is_what_the_spaces_api_takes(path):
    """space.json: the id names its directory, and the fields are the ones
    POST /api/spaces/space accepts (id, name, initials <= 2 chars, a hex
    colour, disabledFeatures a list) — the same shape DX_DFIR's
    elastic/dashboards/<id>/space.json carries, so either deployer reads it."""
    space = _load_json(path)
    assert space["id"] == os.path.basename(os.path.dirname(path))
    assert space["id"] == space["id"].lower() and " " not in space["id"]
    assert space["name"]
    assert len(space["initials"]) <= 2
    assert len(space["color"]) == 7 and space["color"].startswith("#")
    int(space["color"][1:], 16)
    assert isinstance(space["disabledFeatures"], list)
    assert set(space) <= {"id", "name", "description", "initials", "color", "disabledFeatures"}


@pytest.mark.parametrize("path", BUNDLES, ids=lambda p: os.path.basename(p))
def test_bundle_parses(path):
    assert _objects(path), f"{path}: empty"


@pytest.mark.parametrize("path", BUNDLES, ids=lambda p: os.path.basename(p))
def test_ids_unique_and_references_resolve_in_import_unit(path):
    unit = _unit_objects(path)
    ids = [o["id"] for o in unit]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"{path}: duplicate id(s) {dupes} within its import unit"
    ids_here = set(ids)
    for o in _objects(path):
        for ref in o.get("references", []):
            assert ref["id"] in ids_here, f"{path}: {o['id']} -> dangling ref {ref['id']!r}"


@pytest.mark.parametrize("path", BUNDLES, ids=lambda p: os.path.basename(p))
def test_data_view_time_field_exists(path):
    for o in _objects(path):
        if o["type"] != "index-pattern":
            continue
        tf = o["attributes"].get("timeFieldName")
        if not tf:
            continue
        title = o["attributes"]["title"]
        fields = _fields_for_title(title)
        assert fields, f"{path}: data view {o['id']} title {title!r} matches no rendered stream"
        assert _field_ok(tf, fields), (
            f"{path}: {o['id']} timeFieldName {tf!r} not in any stream {title!r} matches")


@pytest.mark.parametrize("path", BUNDLES, ids=lambda p: os.path.basename(p))
def test_search_columns_and_sort_exist_in_matched_streams(path):
    objs = _objects(path)
    views = {o["id"]: o for o in _unit_objects(path) if o["type"] == "index-pattern"}
    for o in objs:
        if o["type"] != "search":
            continue
        idx_refs = [r for r in o["references"] if r["type"] == "index-pattern"]
        assert len(idx_refs) == 1, f"{path}: {o['id']} needs exactly one index-pattern reference"
        view = views[idx_refs[0]["id"]]
        title = view["attributes"]["title"]
        fields = _fields_for_title(title)
        assert fields, f"{path}: data view {view['id']} title {title!r} matches no rendered stream"
        attrs = o["attributes"]
        for col in attrs.get("columns") or []:
            assert _field_ok(col, fields), (
                f"{path}: {o['id']} column {col!r} not in any stream {title!r} matches")
        for pair in attrs.get("sort") or []:
            if isinstance(pair, list) and pair:
                assert _field_ok(pair[0], fields), (
                    f"{path}: {o['id']} sort field {pair[0]!r} not in any stream {title!r} matches")


# --------------------------------------------------------------------------- #
# The dashboard (id car-timeline-dashboard) + its Lens panel: last in the
# file, panels reference-consistent, and (uSaid's own falsified-live rule)
# every lens carries the migration stamps an unstamped Kibana 9.5.3 import
# 500s without. Mirrors /home/user/uSaid/tests/test_kibana_views.py.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", BUNDLES, ids=lambda p: os.path.basename(p))
def test_dashboard_is_last_object_in_the_file(path):
    objs = _objects(path)
    dashboards = [o for o in objs if o["type"] == "dashboard"]
    if not dashboards:
        pytest.skip(f"{path}: no dashboard object")
    assert objs[-1]["type"] == "dashboard", f"{path}: the dashboard must be the last object"


@pytest.mark.parametrize("path", BUNDLES, ids=lambda p: os.path.basename(p))
def test_dashboard_panels_reference_consistently(path):
    objs = _objects(path)
    ids_here = {o["id"] for o in _unit_objects(path)}
    for o in objs:
        if o["type"] != "dashboard":
            continue
        panels = json.loads(o["attributes"]["panelsJSON"])
        ref_names = {r["name"] for r in o.get("references", [])}
        panel_names = {p["panelRefName"] for p in panels}
        assert panel_names == ref_names, (
            f"{path}: {o['id']} panelsJSON panelRefNames {panel_names} != "
            f"references {ref_names}")
        for r in o.get("references", []):
            assert r["id"] in ids_here, f"{path}: {o['id']} -> dangling ref {r['id']!r}"


@pytest.mark.parametrize("path", BUNDLES, ids=lambda p: os.path.basename(p))
def test_lens_source_fields_exist_in_matched_streams(path):
    objs = _objects(path)
    views = {o["id"]: o for o in _unit_objects(path) if o["type"] == "index-pattern"}
    for o in objs:
        if o["type"] != "lens":
            continue
        idx_refs = [r for r in o["references"] if r["type"] == "index-pattern"]
        assert idx_refs, f"{path}: lens {o['id']} needs an index-pattern reference"
        title = views[idx_refs[0]["id"]]["attributes"]["title"]
        fields = _fields_for_title(title)
        assert fields, f"{path}: data view {idx_refs[0]['id']} title {title!r} matches no rendered stream"
        layers = o["attributes"]["state"]["datasourceStates"]["formBased"]["layers"]
        for layer in layers.values():
            for col in layer["columns"].values():
                sf = col.get("sourceField")
                if sf and sf != "___records___":
                    assert _field_ok(sf, fields), (
                        f"{path}: lens {o['id']} sourceField {sf!r} not in any stream {title!r} matches")


@pytest.mark.parametrize("path", BUNDLES, ids=lambda p: os.path.basename(p))
def test_lens_objects_carry_migration_stamps(path):
    """Lens objects are hand-authored in the MODERN (8.9-frozen) state shape,
    so they must SAY so: typeMigrationVersion 8.9.0 (where lens type
    migrations froze) and coreMigrationVersion 8.8.0, the pair a real
    `_export` emits — proven against live Kibana 9.5.3 in
    /home/user/uSaid/tests/test_kibana_views.py: unstamped -> import 500,
    stamped -> success:true. Other object types import fine unstamped."""
    for o in _objects(path):
        if o["type"] != "lens":
            continue
        assert o.get("typeMigrationVersion") == "8.9.0", (
            f"{path}: lens {o['id']} must carry typeMigrationVersion '8.9.0'")
        assert o.get("coreMigrationVersion") == "8.8.0", (
            f"{path}: lens {o['id']} must carry coreMigrationVersion '8.8.0'")

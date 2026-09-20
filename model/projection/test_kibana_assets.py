"""Structural checks for the rendered Kibana bundle (rendered/kibana/*.ndjson).

Mirrors the idea in /home/user/uSaid/tests/test_kibana_views.py: a saved-object
bundle is an import artifact, not code, so nothing catches a renamed/typo'd
field at import time -- a saved search just renders an empty column forever.
These checks hold the rendered bundle to the same contract render_elastic.py's
own decisions imply: every column/sort/timeField must actually be a field
(concrete or alias) of some stream the referenced data view's title pattern
matches, every reference must resolve within the file, and every object id
must be unique. render_elastic.py --check (test_projection_contract.py) is
what proves the bundle on disk is what render_elastic.py would write today;
this file proves what it writes is internally consistent.
"""
from __future__ import annotations

import fnmatch
import glob
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
RENDERED = os.path.join(HERE, "rendered")
KIBANA_DIR = os.path.join(RENDERED, "kibana")
COMPONENT_DIR = os.path.join(RENDERED, "component_templates")
INDEX_DIR = os.path.join(RENDERED, "index_templates")

BUNDLES = sorted(glob.glob(os.path.join(KIBANA_DIR, "*.ndjson")))


def _objects(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]


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
    assert BUNDLES, f"no {KIBANA_DIR}/*.ndjson -- run python model/projection/render_elastic.py"


@pytest.mark.parametrize("path", BUNDLES, ids=lambda p: os.path.basename(p))
def test_bundle_parses(path):
    assert _objects(path), f"{path}: empty"


@pytest.mark.parametrize("path", BUNDLES, ids=lambda p: os.path.basename(p))
def test_ids_unique_and_references_resolve_in_file(path):
    objs = _objects(path)
    ids = [o["id"] for o in objs]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"{path}: duplicate id(s) {dupes}"
    ids_here = set(ids)
    for o in objs:
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
    views = {o["id"]: o for o in objs if o["type"] == "index-pattern"}
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

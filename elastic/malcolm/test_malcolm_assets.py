"""Structural checks on elastic/malcolm: the Kibana bundle under kibana/, the
Elasticsearch objects under elasticsearch/ and the Ansible role under ansible/.
pyyaml only; no Elastic connection."""
import glob
import json
import os
import re

import pytest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
KIBANA = os.path.join(HERE, "kibana")
ES = os.path.join(HERE, "elasticsearch")
ROLE = os.path.join(HERE, "ansible", "roles", "malcolm_space")

LENS_TYPES = {"lnsDatatable", "lnsPie", "lnsMetric", "lnsXY", "lnsTagcloud"}
# Malcolm's ECS-normalised names; none may survive in a field reference
MALCOLM_PREFIXES = ("zeek.", "source.", "destination.", "network.protocol", "rule.", "event.action",
                    "event.result", "event.severity", "related.", "url.", "user_agent.", "file.")
PIPELINE_FIELDS = {"@timestamp", "event.dataset", "event.provider", "event.ingested", "event.kind", "network.bytes",
                   "host.name", "log.file.path"}


def ndjson(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def dashboard_files():
    return sorted(glob.glob(os.path.join(KIBANA, "dashboards", "*.ndjson")))


@pytest.fixture(scope="module")
def data_views():
    views = ndjson(os.path.join(KIBANA, "data-views.ndjson"))
    return {v["id"]: v for v in views}


@pytest.fixture(scope="module")
def bundles():
    return {os.path.basename(f): ndjson(f) for f in dashboard_files()}


def test_space():
    with open(os.path.join(KIBANA, "space.json"), encoding="utf-8") as fh:
        space = json.load(fh)
    assert space["id"] == "malcolm"
    assert set(space) >= {"id", "name", "description", "initials", "color", "disabledFeatures"}
    with open(os.path.join(ROLE, "defaults", "main.yml"), encoding="utf-8") as fh:
        defaults = yaml.safe_load(fh)
    assert defaults["malcolm_space_id"] == space["id"]


def test_data_views(data_views):
    assert {v["attributes"]["title"] for v in data_views.values()} == {"logs-dxdfir.zeek-*", "logs-dxdfir.detections-*"}
    for view in data_views.values():
        assert view["type"] == "index-pattern"
        assert view["attributes"]["timeFieldName"] == "@timestamp"


def test_bundle_shape(bundles, data_views):
    seen = {}
    for name, objs in bundles.items():
        dashboards = [o for o in objs if o["type"] == "dashboard"]
        assert len(dashboards) == 1, name
        assert objs[-1]["type"] == "dashboard", f"{name}: the dashboard comes last"
        for o in objs:
            assert o["type"] in {"search", "dashboard"}, (name, o["type"])
            # a saved search several dashboards use is repeated in each of their files, byte for byte
            if o["id"] in seen:
                assert o["type"] == "search" and seen[o["id"]] == o, f"{o['id']} differs between files"
            seen[o["id"]] = o
            assert o["coreMigrationVersion"] == "8.7.1"
            assert o["managed"] is False
        for s in objs[:-1]:
            refs = {r["name"]: r for r in s["references"]}
            assert refs["kibanaSavedObjectMeta.searchSourceJSON.index"]["id"] in data_views, (name, s["attributes"]["title"])
            source = json.loads(s["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            assert source["query"]["language"] == "kuery"
            assert source["indexRefName"] == "kibanaSavedObjectMeta.searchSourceJSON.index"
            assert s["attributes"]["columns"]
            assert s["attributes"]["sort"] == [["@timestamp", "desc"]]


def test_dashboard_panels(bundles, data_views):
    dashboard_ids = {objs[-1]["id"] for objs in bundles.values()}
    for name, objs in bundles.items():
        dash = objs[-1]
        searches = {o["id"] for o in objs if o["type"] == "search"}
        refs = {r["name"]: r for r in dash["references"]}
        panels = json.loads(dash["attributes"]["panelsJSON"])
        assert panels, name
        indexes = [p["panelIndex"] for p in panels]
        assert len(indexes) == len(set(indexes)), f"{name}: duplicate panelIndex"
        used_refs = set()
        for p in panels:
            assert p["gridData"]["i"] == p["panelIndex"]
            assert p["version"] == "8.7.1"
            if p["type"] == "search":
                ref = refs[p["panelRefName"]]
                assert ref["type"] == "search" and ref["id"] in searches, (name, p["panelRefName"])
                used_refs.add(p["panelRefName"])
            elif p["type"] == "lens":
                attrs = p["embeddableConfig"]["attributes"]
                assert attrs["type"] == "lens"
                assert attrs["visualizationType"] in LENS_TYPES, (name, p["title"], attrs["visualizationType"])
                assert attrs["state"]["query"]["language"] == "kuery"
                layers = attrs["state"]["datasourceStates"]["formBased"]["layers"]
                assert len(layers) == 1
                for layer_id, layer in layers.items():
                    assert set(layer["columnOrder"]) == set(layer["columns"]), (name, p["title"])
                    for col in layer["columns"].values():
                        field = col["sourceField"]
                        assert field == "___records___" or field in PIPELINE_FIELDS or not field.startswith(MALCOLM_PREFIXES), (name, p["title"], field)
                        assert not field.startswith("MALCOLM_")
                    ref_name = f"indexpattern-datasource-layer-{layer_id}"
                    assert attrs["references"] == [{"id": attrs["references"][0]["id"], "name": ref_name, "type": "index-pattern"}]
                    assert attrs["references"][0]["id"] in data_views
                    dash_ref = f"{p['panelIndex']}:{ref_name}"
                    assert refs[dash_ref]["id"] == attrs["references"][0]["id"], (name, p["title"])
                    used_refs.add(dash_ref)
            elif p["type"] == "visualization":
                vis = p["embeddableConfig"]["savedVis"]
                assert vis["type"] in {"markdown", "vega"}, (name, vis["type"])
                if vis["type"] == "markdown":
                    for target in re.findall(r"\(#/view/([0-9a-f-]+)\)", vis["params"]["markdown"]):
                        assert target in dashboard_ids, (name, target)
                else:
                    assert "logs-dxdfir." in vis["params"]["spec"]
            else:
                raise AssertionError(f"{name}: panel type {p['type']}")
        assert used_refs == set(refs), f"{name}: unused or missing dashboard references"
        options = json.loads(dash["attributes"]["optionsJSON"])
        assert options["useMargins"] is True
        assert dash["attributes"]["timeRestore"] is False


def test_no_placeholders_or_malcolm_sources():
    for path in [os.path.join(KIBANA, "space.json"), os.path.join(KIBANA, "data-views.ndjson"), *dashboard_files()]:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        assert "MALCOLM_" not in text, path
        assert "arkime" not in text, path
        assert "_source." not in text, path


def test_elasticsearch_objects():
    pipelines = {os.path.basename(f)[:-5] for f in glob.glob(os.path.join(ES, "ingest_pipelines", "*.json"))}
    components = {os.path.basename(f)[:-5] for f in glob.glob(os.path.join(ES, "component_templates", "*.json"))}
    assert pipelines == components == {"logs-dxdfir.zeek@malcolm", "logs-dxdfir.detections@malcolm"}
    for path in glob.glob(os.path.join(ES, "*", "*.json")):
        with open(path, encoding="utf-8") as fh:
            obj = json.load(fh)
        assert obj["_meta"]["managed_by"] == "byakugan elastic/malcolm", path
        assert isinstance(obj["_meta"]["version"], int), path
    for name in components:
        with open(os.path.join(ES, "component_templates", name + ".json"), encoding="utf-8") as fh:
            tpl = json.load(fh)
        assert tpl["template"]["settings"]["index"]["default_pipeline"] == name
        assert tpl["template"]["mappings"]["properties"]["@timestamp"] == {"type": "date"}
    for name in pipelines:
        with open(os.path.join(ES, "ingest_pipelines", name + ".json"), encoding="utf-8") as fh:
            pipeline = json.load(fh)
        kinds = [next(iter(p)) for p in pipeline["processors"]]
        assert "date" in kinds and kinds[-1] == "pipeline", name
        assert pipeline["processors"][-1]["pipeline"] == {"name": "logs@default-pipeline", "ignore_missing_pipeline": True}
    for stream, component in (("logs-dxdfir.zeek", "logs-dxdfir.zeek@malcolm"), ("logs-dxdfir.detections", "logs-dxdfir.detections@malcolm")):
        with open(os.path.join(ES, "index_templates", stream + ".json"), encoding="utf-8") as fh:
            tpl = json.load(fh)
        assert tpl["index_patterns"] == [stream + "-*"]
        assert tpl["priority"] > 100
        assert tpl["data_stream"] == {}
        assert tpl["composed_of"][-1] == component
        assert {"logs@mappings", "logs@settings", "ecs@mappings"} <= set(tpl["composed_of"])


def test_role_streams_match_pipelines():
    with open(os.path.join(ROLE, "defaults", "main.yml"), encoding="utf-8") as fh:
        defaults = yaml.safe_load(fh)
    for stream in defaults["malcolm_space_streams"]:
        assert os.path.isfile(os.path.join(ES, "ingest_pipelines", stream["pipeline"] + ".json")), stream
        assert os.path.isfile(os.path.join(ES, "index_templates", stream["pattern"].replace("-*", "") + ".json")), stream
    for path in glob.glob(os.path.join(HERE, "ansible", "**", "*.yml"), recursive=True):
        with open(path, encoding="utf-8") as fh:
            assert yaml.safe_load(fh) is not None, path
    with open(os.path.join(ROLE, "meta", "argument_specs.yml"), encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)["argument_specs"]["main"]["options"]
    assert set(spec) == set(defaults)

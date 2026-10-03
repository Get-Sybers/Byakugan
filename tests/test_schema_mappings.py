"""Phase 5 (#134): the Model Mapping layer.

The ir surface as declarations — generated from go/internal/ir/ir.json,
schema-validated, and held to ir.json BOTH ways (lanes, predicates,
artefact classes, spindle identities)."""

import json
import os

import yaml

from byakugan import conform as c
from byakugan import schema_gen

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAPPINGS = os.path.join(_ROOT, "model", "schema", "mappings")


def _load(name):
    return yaml.safe_load(open(os.path.join(MAPPINGS, name), encoding="utf-8"))


def _ir():
    return json.load(open(os.path.join(_ROOT, "go", "internal", "ir", "ir.json"),
                          encoding="utf-8"))


def test_every_ir_lane_has_a_declaration_and_vice_versa():
    ir = _ir()
    declared = {n[:-len(".yaml")] for n in os.listdir(MAPPINGS)
                if n.endswith(".yaml") and n != "routes.yaml"}
    assert declared == set(ir["mappings"])


def test_declarations_regenerate_byte_identical():
    files = schema_gen.render_mappings()
    for rel, want in files.items():
        have = open(os.path.join(_ROOT, "model", "schema", *rel.split("/")),
                    encoding="utf-8").read()
        assert have == want, rel


def test_mapping_declaration_surface():
    doc = _load("l2t_mft.yaml")
    assert doc["source"] == "generated" and doc["artefact_class"] == "mft"
    v = doc["variants"][0]
    assert v["when"] == "l2t_td_create"          # predicate BY NAME only
    assert (v["object"], v["action"]) == ("file", "create")
    assert v["identity"] == "l2t_mft"            # the spindle recipe ref
    assert "file_path" in v["fields"]


def test_split_lane_carries_per_variant_artefact_class():
    doc = _load("plaso_exec_winreg.yaml")
    assert doc["artefact_class"] is None         # not a uniform lane
    by_when = {v["when"]: v["artefact_class"] for v in doc["variants"]}
    assert by_when["plaso_is_amcache"] == "amcache"
    assert by_when["plaso_is_appcompatcache"] == "shimcache"
    assert by_when["plaso_is_userassist_run"] == "userassist"
    assert by_when["plaso_is_bam"] == "registry-hives"


def test_routing_table_carries_recognise_and_skip():
    doc = _load("routes.yaml")
    by_match = {r["match"]: r["lanes"] for r in doc["routes"]}
    assert by_match["_EvtxECmd_Output"]          # routed
    assert by_match["dhcp.json"] == []           # recognised, deliberately unmapped
    assert doc["adapters"]["jlecmd_dest"] == {"adapter": "jlecmd",
                                              "maps": ["jlecmd_dest"]}
    assert doc["evtx_maps"] == list(_ir()["evtx_maps"])


def test_predicates_declared_equals_registered_both_ways():
    ir = _ir()
    whens = set()
    for name in os.listdir(MAPPINGS):
        if not name.endswith(".yaml") or name == "routes.yaml":
            continue
        doc = _load(name)
        whens |= {v["when"] for v in doc["variants"] if v.get("when")}
    assert whens == set(ir["predicate_names"])   # ONE set, both directions


def test_mapping_conform_rules_green():
    assert [f.as_dict() for f in c._RULES["mapping-structure"]()] == []
    assert [f.as_dict() for f in c._RULES["mapping-coverage"]()] == []


def test_mapping_structure_is_a_real_gate(tmp_path, monkeypatch):
    """A doctored declaration (illegal shape / unknown predicate) is a
    finding, not a silent pass."""
    import shutil
    fake = tmp_path / "schema"
    shutil.copytree(os.path.join(_ROOT, "model", "schema"), fake)
    doc = yaml.safe_load(open(fake / "mappings" / "l2t_mft.yaml"))
    doc["variants"][0].pop("fields")
    doc["variants"][0]["when"] = "no_such_predicate"
    (fake / "mappings" / "l2t_mft.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
    monkeypatch.setattr(c, "SCHEMA_DIR", str(fake))
    structure = [f.as_dict() for f in c._RULES["mapping-structure"]()]
    coverage = [f.as_dict() for f in c._RULES["mapping-coverage"]()]
    assert any("fields" in (f.get("message") or "") + (f.get("path") or "")
               for f in structure)
    assert any("no_such_predicate" in (f.get("path") or "") for f in coverage)

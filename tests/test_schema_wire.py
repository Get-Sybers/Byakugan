"""Phase 4 (#133): the Object Model wire layer.

The generated composed schemas (model/schema/wire/*) admit exactly what the
projection emits; wirecheck is count-and-carry over produced bundles; the
R3/R5/R6 conformance follow-ups hold.
"""

import copy
import json
import os

from byakugan import stix, wirecheck
from byakugan import conform as c
from byakugan import schema_gen
from byakugan.exchange.attack_index import load_attack_index
from byakugan.exchange.objects import EVIDENCE_PROPERTIES

from tests.test_stix import _H, _ev, _proc

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIRE = os.path.join(_ROOT, "model", "schema", "wire")


def _load(name):
    return json.load(open(os.path.join(WIRE, name), encoding="utf-8"))


def _small_bundle():
    events = [_proc("P1", image_path=r"C:\a.exe"),
              _ev("file", "create", "F1", ts="2020-01-01T00:00:01Z",
                  file_path=r"C:\a.exe", pid=100)]
    bundle, _stats = stix.project(events, case="c")
    return bundle


# --------------------------------------------------------------------------- #
# the generated relationship schema (D3)
# --------------------------------------------------------------------------- #
def test_relationship_enum_is_closed_and_excludes_generics():
    rel = _load("relationship.schema.json")
    enum = rel["allOf"][1]["properties"]["relationship_type"]["enum"]
    assert len(enum) == 56 and enum[-1] == "indicates"      # 55 verbs + indicates
    for generic in ("related-to", "duplicate-of", "derived-from"):
        assert generic not in enum
    assert "attempted-to-authenticate" in enum              # hyphenation is a MUST


def test_relationship_pair_constraints_are_pair_wise_and_grounded():
    rel = _load("relationship.schema.json")
    by_verb = {b["if"]["properties"]["relationship_type"]["const"]: b["then"]
               for b in rel["allOf"][2:]}
    # a verb with no wire grounding can never appear (then: false), but it
    # stays in the vocabulary enum
    assert False in by_verb.values()
    # byakugan's own extension-typed edge grounds even though the catalogue
    # pair (command, script) does not: process --executed--> file
    executed = by_verb["executed"]
    assert any("^(file|x-car-inferred-node)--" == b["properties"]["target_ref"]["pattern"]
               and "process" in b["properties"]["source_ref"]["pattern"]
               for b in executed["anyOf"])
    # indicates is the airway edge: indicator -> attack-pattern (referenced)
    ind = by_verb["indicates"]
    assert ind["properties"]["source_ref"]["pattern"] == "^indicator--"
    assert ind["properties"]["target_ref"]["pattern"] == "^attack-pattern--"


def test_wire_type_inventory_is_the_emitted_surface():
    objs = _load("objects.schema.json")
    types = objs["properties"]["type"]["enum"]
    assert "attack-pattern" not in types and "marking-definition" not in types
    assert {"x-car-thread", "x-car-record", "x-car-inferred-node",
            "observed-data", "relationship", "sighting", "indicator",
            "extension-definition"} <= set(types)
    assert types == schema_gen.harvest_wire_types()


# --------------------------------------------------------------------------- #
# wirecheck: count-and-carry over produced bundles
# --------------------------------------------------------------------------- #
def test_produced_bundle_carries_zero_findings():
    assert wirecheck.run(_small_bundle()) == []


def test_wirecheck_rules_fire_on_doctored_content():
    b = copy.deepcopy(_small_bundle())
    sco = next(o for o in b["objects"] if o["type"] == "file")
    sco["x_car_bogus"] = 1                                  # outside the closed list
    b["objects"].append({"type": "attack-pattern",
                         "id": "attack-pattern--00000000-0000-4000-8000-000000000000"})
    b["objects"].append({"type": "marking-definition",
                         "id": "marking-definition--00000000-0000-4000-8000-000000000001"})
    b["objects"].append({"type": "x-car-unknown",
                         "id": "x-car-unknown--00000000-0000-4000-8000-000000000002"})
    sco2 = next(o for o in b["objects"] if o["type"] == "process")
    sco2["object_marking_refs"] = ["marking-definition--00000000-0000-4000-8000-000000000001"]
    tally = wirecheck.tally(wirecheck.run(b))
    assert tally["airway"] == 1
    assert tally["third-party-marking"] == 2                # member + the ref
    assert tally["wire-type"] == 1
    assert tally["x-property"] == 2                         # bogus prop + x- type
    assert "wire-schema" in tally                           # the bogus prop also
    #                                       fails the composed unevaluated gate


def test_wirecheck_id_namespace_gate_recomputes_catalogue_ids():
    b = copy.deepcopy(_small_bundle())
    b["objects"].append({"type": "indicator", "spec_version": "2.1",
                         "id": "indicator--00000000-0000-4000-8000-000000000009",
                         "created": stix.EPOCH, "modified": stix.EPOCH,
                         "pattern": "x", "pattern_type": "car",
                         "valid_from": stix.EPOCH,
                         "x_car_analytic": "CAR-2013-02-003"})
    tally = wirecheck.tally(wirecheck.run(b))
    assert tally["id-namespace"] == 1


def test_related_to_is_rejected_by_the_closed_enum():
    b = copy.deepcopy(_small_bundle())
    b["objects"].append({
        "type": "relationship", "spec_version": "2.1",
        "id": "relationship--00000000-0000-4000-8000-000000000003",
        "created": "2020-01-01T00:00:00.000Z", "modified": "2020-01-01T00:00:00.000Z",
        "relationship_type": "related-to",
        "source_ref": next(o["id"] for o in b["objects"] if o["type"] == "process"),
        "target_ref": next(o["id"] for o in b["objects"] if o["type"] == "file")})
    findings = wirecheck.run(b)
    assert any(f.rule == "wire-schema" and f.object_id.startswith("relationship--")
               for f in findings)


# --------------------------------------------------------------------------- #
# R5: an unmappable verb is tallied, never emitted as a generic
# --------------------------------------------------------------------------- #
def test_unmapped_verb_is_tallied_never_emitted():
    events = [_proc("P1", image_path=r"C:\a.exe"),
              _proc("P2", image_path=r"C:\b.exe")]
    edge = {"class": "declared", "relationship": "", "source_host": _H,
            "source_object": "process", "source_guid": "P1",
            "target_object": "process", "target_guid": "P2",
            "confidence": "definitive", "method": "test"}
    bundle, stats = stix.project(events, edges=[edge], case="c")
    assert stats["relationships_unmapped"] == 1
    assert [o for o in bundle["objects"] if o["type"] == "relationship"] == []


# --------------------------------------------------------------------------- #
# R3: catalogue `modified` folds BOTH pins
# --------------------------------------------------------------------------- #
def test_catalogue_modified_is_the_later_of_both_pins():
    index = load_attack_index()
    got = stix.catalogue_modified(index)
    assert got == max(stix.CAR_CORPUS["modified"], index.modified)

    class _Stale:
        modified = "2000-01-01T00:00:00.000Z"

    class _Newer:
        modified = "2099-01-01T00:00:00.000Z"

    assert stix.catalogue_modified(_Stale()) == stix.CAR_CORPUS["modified"]
    assert stix.catalogue_modified(_Newer()) == "2099-01-01T00:00:00.000Z"


# --------------------------------------------------------------------------- #
# R6: the standing harvest gate
# --------------------------------------------------------------------------- #
def test_x_property_registry_is_one_list_everywhere():
    harvested = schema_gen.harvest_x_car()
    assert harvested == sorted(EVIDENCE_PROPERTIES)
    overlay = _load("objects.schema.json")["$defs"]["overlay"]["properties"]
    assert sorted(k for k in overlay if k.startswith("x_car_")) == harvested
    assert [f.as_dict() for f in c._RULES["x-property-registry"]()] == []


def test_wire_schemas_conform_rule_green():
    assert [f.as_dict() for f in c._RULES["wire-schemas"]()] == []


def test_full_bundle_validates_against_the_composed_bundle_schema():
    v = wirecheck._load_validators()  # noqa: SLF001 — the consumers' entry point
    assert list(v["bundle"].iter_errors(_small_bundle())) == []


def test_unmapped_verb_with_inferred_end_strands_no_node():
    """Review follow-up: the verb gate runs BEFORE end resolution, so a
    dropped edge never leaves a dangling x-car-inferred-node on the wire."""
    events = [_proc("P1", image_path=r"C:\a.exe")]
    edge = {"class": "derived", "relationship": "", "source_host": _H,
            "source_object": "process", "source_guid": "GHOST",
            "inferred_end": "source",
            "target_object": "process", "target_guid": "P1",
            "confidence": "inferred", "method": "test"}
    bundle, stats = stix.project(events, edges=[edge], case="c")
    assert stats["relationships_unmapped"] == 1
    assert [o for o in bundle["objects"] if o["type"] == "x-car-inferred-node"] == []


def test_wire_schemas_crawl_covers_every_dispatch_branch(tmp_path, monkeypatch):
    """Review follow-up: the $ref crawl is transitive over every type leg —
    a typo'd vendor path in a non-identity branch is a finding."""
    import shutil
    fake = tmp_path / "schema"
    shutil.copytree(os.path.join(_ROOT, "model", "schema"), fake)
    p = fake / "wire" / "objects.schema.json"
    doc = json.loads(p.read_text())
    doc["$defs"]["process"]["allOf"][0]["$ref"] = "../vendor/oasis/observables/no-such.json"
    p.write_text(json.dumps(doc))
    monkeypatch.setattr(c, "SCHEMA_DIR", str(fake))
    monkeypatch.setattr(wirecheck, "SCHEMA_DIR", str(fake))
    monkeypatch.setattr(wirecheck, "WIRE_DIR", str(fake / "wire"))
    monkeypatch.setattr(wirecheck, "_validators", None)
    try:
        findings = [f.as_dict() for f in c._RULES["wire-schemas"]()]
    finally:
        wirecheck._validators = None            # never leak the doctored cache
    assert any("no-such.json" in (f.get("path") or "") for f in findings)

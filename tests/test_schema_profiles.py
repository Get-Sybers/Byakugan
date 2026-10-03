"""Phase 6 (#135): the Parser Profile layer.

One declaration per (parser, artefact class) — the record surface as data,
generated from the curated seed (mined in-house structs) joined with the
reviewed sources/*.yaml lane surfaces, and gated: bound mapping closure ⊆
the class's evidences."""

import os

import yaml

from byakugan import conform as c
from byakugan import schema_gen

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES = os.path.join(_ROOT, "model", "schema", "profiles")


def _load(name):
    return yaml.safe_load(open(os.path.join(PROFILES, name), encoding="utf-8"))


def test_profiles_regenerate_byte_identical():
    for rel, want in schema_gen.render_profiles().items():
        have = open(os.path.join(_ROOT, "model", "schema", *rel.split("/")),
                    encoding="utf-8").read()
        assert have == want, rel


def test_every_laned_family_has_a_profile():
    seed = yaml.safe_load(open(os.path.join(_ROOT, "model", "schema",
                                            "classes-seed.yaml")))["families"]
    covered = {(_load(n) or {}).get("artefact_class")
               for n in os.listdir(PROFILES) if n.endswith(".yaml")}
    for fam, spec in seed.items():
        if not spec.get("held") and (spec.get("lanes") or []):
            assert fam in covered, fam


def test_in_house_struct_rides_with_grounding_and_types():
    doc = _load("prefetch-dump--prefetch.yaml")
    assert doc["parser"]["in_house"] and doc["transport"] == "jsonl"
    by_name = {f["name"]: f for f in doc["fields"]}
    assert by_name["RunCount"]["type"] == "int"
    assert by_name["LastRun"]["type"] == "timestamp"
    assert all(f.get("at", "").startswith("gowindowlicker ")
               for f in doc["fields"])                # file:line grounding
    # the reviewed lane surface decides the binding
    assert by_name["Executable"]["binds"] == "mapping"


def test_external_surface_is_the_reviewed_lane_surface():
    doc = _load("plaso--mft.yaml")
    assert doc["parser"]["in_house"] is False
    names = {f["name"] for f in doc["fields"]}
    assert {"Timestamp", "name", "filename", "image_hostname"} <= names
    by_name = {f["name"]: f for f in doc["fields"]}
    assert by_name["Timestamp"]["type"] == "timestamp"
    # the NTFS entry reference is what the l2t_mft spindle recipe hashes
    assert by_name["file_reference"]["binds"] == "identity"


def test_csv_transports_are_all_string():
    for name in ("recmd--registry-hives.yaml", "jlecmd--lnk-jumplists.yaml"):
        doc = _load(name)
        assert doc["transport"] == "csv"
        assert all(f["type"] == "string" for f in doc["fields"])


def test_coverage_debt_is_declared_never_silent():
    journal = _load("godaemonhunter--unrouted.yaml")
    assert journal["artefact_class"] is None and journal["lanes"] == []
    assert journal["coverage_debt"] and "held" in journal["coverage_debt"].lower()
    memory = _load("anamnesis--unrouted.yaml")
    assert memory["artefact_class"] is None
    ese = _load("ese-dump--srum.yaml")
    assert "dynamic" in ese                       # schema-dynamic remainder, named


def test_alternates_declare_the_shared_class():
    goevtx = _load("goevtx--evtx.yaml")
    assert goevtx["artefact_class"] == "evtx" and goevtx["lanes"] == []
    assert goevtx["alternate_for"] == "EvtxECmd"
    gomft = _load("gomft--mft.yaml")
    assert gomft["artefact_class"] == "mft"
    # the literal emitted JSON key, encoder escaping and all
    assert any(f["name"] == "SI<FN" for f in gomft["fields"])


def test_split_lane_profiles_carry_per_variant_surfaces():
    """Review follow-up: classes sharing a split lane get PER-VARIANT field
    surfaces from the ir closure, never one whole-lane copy."""
    am = {f["name"] for f in _load("plaso--amcache.yaml")["fields"]}
    shim = {f["name"] for f in _load("plaso--shimcache.yaml")["fields"]}
    ua = {f["name"] for f in _load("plaso--userassist.yaml")["fields"]}
    assert am != shim != ua and am != ua
    assert "company_name" in am and "company_name" not in shim
    # the shared (process, execute) native keys ride every sibling class;
    # the CONSUMED distinction shows in the binds: userassist's recipe and
    # mapping read value_name, amcache's never do
    ua_binds = {f["name"]: f["binds"] for f in _load("plaso--userassist.yaml")["fields"]}
    am_binds = {f["name"]: f["binds"] for f in _load("plaso--amcache.yaml")["fields"]}
    assert ua_binds["value_name"] == "identity"
    assert am_binds.get("value_name", "surplus") == "surplus"


def test_identity_binds_fire_from_the_spindle_recipes():
    """Review follow-up: the identity bind is a live path — a recipe's
    native.<key> targets and the raw->car provenance both resolve."""
    mft = {f["name"]: f["binds"] for f in _load("plaso--mft.yaml")["fields"]}
    assert mft["file_reference"] == "identity"        # native.file_reference
    pf = {f["name"]: f["binds"] for f in _load("plaso--prefetch.yaml")["fields"]}
    assert pf["executable"] == "identity"             # raw -> car exe (recipe input)
    assert pf["prefetch_hash"] == "identity"          # native.prefetch_hash


def test_profile_conform_rules_green():
    assert [f.as_dict() for f in c._RULES["profile-structure"]()] == []
    assert [f.as_dict() for f in c._RULES["profile-coverage"]()] == []


def test_profile_coverage_is_a_real_gate(tmp_path, monkeypatch):
    """A profile whose lane binds a closure outside its class's evidences is
    a finding — the design's subset gate, exercised."""
    import shutil
    fake = tmp_path / "schema"
    shutil.copytree(os.path.join(_ROOT, "model", "schema"), fake)
    p = fake / "profiles" / "plaso--mft.yaml"
    doc = yaml.safe_load(open(p))
    doc["lanes"].append("l2t_usnjrnl")            # another class's lane
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    monkeypatch.setattr(c, "SCHEMA_DIR", str(fake))
    findings = [f.as_dict() for f in c._RULES["profile-coverage"]()]
    assert any("l2t_usnjrnl" in (f.get("path") or "") for f in findings)
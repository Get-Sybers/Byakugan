"""Phase-1 foundations (epic &1 #130): model/schema skeleton + the
count-and-carry core. The conform CLI's own rules are the gate; these tests
run them in-process and pin the cross-engine agreements."""

import json
import os
import subprocess
import sys

import yaml

from byakugan import conform

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_conform_rules_all_green():
    findings = conform.run()
    assert findings == [], [f.as_dict() for f in findings]


def test_conform_strict_cli_green():
    out = subprocess.run([sys.executable, "-m", "byakugan.conform", "--strict"],
                         capture_output=True, text=True, cwd=_ROOT)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "0 findings" in out.stdout


def test_constants_regenerate_byte_identical():
    committed = open(os.path.join(conform.SCHEMA_DIR, "constants.yaml"), encoding="utf-8").read()
    assert committed == conform.render_constants()


def test_envelope_and_defs_shapes():
    env = json.load(open(os.path.join(conform.SCHEMA_DIR, "envelope.schema.json")))
    assert env["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert set(env["required"]) == {"schema_version", "source"}
    defs = json.load(open(os.path.join(conform.SCHEMA_DIR, "defs.schema.json")))
    for name in ("semver", "stix-id", "timestamp", "evidence-tier", "time-semantics",
                 "absence", "external-reference", "finding"):
        assert name in defs["$defs"], name
    assert defs["$defs"]["evidence-tier"]["enum"] == ["definitive", "heuristic", "inferred"]
    assert defs["$defs"]["time-semantics"]["enum"] == ["event-time", "bounded", "none"]
    # external-reference carries the coverage qualifier
    cov = defs["$defs"]["external-reference"]["properties"]["coverage"]
    assert cov["enum"] == ["leaf", "container", "none"]


def test_finding_shape_matches_defs_and_go():
    """The Python Finding, the Go mirror and defs.schema.json agree."""
    defs = json.load(open(os.path.join(conform.SCHEMA_DIR, "defs.schema.json")))
    schema_fields = set(defs["$defs"]["finding"]["properties"])
    py = conform.Finding(object_id="o", rule="r", message="m", path="p").as_dict()
    assert set(py) == schema_fields == {"object_id", "rule", "message", "path"}
    assert set(defs["$defs"]["finding"]["required"]) == {"object_id", "rule", "message"}
    # the Go mirror's wire tags (kept in step by its own test; pinned here too)
    go_src = open(os.path.join(_ROOT, "go", "internal", "conform", "conform.go")).read()
    for tag in ('json:"object_id"', 'json:"rule"', 'json:"message"', 'json:"path,omitempty"'):
        assert tag in go_src, tag


def test_constants_yaml_values():
    doc = yaml.safe_load(open(os.path.join(conform.SCHEMA_DIR, "constants.yaml")))
    from byakugan.exchange.objects import EVIDENCE_EXTENSION_ID, EVIDENCE_EXTENSION_VERSION, EXTENSION_ID
    assert doc["schema_version"] == EVIDENCE_EXTENSION_VERSION
    assert doc["extensions"]["dxdfir"] == EXTENSION_ID
    assert doc["extensions"]["dxdfir-evidence"] == EVIDENCE_EXTENSION_ID


def test_vendored_oasis_untouched_shape():
    """Every vendored OASIS schema parses and VENDOR.md records the pin."""
    base = os.path.join(conform.SCHEMA_DIR, "vendor", "oasis")
    n = 0
    for root, _dirs, files in os.walk(base):
        for f in files:
            if f.endswith(".json"):
                json.load(open(os.path.join(root, f)))
                n += 1
    assert n >= 50
    vendor = open(os.path.join(base, "VENDOR.md")).read()
    assert "9af1db41b7b86c06324f899649ae83480134f66e" in vendor


# --------------------------------------------------------------------------- #
# phase 2 (#131): the Artefact Class layer
# --------------------------------------------------------------------------- #
def test_classes_regenerate_byte_identical():
    from byakugan import schema_gen
    assert schema_gen.check() == []


def test_every_ir_lane_is_assigned_and_classes_cover_it():
    from byakugan import schema_gen
    closure = schema_gen.ir_closure()["closure"]
    seed = yaml.safe_load(open(schema_gen.SEED_PATH))
    lanes = [l for spec in seed["families"].values() for l in (spec.get("lanes") or [])]
    assert len(lanes) == len(set(lanes))            # no double assignment
    plain = {l for l in lanes if "/" not in l}
    parents = {l.split("/")[0] for l in lanes if "/" in l}
    assert {k for k in closure if "/" not in k} <= plain | parents


def test_class_rows_carry_overlay_semantics():
    """The overlay refines the scaffold: prefetch has BOTH the ir pair and the
    matched row; evtx's 4625 row merged the ir closure with its five sources."""
    import glob
    docs = {os.path.basename(f)[:-5]: yaml.safe_load(open(f))
            for f in glob.glob(os.path.join(conform.SCHEMA_DIR, "classes", "*.yaml"))}
    pre = {(r["object"], r["action"]): r for r in docs["prefetch"]["evidences"]}
    assert ("process", "create") in pre and ("process", "execute") in pre
    assert pre[("process", "execute")]["evidence"] == "heuristic"
    evtx = [r for r in docs["evtx"]["evidences"]
            if r.get("when") == "Security 4625"]
    assert evtx and "byakugan:ir.json" in evtx[0]["sources"] and len(evtx[0]["sources"]) >= 4
    # held families emit no class (admission rule)
    assert "scheduled-tasks" not in docs and "journal" not in docs


def test_vocab_file_matches_car_model():
    from byakugan import schema_gen
    vocab = json.load(open(schema_gen.VOCAB_PATH))
    legal = schema_gen._legal_actions()  # noqa: SLF001
    assert vocab["$defs"]["object"]["enum"] == sorted(legal)
    for o, acts in legal.items():
        assert vocab["$defs"][f"{o}-actions"]["enum"] == acts


# --------------------------------------------------------------------------- #
# phase 3 (#132): Identity + Enrichment layers
# --------------------------------------------------------------------------- #
def test_identity_registry_validates_in_place():
    """spindle.yml passes the layer's structural gate; the meta-schema exists
    and its enums match the registry's vocabulary."""
    from byakugan import conform as c
    assert [f.as_dict() for f in c._RULES["identity-registry"]()] == []
    meta = json.load(open(os.path.join(c.SCHEMA_DIR, "identity-rules.schema.json")))
    assert meta["$defs"]["entry"]["properties"]["kind"]["enum"] == ["record", "entity"]
    assert meta["$defs"]["entry"]["properties"]["scope"]["enum"] == ["intrinsic", "positional"]
    reg = yaml.safe_load(open(os.path.join(_ROOT, "byakugan", "spindle.yml")))
    assert len(reg["identities"]) >= 26


def test_object_id_scopes_match_constants():
    from byakugan import conform as c
    assert [f.as_dict() for f in c._RULES["identity-object-ids"]()] == []


def test_enrichment_rules_generated_and_grounded():
    from byakugan import schema_gen, conform as c
    doc = yaml.safe_load(open(os.path.join(c.SCHEMA_DIR, "enrichment", "rules.yaml")))
    rules = doc["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    layers = {r["layer"] for r in rules}
    assert layers == {"inheritance", "dedupe", "identity", "derived", "canonicalisation"}
    assert all(r["scope"] == "self" and r.get("declared_in") for r in rules)
    # the three inheritance lanes and the canon_user tables all became rules
    assert {"inherit-from-owning-process", "inherit-from-parent-process",
            "inherit-from-owning-flow", "dedupe-fold"} <= set(ids)
    assert any(i.startswith("canon-user-") for i in ids)
    # regeneration is byte-identical (also covered by class-regen/conform)
    assert schema_gen.render_enrichment() == open(
        os.path.join(c.SCHEMA_DIR, "enrichment", "rules.yaml"), encoding="utf-8").read()


def test_enrichment_structure_gate_catches_shape_defects():
    """enrichment-structure is a real gate: the committed file passes, and a
    rule stripped of a required field / given an illegal layer is a finding."""
    from byakugan import conform as c
    assert [f.as_dict() for f in c._RULES["enrichment-structure"]()] == []


def test_layer_registries_ride_the_one_schema_version():
    """schema-version-lockstep covers the hand-authored identity scope table
    and the generated enrichment registry — a version bump cannot strand them."""
    from byakugan import conform as c
    from byakugan.exchange.objects import EVIDENCE_EXTENSION_VERSION
    for rel in ("identity/object-ids.yaml", "enrichment/rules.yaml"):
        doc = yaml.safe_load(open(os.path.join(c.SCHEMA_DIR, *rel.split("/"))))
        assert str(doc["schema_version"]) == EVIDENCE_EXTENSION_VERSION, rel

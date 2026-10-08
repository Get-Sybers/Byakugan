"""The spindle registry exists twice — `byakugan/spindle.yml` (what spindle.py,
`spindle --check` and the model/spindle snapshot read) and the IR's `spindle`
section (what go/internal/authoring/ir_sections.go declares and the engine
mints from). The YAML is the superset: it also carries the `memory_*` external
forms the Anamnesis passthrough brings in, which the engine never mints. For
the shared part nothing else holds the two statements together; this test
does. Edit both.
"""
import json
import os

import yaml

_ROOT = os.path.join(os.path.dirname(__file__), "..")
_IR = os.path.join(_ROOT, "go", "internal", "ir", "ir.json")
_YML = os.path.join(_ROOT, "byakugan", "spindle.yml")


def _ir() -> dict:
    with open(_IR, encoding="utf-8") as fh:
        return json.load(fh)["spindle"]


def _yml() -> dict:
    with open(_YML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_identities_match_the_ir():
    ir, reg = _ir()["identities"], _yml()["identities"]
    assert set(ir) == set(reg)
    for name, spec in ir.items():
        for key in ("object", "kind", "scope", "version"):
            assert reg[name][key] == spec[key], (name, key)


def test_engine_external_forms_match_the_ir():
    ir, reg = _ir()["external"], _yml()["external"]
    assert set(ir) <= set(reg), sorted(set(ir) - set(reg))
    for name, spec in ir.items():
        assert reg[name]["form"] == spec["form"], name
        assert reg[name]["golden"]["object"] == spec["object"], name
    # the YAML-only forms are exactly the memory passthrough's — the engine mints none of them
    assert all(n.startswith("memory_") for n in set(reg) - set(ir)), \
        sorted(n for n in set(reg) - set(ir) if not n.startswith("memory_"))

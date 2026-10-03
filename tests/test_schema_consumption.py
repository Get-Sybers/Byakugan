"""Phase 7 (#136): the Python graph engine consumes the one schema.

schemadata resolution, the count-and-carry row gate at load, the elastic
drift gates as conform rules, and the named check-pass conformance table
both engines read."""

import json
import os

from byakugan import conform as c
from byakugan import schemadata

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_schema_dir_resolution_order(tmp_path, monkeypatch):
    # repo checkout wins by default
    assert schemadata.schema_dir() == os.path.join(_ROOT, "model", "schema")
    # explicit override wins over everything
    fake = tmp_path / "pinned"
    (fake / "wire").mkdir(parents=True)
    monkeypatch.setenv("BYAKUGAN_SCHEMA_DIR", str(fake))
    assert schemadata.schema_dir() == str(fake)
    # a bad override fails loud, never falls through silently
    monkeypatch.setenv("BYAKUGAN_SCHEMA_DIR", str(tmp_path / "nope"))
    import pytest
    with pytest.raises(SystemExit):
        schemadata.schema_dir()


def test_packaged_schema_symlink_and_package_data():
    link = os.path.join(_ROOT, "byakugan", "_schema")
    assert os.path.islink(link)
    assert os.path.realpath(link) == os.path.realpath(
        os.path.join(_ROOT, "model", "schema"))
    pyproject = open(os.path.join(_ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert '"_schema/wire/*.json"' in pyproject


def test_load_gate_tallies_nonconforming_rows(tmp_path):
    from byakugan.elastic import load as elload
    src = tmp_path / "case" / "host"
    src.mkdir(parents=True)
    rows = [
        {"car_object": "process", "car_action": "create", "guid": "P1",
         "timestamp": "2020-01-01T00:00:00Z", "source_host": "h",
         "source_artefact": "evtx_sysmon", "exe": "a.exe"},
        # outside the closed vocabulary: tallied, still loaded
        {"car_object": "process", "car_action": "frobnicate", "guid": "P2",
         "timestamp": "2020-01-01T00:00:01Z", "source_host": "h",
         "source_artefact": "evtx_sysmon", "exe": "b.exe"},
    ]
    with open(src / "car_process.jsonl", "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    out = elload.project_tree(str(tmp_path / "case"), [str(src)], "default")
    stats = out["per_source"]["host"]
    assert stats["records"] == 2                    # count-and-carry: both load
    assert stats["nonconforming"] == 1
    # the bucket key is the CONSTRAINT (path + keyword), never the value —
    # a thousand distinct bad values stay one bucket
    (key,) = out["nonconforming"]
    assert "car_action" in key and key.endswith("enum")
    assert "frobnicate" not in key


def test_conformance_table_is_generated_and_complete():
    table = json.load(open(os.path.join(_ROOT, "model", "schema",
                                        "conformance.json"), encoding="utf-8"))
    committed = open(os.path.join(_ROOT, "model", "schema", "conformance.json"),
                     encoding="utf-8").read()
    assert committed == c.render_conformance()
    names = {e["name"] for e in table["checks"]}
    # every registered python rule is listed…
    assert set(c._RULES) <= names
    # …and the table never claims a python rule that does not run
    python_rules = {e["name"] for e in table["checks"]
                    if e["engine"] == "python"
                    and e["command"].endswith("--strict")}
    assert python_rules == set(c._RULES)
    # the Go gates ride the same table (go/internal/conform reads it back)
    go_names = {e["name"] for e in table["checks"] if e["engine"] == "go"}
    assert go_names == {"gen-ir-check", "registry-against-ir", "finding-wire-parity"}
    go_src = open(os.path.join(_ROOT, "go", "internal", "conform", "conform.go"),
                  encoding="utf-8").read()
    for name in go_names:
        assert f'"{name}"' in go_src


def test_phase7_conform_rules_green():
    for rule in ("row-gate", "elastic-contract", "elastic-rendered",
                 "conformance-table"):
        assert [f.as_dict() for f in c._RULES[rule]()] == [], rule

"""Unit coverage for the CAR run-through over a materialised CAR tree (no
backend, no submodule — the gate reads car_<object>.jsonl; the vocabulary the
engine model supplies is stubbed here so the tally logic is tested in isolation)."""
import json

import pytest

from byakugan import verify


def _write(car_dir, source, obj, rows):
    d = car_dir / source
    d.mkdir(parents=True, exist_ok=True)
    (d / f"car_{obj}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


def _row(obj, action, artefact="evtx_sysmon", **fields):
    return {"car_object": obj, "timestamp": "2020-01-01T00:00:00Z", "car_action": action,
            "guid": f"{obj}-1", "owning_guid": "", "link_confidence": "definitive",
            "source_artefact": artefact, "source_host": "PC1", "native": {}, **fields}


def _failures(c):
    return [line for line in c.lines if line.strip().startswith("✗")]


@pytest.fixture(autouse=True)
def _vocab(monkeypatch):
    # the vocabulary comes from the engine's own model (carmodel, a submodule);
    # the tally logic is tested without it.
    monkeypatch.setattr(verify, "_model_actions",
                        lambda: {"process": {"create", "terminate"}, "flow": {"start", "end"}})


def test_populated_sane_tree_passes(tmp_path):
    _write(tmp_path, "sysmon", "process", [
        _row("process", "create", command_line="cmd.exe /c whoami", sid="S-1-5-18", pid="4536"),
        _row("process", "terminate", pid="0x11b8"),          # the hex PID encoding is numeric too
    ])
    _write(tmp_path, "sysmon", "flow", [
        _row("flow", "start", src_ip="10.0.0.1", dest_ip="fe80::1", dest_port="445")])
    _write(tmp_path, "sysmon", "relationships", [{
        "id": 1, "timestamp": "2020-01-01T00:00:00Z", "source_host": "PC1",
        "relationship": "created", "source_object": "process", "source_guid": "process-1",
        "target_object": "flow", "target_guid": "flow-1", "confidence": "definitive", "method": "pid"}])
    c = verify.run(str(tmp_path))
    assert c.failed == 0, _failures(c)
    assert c.passed > 0
    # every object without rows is reported NOT EXERCISED, never failed
    assert c.skipped == len(verify._OBJECTS) - 2
    assert c.os_families_covered == 1 and c.os_families_total == 5


def test_unpopulated_and_insane_values_fail(tmp_path):
    _write(tmp_path, "s", "process", [
        _row("process", "create", artefact="", command_line="x", sid="not-a-sid", pid="abc"),
        _row("process", "terminate"),
        _row("process", "delete"),                             # not in the model's vocabulary
    ])
    _write(tmp_path, "s", "flow", [
        # 999.999.999.999 is numeric-looking but not a real IPv4 — a charset regex
        # would wrongly pass it; the ipaddress-based check must reject it.
        _row("flow", "start", src_ip="999.999.999.999", dest_ip="::1", dest_port="70000")])
    c = verify.run(str(tmp_path))
    failed = _failures(c)
    assert any("source_artefact" in line for line in failed)
    assert any("vocabulary" in line for line in failed)
    assert any("Windows SID" in line for line in failed)
    assert any("pid is numeric" in line for line in failed)
    assert any("src_ip" in line for line in failed)
    assert any("dest_port" in line for line in failed)
    assert not any("dest_ip" in line for line in failed)       # ::1 is a valid literal
    assert c.failed == 6


def test_relationship_edges_are_checked(tmp_path):
    _write(tmp_path, "s", "process", [_row("process", "create", command_line="x")])
    _write(tmp_path, "s", "relationships", [
        {"relationship": "created", "source_guid": "a", "target_guid": "", "confidence": "definitive"},
        {"relationship": "", "source_guid": "a", "target_guid": "b", "confidence": "guessed"},
        # not a verb the model declares anywhere
        {"relationship": "obliterated", "source_guid": "a", "target_guid": "b",
         "confidence": "definitive"},
        # an association property name outside the registry; properties not a mapping
        {"relationship": "accessed", "source_guid": "a", "target_guid": "b",
         "confidence": "definitive", "properties": {"granted": 1}},
        {"relationship": "accessed", "source_guid": "a", "target_guid": "b",
         "confidence": "definitive", "properties": "0x1010"},
        # an unknown class
        {"relationship": "created", "source_guid": "a", "target_guid": "b",
         "confidence": "definitive", "class": "guessed"},
    ])
    c = verify.run(str(tmp_path))
    failed = _failures(c)
    assert any("source and target guid" in line for line in failed)
    assert any("edge has a verb" in line for line in failed)
    assert any("declared confidence" in line for line in failed)
    assert any("verb is one the model declares" in line for line in failed)
    assert any("registry-declared" in line for line in failed)
    assert any("mapping or null" in line for line in failed)
    assert any("class in" in line for line in failed)


def test_relationship_derived_class_confidence_is_open_but_never_empty(tmp_path):
    _write(tmp_path, "s", "process", [_row("process", "create", command_line="x")])
    _write(tmp_path, "s", "relationships", [
        # a reconstruct edge: derived, confidence `inferred` — legal (open word)
        {"relationship": "created", "source_guid": "A1", "target_guid": "user_session-0x51ca9",
         "confidence": "inferred", "class": "derived", "method": "luid"},
        # the #108 handle facts on a declared edge: registry-named keys — legal
        {"relationship": "accessed", "source_guid": "p", "target_guid": "f",
         "confidence": "definitive", "properties": {"access_level": 1179785, "handle_value": 4}},
    ])
    c = verify.run(str(tmp_path))
    assert c.failed == 0, _failures(c)
    # but an empty derived confidence is a failure
    _write(tmp_path, "s", "relationships", [
        {"relationship": "created", "source_guid": "a", "target_guid": "b",
         "confidence": "", "class": "derived"}])
    failed = _failures(verify.run(str(tmp_path)))
    assert any("derived edge names its confidence" in line for line in failed)


def test_empty_tree_fails_preflight_and_main_exits_2(tmp_path):
    c = verify.run(str(tmp_path))
    assert c.passed == 0 and c.failed == 2                     # no files, no timeline rows
    assert c.skipped == len(verify._OBJECTS) + 1               # every object + relationships
    assert verify.main([str(tmp_path)]) == 2


def test_main_exit_codes(tmp_path, capsys):
    _write(tmp_path, "s", "registry", [_row("registry", "add", key="HKLM\\x")])
    assert verify.main([str(tmp_path)]) == 0
    assert "CAR run-through passed" in capsys.readouterr().out
    _write(tmp_path, "s", "registry", [_row("registry", "add", artefact="")])
    assert verify.main([str(tmp_path)]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_load_rows_spans_sources_and_skips_bad_lines(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "car_file.jsonl").write_text('{"guid": "1"}\n\nnot json\n[1, 2]\n')
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "car_file.jsonl").write_text('{"guid": "2"}\n')
    assert [r["guid"] for r in verify.load_rows(str(tmp_path), "file")] == ["1", "2"]
    assert verify.load_rows(str(tmp_path), "flow") == []


def test_value_helpers():
    assert verify._int("4536") == 4536 and verify._int("0x11b8") == 4536
    assert verify._int("abc") is None and verify._int("") is None
    assert verify.empty(None) and verify.empty("  ") and not verify.empty("0")
    assert verify.has_term("anamnesis_memory_pslist", "memory")
    assert not verify.has_term("memoryless", "memory")
    assert verify._is_ip_literal("10.0.0.1") and verify._is_ip_literal("fe80::1")
    assert not verify._is_ip_literal("999.999.999.999") and not verify._is_ip_literal("12345")

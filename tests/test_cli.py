"""The `byakugan` command (cli.py): the env-driven sub-tools the container
contract drives — build, timeline, verify, car-vocab — each printing exactly
one JSON summary line on stdout with the framework's exit codes, and the argv
pass-through to the engine's own CLIs."""
import json
import os
import subprocess
import sys

import pytest

from byakugan import cli, verify
from go_engine import _binary
from processed_fixtures import write_framework_tree


def _write(car_dir, source, obj, rows):
    d = car_dir / source
    d.mkdir(parents=True, exist_ok=True)
    (d / f"car_{obj}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


def _row(obj, action, artefact="evtx_sysmon", **fields):
    return {"car_object": obj, "timestamp": "2020-01-01T00:00:00Z", "car_action": action,
            "guid": f"{obj}-1", "owning_guid": "", "link_confidence": "definitive",
            "source_artefact": artefact, "source_host": "PC1", "native": {}, **fields}


def _summary(capsys):
    """The one stdout line (parsed) and stderr."""
    captured = capsys.readouterr()
    lines = [line for line in captured.out.splitlines() if line.strip()]
    assert len(lines) == 1, captured.out                    # stdout is exactly one line
    return json.loads(lines[0]), captured.err


def _model_present() -> bool:
    try:
        from byakugan import carmodel
        carmodel.load()
    except Exception:                                        # noqa: BLE001 — submodule absent
        return False
    return True


@pytest.fixture
def env(monkeypatch, tmp_path):
    """A clean BYAKUGAN_* environment whose default output dir is a path that
    does not exist (the host's /output is never touched)."""
    monkeypatch.setattr(cli, "DEFAULT_OUT_DIR", str(tmp_path / "no-such-output"))
    for key in list(os.environ):
        if key.startswith("BYAKUGAN_"):
            monkeypatch.delenv(key)
    return monkeypatch


@pytest.fixture
def vocab(monkeypatch):
    # the vocabulary comes from the engine's own model (a submodule); the
    # sub-tool's tally is tested without it, as test_verify does
    monkeypatch.setattr(verify, "_model_actions",
                        lambda: {"process": {"create", "terminate"}, "registry": {"add"}})


# --- verify -----------------------------------------------------------------

def test_verify_passes_a_sane_tree(tmp_path, env, vocab, capsys):
    car, out = tmp_path / "car", tmp_path / "out"
    _write(car, "sysmon", "process", [_row("process", "create", command_line="cmd.exe /c whoami",
                                          sid="S-1-5-18", pid="4536")])
    env.setenv("BYAKUGAN_VERIFY_INPUT_DIR", str(car))
    env.setenv("BYAKUGAN_VERIFY_OUT_DIR", str(out))
    assert cli.main(["verify"]) == 0
    s, err = _summary(capsys)
    assert (s["tool"], s["subtool"], s["status"], s["exit"]) == ("byakugan", "verify", "ok", 0)
    assert s["inputs"] == 1 and s["processed"] == 1 and s["failed"] == 0 and s["records"] == 1
    assert s["engine"]["passed"] > 0 and s["engine"]["failed"] == 0
    assert s["engine"]["not_exercised"] == len(verify._OBJECTS)       # 12 objects + relationships
    assert s["engine"]["os_families_total"] == 5
    assert "failures" not in s
    # the report: stderr, and verify.txt in the output dir
    assert s["outputs"] == [str(out)]
    report = (out / "verify.txt").read_text()
    assert "CAR run-through passed" in report and report in err
    for key in ("version", "engine_ref", "started", "duration_s", "skipped"):
        assert key in s


def test_verify_fails_the_gate(tmp_path, env, vocab, capsys):
    car = tmp_path / "car"
    _write(car, "s", "process", [_row("process", "create", artefact="", command_line="x", sid="bad")])
    env.setenv("BYAKUGAN_VERIFY_INPUT_DIR", str(car))
    assert cli.main(["verify"]) == 1
    s, err = _summary(capsys)
    assert s["status"] == "failed" and s["exit"] == 1
    assert s["failed"] == s["engine"]["failed"] == 2                # traceability + the SID
    assert [f["item"] for f in s["failures"]] == [
        "process: every row traces to one artefact (source_artefact) (got 1, wanted 0)",
        "process: sid is a Windows SID (S-1-...) (got 1, wanted 0)"]
    assert "CAR run-through FAILED" in err
    assert s["outputs"] == []                                        # no output dir: stderr only


def test_verify_nothing_to_verify_and_config_errors(tmp_path, env, capsys):
    env.setenv("BYAKUGAN_VERIFY_INPUT_DIR", str(tmp_path))          # no car_<object>.jsonl anywhere
    assert cli.main(["verify"]) == 1
    s, err = _summary(capsys)
    assert s["status"] == "nothing" and s["inputs"] == 0 and s["failed"] == 0
    assert "no materialised CAR" in err

    env.setenv("BYAKUGAN_VERIFY_INPUT_DIR", str(tmp_path / "missing"))
    assert cli.main(["verify"]) == 2
    s, _err = _summary(capsys)
    assert s["status"] == "config_error" and "BYAKUGAN_VERIFY_INPUT_DIR" in s["error"]

    env.setenv("BYAKUGAN_VERIFY_INPUT_DIR", str(tmp_path))
    env.setenv("BYAKUGAN_VERIFY_LOG_LEVEL", "loud")
    assert cli.main(["verify"]) == 2
    s, _err = _summary(capsys)
    assert s["status"] == "config_error" and "BYAKUGAN_VERIFY_LOG_LEVEL" in s["error"]


def _sane_tree(tmp_path):
    car = tmp_path / "car"
    _write(car, "sysmon", "process", [_row("process", "create", command_line="cmd.exe /c whoami",
                                          sid="S-1-5-18", pid="4536")])
    return car


def test_verify_runs_without_a_writable_output_dir(tmp_path, env, vocab, capsys):
    """The output mount is optional for verify: an absent, read-only or
    not-a-directory default /output never stops the gate — it runs, reports on
    stderr only and lists no outputs."""
    env.setenv("BYAKUGAN_VERIFY_INPUT_DIR", str(_sane_tree(tmp_path)))

    # absent: the env fixture's default does not exist (and is never created)
    assert cli.main(["verify"]) == 0
    s, err = _summary(capsys)
    assert s["status"] == "ok" and s["outputs"] == []
    assert "CAR run-through passed" in err and "report on stderr only" in err
    assert not os.path.exists(cli.DEFAULT_OUT_DIR)

    # read-only: the default exists (a mounted /output) but nothing can be
    # written under it — the probe fails as it does on a read-only bind mount
    ro = tmp_path / "ro-output"
    ro.mkdir()
    probe = cli._probe_writable
    env.setattr(cli, "DEFAULT_OUT_DIR", str(ro))
    env.setattr(cli, "_probe_writable",
                lambda path: "Read-only file system" if path == str(ro) else probe(path))
    assert cli.main(["verify"]) == 0
    s, err = _summary(capsys)
    assert s["status"] == "ok" and s["outputs"] == []
    assert "Read-only file system" in err and "report on stderr only" in err
    assert not (ro / "verify.txt").exists()
    env.setattr(cli, "_probe_writable", probe)

    # not a directory: the default path is a file
    env.setattr(cli, "DEFAULT_OUT_DIR", str(tmp_path / "output-file"))
    (tmp_path / "output-file").write_text("")
    assert cli.main(["verify"]) == 0
    s, err = _summary(capsys)
    assert s["status"] == "ok" and s["outputs"] == [] and "report on stderr only" in err


def test_verify_named_output_dir_must_be_writable(tmp_path, env, vocab, capsys):
    # an OUT_DIR named explicitly is the operator's intent: unusable = config error
    env.setenv("BYAKUGAN_VERIFY_INPUT_DIR", str(_sane_tree(tmp_path)))
    (tmp_path / "a-file").write_text("")
    env.setenv("BYAKUGAN_VERIFY_OUT_DIR", str(tmp_path / "a-file" / "out"))
    assert cli.main(["verify"]) == 2
    s, _err = _summary(capsys)
    assert s["status"] == "config_error" and "BYAKUGAN_VERIFY_OUT_DIR" in s["error"]


def test_verify_is_dispatchable_from_the_command(tmp_path):
    """`byakugan verify` with nothing else — what the container ENTRYPOINT runs —
    dispatches through __main__ to the env-driven sub-tool; `byakugan verify
    <dir>` is the pass-through to the engine's own CLI."""
    if not _model_present():
        pytest.skip("the pinned CAR model (third_party/car) is not checked out")
    car = tmp_path / "car"
    _write(car, "sysmon", "process", [_row("process", "create", command_line="cmd.exe",
                                          sid="S-1-5-18", pid="1")])
    env = {k: v for k, v in os.environ.items() if not k.startswith("BYAKUGAN_")}
    env["BYAKUGAN_VERIFY_INPUT_DIR"] = str(car)
    env["BYAKUGAN_VERIFY_OUT_DIR"] = str(tmp_path / "out")
    r = subprocess.run([sys.executable, "-m", "byakugan", "verify"], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    lines = [line for line in r.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, r.stdout
    s = json.loads(lines[0])
    assert s["subtool"] == "verify" and s["status"] == "ok" and s["failed"] == 0
    assert "CAR run-through passed" in r.stderr
    assert (tmp_path / "out" / "verify.txt").is_file()

    r = subprocess.run([sys.executable, "-m", "byakugan", "verify", str(car)], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "CAR run-through passed" in r.stdout                     # the engine CLI's own stdout


# --- build ------------------------------------------------------------------

def test_build_batches_the_framework_layouts(tmp_path, env, capsys):
    """`byakugan build` over a processed tree in the framework layouts sees
    every source (the `inputs: 0` the older discovery reported)."""
    _binary()                                    # the Go parse engine (built, or the test skips)
    processed, out = tmp_path / "processed", tmp_path / "car"
    expected = write_framework_tree(processed)
    env.setenv("BYAKUGAN_BUILD_INPUT_DIR", str(processed))
    env.setenv("BYAKUGAN_BUILD_OUT_DIR", str(out))
    assert cli.main(["build"]) == 0
    s, _err = _summary(capsys)
    assert (s["subtool"], s["status"], s["exit"]) == ("build", "ok", 0)
    assert s["inputs"] == s["processed"] == len(expected)
    assert s["skipped"] == s["failed"] == 0 and "failures" not in s
    assert s["records"] == sum(1 for obj in expected.values() if obj) + 1   # goevtx: auth + session
    assert s["outputs"] == sorted(str(out / name) for name in expected)
    assert {r["source"] for r in s["engine"]} == set(expected)
    for name in expected:
        assert (out / name / "car_relationships.jsonl").is_file()   # the build's done-marker
    # idempotent: the second run skips every source and is still ok
    assert cli.main(["build"]) == 0
    s, _err = _summary(capsys)
    assert s["status"] == "ok" and s["skipped"] == len(expected) and s["processed"] == 0


def test_build_over_an_empty_tree_is_nothing(tmp_path, env, capsys):
    env.setenv("BYAKUGAN_BUILD_INPUT_DIR", str(tmp_path))
    env.setenv("BYAKUGAN_BUILD_OUT_DIR", str(tmp_path / "car"))
    assert cli.main(["build"]) == 1
    s, _err = _summary(capsys)
    assert s["status"] == "nothing" and s["inputs"] == 0 and s["engine"] == []


def test_engine_rejecting_its_arguments_is_a_config_error(tmp_path, env, capsys):
    """An engine that exits non-zero without running (argparse refusing the
    argv) is a config error, exit 2 — not `nothing`."""
    env.setenv("BYAKUGAN_BUILD_INPUT_DIR", str(tmp_path))
    env.setenv("BYAKUGAN_BUILD_OUT_DIR", str(tmp_path / "car"))
    env.setenv("BYAKUGAN_BUILD_ARGS", "--no-such-flag")
    assert cli.main(["build"]) == 2
    s, _err = _summary(capsys)
    assert s["status"] == "config_error" and s["exit"] == 2
    assert "exited 2" in s["error"] and "--no-such-flag" in s["error"]
    assert s["inputs"] == 0 and "engine" not in s

    env.setenv("BYAKUGAN_TIMELINE_INPUT_DIR", str(tmp_path))
    env.setenv("BYAKUGAN_TIMELINE_OUT_DIR", str(tmp_path / "tl"))
    env.setenv("BYAKUGAN_TIMELINE_ARGS", "--no-such-flag")
    assert cli.main(["timeline"]) == 2
    s, _err = _summary(capsys)
    assert s["status"] == "config_error" and "exited 2" in s["error"]


def test_run_engine_maps_system_exit():
    def raising(code):
        def main(_argv):
            raise SystemExit(code)
        return main

    assert cli.run_engine(lambda _argv: 1, [])[0::2] == (1, None)     # the engine's own verdict
    assert cli.run_engine(raising(0), [])[0::2] == (0, None)          # SystemExit(0): success
    assert cli.run_engine(raising(None), [])[0::2] == (0, None)       # SystemExit(): success
    rc, _out, message = cli.run_engine(raising(2), ["--bad"])
    assert rc == 2 and message == "engine exited 2 (rejected arguments: --bad)"
    rc, _out, message = cli.run_engine(raising("byakugan-parse not found"), [])
    assert rc is None and message == "byakugan-parse not found"       # the engine's fail-fast message

    def prints(_argv):
        print('{"ok": true}')
        return 0
    assert cli.run_engine(prints, []) == (0, '{"ok": true}\n', None)  # stdout captured


# --- the dispatcher ---------------------------------------------------------

def test_no_subtool_is_a_config_error(env, capsys):
    assert cli.main([]) == 2
    s, err = _summary(capsys)
    assert s["status"] == "config_error" and s["exit"] == 2 and s["subtool"] == ""
    assert "verify" in s["error"] and "usage:" in err


def test_version_and_bad_argv(env, capsys):
    env.setenv("BYAKUGAN_VERSION", "1.2.3")
    env.setenv("BYAKUGAN_REF", "abc123")
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out == "byakugan 1.2.3 (abc123)\n"
    assert cli.main(["car-vocab", "extra"]) == 2                    # car-vocab takes no arguments


def test_car_vocab_is_the_model_vocabulary(env, capsys):
    if not _model_present():
        pytest.skip("the pinned CAR model (third_party/car) is not checked out")
    assert cli.main(["car-vocab"]) == 0
    vocab, _err = _summary(capsys)
    assert set(vocab) >= set(verify._OBJECTS)
    assert "create" in vocab["process"]


# --- the exchange sub-tools ---------------------------------------------------

def _rule(rules_dir, rid):
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / f"{rid}.yml").write_text(
        "query: process where true\nlanguage: eql\ncreated: 2026-09-01\n"
        "updated: 2026-09-02\nseverity: high\nstatus: ported\n")


def test_stix_export_batch_runs_from_its_env_block(tmp_path, env, capsys):
    hits, rules, out = tmp_path / "hits", tmp_path / "rules", tmp_path / "out"
    hits.mkdir()
    (hits / "detections.jsonl").write_text(json.dumps(
        {"RunId": "run-1", "DetectionId": "r1", "Title": "T", "Severity": "high",
         "Source": "evtx", "Timestamp": "2026-09-02T10:00:00Z",
         "DetectedAt": "2026-09-02T10:00:01Z"}) + "\n")
    _rule(rules, "r1")
    env.setenv("BYAKUGAN_STIX_EXPORT_INPUT_DIR", str(hits))
    env.setenv("BYAKUGAN_STIX_EXPORT_OUT_DIR", str(out))
    env.setenv("BYAKUGAN_STIX_EXPORT_RULES_DIR", str(rules))
    env.setenv("BYAKUGAN_STIX_EXPORT_CASE", "CASE-7")
    assert cli.main(["stix-export"]) == 0
    s, _err = _summary(capsys)
    assert (s["tool"], s["subtool"], s["status"], s["exit"]) == ("byakugan", "stix-export", "ok", 0)
    assert s["records"] > 0 and s["failed"] == 0 and s["engine"]["ok"] is True
    bundle = json.loads((out / "bundle.json").read_text())
    types = {o["type"] for o in bundle["objects"]}
    assert {"indicator", "sighting", "identity", "extension-definition"} <= types


def test_stix_behaviour_batch_requires_detections_and_case(tmp_path, env, capsys):
    car = tmp_path / "car"
    car.mkdir()
    env.setenv("BYAKUGAN_STIX_BEHAVIOUR_INPUT_DIR", str(car))
    env.setenv("BYAKUGAN_STIX_BEHAVIOUR_OUT_DIR", str(tmp_path / "out"))
    assert cli.main(["stix-behaviour"]) == 2
    s, _err = _summary(capsys)
    assert s["status"] == "config_error" and "DETECTIONS_DIR" in s["error"]


def test_stix_behaviour_batch_over_a_quiet_tree(tmp_path, env, capsys):
    car, det, out = tmp_path / "car" / "srcA", tmp_path / "det", tmp_path / "out"
    car.mkdir(parents=True)
    det.mkdir()
    (car / "car_relationships.jsonl").write_text("")     # a finished (empty) source
    env.setenv("BYAKUGAN_STIX_BEHAVIOUR_INPUT_DIR", str(tmp_path / "car"))
    env.setenv("BYAKUGAN_STIX_BEHAVIOUR_OUT_DIR", str(out))
    env.setenv("BYAKUGAN_STIX_BEHAVIOUR_DETECTIONS_DIR", str(det))
    env.setenv("BYAKUGAN_STIX_BEHAVIOUR_CASE", "CASE-7")
    assert cli.main(["stix-behaviour"]) == 0
    s, _err = _summary(capsys)
    assert s["status"] == "ok" and s["engine"]["report"]["sightings"] == 0
    assert (out / "behaviour-sightings.json").is_file()


def test_cti_pull_batch_needs_no_input_mount(env, tmp_path, capsys):
    # no INPUT_DIR at all (the one input-less sub-tool) — the refusal must be
    # the exchange's own (endpoint/token), never a missing-input config error
    env.setenv("BYAKUGAN_CTI_PULL_OUT_DIR", str(tmp_path / "out"))
    assert cli.main(["cti-pull"]) == 2
    s, err = _summary(capsys)
    assert s["status"] == "config_error"
    assert "INPUT_DIR" not in (s.get("error") or "") and "OPENCTI" in err


def test_exchange_passthrough_uses_the_exchange_cli(env):
    with pytest.raises(SystemExit) as e:
        cli.main(["cti-pull", "--since", "yesterday"])   # the exchange's own argv validation
    assert e.value.code == 2

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
        assert (out / name / "car.db").is_file()
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

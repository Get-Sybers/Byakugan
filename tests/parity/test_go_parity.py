"""Go ⇄ Python byte-parity over every fixture manifest.

Each tests/parity/fixtures/<name>/manifest.json drives BOTH engines over the
same input; every emitted event line must be BYTE-identical (json.dumps on
the Python side, pyjson.Dumps on the Go side). A new fixture directory is
picked up automatically — porting a family means adding its fixture here and
its predicates in go/internal/predicates/predicates_<family>.go.
"""
from __future__ import annotations

import glob
import os

import pytest

import harness

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = sorted(glob.glob(os.path.join(HERE, "fixtures", "*", "manifest.json")))


def _ids():
    return [os.path.basename(os.path.dirname(m)) for m in FIXTURES]


def test_fixtures_exist():
    assert FIXTURES, "no parity fixtures found under tests/parity/fixtures/"


@pytest.mark.parametrize("manifest", FIXTURES, ids=_ids())
def test_go_parity(manifest, go_binary):
    fixture_dir = os.path.dirname(manifest)
    py_lines = harness.run_python_reference(fixture_dir)
    go_lines = harness.run_go(fixture_dir, go_binary)
    assert len(go_lines) == len(py_lines), (
        f"{os.path.basename(fixture_dir)}: Go emitted {len(go_lines)} events, "
        f"Python {len(py_lines)}\n"
        f"go tail: {go_lines[-3:]}\npy tail: {py_lines[-3:]}")
    for i, (py, go) in enumerate(zip(py_lines, go_lines)):
        assert go.encode("utf-8") == py.encode("utf-8"), (
            f"{os.path.basename(fixture_dir)}: event {i} differs\n"
            f" py: {py}\n go: {go}")
    # the Python side emitted at least one event for every fixture (a fixture
    # whose rows are all dropped would vacuously "pass")
    assert py_lines, f"{os.path.basename(fixture_dir)}: fixture produced no events"

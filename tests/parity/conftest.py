"""Parity-harness fixtures: build go/bin/byakugan-parse once per session.

Skips the whole parity suite with a clear reason when no Go toolchain is on
PATH (CI always has one); a failing BUILD is a hard failure, never a skip.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

# make the harness importable as plain modules (tests/ is not a package)
if HERE not in sys.path:
    sys.path.insert(0, HERE)
if REPO not in sys.path:
    sys.path.insert(0, REPO)


@pytest.fixture(scope="session")
def go_binary() -> str:
    """Path to a freshly built byakugan-parse (make -C go build)."""
    if shutil.which("go") is None:
        pytest.skip("Go toolchain not installed — parity tests need `go` on PATH "
                    "(build target: make -C go build)")
    proc = subprocess.run(["make", "-C", os.path.join(REPO, "go"), "build"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"make -C go build failed:\n{proc.stdout}\n{proc.stderr}",
                    pytrace=False)
    binary = os.path.join(REPO, "go", "bin", "byakugan-parse")
    assert os.path.isfile(binary), binary
    return binary

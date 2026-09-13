"""Drive the GO parse engine (byakugan-parse) from the CAR unit tests.

Phase 4c retires byakugan's Python reference `normalize()` engine and re-anchors
the map tests onto the Go engine that actually runs in production. These helpers
shell `byakugan-parse parse` on a tiny in-memory input and return the emitted CAR
event dict(s) — the exact bytes `pipeline.parse_events` would hand a caller — so
every existing assertion now exercises the Go engine instead of the Python one.

`go_normalize(artefact, rec)` mirrors the old `normalize.normalize(artefact, rec)`
one-for-one: ONE record through ONE map key, returning the single CAR event dict
or `None` (no emitted line = unmapped/dropped, exactly as the Python engine
returned `None`). No default host is applied — `normalize.normalize` did not
apply one either; the map derives `source_host` or leaves it null, and the
pipeline's caller-default fill is a separate concern the pipeline tests cover.

`go_events(artefacts, rec, adapter=...)` is the adapter-aware form: it feeds the
RAW record through the Go engine's own winevt/jlecmd adapter (what the pipeline
selects in production) and returns the LIST of events — replacing the tests' old
"reshape in Python via the frozen reference adapter, then normalize" two-step.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, ".."))

_binary_path: str | None = None


def _binary() -> str:
    """Path to a built `byakugan-parse`, (re)built once per test session.

    Mirrors tests/parity/conftest.py: whenever a Go toolchain is present, run
    `make -C go build` once per session — it is incremental (a no-op when
    nothing changed), so a LOCAL Go edit is always picked up rather than the
    tests silently exercising a stale binary. A failing build is a hard failure,
    never a skip. Only when `go` is missing AND no prebuilt binary exists do we
    skip (loud but not a red build); a prebuilt binary with no toolchain (a CI
    artefact) is used as-is.
    """
    global _binary_path
    if _binary_path is not None:
        return _binary_path
    binary = os.path.join(_REPO, "go", "bin", "byakugan-parse")
    if shutil.which("go") is not None:
        proc = subprocess.run(["make", "-C", os.path.join(_REPO, "go"), "build"],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            pytest.fail(f"make -C go build failed:\n{proc.stdout}\n{proc.stderr}",
                        pytrace=False)
    elif not os.path.isfile(binary):
        pytest.skip("Go toolchain not installed and no prebuilt byakugan-parse — "
                    "the CAR tests run the Go engine (build target: make -C go build)")
    assert os.path.isfile(binary), binary
    _binary_path = binary
    return binary


def _run(artefacts: list[str], rec: dict, adapter: str) -> list[dict]:
    """Run `rec` through the Go engine for `artefacts` (and `adapter`), returning
    the emitted CAR events as dicts, in engine output order."""
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False))
        fh.write("\n")
        in_path = fh.name
    try:
        cmd = [_binary(), "parse", "--in", in_path,
               "--artefacts", ",".join(artefacts), "--adapter", adapter]
        proc = subprocess.run(cmd, capture_output=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f"byakugan-parse exited {proc.returncode}: "
                f"{proc.stderr.decode(errors='replace')}")
        text = proc.stdout.decode("utf-8")
        return [json.loads(line) for line in text.splitlines() if line]
    finally:
        os.unlink(in_path)


def go_normalize(artefact: str, rec: dict) -> dict | None:
    """One raw record → one CAR event dict (or None if unmapped/dropped), via the
    Go engine. The drop-in replacement for `normalize.normalize(artefact, rec)`.

    A single record run through a single map yields at most one event; the Python
    engine returned None for an unmapped key / non-matching variant / null action,
    and the Go engine emits nothing for those cases — so an empty result is None.
    """
    events = _run([artefact], rec, "none")
    if not events:
        return None
    if len(events) > 1:      # a single map over a single record is 0-or-1 events
        raise AssertionError(
            f"{artefact!r} emitted {len(events)} events for one record; use "
            "go_events() for an adapter that fans one record out to many")
    return events[0]


def go_events(artefacts, rec: dict, adapter: str = "none") -> list[dict]:
    """Every CAR event the Go engine emits for `rec` under `artefacts`, optionally
    reshaped first by the Go engine's `winevt`/`jlecmd` adapter (what the pipeline
    runs in production). `artefacts` is a map key or a list of them. Returns a list
    (one jlecmd record fans out to one event per DestListEntry; an unmapped winevt
    row yields [])."""
    if isinstance(artefacts, str):
        artefacts = [artefacts]
    return _run(list(artefacts), rec, adapter)

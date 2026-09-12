"""The two sides of the byte-parity harness.

`run_python_reference(fixture_dir)` replays the exact pre-enrichment reference
path — the FROZEN plumbing copies under tests/parity/reference/ (iter_jsonl +
the adapters that the Go engine replaces) driving the LIVE
byakugan.normalize / byakugan.mappings — and returns one json.dumps(event)
string per event, in input order, with pipeline's default_host fill applied.

`run_go(fixture_dir, binary)` runs `byakugan-parse parse` on the same
manifest and returns its stdout lines. test_go_parity.py asserts per-line
BYTE equality between the two.

Manifest schema (fixture_dir/manifest.json):
    {"artefacts": ["evtx_security", ...],     # map keys, run per record in order
     "host": "H" | null,                      # pipeline default_host fallback
     "adapter": "none" | "winevt" | "jlecmd", # input reshaping (none for raw jsonl)
     "input": "input.jsonl"}                  # file inside the fixture dir
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REFERENCE = os.path.join(HERE, "reference")


def _load_reference(module_file: str):
    """Import a frozen reference module by path (reference/ is not a package)."""
    path = os.path.join(REFERENCE, module_file)
    spec = importlib.util.spec_from_file_location(
        f"parity_reference_{module_file[:-3]}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_manifest(fixture_dir: str) -> dict:
    with open(os.path.join(fixture_dir, "manifest.json"), encoding="utf-8") as fh:
        return json.load(fh)


def run_python_reference(fixture_dir: str) -> list[str]:
    """One json.dumps(event) per event — the byte-authoritative reference."""
    from byakugan import normalize  # LIVE maps + resolver (the spec)
    man = load_manifest(fixture_dir)
    readers_ref = _load_reference("readers_iter_jsonl.py")
    in_path = os.path.join(fixture_dir, man["input"])
    artefacts = man["artefacts"]
    default_host = man.get("host")
    adapter = man.get("adapter", "none")

    def _events(rec):
        for art in artefacts:
            ev = normalize.normalize(art, rec)
            if ev is None:
                continue
            if not ev.get("source_host"):     # pipeline fills AFTER normalize
                ev["source_host"] = default_host
            yield ev

    out: list[str] = []
    if adapter == "none":
        for rec in readers_ref.iter_jsonl(in_path):
            out.extend(json.dumps(ev) for ev in _events(rec))
    elif adapter == "winevt":
        winevt = _load_reference("winevt.py")
        for wrapped in readers_ref.iter_jsonl(in_path):
            shaped = winevt.adapt(wrapped)
            if shaped is not None:
                out.extend(json.dumps(ev) for ev in _events(shaped))
    elif adapter == "jlecmd":
        jlecmd = _load_reference("jlecmd.py")
        for rec in readers_ref.iter_jsonl(in_path):
            for flat in jlecmd.flatten(rec):
                out.extend(json.dumps(ev) for ev in _events(flat))
    else:
        raise ValueError(f"unknown adapter {adapter!r}")
    return out


def run_go(fixture_dir: str, binary: str) -> list[str]:
    """byakugan-parse's stdout lines for the same manifest."""
    man = load_manifest(fixture_dir)
    cmd = [binary, "parse",
           "--in", os.path.join(fixture_dir, man["input"]),
           "--artefacts", ",".join(man["artefacts"]),
           "--adapter", man.get("adapter", "none")]
    if man.get("host"):
        cmd += ["--host", man["host"]]
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"byakugan-parse exited {proc.returncode}: {proc.stderr.decode(errors='replace')}")
    text = proc.stdout.decode("utf-8")
    return text.splitlines() if text else []

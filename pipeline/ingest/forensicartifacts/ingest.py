#!/usr/bin/env python3
# Ingest the ForensicArtifacts catalogue (model/sources/forensicartifacts,
# a refresh-time submodule — engines and tests never read it) into the
# committed structural index next to this script. The committed file is
# canonical; the submodule is only consulted when this tool runs.
#
#   python pipeline/ingest/forensicartifacts/ingest.py           # regenerate
#   python pipeline/ingest/forensicartifacts/ingest.py --check   # drift gate
#
# --check regenerates in memory and byte-compares against the committed
# index. Because the index embeds the submodule commit under
# generated_from, moving the submodule pin without regenerating fails the
# check — the staleness gate from docs/design/schema-layers.md.
"""Build the structural index of ForensicArtifacts definitions."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, "..", "..", ".."))
_SOURCE = os.path.join(_ROOT, "model", "sources", "forensicartifacts")
_DATA = os.path.join(_SOURCE, "artifacts", "data")
_INDEX = os.path.join(_HERE, "index.json")
_UPSTREAM = "https://github.com/ForensicArtifacts/artifacts.git"


def _source_commit() -> str:
    out = subprocess.run(
        ["git", "-C", _SOURCE, "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def build_index() -> dict:
    if not os.path.isdir(_DATA):
        sys.exit(
            "forensicartifacts submodule not checked out — run: "
            "git submodule update --init model/sources/forensicartifacts"
        )
    artifacts = []
    for fname in sorted(os.listdir(_DATA)):
        if not fname.endswith(".yaml"):
            continue
        path = os.path.join(_DATA, fname)
        with open(path, encoding="utf-8") as handle:
            for doc in yaml.safe_load_all(handle):
                if not doc:
                    continue
                sources = doc.get("sources") or []
                types = sorted({src.get("type", "?") for src in sources})
                per_source_os = sorted({
                    o for src in sources
                    for o in (src.get("supported_os") or [])
                })
                members = sorted({
                    member
                    for src in sources
                    if src.get("type") == "ARTIFACT_GROUP"
                    for member in (src.get("attributes") or {}).get("names", [])
                })
                entry = {
                    "name": doc.get("name", ""),
                    "file": fname,
                    "summary": ((doc.get("doc") or "").strip().splitlines() or [""])[0],
                    "source_types": types,
                    "supported_os": (
                        doc["supported_os"]
                        if doc.get("supported_os") is not None
                        else per_source_os
                    ),
                }
                if doc.get("aliases"):
                    entry["aliases"] = sorted(doc["aliases"])
                if members:
                    entry["members"] = members
                artifacts.append(entry)
    artifacts.sort(key=lambda entry: entry["name"])
    return {
        "generated_from": {
            "commit": _source_commit(),
            "repo": _UPSTREAM,
            "tool": "pipeline/ingest/forensicartifacts/ingest.py",
        },
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


def render(index: dict) -> str:
    return json.dumps(index, indent=1, ensure_ascii=False, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="fail if the committed index differs from a fresh regeneration",
    )
    args = parser.parse_args()

    rendered = render(build_index())
    if args.check:
        try:
            with open(_INDEX, encoding="utf-8") as handle:
                committed = handle.read()
        except FileNotFoundError:
            print(f"OUT OF DATE: {os.path.relpath(_INDEX, _ROOT)} missing")
            return 1
        if committed != rendered:
            print(
                f"OUT OF DATE: {os.path.relpath(_INDEX, _ROOT)} — regenerate "
                "with: python pipeline/ingest/forensicartifacts/ingest.py"
            )
            return 1
        print(f"OK: {os.path.relpath(_INDEX, _ROOT)} in sync with the submodule pin")
        return 0

    with open(_INDEX, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    print(f"wrote {os.path.relpath(_INDEX, _ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Export the CAR source (sensor) definitions the maps imply (epic #86).

    python -m byakugan.gen_sources --out DIR      # export, one <source_id>.yaml per source
    python -m byakugan.gen_sources --check DIR    # verify an exported tree against the live maps

Each file is a CAR-schema sensor document EXTENDED with end-to-end provenance
(``derived_from`` / ``extractor`` / ``input_pattern``), all derived by
introspecting :data:`byakugan.mappings.MAPPINGS` (decoded from the IR), the
routing table and :data:`byakugan.sources_model.DERIVATIONS`. Output is
deterministic (sorted keys, stable field order), so an export is idempotent.

Nothing is committed: the manifests are built from the IR on demand — every
build writes its own ``<out>/sources.yaml`` (byakugan.pipeline), the schema
generator reads them in memory (byakugan.schema_gen) and the tests validate
them against ``car_source_schema.yaml``. This exporter is for reading them.
"""
from __future__ import annotations

import argparse
import os
import sys

import yaml

from . import sources_model

_HEADER = ("# EXPORTED by `python -m byakugan.gen_sources --out` — a reading copy, never committed.\n"
           "# Source: byakugan.mappings (coverage) + pipeline routing\n"
           "# (extractor/input_pattern). Regenerate after any map change.\n")


def _dump(doc: dict) -> str:
    """A stable, human-readable YAML rendering (keys kept in insertion order)."""
    body = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=100)
    return _HEADER + body


def write_all(out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for source_id, doc in sorted(sources_model.all_source_docs().items()):
        path = os.path.join(out_dir, f"{source_id}.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_dump(doc))
        written.append(path)
    return written


def check(out_dir: str) -> list[str]:
    """All the ways the generated tree can be wrong; [] means good."""
    problems = sources_model.verify_registry()
    problems += sources_model.validate_against_car_model()
    problems += sources_model.verify_coverage(out_dir)
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="byakugan.gen_sources",
                                 description=__doc__.splitlines()[0])
    ap.add_argument("--out", metavar="DIR", help="export the source manifests into DIR")
    ap.add_argument("--check", metavar="DIR",
                    help="verify a previously exported DIR against the live maps; write nothing")
    args = ap.parse_args(argv)
    if bool(args.out) == bool(args.check):
        ap.error("exactly one of --out DIR or --check DIR")

    reg = sources_model.verify_registry() + sources_model.validate_against_car_model()
    if reg:
        for p in reg:
            print(f"INVALID: {p}", file=sys.stderr)
        return 1

    if args.check:
        out_dir = os.path.abspath(args.check)
        problems = sources_model.verify_coverage(out_dir)
        if problems:
            for p in problems:
                print(f"OUT OF DATE: {p}", file=sys.stderr)
            print("run: python -m byakugan.gen_sources --out DIR", file=sys.stderr)
            return 1
        print(f"OK: {len(sources_model.source_ids())} sources in sync ({out_dir})")
        return 0

    out_dir = os.path.abspath(args.out)
    written = write_all(out_dir)
    print(f"wrote {len(written)} source definitions to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

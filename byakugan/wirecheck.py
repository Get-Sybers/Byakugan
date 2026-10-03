"""Wire count-and-carry validation (epic &1 phase 4 — #133).

Validates a produced STIX bundle against the composed Object Model wire
schemas (model/schema/wire/*, allOf over the verbatim vendored OASIS core)
and the wire conformance rules — count-and-carry: every violation is a
neutral ``Finding {object_id, rule, path, message}``, tallied and carried,
never a crash. This is the Phase 4 decision of record: Python owns wire
validation of the Go-emitted bundles; the Go engine stays stdlib-only.

Rules:
  wire-schema           the object fails its composed type schema
  wire-type             a bundle member's type is outside the closed inventory
  airway                an attack-pattern rides IN the bundle (must be
                        referenced only — the airway)
  third-party-marking   a marking-definition member, or an object_marking_ref
                        outside the four TLP singletons (tallied, never
                        rejected — Ratification F14)
  id-namespace          a recomputable catalogue id that does not match its
                        catalogue_ns recipe (the R3 count-and-carry gate)
  x-property            a top-level x_ property outside the closed harvested
                        list, or an x- type outside the declared extension
                        objects (the R6 count-and-carry gate)

    python -m byakugan.wirecheck bundle.json            # report + tally
    python -m byakugan.wirecheck bundle.json --strict   # exit 1 on findings
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Iterator

from .conform import Finding, SCHEMA_DIR

WIRE_DIR = os.path.join(SCHEMA_DIR, "wire")
VENDOR_DIR = os.path.join(SCHEMA_DIR, "vendor", "oasis")
_GITHUB_RAW = "https://raw.githubusercontent.com/Get-Sybers/Byakugan/main/model/schema/"

# The four TLP marking-definition singletons (STIX 2.1 §7.2.1.4) — the only
# marking refs byakugan itself emits; anything else is third-party (F14).
TLP_IDS = frozenset({
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",   # TLP:WHITE
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",   # TLP:GREEN
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",   # TLP:AMBER
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",   # TLP:RED
})


# --------------------------------------------------------------------------- #
# the composed validator: every schema under model/schema is registered under
# its GitHub raw URI; every vendored OASIS file ALSO under its upstream $id,
# so the vendored files' own relative $refs resolve byte-verbatim.
# --------------------------------------------------------------------------- #
_validators: dict | None = None


def _load_validators() -> dict:
    global _validators
    if _validators is not None:
        return _validators
    import jsonschema
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    resources = []
    for base, _dirs, names in os.walk(SCHEMA_DIR):
        for name in sorted(names):
            if not name.endswith(".json"):
                continue
            path = os.path.join(base, name)
            doc = json.load(open(path, encoding="utf-8"))
            rel = os.path.relpath(path, SCHEMA_DIR).replace(os.sep, "/")
            res = Resource.from_contents(doc, default_specification=DRAFT202012)
            resources.append((_GITHUB_RAW + rel, res))
            if doc.get("$id"):
                resources.append((doc["$id"], res))
    registry = Registry().with_resources(resources)  # exposed below: the one
    #            resolution surface every model/schema consumer builds on
    objects_schema = json.load(open(os.path.join(WIRE_DIR, "objects.schema.json"),
                                    encoding="utf-8"))
    bundle_schema = json.load(open(os.path.join(WIRE_DIR, "bundle.schema.json"),
                                   encoding="utf-8"))
    _validators = {
        "registry": registry,
        "types": frozenset(objects_schema["properties"]["type"]["enum"]),
        "x_props": frozenset(k for k in objects_schema["$defs"]["overlay"]["properties"]
                             if k.startswith("x_car_")),
        "member": jsonschema.Draft202012Validator(
            {"$ref": _GITHUB_RAW + "wire/objects.schema.json"}, registry=registry),
        # the whole-bundle validator (consumers' entry point; wirecheck itself
        # walks members so findings carry object ids)
        "bundle": jsonschema.Draft202012Validator(
            {"$ref": _GITHUB_RAW + "wire/bundle.schema.json"}, registry=registry),
    }
    return _validators


def _check_bundle(bundle: dict) -> Iterator[Finding]:
    """The §8 envelope in plain code (members carry their own findings):
    type/id/objects and nothing else."""
    v = _load_validators()
    bid = bundle.get("id") or "<bundle>"
    if bundle.get("type") != "bundle":
        yield Finding(object_id=bid, rule="wire-schema", path="type",
                      message=f"{bundle.get('type')!r} != 'bundle'")
    import re as _re
    if not _re.fullmatch(r"bundle--[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                         str(bundle.get("id") or "")):
        yield Finding(object_id=bid, rule="wire-schema", path="id",
                      message="not a bundle-- identifier")
    if not isinstance(bundle.get("objects"), list) or not bundle.get("objects"):
        yield Finding(object_id=bid, rule="wire-schema", path="objects",
                      message="missing or empty objects array")
    for key in bundle:
        if key not in ("type", "id", "objects"):
            yield Finding(object_id=bid, rule="wire-schema", path=key,
                          message="outside the §8 bundle envelope (type/id/objects)")
    for i, obj in enumerate(bundle.get("objects") or []):
        oid = obj.get("id") or f"objects[{i}]"
        otype = obj.get("type") or ""
        if otype == "attack-pattern":
            yield Finding(object_id=oid, rule="airway",
                          message="attack-pattern is referenced via the pinned index, "
                                  "never a bundle member")
            continue
        if otype == "marking-definition":
            yield Finding(object_id=oid, rule="third-party-marking",
                          message="marking-definition member (spec singletons ride "
                                  "by reference; third-party content is tallied)")
            continue
        if otype not in v["types"]:
            yield Finding(object_id=oid, rule="wire-type",
                          message=f"type {otype!r} outside the closed wire inventory")
            if otype.startswith("x-"):
                yield Finding(object_id=oid, rule="x-property",
                              message=f"undeclared x- type {otype!r}")
            continue
        err = None
        for err in v["member"].iter_errors(obj):
            break                       # the composed root error is the finding;
        if err is not None:             # full trees ride --verbose futures, not v1
            yield Finding(object_id=oid, rule="wire-schema",
                          path="/".join(str(p) for p in err.absolute_path),
                          message=err.message[:200])
        yield from _check_x_properties(oid, obj, v["x_props"])
        yield from _check_markings(oid, obj)
        yield from _check_catalogue_id(oid, obj)


def _check_x_properties(oid: str, obj: dict, declared: frozenset) -> Iterator[Finding]:
    for key in obj:
        if key.startswith("x_") and key not in declared:
            yield Finding(object_id=oid, rule="x-property", path=key,
                          message="top-level x_ property outside the closed, "
                                  "harvested extension_properties list")


def _check_markings(oid: str, obj: dict) -> Iterator[Finding]:
    for ref in obj.get("object_marking_refs") or []:
        if ref not in TLP_IDS:
            yield Finding(object_id=oid, rule="third-party-marking",
                          path="object_marking_refs",
                          message=f"non-TLP marking ref {ref} (tallied, never rejected)")


def _check_catalogue_id(oid: str, obj: dict) -> Iterator[Finding]:
    """The R3 gate: a catalogue indicator's id must be its catalogue_ns
    recipe over the analytic id — recomputed, not pattern-matched."""
    if obj.get("type") != "indicator" or not obj.get("x_car_analytic"):
        return
    from .stix import catalogue_id
    want = catalogue_id("indicator", obj["x_car_analytic"])
    if oid != want:
        yield Finding(object_id=oid, rule="id-namespace",
                      message=f"catalogue indicator id is not the catalogue_ns "
                              f"recipe over {obj['x_car_analytic']} (want {want})")


def run(bundle: dict) -> list[Finding]:
    return list(_check_bundle(bundle))


def tally(findings: list[Finding]) -> dict[str, int]:
    from collections import Counter
    return dict(sorted(Counter(f.rule for f in findings).items()))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="byakugan.wirecheck", description=__doc__)
    ap.add_argument("bundle", help="a produced STIX bundle (JSON)")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when any finding is carried")
    args = ap.parse_args(argv)
    bundle = json.load(open(args.bundle, encoding="utf-8"))
    findings = run(bundle)
    for f in findings:
        print(json.dumps(f.as_dict(), ensure_ascii=False))
    counts = tally(findings)
    print(f"wirecheck: {len(bundle.get('objects') or [])} objects, "
          f"{len(findings)} findings" + (f" {counts}" if counts else ""),
          file=sys.stderr)
    return 1 if (args.strict and findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())

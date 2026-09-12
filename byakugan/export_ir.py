"""Serialize the live Python parse tables to the Go engine's IR (go/DESIGN.md).

The Go parse engine (go/) does not re-declare the mappings, routes, spindle
registry or canonicalization tables — it EMBEDS a JSON snapshot of the live
Python ones (go/internal/ir/ir.json) so the two engines cannot drift: this
module is the single serializer, `--check` is the CI gate (the gen_sources
pattern), and the committed ir.json is what `go:embed` compiles in.

MARKER ENCODING — JSON loses Python's tuple-vs-list distinction, so a marker
tuple ``("kind", args...)`` serializes as ``{"!": ["kind", <arg>...]}`` with
each arg recursively encoded by the kind's own signature (a nested marker →
``{"!": [...]}``; a plain string source stays a string — exactly mirroring
normalize._resolve's ``isinstance(src, str)`` check; a map_value table → a
sorted JSON object; scalars → literals). Serialization is by STRUCTURE, never
by repr.

Output is deterministic: object keys sorted where order is not semantic,
ordered ARRAYS where it is (props / native_extract / variants / routes /
identity fields), `ensure_ascii=False`, `indent=1`, trailing newline.

    python -m byakugan.export_ir [--out PATH] [--check]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import ids, normalize, pipeline, spindle

IR_VERSION = 1
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(_HERE, "..", "go", "internal", "ir", "ir.json")

MARKER_KEY = "!"

# every marker kind's argument signature — the mirror of normalize._resolve's
# destructuring (and of the constructor calls in normalize.py). `src` is a
# recursively-encoded source (field-name string | nested marker); everything
# else is a literal of the stated type.
#   variadic : arg is a tuple of sources, spread            → ["kind", src...]
#   unary    : arg is one source                            → ["kind", src]
#   fixed    : arg is a tuple, per-position literal/source  → ["kind", ...]
_VARIADIC = {"first", "concat"}
_UNARY = {"basename", "ext", "lower", "domain_of", "epoch_ts", "exe_path",
          "host_label", "hex_int", "unescape_backslashes",
          "win_program_path", "win_program_name", "user_canon"}
# fixed signatures: True = source (recurse), False = literal
_FIXED = {
    "regex1": (True, False),           # (src, pattern)
    "payload": (False, False),         # (field, key) — both literal strings
    "userdata": (False, False),        # (field, key)
    "map_value": (True, False, False),  # (src, table, upper)
    "replace": (True, False, False),   # (src, old, new)
    "at": (True, False),               # (src, index)
    "ts_before": (True, True),         # (src, other) — both sources
}
MARKER_KINDS = sorted(_VARIADIC | _UNARY | set(_FIXED) | {"const"})


def _literal(v):
    """A marker's literal argument as JSON: scalars stay; a map_value table
    dict is emitted with sorted keys (lookup order is not semantic)."""
    if isinstance(v, dict):
        for k in v:
            if k == MARKER_KEY:
                raise ValueError(f"literal table key {MARKER_KEY!r} collides with the marker envelope")
        return {k: _literal(v[k]) for k in sorted(v)}
    if isinstance(v, (list, tuple)):
        return [_literal(x) for x in v]
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    raise TypeError(f"unserializable marker literal {v!r}")


def encode_source(src):
    """A resolver source: a field-name string, or a marker tuple."""
    if isinstance(src, str):
        return src
    if not (isinstance(src, tuple) and len(src) == 2 and isinstance(src[0], str)):
        raise TypeError(f"not a marker: {src!r}")
    kind, arg = src
    if kind == "const":
        return {MARKER_KEY: [kind, _literal(arg)]}
    if kind in _VARIADIC:
        return {MARKER_KEY: [kind, *(encode_source(a) for a in arg)]}
    if kind in _UNARY:
        return {MARKER_KEY: [kind, encode_source(arg)]}
    sig = _FIXED.get(kind)
    if sig is None:
        raise ValueError(f"unknown marker kind {kind!r}")
    if len(arg) != len(sig):
        raise ValueError(f"marker {kind!r} arity {len(arg)} != {len(sig)}")
    out = [kind]
    for is_src, a in zip(sig, arg):
        out.append(encode_source(a) if is_src else _literal(a))
    return {MARKER_KEY: out}


def _encode_guid(spec):
    """A leaf's guid spec: null | {"none": true} | {"field": f} |
    {"fields": [...]} | {"marker": <encoded>} | {"spindle": name}."""
    if spec is None:
        return None
    if spec.get("none"):
        return {"none": True}
    if "spindle" in spec:
        return {"spindle": spec["spindle"]}
    if "marker" in spec:
        return {"marker": encode_source(spec["marker"])}
    if "field" in spec:
        return {"field": spec["field"]}
    if "fields" in spec:
        return {"fields": list(spec["fields"])}
    raise ValueError(f"unknown guid spec {spec!r}")


def _encode_leaf(leaf: dict) -> dict:
    """One concrete map (a variant submap, a default, or a variant-less entry)
    with every engine-consumed key present, ordered pairs where declaration
    order is semantic (props resolve/merge order, native_extract order)."""
    return {
        "object": leaf["object"],
        "action": encode_source(leaf["action"]),
        "ts": None if leaf.get("ts") is None else encode_source(leaf["ts"]),
        "guid": _encode_guid(leaf.get("guid")),
        "host": None if leaf.get("host") is None else encode_source(leaf["host"]),
        "owning_pid": None if leaf.get("owning_pid") is None else encode_source(leaf["owning_pid"]),
        "owning_guid": None if leaf.get("owning_guid") is None else encode_source(leaf["owning_guid"]),
        "parent_pid": None if leaf.get("parent_pid") is None else encode_source(leaf["parent_pid"]),
        "props": [[car, encode_source(sp)] for car, sp in (leaf.get("props") or {}).items()],
        "keep": list(leaf.get("keep") or []),
        "native_extract": [[name, encode_source(sp)]
                           for name, sp in (leaf.get("native_extract") or {}).items()],
    }


def _encode_entry(entry: dict) -> dict:
    """A MAPPINGS entry: variants (ordered — first match wins) + default, or
    the leaf itself (normalize._select's exact dispatch)."""
    if "variants" not in entry:
        return _encode_leaf(entry)
    return {
        "variants": [[pred, None if sub is None else _encode_leaf(sub)]
                     for pred, sub in entry["variants"]],
        "default": None if entry.get("default") is None else _encode_leaf(entry["default"]),
    }


def _spindle_section() -> dict:
    """The registry the Go engine mints from, re-serialized from spindle.yml:
    identity fields in declared order, the positional fallback, the external
    forms (their golden `object` names the fields-guid prefix)."""
    identities = {}
    for name in sorted(spindle.identities()):
        e = spindle.identities()[name]
        identities[name] = {
            "object": e["object"],
            "kind": e.get("kind"),
            "scope": e.get("scope"),
            "version": e["version"],
            "identity": [[iname, source, mode]
                         for iname, source, mode in spindle.identity_fields(e)],
        }
    external = {}
    for name in sorted(spindle.externals()):
        e = spindle.externals()[name]
        external[name] = {
            "object": spindle.golden(e).get("object"),
            "form": _literal(e.get("form")),
        }
    return {
        "namespace": {"CAR_NS_URL": ids.CAR_NS_URL, "SPINDLE_LABEL": ids.SPINDLE_LABEL,
                      "CAR_NS": str(ids.CAR_NS), "SPINDLE_NS": str(ids.SPINDLE_NS)},
        "object_key": ids.OBJECT_KEY,
        "version_key": ids.VERSION_KEY,
        "renderings": list(ids.RENDERINGS),
        "positional": {"fields": spindle.positional(),
                       "version": spindle.positional_version()},
        "identities": identities,
        "external": external,
    }


def _canon_user_section() -> dict:
    """The _canon_user well-known tables (normalize.py) — data, verbatim."""
    return {
        "wellknown_sids": {k: normalize._WELLKNOWN_SIDS[k]  # noqa: SLF001
                           for k in sorted(normalize._WELLKNOWN_SIDS)},  # noqa: SLF001
        "wellknown_names": {k: normalize._WELLKNOWN_NAMES[k]  # noqa: SLF001
                            for k in sorted(normalize._WELLKNOWN_NAMES)},  # noqa: SLF001
        "wellknown_authorities": sorted(normalize._WELLKNOWN_AUTHORITIES),  # noqa: SLF001
    }


def build_ir() -> dict:
    """The complete IR document (insertion order is the document order)."""
    from . import mappings
    golden = spindle.golden_doc()   # the pinned vectors, re-encoded as JSON for the Go tests
    return {
        "ir_version": IR_VERSION,
        "marker_kinds": MARKER_KINDS,
        "mappings": {k: _encode_entry(mappings.MAPPINGS[k]) for k in sorted(mappings.MAPPINGS)},
        "routes": [[pattern, list(keys)] for pattern, keys in pipeline.ROUTES],
        "evtx_maps": list(pipeline.EVTX_MAPS),
        # route keys that are ADAPTERS, not mappings (pipeline._consume):
        # l2t_winevt reshapes each Plaso winevt/winevtx record to the EvtxECmd
        # shape and fans it through the evtx map family; jlecmd_dest flattens
        # a JLECmd jump-list record before its own map runs.
        "adapters": {
            "jlecmd_dest": {"adapter": "jlecmd", "maps": ["jlecmd_dest"]},
            "l2t_winevt": {"adapter": "winevt", "maps": list(pipeline.EVTX_MAPS)},
        },
        "spindle": _spindle_section(),
        "canon_user": _canon_user_section(),
        "predicate_names": sorted(mappings.PREDICATES),
        "golden": golden,
    }


def render() -> str:
    return json.dumps(build_ir(), ensure_ascii=False, indent=1) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="byakugan.export_ir",
                                 description="serialize the live parse tables to the Go engine's IR")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="output path (default: go/internal/ir/ir.json)")
    ap.add_argument("--check", action="store_true",
                    help="byte-compare the committed IR against a fresh rendering; write nothing")
    args = ap.parse_args(argv)
    out = os.path.abspath(args.out)
    text = render()
    if args.check:
        if not os.path.exists(out):
            print(f"OUT OF DATE: {out}: missing (run python -m byakugan.export_ir)", file=sys.stderr)
            return 1
        with open(out, encoding="utf-8") as fh:
            if fh.read() != text:
                print(f"OUT OF DATE: {out}: drifted from the live tables "
                      "(run python -m byakugan.export_ir)", file=sys.stderr)
                return 1
        print(f"OK: {out} in sync with the live tables")
        return 0
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

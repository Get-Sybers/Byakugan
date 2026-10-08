"""Artefact Class generators (epic &1 phase 2 — #131).

Scaffolds the class declarations from the curated seed table:

    model/schema/classes-seed.yaml   (human decisions: families, facets, lanes)
      + go/internal/ir/ir.json        (the reachable (object, action) closure)
      + docs/research/dfir-context/matched-evidences.yaml  (the source overlay)
      + model/car/objects/*.yml       (the legal action vocabularies)
    -> model/schema/vocab/car-actions.schema.json   (generated vocabulary)
    -> model/schema/classes/<family>.yaml           (one class per family)

The canonical evidences set per family is the ir closure UNION the overlay
(matched-evidences.yaml `matched-is-overlay` rule): overlay rows refine the
scaffold's semantics where the (object, action) pair matches; ir-only rows
carry the family default tiers with a scaffold basis; overlay-only rows ride
as-is. Held families (admission rule) emit no class and are tallied.

    python -m byakugan.schema_gen            # regenerate everything
    python -m byakugan.schema_gen --check    # byte-exact drift gate
"""

from __future__ import annotations

import argparse
import json
import os
import re

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
SCHEMA_DIR = os.path.join(_ROOT, "model", "schema")
CLASSES_DIR = os.path.join(SCHEMA_DIR, "classes")
VOCAB_PATH = os.path.join(SCHEMA_DIR, "vocab", "car-actions.schema.json")
SEED_PATH = os.path.join(SCHEMA_DIR, "classes-seed.yaml")
IR_PATH = os.path.join(_ROOT, "go", "internal", "ir", "ir.json")
OVERLAY_PATH = os.path.join(_ROOT, "docs", "research", "dfir-context",
                            "matched-evidences.yaml")
CAR_OBJECTS_DIR = os.path.join(_ROOT, "model", "car", "objects")
RELATIONSHIPS_PATH = os.path.join(_HERE, "relationships.yml")
ENRICHMENT_REL = "enrichment/rules.yaml"

PLATFORMS = ("windows", "linux", "macos")   # closed; extension is envelope-versioned
DOMAINS = ("filesystem", "memory", "network", "cloud")


# --------------------------------------------------------------------------- #
# ir.json closure: the reachable (object, action) pairs per lane / sub-entry
# --------------------------------------------------------------------------- #
def _action_literals(expr) -> tuple[set[str], bool]:
    """(closed literal set, open?) for an ir action expression. Ops are the
    closed set the authoring tables use; an unknown op fails loudly."""
    if expr is None:
        return set(), False
    if isinstance(expr, str):
        return {expr}, False
    if isinstance(expr, dict) and "!" in expr:
        op, *args = expr["!"]
        if op == "const":
            return _action_literals(args[0] if args else None)
        if op == "map_value":
            out: set[str] = set()
            open_ = False
            mapping = args[1] if len(args) > 1 else {}
            for v in (mapping or {}).values():
                lits, o = _action_literals(v)
                out |= lits
                open_ |= o
            fallback = args[2] if len(args) > 2 else None
            if isinstance(fallback, str):
                out.add(fallback)
            elif fallback:                      # keep-original: value-sourced
                open_ = True
            return out, open_
        if op == "first":
            out, open_ = set(), False
            for a in args:
                lits, o = _action_literals(a)
                out |= lits
                open_ |= o
            return out, open_
        if op == "payload":                     # runtime field read: open
            return set(), True
        raise SystemExit(f"schema_gen: unknown action op {op!r} — extend the walker")
    raise SystemExit(f"schema_gen: unhandled action expression {expr!r}")


def ir_closure() -> dict[str, list[dict]]:
    """{lane or lane/sub: [{object, action, open}]} over every mapping leaf."""
    ir = json.load(open(IR_PATH, encoding="utf-8"))
    out: dict[str, list[dict]] = {}

    def add(key: str, leaf: dict) -> None:
        obj = leaf.get("object")
        lits, open_ = _action_literals(leaf.get("action"))
        rows = out.setdefault(key, [])
        for a in sorted(lits):
            if not any(r["object"] == obj and r["action"] == a for r in rows):
                rows.append({"object": obj, "action": a, "open": False})
        if open_:
            rows.append({"object": obj, "action": None, "open": True})

    for lane, spec in ir["mappings"].items():
        for _pred, leaf in spec.get("variants", []):
            sub = (leaf.get("guid") or {}).get("spindle")
            add(lane, leaf)
            if sub and sub.startswith(lane + "/"):
                add(sub, leaf)
        if spec.get("default"):
            add(lane, spec["default"])
    return {"ir_version": ir["ir_version"], "closure": out}   # type: ignore[return-value]


# --------------------------------------------------------------------------- #
# inputs
# --------------------------------------------------------------------------- #
# The ruled promotions (docs/research/car-vocabulary-ruling.md): superset
# objects adopted into the schema vocabulary with pin-derived actions.
# user_account deliberately drops `authenticate` — authentication keeps its
# single CAR home (the ruling's recorded divergence from the superset row).
SUPERSET_PATH = os.path.join(_ROOT, "model", "superset", "model-objects.yml")
PROMOTED: dict[str, dict] = {
    "user_account": {"drop": ("authenticate",)},
    "group": {},
    "scheduled_job": {},
}


def _legal_actions() -> dict[str, list[str]]:
    out = {}
    for name in sorted(os.listdir(CAR_OBJECTS_DIR)):
        if name.endswith(".yml"):
            doc = yaml.safe_load(open(os.path.join(CAR_OBJECTS_DIR, name), encoding="utf-8"))
            out[name[:-4]] = sorted(doc.get("car_action") or [])
    superset = yaml.safe_load(open(SUPERSET_PATH, encoding="utf-8"))["model_objects"]
    by_name = {o["name"]: o for o in superset}
    for obj, spec in PROMOTED.items():
        if obj not in by_name:
            raise SystemExit(f"schema_gen: PROMOTED object {obj!r} not found in "
                             f"the superset ({SUPERSET_PATH})")
        row = by_name[obj]
        drop = set(spec.get("drop") or ())
        out[obj] = sorted(a for a in row["actions"] if a not in drop)
    return out


def _overlay() -> dict[str, list[dict]]:
    doc = yaml.safe_load(open(OVERLAY_PATH, encoding="utf-8"))
    return {fam: rows for fam, rows in doc.items()
            if fam != "constraints" and isinstance(rows, list)}


def _schema_version() -> str:
    doc = yaml.safe_load(open(os.path.join(SCHEMA_DIR, "constants.yaml"), encoding="utf-8"))
    return str(doc["schema_version"])


# --------------------------------------------------------------------------- #
# renders
# --------------------------------------------------------------------------- #
def render_vocab(legal: dict[str, list[str]]) -> str:
    """The generated (object, action) vocabulary: object enum + per-object
    action enums + the pair-wise if/then constraint block."""
    doc = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": _GITHUB_RAW + "vocab/car-actions.schema.json",
        "title": "CAR object/action vocabulary — GENERATED from model/car/objects",
        "description": ("Never hand-edited: python -m byakugan.schema_gen regenerates it; "
                        "the conform rule class-regen gates drift."),
        "$defs": {
            "object": {"enum": sorted(legal)},
            **{f"{o}-actions": {"enum": acts} for o, acts in sorted(legal.items())},
            "pair": {
                "type": "object",
                "properties": {"object": {"$ref": "#/$defs/object"}},
                "allOf": [
                    {"if": {"properties": {"object": {"const": o}}, "required": ["object"]},
                     "then": {"properties": {"action": {"$ref": f"#/$defs/{o}-actions"}}}}
                    for o in sorted(legal)
                ],
            },
        },
    }
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


def _merge_rows(fam: str, seed: dict, lane_rows: list[dict],
                overlay_rows: list[dict]) -> tuple[list[dict], list[str]]:
    default = seed.get("default") or {}
    notes: list[str] = []
    # Mechanism-distinct rows survive: the key includes `when`, so two
    # mechanisms for one (object, action) pair are two rows. An overlay row
    # subsumes the pair's ir scaffold (the closure grounds it; the mechanism
    # rows carry the semantics) — a scaffold row remains only for pairs no
    # overlay mechanism covers. A duplicate overlay key is a hard error:
    # silently merging would lose a curated sources/basis entry.
    scaffold: dict[tuple, dict] = {}
    for r in lane_rows:
        if r.get("open"):
            note = (f"{fam}: an action expression reads a payload field — "
                    "closure is open for that variant (declared rows only)")
            if note not in notes:
                notes.append(note)
            continue
        scaffold[(r["object"], r["action"])] = {
            "object": r["object"], "action": r["action"],
            "evidence": default.get("evidence", "definitive"),
            "time": default.get("time", "event-time"),
            "basis": "ir.json closure (scaffold — semantics from the family default)",
            "sources": ["byakugan:ir.json"],
        }
    merged: dict[tuple, dict] = {}
    covered_pairs: set[tuple] = set()
    for r in overlay_rows:
        pair = (r["object"], r["action"])
        key = (r["object"], r["action"], str(r.get("when") or ""))
        if key in merged:
            raise SystemExit(f"schema_gen: {fam}: duplicate overlay row for "
                             f"{key} — merge would silently drop curated content")
        row = {k: r[k] for k in ("object", "action", "evidence", "time") if k in r}
        for opt in ("when", "basis", "note"):
            if r.get(opt):
                row[opt] = r[opt]
        row["sources"] = list(r.get("sources") or [])
        if pair in scaffold:
            row["sources"] = sorted(set(row["sources"]) | {"byakugan:ir.json"})
            covered_pairs.add(pair)
        merged[key] = row
    for pair, row in scaffold.items():
        if pair not in covered_pairs:
            merged[(pair[0], pair[1], "")] = row
    rows = [merged[k] for k in sorted(merged, key=lambda k: (str(k[0]), str(k[1]), str(k[2])))]
    return rows, notes


def build_classes() -> tuple[dict[str, str], list[str], list[str]]:
    """{relpath: content}, held families, notes."""
    seed_doc = yaml.safe_load(open(SEED_PATH, encoding="utf-8"))
    families = seed_doc["families"]
    legal = _legal_actions()
    closure_doc = ir_closure()
    closure, ir_version = closure_doc["closure"], closure_doc["ir_version"]
    overlay = _overlay()
    version = _schema_version()

    # every ir lane must be assigned to exactly one family (sub-entries split lanes)
    assigned: dict[str, str] = {}
    for fam, spec in families.items():
        for lane in spec.get("lanes") or []:
            if lane in assigned:
                raise SystemExit(f"schema_gen: lane {lane} assigned to both "
                                 f"{assigned[lane]} and {fam}")
            assigned[lane] = fam
    ir_lanes = {k for k in closure if "/" not in k}
    plain_assigned = {l for l in assigned if "/" not in l}
    split_parents = {l.split("/")[0] for l in assigned if "/" in l}
    unassigned = ir_lanes - plain_assigned - split_parents
    if unassigned:
        raise SystemExit(f"schema_gen: ir lanes with no family: {sorted(unassigned)}")
    # a SPLIT lane must have every sub-entry claimed: a new spindle sub-entry
    # in ir.json without a seed assignment must fail, never silently vanish
    for parent in split_parents:
        subs = {k for k in closure if k.startswith(parent + "/")}
        unclaimed = subs - set(assigned)
        if unclaimed:
            raise SystemExit(f"schema_gen: split lane {parent}: sub-entries with "
                             f"no family: {sorted(unclaimed)}")
    unknown = set(overlay) - set(families)
    if unknown:
        raise SystemExit(f"schema_gen: overlay families not in the seed: {sorted(unknown)}")

    out: dict[str, str] = {}
    held: list[str] = []
    notes: list[str] = []
    for fam in sorted(families):
        spec = families[fam]
        if spec.get("held"):
            held.append(fam)
            continue
        lane_rows: list[dict] = []
        for lane in spec.get("lanes") or []:
            lane_rows.extend(closure.get(lane, []))
        rows, fam_notes = _merge_rows(fam, spec, lane_rows, overlay.get(fam, []))
        notes.extend(fam_notes)
        for r in rows:
            if r["object"] not in legal or r["action"] not in legal[r["object"]]:
                raise SystemExit(f"schema_gen: {fam}: illegal pair "
                                 f"({r['object']}, {r['action']})")
        doc = {
            "schema_version": version,
            "source": "generated",
            "generated_from": {
                "ir_version": ir_version,
                "seed": "model/schema/classes-seed.yaml",
                "overlay": "docs/research/dfir-context/matched-evidences.yaml",
                "car_actions": "model/car/objects",
            },
            "family": fam,
            "platform": spec.get("platform") or [],
            "domain": spec["domain"],
            "object": spec.get("object"),
            "references": [dict({"source_name": "forensicartifacts"}, external_id=f["id"],
                                coverage=f.get("coverage", "leaf"))
                           for f in (spec.get("fa") or [])],
            "aliases": [],
            "evidences": rows,
        }
        header = ("# GENERATED by python -m byakugan.schema_gen — do not hand-edit.\n"
                  "# Curated inputs: classes-seed.yaml (decisions), the matched overlay\n"
                  "# (semantics), ir.json (the reachable closure).\n")
        out[f"classes/{fam}.yaml"] = header + yaml.safe_dump(
            doc, sort_keys=False, allow_unicode=True, width=88)
    return out, held, notes


def render_enrichment() -> str:
    """The Enrichment Rules layer, generated from byakugan/relationships.yml
    (inheritance / dedupe / identity / derived) and the ir.json canon_user
    table — one declaration per rule, provenance attributable."""
    rel = yaml.safe_load(open(RELATIONSHIPS_PATH, encoding="utf-8"))
    ir = json.load(open(IR_PATH, encoding="utf-8"))
    rules: list[dict] = []
    for name, fields in sorted((rel.get("inheritance") or {}).items()):
        rules.append({"id": f"inherit-{name.replace('_', '-')}", "layer": "inheritance",
                      "applies_to": "spoke rows whose owner/parent/flow the cascade resolved",
                      "method": f"inheritance.{name}", "scope": "self",
                      "inputs": ["the resolved owning/parent/flow row"],
                      "emits": list(fields), "declared_in": "byakugan/relationships.yml#inheritance"})
    ded = rel.get("dedupe") or {}
    rules.append({"id": "dedupe-fold", "layer": "dedupe",
                  "applies_to": "rows sharing the same-event key",
                  "method": f"dedupe.fold[{ded.get('fold')}]", "scope": "self",
                  "inputs": list(ded.get("key") or []),
                  "emits": ["contributions", "contributed_by"],
                  "declared_in": "byakugan/relationships.yml#dedupe"})
    for name in sorted(rel.get("identity") or {}):
        rules.append({"id": f"identity-{name.replace('_', '-')}", "layer": "identity",
                      "applies_to": "sid / account-name fields",
                      "method": f"identity.{name}", "scope": "self",
                      "inputs": [name], "emits": ["canonical user identity"],
                      "declared_in": "byakugan/relationships.yml#identity"})
    der = rel.get("derived") or {}
    for section in sorted(der):
        spec = der[section]
        names = (sorted(spec) if isinstance(spec, dict)
                 else [r.get("name") for r in spec if isinstance(r, dict)])
        for n in names:
            rules.append({"id": f"derived-{section}-{str(n).replace('_', '-')}",
                          "layer": "derived",
                          "applies_to": f"derived.{section}",
                          "method": f"derived.{section}.{n}", "scope": "self",
                          "declared_in": "byakugan/relationships.yml#derived"})
    for table in sorted(ir.get("canon_user") or {}):
        rules.append({"id": f"canon-user-{table.replace('_', '-')}",
                      "layer": "canonicalisation",
                      "applies_to": "user / sid fields",
                      "method": f"canon_user.{table}", "scope": "self",
                      "inputs": [table],
                      "emits": ["canonical account name"],
                      "declared_in": "go/internal/ir/ir.json#canon_user"})
    doc = {
        "schema_version": _schema_version(),
        "source": "generated",
        "generated_from": {
            "relationships": "byakugan/relationships.yml",
            "canon_user": f"go/internal/ir/ir.json (ir_version {ir['ir_version']})",
        },
        "rules": rules,
    }
    header = ("# GENERATED by python -m byakugan.schema_gen — do not hand-edit.\n"
              "# One declaration per self-enrichment rule; the method names are the\n"
              "# registered code seams (enrichment provenance stays attributable).\n")
    return header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=88)


# --------------------------------------------------------------------------- #
# the Object Model wire layer (epic &1 phase 4 — #133): composed OASIS +
# overlay schemas for what byakugan actually emits. Everything below is
# GENERATED — the closed x_car_* property list is harvested from the emitted
# surface (Ratification F1), the relationship vocabulary from the pinned
# superset, the type inventory from the projection source.
# --------------------------------------------------------------------------- #
RELTYPES_PATH = os.path.join(_ROOT, "model", "superset", "relationship-types.yml")
STIX_OBJECTS_PATH = os.path.join(_ROOT, "model", "stix", "objects.yml")
GENERATE_PY = os.path.join(_ROOT, "model", "generate.py")
VENDOR_DIR = os.path.join(SCHEMA_DIR, "vendor", "oasis")
_GITHUB_RAW = "https://raw.githubusercontent.com/Get-Sybers/Byakugan/main/model/schema/"
# x_car_* names ride the wire from exactly these files (F1: conventions.yml
# alone is not a complete registry — the emitted surface is the authority)
HARVEST_SOURCES = ("byakugan/stix.py", "model/stix/conventions.yml",
                   "model/stix/objects.yml")
# the wire type inventory is harvested from these emitters' string literals
TYPE_SOURCES = ("byakugan/stix.py", "byakugan/exchange/objects.py")
# never bundle members, whatever the source mentions: attack-patterns ride the
# airway (referenced only) and marking-definitions are spec singletons
_NEVER_MEMBERS = {"attack-pattern", "marking-definition"}
_X_CAR_SDOS = {"x-car-inferred-node"}          # new-sdo; the rest are new-sco


def harvest_x_car() -> list[str]:
    """The closed x_car_* property list, harvested from the emitted surface —
    the R6 standing gate compares this against exchange.objects
    EVIDENCE_PROPERTIES and the generated wire overlay."""
    names: set[str] = set()
    for rel in HARVEST_SOURCES:
        text = open(os.path.join(_ROOT, *rel.split("/")), encoding="utf-8").read()
        names |= set(re.findall(r"\bx_car_[a-z0-9_]+\b", text))
    return sorted(names)


def harvest_wire_types() -> list[str]:
    """Every STIX type the projection emits as a bundle member, harvested from
    the emitters' construction idioms (`"type": …`, `_value_sco(…)`, `_sdo(…)`)
    — never from loose string literals, so a column name can't become a wire
    type."""
    idioms = (r'"type": "([a-z0-9-]{3,})"',
              r'_value_sco\(\s*"([a-z0-9-]{3,})"',
              r'_value_sco\("[a-z0-9-]+" if [^)]+ else "([a-z0-9-]{3,})"',
              r'_sdo\(\s*"([a-z0-9-]{3,})"')
    seen: set[str] = set()
    for rel in TYPE_SOURCES:
        text = open(os.path.join(_ROOT, *rel.split("/")), encoding="utf-8").read()
        for pat in idioms:
            seen |= set(re.findall(pat, text))
    return sorted(seen - _NEVER_MEMBERS - {"bundle"})


def _element_prefixes() -> dict[str, set[str]]:
    """ATT&CK vocabulary element -> the id prefixes a wire end may carry,
    resolved through model/stix/objects.yml (sco / sro_end) and the element
    aliasing in model/generate.py — one aliasing table, imported, never
    retyped."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_model_generate", GENERATE_PY)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    stix_objects = yaml.safe_load(open(STIX_OBJECTS_PATH, encoding="utf-8"))["objects"]
    out: dict[str, set[str]] = {}
    for car_obj, decl in stix_objects.items():
        end = decl["sco"] if decl.get("sro_end") == "sco" else "observed-data"
        for element in gen._ELEMENT_ALIASES.get(car_obj, {car_obj}):
            out.setdefault(element, set()).add(end)
    return out


def _declared_edge_prefixes() -> dict[str, list]:
    """slugged verb -> [(source prefixes, target prefixes)] for every concrete
    `form: <car_obj> --<verb>--> <car_obj>` in model/relationships/ (templates
    with placeholders are the spoke_owner table, already covered pair-wise)."""
    stix_objects = yaml.safe_load(open(STIX_OBJECTS_PATH, encoding="utf-8"))["objects"]

    def end_of(car_obj: str) -> set[str] | None:
        if car_obj == "user_account":
            return {"user-account"}   # actor-edge end: the global SID SCO
        decl = stix_objects.get(car_obj)                # (stix.py _end)
        if decl is None:
            return None
        return {decl["sco"] if decl.get("sro_end") == "sco" else "observed-data"}

    forms: list[str] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "form" and isinstance(v, str):
                    forms.append(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for name in ("declared.yml", "derived.yml"):
        walk(yaml.safe_load(open(os.path.join(_ROOT, "model", "relationships", name),
                                 encoding="utf-8")))
    out: dict[str, list] = {}
    for form in forms:
        m = re.fullmatch(r"(\w+) --(.+?)--> (\w+)", form.strip())
        if not m:
            continue                          # a template form, not a concrete edge
        s_pre, t_pre = end_of(m.group(1)), end_of(m.group(3))
        if s_pre is None or t_pre is None:
            raise SystemExit(f"schema_gen: form {form!r} names an object outside "
                             f"model/stix/objects.yml")
        pair = (s_pre, t_pre)
        rows = out.setdefault(_slug(m.group(2)), [])
        if pair not in rows:
            rows.append(pair)
    return out


def _leg_pattern(prefixes: set[str]) -> str:
    """A leg is an id-prefix check (§2.9: ids carry their type); a derived
    edge's missing end is legally an inferred node on either leg."""
    return "^(" + "|".join(sorted(prefixes | {"x-car-inferred-node"})) + ")--"


def _slug(verb: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", verb.lower()).strip("-")


def _wire_overlay() -> dict:
    """The shared overlay every composed wire schema carries: the closed,
    harvested x_car_* top-level properties and the evidence extension entry.
    `extensions` stays OPEN inside (predefined STIX extensions ride the
    vendored dictionary rules). The x_ gate is an explicit generated
    patternProperties regime — the vendored common/properties.json admits
    ANY lowercase custom property (its catch-all pattern), so
    unevaluatedProperties alone cannot close the x_ surface."""
    from .exchange.objects import EVIDENCE_EXTENSION_ID
    names = harvest_x_car()
    suffixes = "|".join(n[len("x_car_"):] for n in names)
    return {
        "properties": {
            **{name: True for name in names},
            "extensions": {
                "type": "object",
                "properties": {EVIDENCE_EXTENSION_ID: {
                    "type": "object",
                    "properties": {"extension_type": {
                        "enum": ["toplevel-property-extension", "new-sco", "new-sdo"]}},
                    "required": ["extension_type"],
                }},
            },
        },
        "patternProperties": {f"^x_(?!car_(?:{suffixes})$)": False},
    }


def render_wire_relationship() -> str:
    """relationship.schema.json (D3): verbatim OASIS core + the closed
    generated verb enum + pair-wise if/then leg constraints from the pinned
    243-edge vocabulary. Pairs whose element has no wire grounding contribute
    no branch; a verb with NO groundable pair gets `then: false` — in the
    vocabulary, never on byakugan's wire."""
    doc = yaml.safe_load(open(RELTYPES_PATH, encoding="utf-8"))["relationship_types"]
    prefixes = _element_prefixes()
    pairs: dict[str, list] = {}
    for source_el, rows in doc.items():
        for row in rows:
            pairs.setdefault(_slug(row["relationship"]), []).append(
                (source_el, row["target"]))
    # byakugan's own materialised edges (model/relationships/ `form:` lines,
    # CAR-object legs): the catalogue verb applied where our evidence is
    # finer-grained than ATT&CK's elements (typing: extension) still needs a
    # groundable branch — process --executed--> file is legal wire.
    own_pairs = _declared_edge_prefixes()
    for verb, legs in own_pairs.items():
        if verb not in pairs:
            raise SystemExit(f"schema_gen: model/relationships verb {verb!r} is "
                             f"outside the pinned catalogue vocabulary")
    constraints = []
    for verb in sorted(pairs):
        branches = []
        for s_el, t_el in pairs[verb]:
            s_pre, t_pre = prefixes.get(s_el), prefixes.get(t_el)
            if not s_pre or not t_pre:
                continue                      # no wire grounding for this element
            branch = {"properties": {"source_ref": {"pattern": _leg_pattern(s_pre)},
                                     "target_ref": {"pattern": _leg_pattern(t_pre)}}}
            if branch not in branches:
                branches.append(branch)
        for s_pre, t_pre in own_pairs.get(verb, []):
            branch = {"properties": {"source_ref": {"pattern": _leg_pattern(s_pre)},
                                     "target_ref": {"pattern": _leg_pattern(t_pre)}}}
            if branch not in branches:
                branches.append(branch)
        constraints.append({
            "if": {"properties": {"relationship_type": {"const": verb}},
                   "required": ["relationship_type"]},
            "then": {"anyOf": branches} if branches else False,
        })
    constraints.append({
        "if": {"properties": {"relationship_type": {"const": "indicates"}},
               "required": ["relationship_type"]},
        "then": {"properties": {"source_ref": {"pattern": "^indicator--"},
                                "target_ref": {"pattern": "^attack-pattern--"}}},
    })
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": _GITHUB_RAW + "wire/relationship.schema.json",
        "title": "Wire relationship — GENERATED from model/superset/relationship-types.yml",
        "description": ("Never hand-edited: python -m byakugan.schema_gen regenerates it "
                        "(conform class-regen gates drift). Composed over the verbatim "
                        "vendored OASIS core; the closed relationship_type enum means an "
                        "undeclared verb cannot pass vacuously (generics like related-to "
                        "are excluded by construction — doubt is tallied, never modeled)."),
        "allOf": [
            {"$ref": "../vendor/oasis/sros/relationship.json"},
            {"properties": {
                "relationship_type": {"enum": sorted(pairs) + ["indicates"]},
                **_wire_overlay()["properties"],
            }, "patternProperties": _wire_overlay()["patternProperties"]},
            *constraints,
        ],
        "unevaluatedProperties": False,
    }
    return json.dumps(schema, indent=1, ensure_ascii=False) + "\n"


# type -> vendored OASIS schema path (relative to wire/)
def _vendor_ref(t: str) -> str | None:
    for sub in ("observables", "sdos", "sros", "common"):
        if os.path.isfile(os.path.join(VENDOR_DIR, sub, t + ".json")):
            return f"../vendor/oasis/{sub}/{t}.json"
    return None


def render_wire_objects() -> str:
    """objects.schema.json: one composed schema per emitted bundle-member type
    (allOf: verbatim vendored OASIS + the closed overlay, unevaluatedProperties
    false), the x-car-* extension objects on their category cores (§7.3), and
    a type-dispatch root over the closed inventory."""
    overlay = _wire_overlay()
    types = harvest_wire_types()
    defs: dict[str, dict] = {"overlay": overlay}
    for t in types:
        if t == "relationship":
            defs[t] = {"$ref": "relationship.schema.json"}
            continue
        vendor = _vendor_ref(t)
        if vendor:
            defs[t] = {"allOf": [{"$ref": vendor}, {"$ref": "#/$defs/overlay"}],
                       "unevaluatedProperties": False}
            continue
        if not t.startswith("x-car-"):
            raise SystemExit(f"schema_gen: emitted type {t!r} has no vendored "
                             f"OASIS schema and is not a declared x-car-* object")
        core = ("../vendor/oasis/common/core.json" if t in _X_CAR_SDOS
                else "../vendor/oasis/common/cyber-observable-core.json")
        defs[t] = {"allOf": [{"$ref": core}, {"$ref": "#/$defs/overlay"},
                             {"properties": {"type": {"const": t}}}],
                   "unevaluatedProperties": False}
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": _GITHUB_RAW + "wire/objects.schema.json",
        "title": "Wire bundle members — GENERATED type-dispatched composition",
        "description": ("Never hand-edited: python -m byakugan.schema_gen regenerates it "
                        "(conform class-regen gates drift). The closed type inventory is "
                        "harvested from the projection source; attack-pattern and "
                        "marking-definition are excluded by design (the airway / spec "
                        "singletons — wirecheck tallies them, the schema never admits them)."),
        "type": "object",
        "required": ["type"],
        "properties": {"type": {"enum": types}},
        "allOf": [{"if": {"properties": {"type": {"const": t}}, "required": ["type"]},
                   "then": {"$ref": f"#/$defs/{t}"}} for t in types],
        "$defs": defs,
    }
    return json.dumps(schema, indent=1, ensure_ascii=False) + "\n"


def render_wire_bundle() -> str:
    """bundle.schema.json: the §8 envelope with every member dispatched
    through objects.schema.json. NOT composed over the vendored bundle.json —
    its `objects.items` dispatches to the 2.1 standard types only, which
    would reject the declared x-car-* extension objects; the envelope shape
    (type/id/objects, nothing else) is restated, the identifier grammar is
    still the vendored file's."""
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": _GITHUB_RAW + "wire/bundle.schema.json",
        "title": "Wire bundle — GENERATED envelope",
        "description": ("Never hand-edited: python -m byakugan.schema_gen regenerates it "
                        "(conform class-regen gates drift)."),
        "type": "object",
        "required": ["type", "id", "objects"],
        "properties": {
            "type": {"const": "bundle"},
            "id": {"allOf": [{"$ref": "../vendor/oasis/common/identifier.json"},
                             {"pattern": "^bundle--"}]},
            "objects": {"type": "array", "minItems": 1,
                        "items": {"$ref": "objects.schema.json"}},
        },
        "unevaluatedProperties": False,
    }
    return json.dumps(schema, indent=1, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- #
# the Model Mapping layer (epic &1 phase 5 — #134): the hourglass waist as
# declarations. GENERATED from go/internal/ir/ir.json — gen-ir stays the
# byte-exact gate on ir.json against the Go authoring tables; these files
# flip the mapping surface from code-owned to DECLARED data the conform
# rules can hold both engines to. Predicates ride BY NAME ONLY: the
# implementations live in the code registries (go/internal/predicates now;
# the Python engine registry at phase 7).
# --------------------------------------------------------------------------- #
def _mapping_action(expr) -> object:
    lits, open_ = _action_literals(expr)
    if not open_ and len(lits) == 1:
        return next(iter(lits))
    return {"declared": sorted(lits), "open": open_}


def _lane_families() -> dict[str, str]:
    seed = yaml.safe_load(open(SEED_PATH, encoding="utf-8"))["families"]
    assigned: dict[str, str] = {}
    for fam, spec in seed.items():
        for lane in spec.get("lanes") or []:
            assigned[lane] = fam
    return assigned


def render_mappings() -> dict[str, str]:
    """One declaration per ir lane (input: the Artefact Class it feeds;
    output: the (object, action) pairs; identity: the spindle recipe;
    predicates by name) plus the routing table — mappings/<lane>.yaml and
    mappings/routes.yaml."""
    ir = json.load(open(IR_PATH, encoding="utf-8"))
    assigned = _lane_families()
    generated_from = {"ir": f"go/internal/ir/ir.json (ir_version {ir['ir_version']})"}
    header = ("# GENERATED by python -m byakugan.schema_gen — do not hand-edit.\n"
              "# The Model Mapping layer: the ir surface as declarations; gen-ir\n"
              "# keeps ir.json byte-exact against the Go authoring tables and the\n"
              "# conform rules hold these declarations to ir.json both ways.\n")

    def leaf_decl(lane: str, leaf: dict, when: str | None) -> dict:
        recipe = (leaf.get("guid") or {}).get("spindle")
        fam = assigned.get(recipe) if recipe and "/" in recipe else None
        out = {}
        if when is not None:
            out["when"] = when
        out.update({
            "object": leaf.get("object"),
            "action": _mapping_action(leaf.get("action")),
            "identity": recipe,
            "artefact_class": fam or assigned.get(lane),
            "fields": [name for name, _expr in (leaf.get("props") or [])],
        })
        return out

    files: dict[str, str] = {}
    for lane, spec in sorted(ir["mappings"].items()):
        variants = [leaf_decl(lane, leaf, pred)
                    for pred, leaf in spec.get("variants", [])]
        default = (leaf_decl(lane, spec["default"], None)
                   if spec.get("default") else None)
        # uniformity is decided over EVERY leaf, default included — a default
        # whose family differed from its siblings keeps the lane split, with
        # per-leaf classes, rather than being silently discarded
        leaves = variants + ([default] if default else [])
        classes = sorted({v["artefact_class"] for v in leaves if v["artefact_class"]})
        doc = {
            "schema_version": _schema_version(),
            "source": "generated",
            "generated_from": generated_from,
            "lane": lane,
            "artefact_class": classes[0] if len(classes) == 1 else None,
            "variants": variants,
            "default": default,
        }
        if doc["artefact_class"]:                 # uniform lane: drop the repeats
            for v in leaves:
                v.pop("artefact_class")
        files[f"mappings/{lane}.yaml"] = header + yaml.safe_dump(
            doc, sort_keys=False, allow_unicode=True, width=88)
    routes = {
        "schema_version": _schema_version(),
        "source": "generated",
        "generated_from": generated_from,
        "routes": [{"match": match, "lanes": lanes} for match, lanes in ir["routes"]],
        "evtx_maps": list(ir["evtx_maps"]),
        "adapters": {name: dict(spec) for name, spec in sorted(ir["adapters"].items())},
    }
    files["mappings/routes.yaml"] = header + yaml.safe_dump(
        routes, sort_keys=False, allow_unicode=True, width=88)
    return files


# --------------------------------------------------------------------------- #
# the Parser Profile layer (epic &1 phase 6 — #135): what one parser
# literally emits, one declaration per (parser, artefact class). GENERATED
# from the curated seed (profiles-seed.yaml — tool metadata + the mined
# in-house record structs, file:line grounded) joined with the reviewed
# lane surfaces in sources/*.yaml (field_provenance sources + native/join
# keys) and the spindle registry (identity-hashed fields).
# --------------------------------------------------------------------------- #
PROFILES_SEED_PATH = os.path.join(SCHEMA_DIR, "profiles-seed.yaml")
SOURCES_DIR = os.path.join(_ROOT, "sources")
SPINDLE_PATH = os.path.join(_HERE, "spindle.yml")


def _lane_surfaces() -> dict[str, dict]:
    """lane -> the reviewed sources/*.yaml surface, kept at PER-PAIR
    granularity: consumed/native per (object, action), plus the raw->car
    provenance reverse map (which CAR fields a raw parser field feeds)."""
    out: dict[str, dict] = {}
    for name in sorted(os.listdir(SOURCES_DIR)):
        if not name.endswith(".yaml"):
            continue
        doc = yaml.safe_load(open(os.path.join(SOURCES_DIR, name), encoding="utf-8"))
        consumed_by_pair: dict[tuple, set] = {}
        raw2car: dict[str, set] = {}
        for m in doc.get("mappings") or []:
            pair = (m.get("object"), m.get("action"))
            bucket = consumed_by_pair.setdefault(pair, set())
            for car_field, v in (m.get("field_provenance") or {}).items():
                srcs = re.sub(r"\s*\[[a-z]+\]$", "", v)
                for raw in re.split(r"\s*\|\s*", srcs):
                    raw = raw.strip()
                    if raw:
                        bucket.add(raw)
                        raw2car.setdefault(raw, set()).add(car_field)
        native_by_pair: dict[tuple, set] = {}
        for line in doc.get("other_coverage") or []:
            m2 = re.match(r"native/join keys \(([^/]+)/([^)]+)\): (.*)", line)
            if m2:
                pair = (m2.group(1).strip(), m2.group(2).strip())
                native_by_pair.setdefault(pair, set()).update(
                    f.strip() for f in m2.group(3).split(",") if f.strip())
        out[doc["sensor_name"]] = {"tool": doc["extractor"]["tool"],
                                   "consumed_by_pair": consumed_by_pair,
                                   "native_by_pair": native_by_pair,
                                   "raw2car": raw2car}
    return out


def _leaf_consumed(leaf: dict) -> set[str]:
    """The raw record/payload fields ONE ir leaf reads — conservative: bare
    `ts`/pid slots, payload/userdata path components, nothing guessed from
    unknown-op string literals."""
    out: set[str] = set()

    def walk(v) -> None:
        if isinstance(v, dict) and "!" in v:
            op, *args = v["!"]
            if op in ("payload", "userdata"):
                for a in args[1:]:
                    out.add(a) if isinstance(a, str) else walk(a)
            elif op == "const":
                return
            elif op == "map_value":
                walk(args[0] if args else None)
            else:
                for a in args:
                    walk(a)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    for slot in ("ts", "owning_pid", "parent_pid", "owning_guid"):
        if isinstance(leaf.get(slot), str):
            out.add(leaf[slot])
        else:
            walk(leaf.get(slot))
    for _name, expr in leaf.get("props") or []:
        walk(expr)
    walk(leaf.get("host"))
    return out


def _lane_variant_facts() -> dict[str, list[dict]]:
    """lane -> [{fam, pairs, consumed, recipe}] per ir leaf — the SAME class
    resolution render_mappings uses (a split lane's leaf belongs to its
    spindle sub-entry's family, never its lane-mates')."""
    ir = json.load(open(IR_PATH, encoding="utf-8"))
    assigned = _lane_families()
    out: dict[str, list[dict]] = {}
    for lane, spec in ir["mappings"].items():
        leaves = list(spec.get("variants", []))
        if spec.get("default"):
            leaves.append((None, spec["default"]))
        for _pred, leaf in leaves:
            recipe = (leaf.get("guid") or {}).get("spindle")
            fam = (assigned.get(recipe) if recipe and "/" in recipe
                   else assigned.get(lane))
            lits, _open = _action_literals(leaf.get("action"))
            out.setdefault(lane, []).append({
                "fam": fam,
                "pairs": {(leaf.get("object"), a) for a in lits},
                "consumed": _leaf_consumed(leaf),
                "recipe": recipe,
            })
    return out


def _recipe_targets(recipes: set[str]) -> tuple[set[str], set[str]]:
    """(native keys, CAR fields) the given spindle recipes hash — the
    identity components' sources (`native.<key>` or a CAR field name)."""
    reg = yaml.safe_load(open(SPINDLE_PATH, encoding="utf-8"))["identities"]
    native_keys: set[str] = set()
    car_fields: set[str] = set()
    for name in recipes:
        entry = reg.get(name)
        if not entry:
            continue
        for source in (entry.get("identity") or {}).values():
            if isinstance(source, str) and source.startswith("native."):
                native_keys.add(source[len("native."):])
            elif isinstance(source, str):
                car_fields.add(source)
    return native_keys, car_fields


def render_profiles() -> dict[str, str]:
    seed = yaml.safe_load(open(PROFILES_SEED_PATH, encoding="utf-8"))["tools"]
    surfaces = _lane_surfaces()
    facts = _lane_variant_facts()
    assigned = _lane_families()
    header = ("# GENERATED by python -m byakugan.schema_gen — do not hand-edit.\n"
              "# One Parser Profile per (parser, artefact class): the record\n"
              "# surface as data — curated in profiles-seed.yaml (in-house\n"
              "# structs mined file:line from the tool repos), joined with the\n"
              "# reviewed lane surfaces in sources/*.yaml and the ir closure\n"
              "# (split lanes contribute PER VARIANT, never whole-lane).\n")

    # (tool, class) -> lanes, from the reviewed sources + seed lane families
    by_pair: dict[tuple[str, str], list[str]] = {}
    for lane, surf in surfaces.items():
        for key, fam in assigned.items():
            if key.split("/")[0] == lane:
                by_pair.setdefault((surf["tool"], fam), [])
                if lane not in by_pair[(surf["tool"], fam)]:
                    by_pair[(surf["tool"], fam)].append(lane)
    files: dict[str, str] = {}
    for tool_name, spec in sorted(seed.items()):
        classes = sorted({fam for (t, fam) in by_pair if t == tool_name})
        if spec.get("no_class") or (not classes and spec.get("artefact_class")):
            classes = [spec.get("artefact_class")]      # declared, unrouted
        for fam in classes:
            lanes = sorted(by_pair.get((tool_name, fam), []))
            consumed: set[str] = set()
            native: set[str] = set()
            recipes: set[str] = set()
            raw2car: dict[str, set] = {}
            for lane in lanes:
                surf = surfaces[lane]
                lane_facts = facts.get(lane) or []
                split = len({f["fam"] for f in lane_facts}) > 1
                fam_facts = [f for f in lane_facts if f["fam"] == fam]
                fam_pairs = set().union(*(f["pairs"] for f in fam_facts)) \
                    if fam_facts else set()
                if split:
                    # per-variant truth from the ir closure; the reviewed
                    # manifest must stay explained by it, loudly
                    walker_union = set().union(*(f["consumed"] for f in lane_facts))
                    reviewed = set().union(*surf["consumed_by_pair"].values()) \
                        if surf["consumed_by_pair"] else set()
                    if not reviewed <= walker_union:
                        raise SystemExit(
                            f"schema_gen: split lane {lane!r}: reviewed fields "
                            f"{sorted(reviewed - walker_union)} not explained by "
                            f"the ir walker — extend _leaf_consumed")
                    consumed |= set().union(*(f["consumed"] for f in fam_facts)) \
                        if fam_facts else set()
                else:
                    consumed |= set().union(*surf["consumed_by_pair"].values()) \
                        if surf["consumed_by_pair"] else set()
                for pair, keys in surf["native_by_pair"].items():
                    if not split or pair in fam_pairs:
                        native |= keys
                recipes |= {f["recipe"] for f in fam_facts if f["recipe"]}
                for raw, cars in surf["raw2car"].items():
                    raw2car.setdefault(raw, set()).update(cars)
            id_native, id_car = _recipe_targets(recipes)

            def bind_of(name: str) -> str:
                if name in id_native or (raw2car.get(name, set()) & id_car) \
                        or name in id_car:
                    return "identity"          # a spindle recipe hashes it
                if name in consumed:
                    return "mapping"
                return "surplus"

            if spec.get("in_house"):
                fields = [{"name": f["name"], "type": f["type"],
                           "binds": bind_of(f["name"]), "at": f["at"]}
                          for f in spec["fields"]]
            else:
                types = spec.get("types") or {}
                fields = [{"name": n,
                           "type": ("string" if spec["transport"] in ("csv", "tsv")
                                    else types.get(n, "string")),
                           "binds": bind_of(n)}
                          for n in sorted(consumed | native)]
            doc = {
                "schema_version": _schema_version(),
                "source": "generated",
                "generated_from": {
                    "seed": "model/schema/profiles-seed.yaml",
                    "surfaces": "sources/*.yaml (reviewed lane manifests) + "
                                "go/internal/ir/ir.json (per-variant closure)",
                },
                "profile": f"{spec['slug']}--{fam or 'unrouted'}",
                "parser": {"tool": tool_name,
                           "version_range": spec["version_range"],
                           "url": spec["url"],
                           "in_house": bool(spec.get("in_house"))},
                "artefact_class": fam,
                "lanes": lanes,
                "transport": spec["transport"],
                "fields": fields,
            }
            if spec.get("dynamic"):
                doc["dynamic"] = spec["dynamic"]
            if spec.get("no_class"):
                doc["coverage_debt"] = spec["no_class"]
            if spec.get("alternate_for"):
                doc["alternate_for"] = spec["alternate_for"]
            files[f"profiles/{doc['profile']}.yaml"] = header + yaml.safe_dump(
                doc, sort_keys=False, allow_unicode=True, width=88)
    return files


# --------------------------------------------------------------------------- #
# the engine-input row schema (epic &1 phase 7 — #136): what the Python
# graph engine loads (car_*.jsonl). GENERATED — the event gate is the same
# closed (object, action) vocabulary the classes ride.
# --------------------------------------------------------------------------- #
def render_row() -> str:
    import importlib
    store = importlib.import_module("byakugan.store")
    header_props = {name: (True if name == "native"
                           else {"type": ["string", "number", "null"]})
                    for name in store.HEADER}
    car_objects = sorted(
        name[:-4] for name in os.listdir(CAR_OBJECTS_DIR) if name.endswith(".yml"))
    legal = _legal_actions()
    confidence = {"enum": ["definitive", "heuristic", "inferred", None]}
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": _GITHUB_RAW + "wire/row.schema.json",
        "title": "Engine-input rows — GENERATED load gate",
        "description": ("Never hand-edited: python -m byakugan.schema_gen regenerates it "
                        "(conform class-regen gates drift). byakugan.elastic.load "
                        "validates every consumed row against the matching $def — "
                        "count-and-carry: a nonconforming row is TALLIED in the load "
                        "summary, never a crash and never silently admitted. Rows stay "
                        "open beyond the gated surface (per-object properties ride "
                        "flat); the gate is the closed (object, action) vocabulary "
                        "plus the header/edge grammar."),
        "$defs": {
            "event": {
                "type": "object",
                "required": ["car_object"],
                "properties": {
                    "car_object": {"enum": car_objects},
                    "car_action": {"type": ["string", "null"]},
                    **header_props,
                },
                "allOf": [
                    {"if": {"properties": {"car_object": {"const": o}},
                            "required": ["car_object"]},
                     "then": {"properties": {"car_action": {
                         "enum": sorted(legal[o]) + [None]}}}}
                    for o in car_objects
                ],
            },
            "relationship": {
                "type": "object",
                "required": ["class", "source_object", "source_guid",
                             "target_object", "target_guid"],
                "properties": {
                    "class": {"enum": ["declared", "derived"]},
                    "confidence": confidence,
                    "relationship": {"type": ["string", "null"]},
                    "timestamp": {"type": ["string", "null"]},
                },
            },
            "inferred": {
                "type": "object",
                "required": ["node_id"],
                "properties": {"node_id": {"type": ["string", "number"]}},
            },
            "content": {
                "type": "object",
                "required": ["node_id"],
                "properties": {"node_id": {"type": ["string", "number"]}},
            },
        },
    }
    return json.dumps(schema, indent=1, ensure_ascii=False) + "\n"


def render_all() -> dict[str, str]:
    files, _held, _notes = build_classes()
    files["vocab/car-actions.schema.json"] = render_vocab(_legal_actions())
    files[ENRICHMENT_REL] = render_enrichment()
    files["wire/relationship.schema.json"] = render_wire_relationship()
    files["wire/objects.schema.json"] = render_wire_objects()
    files["wire/bundle.schema.json"] = render_wire_bundle()
    files.update(render_mappings())
    files.update(render_profiles())
    files["wire/row.schema.json"] = render_row()
    return files


def check() -> list[str]:
    """Byte-exact drift findings ([] when in sync)."""
    problems: list[str] = []
    want = render_all()
    for rel, content in sorted(want.items()):
        p = os.path.join(SCHEMA_DIR, rel)
        try:
            have = open(p, encoding="utf-8").read()
        except FileNotFoundError:
            problems.append(f"{rel}: missing — regenerate")
            continue
        if have != content:
            problems.append(f"{rel}: out of date — regenerate")
    if os.path.isdir(CLASSES_DIR):
        for name in sorted(os.listdir(CLASSES_DIR)):
            if name.endswith(".yaml") and f"classes/{name}" not in want:
                problems.append(f"classes/{name}: not generated by the seed — remove")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="byakugan.schema_gen", description=__doc__)
    ap.add_argument("--check", action="store_true", help="byte-exact drift gate")
    args = ap.parse_args(argv)
    if args.check:
        problems = check()
        for p in problems:
            print(f"OUT OF DATE: {p}")
        if problems:
            return 1
        print("OK: model/schema classes + vocab in sync with the seed/ir/overlay")
        return 0
    files, held, notes = build_classes()
    files["vocab/car-actions.schema.json"] = render_vocab(_legal_actions())
    files[ENRICHMENT_REL] = render_enrichment()
    files["wire/relationship.schema.json"] = render_wire_relationship()
    files["wire/objects.schema.json"] = render_wire_objects()
    files["wire/bundle.schema.json"] = render_wire_bundle()
    files.update(render_mappings())
    files.update(render_profiles())
    files["wire/row.schema.json"] = render_row()
    for rel, content in sorted(files.items()):
        p = os.path.join(SCHEMA_DIR, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        print("wrote", os.path.relpath(p, _ROOT))
    for fam in held:
        print(f"held (admission rule, no class emitted): {fam}")
    for n in notes:
        print("note:", n)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

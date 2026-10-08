"""Count-and-carry conformance core (schema mission, epic &1 phase 1).

The one finding shape both engines emit (mirrored by go/internal/conform):

    {object_id, rule, path, message}

Policy (docs/design/schema-layers.md): every object validates, every failure
tallies into a neutral finding — nothing is dropped for being unfamiliar —
and strict mode fails on a nonzero tally. Rules register here per layer as
the epic phases land; phase 1 ships the foundation rules over model/schema/
itself.

    python -m byakugan.conform            # run, print findings + tally
    python -m byakugan.conform --strict   # exit 1 on any finding
    python -m byakugan.conform --write-constants   # regenerate constants.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Callable, Iterable, Iterator

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
# the one resolution seam (env override -> repo checkout -> packaged copy):
# conform reads wherever the engine reads, so the gate travels with it
from .schemadata import schema_dir as _schema_dir_seam
SCHEMA_DIR = _schema_dir_seam()


@dataclass(frozen=True)
class Finding:
    """The neutral finding record — identical in both engines
    (defs.schema.json#/$defs/finding)."""
    object_id: str
    rule: str
    message: str
    path: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        if not d["path"]:
            del d["path"]
        return d


Rule = Callable[[], Iterator[Finding]]
_RULES: dict[str, Rule] = {}


def rule(rule_id: str) -> Callable[[Rule], Rule]:
    """Register a conformance rule; its findings carry rule=rule_id."""
    def deco(fn: Rule) -> Rule:
        _RULES[rule_id] = fn
        return fn
    return deco


def run(rule_ids: Iterable[str] | None = None) -> list[Finding]:
    """Run the registered rules (all by default); findings, never raises."""
    out: list[Finding] = []
    for rid in (rule_ids or sorted(_RULES)):
        try:
            out.extend(_RULES[rid]())
        except Exception as exc:  # a broken rule is itself a finding
            out.append(Finding(object_id=rid, rule="rule-error", message=str(exc)))
    return out


def tally(findings: Iterable[Finding]) -> Counter:
    return Counter(f.rule for f in findings)


# --------------------------------------------------------------------------- #
# constants.yaml is GENERATED from the code constants — regenerating must be
# byte-identical (the staleness-gate pattern; rule schema-constants below).
# --------------------------------------------------------------------------- #
def render_constants() -> str:
    from .exchange.objects import (DX_NAMESPACE, EVIDENCE_EXTENSION_ID,
                                   EVIDENCE_EXTENSION_VERSION, EXTENSION_ID)
    from .ids import CAR_NS, SPINDLE_NS, STIX_NS
    from .stix import CATALOGUE_NS
    return f"""# model/schema/constants.yaml — the wire-format constants, stated once.
# GENERATED VALUES: every uuid below is computed from the seeds recorded next
# to it; regenerating from byakugan.ids / byakugan.exchange.objects must
# reproduce this file byte-identically (tests/test_schema_foundations.py).
# These are wire format: they never change (schema-layers.md, Identity Rules).

schema_version: "{EVIDENCE_EXTENSION_VERSION}"   # THE one version; renders into extension-definition.version

namespaces:
  STIX_NS: {STIX_NS}    # STIX 2.1 s2.9 SCO namespace — mints SCO ids ONLY
  CAR_NS: {CAR_NS}      # uuid5(NAMESPACE_URL, "https://github.com/Get-Sybers/Byakugan/stix") — seed URL is wire, not a link
  SPINDLE_NS: {SPINDLE_NS}   # uuid5(CAR_NS, "spindle") — row identity; NEVER an object id
  CATALOGUE_NS: {CATALOGUE_NS}   # uuid5(CAR_NS, "catalogue") — indicator / indicates
  DX_NAMESPACE: {DX_NAMESPACE}   # the exchange's deterministic-id root
  case_ns: uuid5(CAR_NS, "case|<case>")          # recipe — per-case instance scope

extensions:
  dxdfir: {EXTENSION_ID}
  dxdfir-evidence: {EVIDENCE_EXTENSION_ID}
"""


_CONSTANTS = os.path.join(SCHEMA_DIR, "constants.yaml")


@rule("schema-json")
def _schema_files_parse() -> Iterator[Finding]:
    """Every JSON file under model/schema/ parses."""
    for base, _dirs, files in os.walk(SCHEMA_DIR):
        for name in sorted(files):
            if not name.endswith(".json"):
                continue
            p = os.path.join(base, name)
            rel = os.path.relpath(p, _ROOT)
            try:
                json.load(open(p, encoding="utf-8"))
            except Exception as exc:
                yield Finding(object_id=rel, rule="schema-json", message=str(exc))


@rule("schema-constants")
def _constants_in_sync() -> Iterator[Finding]:
    """constants.yaml regenerates byte-identically from the code constants."""
    rel = os.path.relpath(_CONSTANTS, _ROOT)
    try:
        committed = open(_CONSTANTS, encoding="utf-8").read()
    except FileNotFoundError:
        yield Finding(object_id=rel, rule="schema-constants", message="missing")
        return
    if committed != render_constants():
        yield Finding(object_id=rel, rule="schema-constants",
                      message="out of date — regenerate: python -m byakugan.conform --write-constants")


@rule("schema-version-lockstep")
def _version_lockstep() -> Iterator[Finding]:
    """ONE version: constants.yaml == extension-definition == its schema file."""
    from .exchange.objects import EVIDENCE_EXTENSION_VERSION
    import yaml
    doc = yaml.safe_load(open(_CONSTANTS, encoding="utf-8"))
    if doc.get("schema_version") != EVIDENCE_EXTENSION_VERSION:
        yield Finding(object_id="model/schema/constants.yaml", rule="schema-version-lockstep",
                      path="schema_version",
                      message=f"{doc.get('schema_version')!r} != EVIDENCE_EXTENSION_VERSION")
    ext = json.load(open(os.path.join(SCHEMA_DIR, "extensions",
                                      "dxdfir-evidence.schema.json"), encoding="utf-8"))
    if ext.get("version") != EVIDENCE_EXTENSION_VERSION:
        yield Finding(object_id="model/schema/extensions/dxdfir-evidence.schema.json",
                      rule="schema-version-lockstep", path="version",
                      message=f"{ext.get('version')!r} != EVIDENCE_EXTENSION_VERSION")
    for rel in ("identity/object-ids.yaml", "enrichment/rules.yaml"):
        doc2 = yaml.safe_load(open(os.path.join(SCHEMA_DIR, *rel.split("/")),
                                   encoding="utf-8"))
        if str(doc2.get("schema_version")) != EVIDENCE_EXTENSION_VERSION:
            yield Finding(object_id=f"model/schema/{rel}", rule="schema-version-lockstep",
                          path="schema_version",
                          message=f"{doc2.get('schema_version')!r} != EVIDENCE_EXTENSION_VERSION")


@rule("schema-namespace-values")
def _namespace_values() -> Iterator[Finding]:
    """The literal uuids in constants.yaml equal the code-derived values."""
    import yaml
    from .exchange.objects import DX_NAMESPACE
    from .ids import CAR_NS, SPINDLE_NS, STIX_NS
    from .stix import CATALOGUE_NS
    doc = yaml.safe_load(open(_CONSTANTS, encoding="utf-8"))
    ns = doc.get("namespaces") or {}
    expected = {"STIX_NS": STIX_NS, "CAR_NS": CAR_NS, "SPINDLE_NS": SPINDLE_NS,
                "CATALOGUE_NS": CATALOGUE_NS, "DX_NAMESPACE": DX_NAMESPACE}
    for key, want in expected.items():
        have = ns.get(key)
        if str(have) != str(want):
            yield Finding(object_id="model/schema/constants.yaml",
                          rule="schema-namespace-values", path=f"namespaces.{key}",
                          message=f"{have!r} != {want}")
    # derivations hold: SPINDLE and CATALOGUE are CAR_NS children
    if uuid.uuid5(CAR_NS, "spindle") != SPINDLE_NS:
        yield Finding(object_id="byakugan/ids.py", rule="schema-namespace-values",
                      message="SPINDLE_NS is not uuid5(CAR_NS, 'spindle')")
    if uuid.uuid5(CAR_NS, "catalogue") != CATALOGUE_NS:
        yield Finding(object_id="byakugan/stix.py", rule="schema-namespace-values",
                      message="CATALOGUE_NS is not uuid5(CAR_NS, 'catalogue')")


@rule("class-regen")
def _classes_in_sync() -> Iterator[Finding]:
    """The generated classes + vocabulary regenerate byte-identically
    (seed / ir.json / matched-overlay drift gate — phase 2, #131)."""
    from . import schema_gen
    for problem in schema_gen.check():
        rel, _, msg = problem.partition(": ")
        yield Finding(object_id=f"model/schema/{rel}", rule="class-regen", message=msg or problem)


@rule("class-structure")
def _class_structure() -> Iterator[Finding]:
    """Structural gate over every class declaration: facets present, closed
    enums respected, evidences rows complete and vocabulary-legal."""
    import yaml
    from . import schema_gen
    try:
        legal = {o: set(a) for o, a in schema_gen._legal_actions().items()}  # noqa: SLF001
    except FileNotFoundError:
        return  # no car model checked out: the regen rule already reports
    classes_dir = os.path.join(SCHEMA_DIR, "classes")
    if not os.path.isdir(classes_dir):
        return
    for name in sorted(os.listdir(classes_dir)):
        if not name.endswith(".yaml"):
            continue
        rel = f"model/schema/classes/{name}"
        doc = yaml.safe_load(open(os.path.join(classes_dir, name), encoding="utf-8"))
        for facet in ("schema_version", "source", "family", "platform", "domain",
                      "references", "aliases", "evidences"):
            if facet not in doc:
                yield Finding(object_id=rel, rule="class-structure",
                              path=facet, message="missing facet")
        for p in doc.get("platform") or []:
            if p not in schema_gen.PLATFORMS:
                yield Finding(object_id=rel, rule="class-structure",
                              path="platform", message=f"{p!r} outside the closed enum")
        if doc.get("domain") not in schema_gen.DOMAINS:
            yield Finding(object_id=rel, rule="class-structure",
                          path="domain", message=f"{doc.get('domain')!r} outside the closed enum")
        for i, row in enumerate(doc.get("evidences") or []):
            where = f"evidences[{i}]"
            if row.get("action") not in legal.get(row.get("object"), set()):
                yield Finding(object_id=rel, rule="class-structure", path=where,
                              message=f"illegal pair ({row.get('object')}, {row.get('action')})")
            if row.get("evidence") not in ("definitive", "heuristic", "inferred"):
                yield Finding(object_id=rel, rule="class-structure", path=where,
                              message=f"illegal evidence tier {row.get('evidence')!r}")
            if row.get("time") not in ("event-time", "bounded", "none"):
                yield Finding(object_id=rel, rule="class-structure", path=where,
                              message=f"illegal time semantics {row.get('time')!r}")
            if not row.get("sources"):
                yield Finding(object_id=rel, rule="class-structure", path=where,
                              message="row cites no source (row-grounding MUST)")


_REGISTRY_ID = "byakugan.spindle.rules() (ir.json spindle + golden, with the byakugan/spindle.yml notes)"


@rule("identity-registry")
def _identity_registry() -> Iterator[Finding]:
    """The assembled spindle registry validates against the Identity Rules
    layer (identity-rules.schema.json, structurally): every entry carries
    the eight declared fields, legal kind/scope enums, an integer version
    and a golden vector — the registry (the IR's spindle + golden sections
    joined with the spindle.yml notes) is validated IN PLACE, never copied."""
    from . import spindle
    doc = spindle.rules()
    sp = doc.get("spindle") or {}
    if not isinstance(sp.get("version"), int) or sp.get("version") < 1:
        yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                      path="spindle.version", message="missing or non-positive")
    ns = sp.get("namespace") or {}
    if (ns.get("parent"), ns.get("label")) != ("CAR_NS", "spindle"):
        yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                      path="spindle.namespace", message="not the CAR_NS/spindle derivation")
    for key in ("object_key", "version_key"):
        if not isinstance(sp.get(key), str) or not sp.get(key):
            yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                          path=f"spindle.{key}", message="missing or not a non-empty string")
    if set(sp.get("scopes") or {}) != {"intrinsic", "positional"}:
        yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                      path="spindle.scopes",
                      message="must define exactly the intrinsic/positional scopes")
    if set(sp.get("kinds") or {}) != {"record", "entity"}:
        yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                      path="spindle.kinds",
                      message="must define exactly the record/entity kinds")
    pos = sp.get("positional") or {}
    if not pos.get("fields") or not isinstance(pos.get("version"), int) or not pos.get("golden"):
        yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                      path="spindle.positional", message="fields/version/golden incomplete")
    required = ("object", "kind", "scope", "version", "validated_against",
                "stable_across", "identity", "golden")
    for name, entry in sorted((doc.get("identities") or {}).items()):
        where = f"identities.{name}"
        for field in required:
            if field not in entry:
                yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                              path=f"{where}.{field}", message="missing")
        if entry.get("kind") not in ("record", "entity"):
            yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                          path=f"{where}.kind", message=f"{entry.get('kind')!r} outside the enum")
        if entry.get("scope") not in ("intrinsic", "positional"):
            yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                          path=f"{where}.scope", message=f"{entry.get('scope')!r} outside the enum")
        if not isinstance(entry.get("version"), int) or entry.get("version", 0) < 1:
            yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                          path=f"{where}.version", message="not a positive integer")
        golden = entry.get("golden") or {}
        if golden.get("source") not in ("real", "synthetic") or not golden.get("values"):
            yield Finding(object_id=_REGISTRY_ID, rule="identity-registry",
                          path=f"{where}.golden", message="source/values incomplete")


@rule("identity-object-ids")
def _identity_object_ids() -> Iterator[Finding]:
    """identity/object-ids.yaml (the R1-R5 scope table) names exactly the five
    scopes and only namespaces that constants.yaml declares."""
    import yaml
    rel = "model/schema/identity/object-ids.yaml"
    doc = yaml.safe_load(open(os.path.join(SCHEMA_DIR, "identity", "object-ids.yaml"),
                              encoding="utf-8"))
    scopes = doc.get("scopes") or {}
    want = {"global-content", "case", "catalogue", "smo", "row"}
    if set(scopes) != want:
        yield Finding(object_id=rel, rule="identity-object-ids", path="scopes",
                      message=f"scopes {sorted(scopes)} != {sorted(want)}")
    constants = yaml.safe_load(open(_CONSTANTS, encoding="utf-8"))
    declared_ns = set(constants.get("namespaces") or {})
    for name, spec in scopes.items():
        ns = (spec or {}).get("namespace")
        if ns not in declared_ns:
            yield Finding(object_id=rel, rule="identity-object-ids",
                          path=f"scopes.{name}.namespace",
                          message=f"{ns!r} not declared in constants.yaml")


@rule("enrichment-structure")
def _enrichment_structure() -> Iterator[Finding]:
    """enrichment/rules.yaml validates against the Enrichment Rules layer
    (enrichment-rule.schema.json, structurally) — regeneration byte-equality
    (class-regen) gates drift, this gates SHAPE: a generator bug that emitted
    a schema-invalid declaration is a finding, not a silent pass."""
    import yaml
    rel = "model/schema/enrichment/rules.yaml"
    doc = yaml.safe_load(open(os.path.join(SCHEMA_DIR, "enrichment", "rules.yaml"),
                              encoding="utf-8"))
    rules_ = doc.get("rules")
    if not isinstance(rules_, list) or not rules_:
        yield Finding(object_id=rel, rule="enrichment-structure", path="rules",
                      message="missing or empty rules array")
        return
    required = ("id", "layer", "applies_to", "method", "scope", "declared_in")
    allowed = set(required) | {"inputs", "emits"}
    seen: set[str] = set()
    for i, r in enumerate(rules_):
        where = f"rules[{i}]"
        for field in required:
            if not isinstance(r.get(field), str) or not r.get(field):
                yield Finding(object_id=rel, rule="enrichment-structure",
                              path=f"{where}.{field}", message="missing or not a string")
        if extra := set(r) - allowed:
            yield Finding(object_id=rel, rule="enrichment-structure", path=where,
                          message=f"undeclared properties {sorted(extra)}")
        if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9_]+)*", str(r.get("id") or "")):
            yield Finding(object_id=rel, rule="enrichment-structure",
                          path=f"{where}.id", message=f"{r.get('id')!r} outside the id pattern")
        if r.get("layer") not in ("inheritance", "dedupe", "identity", "derived",
                                  "canonicalisation"):
            yield Finding(object_id=rel, rule="enrichment-structure",
                          path=f"{where}.layer", message=f"{r.get('layer')!r} outside the enum")
        if r.get("scope") != "self":
            yield Finding(object_id=rel, rule="enrichment-structure",
                          path=f"{where}.scope", message=f"{r.get('scope')!r} != 'self'")
        for lst in ("inputs", "emits"):
            if lst in r and (not isinstance(r[lst], list)
                             or any(not isinstance(x, str) for x in r[lst])):
                yield Finding(object_id=rel, rule="enrichment-structure",
                              path=f"{where}.{lst}", message="not a list of strings")
        if r.get("id") in seen:
            yield Finding(object_id=rel, rule="enrichment-structure",
                          path=f"{where}.id", message=f"duplicate rule id {r.get('id')!r}")
        seen.add(r.get("id"))


@rule("wire-schemas")
def _wire_schemas() -> Iterator[Finding]:
    """Every generated wire schema is a valid 2020-12 schema whose $refs all
    resolve against the vendored OASIS set — the crawl is TRANSITIVE over
    every branch (a typo'd vendor path in any type leg is a finding), not a
    single-instance probe that only exercises one dispatch arm."""
    import jsonschema
    from .wirecheck import _load_validators
    registry = _load_validators()["registry"]

    def refs_in(node) -> Iterator[str]:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "$ref" and isinstance(v, str):
                    yield v
                else:
                    yield from refs_in(v)
        elif isinstance(node, list):
            for item in node:
                yield from refs_in(item)

    for name in ("relationship.schema.json", "objects.schema.json",
                 "bundle.schema.json"):
        rel = f"model/schema/wire/{name}"
        doc = json.load(open(os.path.join(SCHEMA_DIR, "wire", name), encoding="utf-8"))
        try:
            jsonschema.Draft202012Validator.check_schema(doc)
        except jsonschema.SchemaError as exc:
            yield Finding(object_id=rel, rule="wire-schemas",
                          message=f"not a valid 2020-12 schema: {exc.message[:160]}")
        visited: set[int] = set()
        queue = [(registry.resolver(doc["$id"]), doc)]
        while queue:
            resolver, node = queue.pop()
            if id(node) in visited:
                continue
            visited.add(id(node))
            for ref in refs_in(node):
                try:
                    resolved = resolver.lookup(ref)
                except Exception as exc:
                    yield Finding(object_id=rel, rule="wire-schemas", path=ref,
                                  message=f"unresolvable $ref: "
                                          f"{type(exc).__name__}: {exc}"[:200])
                    continue
                queue.append((resolved.resolver, resolved.contents))


@rule("x-property-registry")
def _x_property_registry() -> Iterator[Finding]:
    """The R6 standing harvest gate: the emitted surface (harvested), the
    declared EVIDENCE_PROPERTIES tuple and the generated wire overlay are ONE
    closed list — a new x_car_* emission or a stale declaration is a finding
    the moment it lands, not at the next review."""
    from .exchange.objects import EVIDENCE_PROPERTIES
    from .schema_gen import harvest_x_car
    harvested, declared = set(harvest_x_car()), set(EVIDENCE_PROPERTIES)
    for name in sorted(harvested - declared):
        yield Finding(object_id="byakugan/exchange/objects.py",
                      rule="x-property-registry", path=name,
                      message="emitted but not declared in EVIDENCE_PROPERTIES")
    for name in sorted(declared - harvested):
        yield Finding(object_id="byakugan/exchange/objects.py",
                      rule="x-property-registry", path=name,
                      message="declared but no longer on the emitted surface")
    wire = json.load(open(os.path.join(SCHEMA_DIR, "wire", "objects.schema.json"),
                          encoding="utf-8"))
    overlay = {k for k in wire["$defs"]["overlay"]["properties"]
               if k.startswith("x_car_")}
    if overlay != harvested:
        yield Finding(object_id="model/schema/wire/objects.schema.json",
                      rule="x-property-registry", path="$defs.overlay",
                      message="overlay list != harvested list — regenerate")


@rule("mapping-structure")
def _mapping_structure() -> Iterator[Finding]:
    """Every generated mappings/*.yaml validates against the Model Mapping
    layer schema (model-mapping.schema.json) — the phase-4 validator applied
    to the layer's own declarations: shape gating beside class-regen's byte
    gate."""
    import jsonschema
    import yaml
    from .wirecheck import _GITHUB_RAW, _load_validators
    registry = _load_validators()["registry"]
    mappings_dir = os.path.join(SCHEMA_DIR, "mappings")
    for name in sorted(os.listdir(mappings_dir)):
        if not name.endswith(".yaml"):
            continue
        fragment = "routing" if name == "routes.yaml" else "mapping"
        validator = jsonschema.Draft202012Validator(
            {"$ref": _GITHUB_RAW + f"model-mapping.schema.json#/$defs/{fragment}"},
            registry=registry)
        doc = yaml.safe_load(open(os.path.join(mappings_dir, name), encoding="utf-8"))
        for err in validator.iter_errors(doc):
            yield Finding(object_id=f"model/schema/mappings/{name}",
                          rule="mapping-structure",
                          path="/".join(str(p) for p in err.absolute_path),
                          message=err.message[:200])


@rule("mapping-coverage")
def _mapping_coverage() -> Iterator[Finding]:
    """The declarations and ir.json hold each other BOTH ways: every ir lane
    is declared and every declaration is an ir lane; the declared predicate
    names and ir.predicate_names are ONE set (declared == registered — the
    Go registry side is gen-ir/TestRegistryAgainstIR); every artefact_class
    is a seed family and every identity a spindle recipe."""
    import yaml
    ir = json.load(open(os.path.join(_ROOT, "go", "internal", "ir", "ir.json"),
                        encoding="utf-8"))
    mappings_dir = os.path.join(SCHEMA_DIR, "mappings")
    declared_lanes: set[str] = set()
    whens: set[str] = set()
    families = set(yaml.safe_load(open(os.path.join(SCHEMA_DIR, "classes-seed.yaml"),
                                       encoding="utf-8"))["families"])
    from . import spindle as _spindle
    recipes = set(_spindle.identities())
    for name in sorted(os.listdir(mappings_dir)):
        if not name.endswith(".yaml") or name == "routes.yaml":
            continue
        rel = f"model/schema/mappings/{name}"
        doc = yaml.safe_load(open(os.path.join(mappings_dir, name), encoding="utf-8"))
        declared_lanes.add(doc.get("lane"))
        leaves = list(doc.get("variants") or [])
        if doc.get("default"):
            leaves.append(doc["default"])
        n_variants = len(doc.get("variants") or [])
        for i, leaf in enumerate(leaves):
            where = f"variants[{i}]" if i < n_variants else "default"
            if leaf.get("when"):
                whens.add(leaf["when"])
            fam = leaf.get("artefact_class") or doc.get("artefact_class")
            if fam not in families:
                yield Finding(object_id=rel, rule="mapping-coverage",
                              path=f"{where}.artefact_class",
                              message=f"{fam!r} is not a seed family")
            recipe = leaf.get("identity")
            if recipe is not None and recipe not in recipes:
                yield Finding(object_id=rel, rule="mapping-coverage",
                              path=f"{where}.identity",
                              message=f"{recipe!r} is not a spindle recipe")
    ir_lanes = set(ir["mappings"])
    for lane in sorted(ir_lanes - declared_lanes):
        yield Finding(object_id="model/schema/mappings", rule="mapping-coverage",
                      path=lane, message="ir lane with no declaration — regenerate")
    for lane in sorted(declared_lanes - ir_lanes):
        yield Finding(object_id="model/schema/mappings", rule="mapping-coverage",
                      path=str(lane), message="declaration with no ir lane — remove")
    registered = set(ir["predicate_names"])
    for name in sorted(whens - registered):
        yield Finding(object_id="model/schema/mappings", rule="mapping-coverage",
                      path=name, message="declared predicate not in ir.predicate_names")
    for name in sorted(registered - whens):
        yield Finding(object_id="model/schema/mappings", rule="mapping-coverage",
                      path=name, message="registered predicate no declaration uses")


@rule("profile-structure")
def _profile_structure() -> Iterator[Finding]:
    """Every generated profiles/*.yaml validates against the Parser Profile
    layer schema (parser-profile.schema.json)."""
    import jsonschema
    import yaml
    from .wirecheck import _GITHUB_RAW, _load_validators
    validator = jsonschema.Draft202012Validator(
        {"$ref": _GITHUB_RAW + "parser-profile.schema.json"},
        registry=_load_validators()["registry"])
    profiles_dir = os.path.join(SCHEMA_DIR, "profiles")
    for name in sorted(os.listdir(profiles_dir)):
        if not name.endswith(".yaml"):
            continue
        doc = yaml.safe_load(open(os.path.join(profiles_dir, name), encoding="utf-8"))
        for err in validator.iter_errors(doc):
            yield Finding(object_id=f"model/schema/profiles/{name}",
                          rule="profile-structure",
                          path="/".join(str(p) for p in err.absolute_path),
                          message=err.message[:200])


@rule("profile-coverage")
def _profile_coverage() -> Iterator[Finding]:
    """The design's gate: each profile's lanes exist in the mapping layer and
    feed the profile's class; the bound mapping closure (the lanes' (object,
    action) pairs) is a SUBSET of the class's evidences; and the admission
    direction — every non-held family with lanes has at least one profile."""
    import yaml
    profiles_dir = os.path.join(SCHEMA_DIR, "profiles")
    mappings_dir = os.path.join(SCHEMA_DIR, "mappings")
    seed = yaml.safe_load(open(os.path.join(SCHEMA_DIR, "classes-seed.yaml"),
                               encoding="utf-8"))["families"]
    # lane -> class from the mapping declarations; lane closure per class
    lane_class: dict[str, set] = {}
    lane_pairs: dict[str, set] = {}
    for name in sorted(os.listdir(mappings_dir)):
        if not name.endswith(".yaml") or name == "routes.yaml":
            continue
        doc = yaml.safe_load(open(os.path.join(mappings_dir, name), encoding="utf-8"))
        leaves = list(doc.get("variants") or [])
        if doc.get("default"):
            leaves.append(doc["default"])
        classes = set()
        for leaf in leaves:
            fam = leaf.get("artefact_class") or doc.get("artefact_class")
            classes.add(fam)
            action = leaf.get("action")
            for a in ([action] if isinstance(action, str)
                      else (action or {}).get("declared") or []):
                # a split lane's closure binds PER VARIANT: each row belongs
                # to the variant's own class, never its lane-mates'
                lane_pairs.setdefault((doc["lane"], fam), set()).add(
                    (leaf.get("object"), a))
        lane_class[doc["lane"]] = classes
    class_evidences: dict[str, set] = {}
    classes_dir = os.path.join(SCHEMA_DIR, "classes")
    for name in sorted(os.listdir(classes_dir)):
        if name.endswith(".yaml"):
            doc = yaml.safe_load(open(os.path.join(classes_dir, name), encoding="utf-8"))
            class_evidences[doc["family"]] = {
                (r.get("object"), r.get("action")) for r in doc.get("evidences") or []}
    covered: set[str] = set()
    for name in sorted(os.listdir(profiles_dir)):
        if not name.endswith(".yaml"):
            continue
        rel = f"model/schema/profiles/{name}"
        doc = yaml.safe_load(open(os.path.join(profiles_dir, name), encoding="utf-8"))
        fam = doc.get("artefact_class")
        if fam is None:
            continue                       # declared coverage debt
        if fam not in seed:
            yield Finding(object_id=rel, rule="profile-coverage",
                          path="artefact_class", message=f"{fam!r} is not a seed family")
            continue
        covered.add(fam)
        bound: set = set()
        for lane in doc.get("lanes") or []:
            if lane not in lane_class:
                yield Finding(object_id=rel, rule="profile-coverage",
                              path=f"lanes.{lane}", message="not a mapping-layer lane")
                continue
            if fam not in lane_class[lane]:
                yield Finding(object_id=rel, rule="profile-coverage",
                              path=f"lanes.{lane}",
                              message=f"lane feeds {sorted(lane_class[lane])}, not {fam!r}")
            bound |= lane_pairs.get((lane, fam), set())
        outside = bound - class_evidences.get(fam, set())
        for obj, act in sorted(outside):
            yield Finding(object_id=rel, rule="profile-coverage",
                          path=f"({obj}, {act})",
                          message="bound mapping closure outside the class's evidences")
    for fam, spec in sorted(seed.items()):
        if spec.get("held") or not (spec.get("lanes") or []):
            continue
        if fam not in covered:
            yield Finding(object_id="model/schema/profiles", rule="profile-coverage",
                          path=fam, message="family has lanes but no Parser Profile")


@rule("row-gate")
def _row_gate() -> Iterator[Finding]:
    """The engine-input load gate is live: row.schema.json exists, compiles,
    and its event gate carries the SAME closed (object, action) vocabulary
    as vocab/car-actions.schema.json — one vocabulary, two carriers, held
    equal here."""
    import jsonschema
    rel = "model/schema/wire/row.schema.json"
    try:
        doc = json.load(open(os.path.join(SCHEMA_DIR, "wire", "row.schema.json"),
                             encoding="utf-8"))
    except FileNotFoundError:
        yield Finding(object_id=rel, rule="row-gate", message="missing — regenerate")
        return
    for kind in ("event", "relationship", "inferred", "content"):
        try:
            jsonschema.Draft202012Validator.check_schema(doc["$defs"][kind])
        except (KeyError, jsonschema.SchemaError) as exc:
            yield Finding(object_id=rel, rule="row-gate", path=kind,
                          message=f"invalid: {exc}"[:200])
            return
    vocab = json.load(open(os.path.join(SCHEMA_DIR, "vocab",
                                        "car-actions.schema.json"), encoding="utf-8"))
    row_pairs, vocab_pairs = {}, {}
    for c in doc["$defs"]["event"]["allOf"]:
        obj = c["if"]["properties"]["car_object"]["const"]
        row_pairs[obj] = sorted(a for a in c["then"]["properties"]["car_action"]["enum"]
                                if a is not None)
    for name, spec in vocab["$defs"].items():
        if name.endswith("-actions"):
            vocab_pairs[name[:-len("-actions")]] = sorted(spec["enum"])
    for obj, acts in sorted(row_pairs.items()):
        if vocab_pairs.get(obj) != acts:
            yield Finding(object_id=rel, rule="row-gate", path=obj,
                          message="event action enum != vocab enum — regenerate")


@rule("elastic-contract")
def _elastic_contract() -> Iterator[Finding]:
    """The ECS projection contract validates against the CAR model
    (elastic/projection/validate.py) — the Object Model side of the served
    store, run as a conform rule so ONE command proves the whole authority."""
    import subprocess
    proc = subprocess.run([sys.executable,
                           os.path.join(_ROOT, "elastic", "projection", "validate.py")],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        yield Finding(object_id="elastic/projection", rule="elastic-contract",
                      message=(proc.stderr or proc.stdout).strip()[-200:])


@rule("elastic-rendered")
def _elastic_rendered() -> Iterator[Finding]:
    """The rendered Elastic assets (component/index templates, Kibana bundle)
    byte-match a regeneration from the projection contract
    (render_elastic.py --check) — the wire-format rule applied to the
    served-store artifacts."""
    import subprocess
    proc = subprocess.run([sys.executable,
                           os.path.join(_ROOT, "elastic", "projection",
                                        "render_elastic.py"), "--check"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        yield Finding(object_id="elastic/projection/rendered", rule="elastic-rendered",
                      message=(proc.stderr or proc.stdout).strip()[-200:])


# --------------------------------------------------------------------------- #
# the named check-pass conformance table (#136 definition of done): every
# gate that proves an engine against the ONE schema, by name, with the
# command that runs it. GENERATED from the registry below + the named
# external gates; --write-table refreshes it, the conformance-table rule
# holds the committed file byte-exact — so the table can never claim a rule
# that does not exist, and a new rule cannot land unlisted.
# --------------------------------------------------------------------------- #
EXTERNAL_GATES = [
    {"name": "gen-ir-check", "engine": "go",
     "command": "make -C go gen-ir-check",
     "proves": "ir.json byte-matches the Go authoring tables"},
    {"name": "registry-against-ir", "engine": "go",
     "command": "go test github.com/Get-Sybers/Byakugan/go/internal/predicates",
     "proves": "registered predicate funcs == ir.predicate_names, both ways"},
    {"name": "finding-wire-parity", "engine": "go",
     "command": "go test github.com/Get-Sybers/Byakugan/go/internal/conform",
     "proves": "the Go Finding record serialises byte-compatibly with Python's"},
    {"name": "schema-gen-check", "engine": "python",
     "command": "python -m byakugan.schema_gen --check",
     "proves": "every generated model/schema file byte-matches regeneration"},
    {"name": "row-load-gate", "engine": "python",
     "command": "byakugan load (tallies `nonconforming` per source)",
     "proves": "graph-engine input rows validate against wire/row.schema.json "
               "at load, count-and-carry"},
    {"name": "wirecheck", "engine": "python",
     "command": "python -m byakugan.wirecheck <bundle.json>",
     "proves": "produced bundles validate against the composed wire schemas, "
               "count-and-carry"},
]


def render_conformance() -> str:
    rules_list = [{"name": name, "engine": "python",
                   "command": "python -m byakugan.conform --strict",
                   "proves": (fn.__doc__ or "").strip().split("\n")[0].rstrip(" .")}
                  for name, fn in sorted(_RULES.items())]
    doc = {"title": "The named check-pass conformance table (epic &1 #136): "
                    "both engines provably gated against one schema",
           "generated_by": "python -m byakugan.conform --write-table",
           "checks": rules_list + EXTERNAL_GATES}
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


@rule("conformance-table")
def _conformance_table() -> Iterator[Finding]:
    """model/schema/conformance.json byte-matches regeneration — the table
    names every registered rule and every external gate; a rule cannot land
    unlisted and the table cannot claim a rule that does not run."""
    rel = "model/schema/conformance.json"
    try:
        have = open(os.path.join(SCHEMA_DIR, "conformance.json"),
                    encoding="utf-8").read()
    except FileNotFoundError:
        yield Finding(object_id=rel, rule="conformance-table",
                      message="missing — python -m byakugan.conform --write-table")
        return
    if have != render_conformance():
        yield Finding(object_id=rel, rule="conformance-table",
                      message="out of date — python -m byakugan.conform --write-table")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="byakugan.conform",
                                 description="count-and-carry conformance: run the registered rules")
    ap.add_argument("--strict", action="store_true", help="exit 1 on any finding")
    ap.add_argument("--write-constants", action="store_true",
                    help="regenerate model/schema/constants.yaml from the code constants")
    ap.add_argument("--write-table", action="store_true",
                    help="regenerate model/schema/conformance.json (the named check-pass table)")
    args = ap.parse_args(argv)
    if args.write_constants:
        with open(_CONSTANTS, "w", encoding="utf-8") as fh:
            fh.write(render_constants())
        print(f"wrote {os.path.relpath(_CONSTANTS, _ROOT)}")
        return 0
    if args.write_table:
        path = os.path.join(SCHEMA_DIR, "conformance.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_conformance())
        print(f"wrote {os.path.relpath(path, _ROOT)}")
        return 0
    findings = run()
    for f in findings:
        print(json.dumps(f.as_dict(), ensure_ascii=False))
    counts = tally(findings)
    total = sum(counts.values())
    print(f"conform: {len(_RULES)} rules, {total} finding{'s' if total != 1 else ''}"
          + (f" {dict(sorted(counts.items()))}" if counts else ""))
    return 1 if (args.strict and findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())

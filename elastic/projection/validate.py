#!/usr/bin/env python3
"""Validate the hand-authored CAR->ECS projection contract against the CAR model.

The contract (conventions.yml + objects/<object>.yml) is written by hand; the
CAR model it projects (model/car/objects/*.yml) is generated from the pinned
submodules. This script keeps the two in lock-step — any drift is a non-zero
exit:

  * every CAR object has an objects/<object>.yml, and there is no orphan file;
  * every object_field of every object has exactly ONE projection entry —
    mapped (`ecs: <path>`) or explicitly homeless (`native: true` + `rationale`
    + `type`) — and no entry names a CAR field the object does not have;
  * conventions.yml projects every common_header field exactly once, and its
    per-object overrides / custom-namespace roots name real objects / fields;
  * every `ecs:` path looks like ECS (lower-case dotted, a known ECS 8.x
    top-level field set); custom homes are expressed as `native: true`, never
    as an `ecs:` path under `car.`;
  * two entries of one object sharing a primary target are explicit about it
    (exactly one primary, `fallback: true` on every other — rules.fallback);
  * event_defaults: a category, and an event.type for every car_action of the
    object (and only those); outcome sources name real actions / fields;
  * `derived:` entries build from real header / object fields.

relationships.yml / inferred.yml (the superset.db `relationship` /
`inferred_node` projections) and ecs_types.yml (the non-keyword mapping-type
overrides) are checked too, on their own terms (validate_edges):

  * their `fields:` cover exactly the source table's column list — no
    duplicate, no unknown key, no column left unprojected;
  * every field entry names an `ecs:` target and a `type:` (or an
    `ecs_types.yml` match) — `also:`/`also_type:` come in pairs;
  * `document_id.recipe` names only real source columns; `constants:` carries
    the data_stream identity (event.kind/module/dataset, data_stream.type/
    dataset, ecs.version), consistent with `dataset:`;
  * every ecs_types.yml path is ECS- or car.*-shaped, and every non-keyword
    override is actually used by some contract file — no dead overrides.

Dependencies: pyyaml only.

    python elastic/projection/validate.py
"""
from __future__ import annotations

import glob
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
# elastic/projection -> the repo root (two levels up) -> model/car/objects:
# the CAR model lives under model/ still; only the projection CONTRACT moved
# out to sit alongside the rest of Elastic (elastic/projection/).
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
CAR_OBJECTS_DIR = os.path.join(REPO_ROOT, "model", "car", "objects")
CONVENTIONS_PATH = os.path.join(HERE, "conventions.yml")
OBJECTS_DIR = os.path.join(HERE, "objects")
RELATIONSHIPS_PATH = os.path.join(HERE, "relationships.yml")
INFERRED_PATH = os.path.join(HERE, "inferred.yml")
ECS_TYPES_PATH = os.path.join(HERE, "ecs_types.yml")

# ECS 8.x top-level field sets (+ the base fields). A cheap guard against
# typos (`proccess.name`) — the full ECS schema is deliberately not vendored.
ECS_TOP_LEVEL = {
    "@timestamp", "labels", "message", "tags",
    "agent", "as", "client", "cloud", "code_signature", "container", "data_stream",
    "destination", "device", "dll", "dns", "ecs", "elf", "email", "error", "event",
    "faas", "file", "geo", "group", "hash", "host", "http", "interface", "log",
    "macho", "network", "observer", "orchestrator", "organization", "os", "package",
    "pe", "process", "registry", "related", "risk", "rule", "server", "service",
    "source", "threat", "tls", "trace", "transaction", "url", "user", "user_agent",
    "vlan", "vulnerability", "x509",
}
CUSTOM_ROOT = "car"
ECS_PATH = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
NATIVE_TYPES = {"keyword", "text", "long", "double", "float", "boolean", "date", "ip", "flattened"}
ENTRY_KEYS = {"car", "ecs", "also", "fallback", "note", "native", "rationale", "type"}
OUTCOMES = {"success", "failure", "unknown"}

# relationships.yml / inferred.yml: the superset.db `relationship` / `inferred_node`
# columns (byakugan/superset.py SupersetStore._create), minus the SQLite `id`
# autoincrement. Hardcoded here (validate.py stays pyyaml-only, no byakugan
# import) — tests/test_projection_rel_drift.py cross-checks this pair against
# the LIVE engine schema via PRAGMA table_info, so a schema change fails there
# until these two contract files (and this list) get a decision.
REL_COLUMNS = ["timestamp", "source_host", "relationship", "source_object", "source_guid",
              "target_object", "target_guid", "confidence", "method", "class",
              "identity_key", "inferred_end", "corroborated_by", "properties"]
INFERRED_COLUMNS = ["node_id", "source_host", "object", "identity_key", "identity_value",
                    "reason", "method", "corroborated_by", "properties", "first_seen",
                    "last_seen"]
EDGE_ENTRY_KEYS = {"car", "ecs", "type", "also", "also_type", "note"}
_RECIPE_SHA1 = re.compile(r"^sha1\((.*)\)$")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_car_model() -> dict[str, dict]:
    """{object: {header: [...], fields: [...], actions: [...]}} from model/car/objects/*.yml."""
    model: dict[str, dict] = {}
    for path in sorted(glob.glob(os.path.join(CAR_OBJECTS_DIR, "*.yml"))):
        doc = _load(path)
        props = doc.get("properties") or {}
        model[doc["name"]] = {
            "header": list(props.get("common_header") or []),
            "fields": [f["name"] for f in (props.get("object_fields") or [])],
            "actions": list(doc.get("car_action") or []),
        }
    return model


def load_contract() -> tuple[dict, dict[str, dict]]:
    """(conventions, {object: objects/<object>.yml doc})."""
    conventions = _load(CONVENTIONS_PATH)
    objects = {}
    for path in sorted(glob.glob(os.path.join(OBJECTS_DIR, "*.yml"))):
        objects[os.path.splitext(os.path.basename(path))[0]] = _load(path)
    return conventions, objects


def _check_path(path, where: str, errors: list[str], allow_custom: bool = False) -> None:
    if path == "@timestamp":
        return
    if not isinstance(path, str) or not ECS_PATH.match(path):
        errors.append(f"{where}: {path!r} is not an ECS-style field path")
        return
    root = path.split(".", 1)[0]
    if root == CUSTOM_ROOT:
        if not allow_custom:
            errors.append(f"{where}: '{path}' is under the custom car.* namespace — "
                          "express a homeless field as native: true, not as an ecs: target")
        return
    if root not in ECS_TOP_LEVEL:
        errors.append(f"{where}: '{path}' — '{root}' is not an ECS 8.x top-level field set")


def _validate_conventions(conv: dict, car: dict[str, dict], errors: list[str]) -> None:
    if not isinstance(conv, dict):
        errors.append("conventions.yml: top-level document must be a mapping")
        return
    header_union: set[str] = set()
    for m in car.values():
        header_union |= set(m["header"])
    entries = conv.get("common_header")
    if not isinstance(entries, dict):
        errors.append("conventions.yml: common_header: must be a mapping of header field -> entry")
        return
    for h in sorted(header_union - set(entries)):
        errors.append(f"conventions.yml common_header: CAR header field '{h}' has no projection")
    for h in sorted(set(entries) - header_union):
        errors.append(f"conventions.yml common_header.{h}: orphan — not a CAR header field")
    custom = conv.get("custom_namespace") or {}
    for h, entry in entries.items():
        where = f"conventions.yml common_header.{h}"
        if not isinstance(entry, dict) or not entry.get("ecs"):
            errors.append(f"{where}: needs an ecs: target")
            continue
        _check_path(entry["ecs"], where, errors, allow_custom=True)
        if str(entry["ecs"]).startswith(CUSTOM_ROOT + ".") and entry["ecs"] not in custom:
            errors.append(f"{where}: custom target '{entry['ecs']}' is not declared in custom_namespace")
        for a in entry.get("also") or []:
            _check_path(a, f"{where} also", errors, allow_custom=True)
        for obj, override in (entry.get("per_object") or {}).items():
            if obj not in car:
                errors.append(f"{where}.per_object: '{obj}' is not a CAR object")
            for a in (override or {}).get("also") or []:
                _check_path(a, f"{where}.per_object.{obj} also", errors, allow_custom=True)
    for obj in conv.get("event_categorisation") or {}:
        if obj not in car:
            errors.append(f"conventions.yml event_categorisation: '{obj}' is not a CAR object")


def _validate_object(name: str, model: dict, doc: dict, header_union: set[str],
                     errors: list[str]) -> None:
    where = f"objects/{name}.yml"
    if not isinstance(doc, dict):
        errors.append(f"{where}: top-level document must be a mapping")
        return
    if doc.get("object") != name:
        errors.append(f"{where}: object: must be '{name}'")
    if doc.get("data_stream") != f"logs-car.{name}-*":
        errors.append(f"{where}: data_stream: must be 'logs-car.{name}-*'")

    fields = doc.get("fields")
    if not isinstance(fields, list):
        errors.append(f"{where}: fields: must be a list of projection entries")
        return
    seen: set[str] = set()
    primary: dict[str, list[tuple[str, bool]]] = {}
    for i, e in enumerate(fields):
        if not isinstance(e, dict) or not e.get("car"):
            errors.append(f"{where} fields[{i}]: entry needs a car: field name")
            continue
        f = e["car"]
        ew = f"{where} fields[{f}]"
        if f not in model["fields"]:
            hint = (" (a common_header field — projected by conventions.yml)"
                    if f in header_union else "")
            errors.append(f"{ew}: orphan — CAR object '{name}' has no field '{f}'{hint}")
            continue
        if f in seen:
            errors.append(f"{ew}: duplicate entry")
            continue
        seen.add(f)
        unknown = sorted(set(e) - ENTRY_KEYS)
        if unknown:
            errors.append(f"{ew}: unknown key(s) {unknown}")
        has_ecs, is_native = "ecs" in e, e.get("native") is True
        if has_ecs == is_native:
            errors.append(f"{ew}: needs exactly one of ecs: <path> or native: true")
        if has_ecs:
            _check_path(e["ecs"], ew, errors)
            primary.setdefault(str(e["ecs"]), []).append((f, bool(e.get("fallback"))))
        if is_native:
            if not isinstance(e.get("rationale"), str) or not e["rationale"].strip():
                errors.append(f"{ew}: native: true needs a one-line rationale")
            if e.get("type") not in NATIVE_TYPES:
                errors.append(f"{ew}: native: true needs type: one of {sorted(NATIVE_TYPES)}")
            for k in ("also", "fallback"):
                if k in e:
                    errors.append(f"{ew}: {k}: is only meaningful with ecs:")
        for a in e.get("also") or []:
            _check_path(a, f"{ew} also", errors)
    for f in model["fields"]:
        if f not in seen:
            errors.append(f"{where}: CAR field '{f}' has no projection entry "
                          "(map it with ecs: or mark it native: true)")
    for target, users in primary.items():
        if len(users) < 2:
            continue
        primaries = [f for f, fallback in users if not fallback]
        if len(primaries) != 1:
            errors.append(f"{where}: target '{target}' is shared by {[f for f, _ in users]} — "
                          f"exactly one entry must be the primary (no fallback:), "
                          f"found {primaries or 'none'} (rules.fallback)")

    ed = doc.get("event_defaults") or {}
    if not isinstance(ed.get("category"), list) or not ed["category"]:
        errors.append(f"{where} event_defaults.category: required (a list)")
    tba = ed.get("type_by_action") or {}
    actions = set(model["actions"])
    for a in sorted(set(tba) - actions):
        errors.append(f"{where} event_defaults.type_by_action: '{a}' is not a car_action of {name}")
    for a in sorted(actions - set(tba)):
        errors.append(f"{where} event_defaults.type_by_action: car_action '{a}' has no event.type")
    for a, t in tba.items():
        if not isinstance(t, list) or not t:
            errors.append(f"{where} event_defaults.type_by_action.{a}: must be a non-empty list")
    for a, o in (ed.get("outcome_from_action") or {}).items():
        if a not in actions:
            errors.append(f"{where} event_defaults.outcome_from_action: '{a}' is not a car_action")
        if o not in OUTCOMES:
            errors.append(f"{where} event_defaults.outcome_from_action.{a}: '{o}' is not an event.outcome")
    off = ed.get("outcome_from_field")
    if off is not None and off not in model["fields"]:
        errors.append(f"{where} event_defaults.outcome_from_field: '{off}' is not a field of {name}")

    for i, d in enumerate(doc.get("derived") or []):
        dw = f"{where} derived[{i}]"
        src = (d or {}).get("from")
        if src not in model["fields"] and src not in header_union:
            errors.append(f"{dw}: from: '{src}' is neither a header nor a {name} field")
        _check_path((d or {}).get("ecs"), dw, errors)


def _recipe_components(recipe: str) -> list[str]:
    """The column names a document_id.recipe names: the `|`-joined args of a
    sha1(...) call, or (inferred.yml's `node_id`) the bare recipe itself."""
    m = _RECIPE_SHA1.match(recipe.strip())
    if m:
        return [c.strip() for c in m.group(1).split("|")]
    return [recipe.strip()]


def _validate_edge_constants(where: str, doc: dict, errors: list[str]) -> None:
    constants = doc.get("constants")
    if not isinstance(constants, dict):
        errors.append(f"{where} constants: must be a mapping")
        return
    for k in ("event.kind", "event.module", "event.dataset",
             "data_stream.type", "data_stream.dataset", "ecs.version"):
        if k not in constants:
            errors.append(f"{where} constants: missing the data_stream identity key '{k}'")
    dataset = doc.get("dataset")
    if dataset:
        for k in ("event.dataset", "data_stream.dataset"):
            if k in constants and constants[k] != dataset:
                errors.append(f"{where} constants.{k}: {constants[k]!r} does not match dataset: {dataset!r}")


def _validate_edge_fields(where: str, doc: dict, columns: list[str], ecs_types: dict,
                          errors: list[str], used_paths: set[str]) -> None:
    fields = doc.get("fields")
    if not isinstance(fields, list):
        errors.append(f"{where} fields: must be a list of projection entries")
        return
    seen: set[str] = set()
    for i, e in enumerate(fields):
        if not isinstance(e, dict) or not e.get("car"):
            errors.append(f"{where} fields[{i}]: entry needs a car: column name")
            continue
        c = e["car"]
        ew = f"{where} fields[{c}]"
        if c not in columns:
            errors.append(f"{ew}: '{c}' is not a column of this table (or is the 'id' autoincrement, "
                          "which is never projected)")
            continue
        if c in seen:
            errors.append(f"{ew}: duplicate entry")
            continue
        seen.add(c)
        unknown = sorted(set(e) - EDGE_ENTRY_KEYS)
        if unknown:
            errors.append(f"{ew}: unknown key(s) {unknown}")
        if "ecs" not in e:
            errors.append(f"{ew}: needs an ecs: target")
        else:
            _check_path(e["ecs"], ew, errors, allow_custom=True)
            used_paths.add(str(e["ecs"]))
        if e.get("type") not in NATIVE_TYPES and str(e.get("ecs")) not in ecs_types:
            errors.append(f"{ew}: needs a type: (one of {sorted(NATIVE_TYPES)}) — every field entry "
                          "here carries its own type explicitly (or resolves via ecs_types.yml)")
        also = e.get("also")
        if also is None:
            if "also_type" in e:
                errors.append(f"{ew}: also_type: is only meaningful with also:")
        else:
            _check_path(also, f"{ew} also", errors, allow_custom=True)
            used_paths.add(str(also))
            if e.get("also_type") not in NATIVE_TYPES:
                errors.append(f"{ew} also: needs also_type: (one of {sorted(NATIVE_TYPES)})")
    for c in columns:
        if c not in seen:
            errors.append(f"{where}: column '{c}' has no projection entry")


def _validate_edge(where: str, doc: dict, expected_object: str, expected_stream: str,
                   expected_dataset: str, columns: list[str], ecs_types: dict,
                   errors: list[str], used_paths: set[str]) -> None:
    """relationships.yml / inferred.yml: a simplified objects/*.yml-shaped contract
    projecting a superset.db table (not a CAR object) onto its own logs-car.* stream."""
    if not isinstance(doc, dict):
        errors.append(f"{where}: top-level document must be a mapping")
        return
    if doc.get("object") != expected_object:
        errors.append(f"{where}: object: must be '{expected_object}'")
    if doc.get("stream") != expected_stream:
        errors.append(f"{where}: stream: must be '{expected_stream}'")
    if doc.get("dataset") != expected_dataset:
        errors.append(f"{where}: dataset: must be '{expected_dataset}'")
    _validate_edge_constants(where, doc, errors)
    dr = doc.get("document_id") or {}
    recipe = dr.get("recipe")
    if not isinstance(recipe, str) or not recipe.strip():
        errors.append(f"{where} document_id: needs a recipe: string")
    else:
        for c in _recipe_components(recipe):
            if c not in columns:
                errors.append(f"{where} document_id.recipe: component '{c}' names no real source column")
    if not isinstance(dr.get("note"), str) or not dr["note"].strip():
        errors.append(f"{where} document_id: needs a note:")
    _validate_edge_fields(where, doc, columns, ecs_types, errors, used_paths)


def _collect_used_ecs_paths(conventions: dict, objects: dict[str, dict],
                            rel_doc: dict, inferred_doc: dict) -> set[str]:
    """Every ECS/car.* target path any contract file actually names — what
    ecs_types.yml's dead-override check treats as 'used'."""
    used: set[str] = set()
    for entry in (conventions.get("common_header") or {}).values():
        if not isinstance(entry, dict):
            continue
        if "ecs" in entry:
            used.add(str(entry["ecs"]))
        used.update(str(a) for a in entry.get("also") or [])
        for override in (entry.get("per_object") or {}).values():
            used.update(str(a) for a in (override or {}).get("also") or [])
    used.update(conventions.get("custom_namespace") or {})
    for doc in objects.values():
        for e in doc.get("fields") or []:
            if not isinstance(e, dict):
                continue
            if "ecs" in e:
                used.add(str(e["ecs"]))
            used.update(str(a) for a in e.get("also") or [])
        for d in doc.get("derived") or []:
            if isinstance(d, dict) and d.get("ecs"):
                used.add(str(d["ecs"]))
    for doc in (rel_doc, inferred_doc):
        for e in (doc or {}).get("fields") or []:
            if not isinstance(e, dict):
                continue
            if "ecs" in e:
                used.add(str(e["ecs"]))
            if e.get("also"):
                used.add(str(e["also"]))
    return used


def _validate_ecs_types(ecs_types: dict, used_paths: set[str], errors: list[str]) -> None:
    for path, spec in ecs_types.items():
        where = f"ecs_types.yml types.{path}"
        if path != "@timestamp" and not ECS_PATH.match(str(path)):
            errors.append(f"{where}: {path!r} is not an ECS- or car.*-shaped field path")
        else:
            root = str(path).split(".", 1)[0]
            if path != "@timestamp" and root != CUSTOM_ROOT and root not in ECS_TOP_LEVEL:
                errors.append(f"{where}: '{root}' is neither an ECS 8.x top-level field set nor '{CUSTOM_ROOT}'")
        if not isinstance(spec, dict) or spec.get("type") not in NATIVE_TYPES:
            errors.append(f"{where}: needs type: one of {sorted(NATIVE_TYPES)}")
            continue
        if spec["type"] != "keyword" and path not in used_paths:
            errors.append(f"{where}: type override '{spec['type']}' is not used by any contract file "
                          "(conventions.yml, objects/*.yml, relationships.yml, inferred.yml) — dead override")


def load_edge_docs() -> tuple[dict, dict, dict]:
    """(relationships.yml doc, inferred.yml doc, ecs_types.yml {path: {type, note}})."""
    ecs_types = (_load(ECS_TYPES_PATH) or {}).get("types") or {}
    return _load(RELATIONSHIPS_PATH), _load(INFERRED_PATH), ecs_types


def validate_edges(conventions: dict, objects: dict[str, dict], rel_doc: dict,
                   inferred_doc: dict, ecs_types: dict) -> list[str]:
    """Every relationships.yml / inferred.yml / ecs_types.yml problem; [] means in step.
    Kept separate from validate() (which stays exactly the objects/*.yml <-> CAR-model
    check it always was) so neither check's signature or behaviour disturbs the other."""
    errors: list[str] = []
    used_paths: set[str] = set()
    _validate_edge("relationships.yml", rel_doc, "rel", "logs-car.rel-*", "car.rel",
                  REL_COLUMNS, ecs_types, errors, used_paths)
    _validate_edge("inferred.yml", inferred_doc, "inferred", "logs-car.inferred-*", "car.inferred",
                  INFERRED_COLUMNS, ecs_types, errors, used_paths)
    used_paths |= _collect_used_ecs_paths(conventions, objects, rel_doc, inferred_doc)
    _validate_ecs_types(ecs_types, used_paths, errors)
    return errors


def edge_summary(rel_doc: dict, inferred_doc: dict) -> str:
    return (f" | rel: {len(rel_doc.get('fields') or [])} fields, "
            f"inferred: {len(inferred_doc.get('fields') or [])} fields")


def validate(car: dict[str, dict], conventions: dict, objects: dict[str, dict]) -> list[str]:
    """Every contract problem as a message; an empty list means the contract is in step."""
    errors: list[str] = []
    for o in sorted(set(car) - set(objects)):
        errors.append(f"objects/{o}.yml: missing — CAR object '{o}' has no projection")
    for o in sorted(set(objects) - set(car)):
        errors.append(f"objects/{o}.yml: orphan — there is no CAR object '{o}'")
    _validate_conventions(conventions, car, errors)
    header_union: set[str] = set()
    for m in car.values():
        header_union |= set(m["header"])
    for name in sorted(set(car) & set(objects)):
        _validate_object(name, car[name], objects[name], header_union, errors)
    return errors


def summary(car: dict[str, dict], conventions: dict, objects: dict[str, dict]) -> str:
    n_fields = sum(len(m["fields"]) for m in car.values())
    entries = [e for o in objects.values() for e in o.get("fields") or []]
    n_native = sum(1 for e in entries if e.get("native") is True)
    targets = {str(e["ecs"]) for e in entries if "ecs" in e}
    for e in entries:
        targets.update(e.get("also") or [])
    return (f"car-ecs projection OK: {len(car)} objects | {n_fields} CAR fields -> "
            f"{n_fields - n_native} ECS-mapped, {n_native} native (car.<object>.*) | "
            f"{len(targets)} distinct ECS targets | header: "
            f"{len(conventions.get('common_header') or {})} fields | "
            f"ECS {conventions.get('contract', {}).get('ecs_version', '?')}")


def main() -> int:
    car = load_car_model()
    if not car:
        print(f"no CAR objects found under {CAR_OBJECTS_DIR}", file=sys.stderr)
        return 1
    conventions, objects = load_contract()
    rel_doc, inferred_doc, ecs_types = load_edge_docs()
    errors = validate(car, conventions, objects)
    errors += validate_edges(conventions, objects, rel_doc, inferred_doc, ecs_types)
    if errors:
        print(f"car-ecs projection DRIFT: {len(errors)} problem(s)", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(summary(car, conventions, objects) + edge_summary(rel_doc, inferred_doc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

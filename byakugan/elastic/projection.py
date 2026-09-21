"""The CAR->ECS forward projector: a `car_<object>.jsonl` / `car_relationships.jsonl`
/ `car_inferred.jsonl` row -> its Elasticsearch document, per the hand-authored
contract in `elastic/projection/` (conventions.yml + objects/<object>.yml (13) +
relationships.yml + inferred.yml + ecs_types.yml — read those first; this
module is deliberately silent on WHY a field lands where it does, since the
contract already says so at length).

Pure and import-light (stdlib + pyyaml only, like the contract's own
validate.py/render_elastic.py) so `byakugan.elastic.load` — and any other
consumer — can import it without pulling in sqlite3, argparse or the rest of
the engine. `load_contract()` resolves `elastic/projection/` relative to the
package the way `byakugan/build_data_model.py` resolves `third_party/` (its
`_HERE`/`_ROOT`): a fixed number of levels up from `byakugan/elastic/` to the
repo root, not an installed data file, because — like the CAR model itself —
the contract is meant to be read from the checked-out source tree, never
vendored.

Design note: this is the FORWARD projection (CAR -> ECS, what `byakugan load`
bulk-loads into Elasticsearch). The INVERSE (ECS -> CAR, reconstructing a CAR
row from an Elastic document — `byakugan timeline --elastic`, epic #99 phase
5) lives in the companion module `byakugan.elastic.inverse_projection`, which
reuses this module's `load_contract()` rather than re-reading the YAML its
own way, so the two directions can never see a different contract.

Two forward-pass adjustments exist ONLY to keep that inverse lossless (both
are ordinary, deterministic projection rules — not inverse-specific code —
and both are covered by tests/test_projection.py alongside every other rule
here):

  - rules.fallback (a shared ECS target with a primary + a `fallback: true`
    entry, e.g. objects/process.yml hostname/fqdn -> host.hostname): a
    fallback that WINS the target outright (the primary was absent) now also
    lands verbatim at car.<object>.<field> — the same capture a LOSING
    fallback already got. Without it, "the fallback alone had a value" and
    "the primary independently held that same value" are indistinguishable
    on the document. The one case this still cannot resolve — primary and
    fallback populated with the EXACT SAME string — is genuinely
    irrecoverable by design (documented, and excluded from the round-trip
    test, in byakugan.elastic.inverse_projection's own docstring).
  - event_defaults.outcome_from_field (socket.yml `success`, user_session.yml
    `login_successful`): these CAR fields' own `fields:` entry maps
    `ecs: event.outcome`, but _compile_object excludes every such entry from
    `groups` (event.outcome is DERIVED, never a plain field copy —
    rules.event_action), so the raw value had no home anywhere once
    _apply_event_defaults collapsed it to success/failure. It is now also
    captured verbatim at car.<object>.<field>, exactly like a native: true
    field (render_elastic.py renders that path concrete, never an alias, for
    the same reason).

Three entry points, one per stream family:

    project_event(ev, namespace)          car_<object>.jsonl row -> logs-car.<object>-<namespace>
    project_relationship(row, namespace)  car_relationships.jsonl row -> logs-car.rel-<namespace>
    project_inferred(row, namespace)      car_inferred.jsonl row -> logs-car.inferred-<namespace>

Each returns `(stream, doc_id, doc)`, or `None` when the row's own time axis
(`timestamp` / `timestamp` / `first_seen`) does not parse (`normalize.parse_ts`
— the one tolerant ISO-8601 parser, never re-implemented here): a data stream
requires `@timestamp`, so a row that cannot supply one is not a documented
failure, it is a normal, expected skip — the SAME reason every time
(`SKIP_NO_TIMESTAMP`), which is what a caller counts. Anything else wrong with
a row (an unrecognised `car_object`, a row with no `node_id`) is a genuine
contract/data mismatch: it raises, for the caller to count as a failure.

Nulls: a missing/blank source value (`None` or `""` — the two spellings a
`car_<object>.jsonl` row uses for "the pipeline never set this") contributes
to nothing: no ECS field, no `also:` copy, no `car.<object>.<field>` fallback
capture (conventions.yml rules.nulls: "a null CAR value projects to an absent
field, never to an empty string"). Coercion (rules.coercion) is attempted only
for the 5 typed buckets ecs_types.yml actually declares — date, long, float,
boolean, ip; every other target (ECS's own keyword/text default, or a
`native: true` field's own declared type) is accepted verbatim, unattempted.
"""
from __future__ import annotations

import glob
import hashlib
import ipaddress
import os
import re

import yaml

from ..normalize import parse_ts

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
MODEL_DIR = os.path.join(_ROOT, "elastic", "projection")
CONVENTIONS_PATH = os.path.join(MODEL_DIR, "conventions.yml")
OBJECTS_DIR = os.path.join(MODEL_DIR, "objects")
RELATIONSHIPS_PATH = os.path.join(MODEL_DIR, "relationships.yml")
INFERRED_PATH = os.path.join(MODEL_DIR, "inferred.yml")
ECS_TYPES_PATH = os.path.join(MODEL_DIR, "ecs_types.yml")

# The one, always-the-same reason project_event/project_relationship/
# project_inferred return None for: see the module docstring.
SKIP_NO_TIMESTAMP = "no parseable timestamp"


# --------------------------------------------------------------------------- #
# Small, generic, pure helpers.
# --------------------------------------------------------------------------- #
def _blank(v) -> bool:
    """A `car_<object>.jsonl` value that means "the pipeline never set this" —
    JSON `null` (a never-populated SQLite column) or `""` (several map/enrich
    paths' own blank spelling, e.g. test fixtures' `owning_guid: ""`). Never
    treated as a real value, per rules.nulls."""
    return v is None or v == ""


def _nest_set(doc: dict, path: str, value) -> None:
    """doc["a"]["b"]["c"] = value for the dotted ECS/car.* path "a.b.c" — the
    document-instance analogue of render_elastic.py's `_nest` (which builds a
    mapping tree instead of a document)."""
    parts = path.split(".")
    node = doc
    for p in parts[:-1]:
        node = node.setdefault(p, {})
    node[parts[-1]] = value


def _append_related(doc: dict, path: str, value) -> None:
    """An ECS `related.*` pivot is an array multiple CAR fields of one event
    may each contribute to unconditionally (e.g. a file row's `fqdn` AND
    `hostname` both feed `related.hosts`) — appended, de-duplicated, in a
    fixed order (a shared target's primary entry, then its fallbacks in file
    order — see _apply_object_fields) that depends only on the contract, so a
    re-render of the same row is byte-identical; not an evidentiary ranking."""
    parts = path.split(".")
    node = doc
    for p in parts[:-1]:
        node = node.setdefault(p, {})
    key = parts[-1]
    lst = node.setdefault(key, [])
    if value not in lst:
        lst.append(value)


def _apply_also(doc: dict, path: str, value) -> None:
    (_append_related if path.startswith("related.") else _nest_set)(doc, path, value)


def _format_iso_z(dt) -> str:
    """`parse_ts`'s aware-UTC `datetime` rendered back as the normalised
    `@timestamp` / typed-date value: UTC ISO-8601, 'Z'-suffixed (cli.py's own
    `time.strftime(...'Z'...)` convention) — fractional seconds kept only when
    the source actually carried them, at parse_ts's own (padded) precision."""
    s = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        s += f".{dt.microsecond:06d}"
    return s + "Z"


# --------------------------------------------------------------------------- #
# Coercion (rules.coercion): the 5 typed ECS buckets attempt a parse and
# report failure; everything else (keyword/text/flattened) is verbatim.
# --------------------------------------------------------------------------- #
_BOOL_TRUE = {"1", "true", "yes", "on"}
_BOOL_FALSE = {"0", "false", "no", "off", ""}


def _coerce_date(value):
    dt = parse_ts(value)
    return (True, _format_iso_z(dt)) if dt is not None else (False, None)


def _coerce_long(value):
    """Ports and byte counts are integers (rules.coercion): a real int/bool-
    free float/numeric string parses; a loose duration ("12ms") or formatted
    byte count ("567 Kb") does not — kept verbatim (see event.duration /
    email.attachments.file.size in ecs_types.yml)."""
    if isinstance(value, bool):
        return False, None
    if isinstance(value, int):
        return True, value
    if isinstance(value, float):
        return (True, int(value)) if value.is_integer() else (False, None)
    try:
        return True, int(str(value).strip())
    except ValueError:
        return False, None


def _coerce_float(value):
    if isinstance(value, bool):
        return False, None
    try:
        return True, float(value)
    except (TypeError, ValueError):
        return False, None


def _coerce_boolean(value):
    """A real bool; a SQLite-round-tripped 0/1 (Python's sqlite3 has no bool
    storage class — see byakugan/store.py — so a mapping-asserted True/False
    comes back as an int); or one of cli.py's own boolean-ish words."""
    if isinstance(value, bool):
        return True, value
    if isinstance(value, int) and value in (0, 1):
        return True, bool(value)
    s = str(value).strip().lower()
    if s in _BOOL_TRUE:
        return True, True
    if s in _BOOL_FALSE:
        return True, False
    return False, None


def _coerce_ip(value):
    """Validated, never reformatted: rules.verbatim projects the value
    exactly as given once it is known to be a real IP literal."""
    try:
        ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False, None
    return True, value


_COERCERS = {"date": _coerce_date, "long": _coerce_long, "float": _coerce_float,
            "boolean": _coerce_boolean, "ip": _coerce_ip}


def _coerce(value, ecs_type: str):
    """(ok, value-to-store). `ecs_type` absent from `_COERCERS` (keyword,
    text, flattened — ECS's own overwhelming default, per ecs_types.yml's own
    docstring) is always ok, value unchanged: rules.verbatim, no parse
    attempted."""
    fn = _COERCERS.get(ecs_type)
    return fn(value) if fn else (True, value)


def _target_type(path: str, ecs_types: dict) -> str:
    """A mapped (`ecs:`) target's coercion type: ecs_types.yml's override,
    else keyword — the exact lookup render_elastic.py's `_ecs_type` uses for
    the same paths, kept in step deliberately."""
    return (ecs_types.get(path) or {}).get("type", "keyword")


# --------------------------------------------------------------------------- #
# The handful of normalisations conventions.yml's rules.verbatim permits,
# each named on the objects/*.yml entry that needs it — hard-coded because
# the YAML only carries them as prose (a `note:`), never as data a generic
# engine could execute. Keyed (object, car field name); applied to the raw
# value before coercion (every target below is ECS keyword, so coercion is a
# verbatim no-op regardless — this is the ONLY transform of the value).
# --------------------------------------------------------------------------- #
def _strip_leading_dot(v):
    s = str(v)
    return s[1:] if s.startswith(".") else s


_HIVE_ABBREVIATIONS = {
    "HKEY_LOCAL_MACHINE": "HKLM", "HKEY_CURRENT_USER": "HKCU",
    "HKEY_USERS": "HKU", "HKEY_CLASSES_ROOT": "HKCR", "HKEY_CURRENT_CONFIG": "HKCC",
}


def _abbreviate_hive(v):
    return _HIVE_ABBREVIATIONS.get(str(v).strip().upper(), v)


def _lower(v):
    return str(v).lower()


_DIRECTION_WORDS = {"in": "inbound", "out": "outbound"}


def _network_direction(v):
    return _DIRECTION_WORDS.get(str(v).strip().lower(), v)


def _split_env_vars(v):
    return str(v).split("\n")


# (object, car field) -> raw value -> raw value, applied before coercion.
_VERBATIM_TRANSFORMS = {
    ("file", "extension"): _strip_leading_dot,                 # file.yml: ECS excludes the leading dot
    ("registry", "hive"): _abbreviate_hive,                    # registry.yml: ECS uses the abbreviated hive
    ("flow", "application_protocol"): _lower,                  # flow.yml: lower-case per ECS
    ("flow", "transport_protocol"): _lower,                    # flow.yml: lower-case per ECS
    ("socket", "protocol"): _lower,                             # socket.yml: lower-case per ECS
    ("flow", "network_direction"): _network_direction,         # flow.yml: the ECS network.direction vocabulary
    ("process", "env_vars"): _split_env_vars,                  # process.yml: ECS wants an array
}

# `derived:` entries (objects/*.yml): the ECS field is built from CAR data
# that is not a field of its own. The only one in the contract today
# (http.yml http.request.method from car_action) — a registry, not a DSL,
# because the transform itself is prose (the entry's `note:`), not data.
def _http_request_method(row: dict):
    action = row.get("car_action")
    if _blank(action):
        return None
    return "CONNECT" if action == "tunnel" else str(action).upper()


_DERIVED_TRANSFORMS = {
    ("http", "http.request.method"): _http_request_method,
}


# --------------------------------------------------------------------------- #
# document_id: one shared sha1 helper (conventions.yml data_stream.document_id
# / relationships.yml document_id — inferred.yml's is the bare node_id, no
# hash: see project_inferred).
# --------------------------------------------------------------------------- #
_RECIPE_SHA1 = re.compile(r"^sha1\((.*)\)$")


def sha1_id(*parts) -> str:
    """sha1 of `parts` joined with '|', a `None` component rendering as an
    empty string — never dropped, so the joiner positions never shift (every
    document_id.recipe note in the contract says this explicitly). Hex
    digest, matching the recipes' own `sha1(...)` naming."""
    joined = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()


def _recipe_components(recipe: str) -> list[str]:
    m = _RECIPE_SHA1.match(recipe.strip())
    if not m:
        raise ValueError(f"not a sha1(...) document_id recipe: {recipe!r}")
    return [c.strip() for c in m.group(1).split("|")]


def _object_document_id(recipe: str, row: dict, name: str) -> str:
    """conventions.yml's single recipe is written once for every object,
    using `<object>` where the object name itself is a component; every other
    component is a plain row field, `timestamp` included — the RAW verbatim
    string (row["timestamp"], the same value car.timestamp keeps), not the
    normalised @timestamp: an id must reproduce from the exact bytes it was
    minted from (the same principle relationships.yml's own note states for
    its own timestamp component)."""
    parts = [name if c == "<object>" else row.get(c) for c in _recipe_components(recipe)]
    return sha1_id(*parts)


def _edge_document_id(recipe: str, row: dict) -> str:
    return sha1_id(*(row.get(c) for c in _recipe_components(recipe)))


# --------------------------------------------------------------------------- #
# Contract loading: conventions.yml + objects/*.yml (13) + relationships.yml
# + inferred.yml + ecs_types.yml, compiled once into the small per-stream
# plans _apply_object_fields / _project_edge actually walk. Cached — the
# contract is read-only process-wide (mirrors carmodel.load()'s own caching).
# --------------------------------------------------------------------------- #
def _yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _compile_object(doc: dict, ecs_types: dict) -> dict:
    """objects/<object>.yml -> {"groups": {target: {"primary", "fallbacks"}},
    "natives": [...], "derived": [...], "event_defaults": {...}}. `groups`
    keys every mapped (`ecs:`) entry by its primary target, `fallback: true`
    entries filed as fallbacks (rules.fallback: validate.py already proves
    exactly one primary per shared target, so this never needs to guess).
    `event.outcome` is excluded from `groups` even when an entry maps to it
    (socket.success, user_session.login_successful): rules.event_action says
    event.outcome is DERIVED from event_defaults, not a plain field copy —
    _apply_event_defaults owns it exclusively, so the raw boolean is never
    also copied there verbatim."""
    groups: dict[str, dict] = {}
    natives: list[dict] = []
    for e in doc.get("fields") or []:
        if e.get("native") is True:
            natives.append(e)
            continue
        target = e["ecs"]
        if target == "event.outcome":
            continue
        g = groups.setdefault(target, {"primary": None, "fallbacks": []})
        if e.get("fallback"):
            g["fallbacks"].append(e)
        else:
            g["primary"] = e
    return {"groups": groups, "natives": natives,
           "derived": list(doc.get("derived") or []),
           "event_defaults": doc.get("event_defaults") or {}}


def _compile_edge(doc: dict) -> dict:
    """relationships.yml / inferred.yml -> {"constants", "fields", "document_id"}.
    Unlike objects/*.yml, every entry already carries an explicit `ecs:` +
    `type:` (+ optional `also:`/`also_type:`) — no fallback groups, no
    `native: true`, no per-object variation — so there is nothing to resolve
    beyond defaulting a missing `type:` to keyword (validate.py allows that
    when the path resolves via ecs_types.yml instead; every entry in both
    files declares `type:` explicitly today, but this stays honest either way)."""
    fields = []
    for e in doc.get("fields") or []:
        fields.append({"car": e["car"], "ecs": e["ecs"], "type": e.get("type") or "keyword",
                       "also": e.get("also"), "also_type": e.get("also_type")})
    return {"constants": doc.get("constants") or {}, "fields": fields,
           "document_id": doc.get("document_id") or {}}


_cache: dict | None = None


def load_contract() -> dict:
    """The compiled contract, cached process-wide: {"conventions", "ecs_types",
    "objects": {name: compiled}, "relationships": compiled, "inferred": compiled}."""
    global _cache
    if _cache is not None:
        return _cache
    ecs_types = (_yaml(ECS_TYPES_PATH) or {}).get("types") or {}
    objects = {}
    for path in sorted(glob.glob(os.path.join(OBJECTS_DIR, "*.yml"))):
        name = os.path.splitext(os.path.basename(path))[0]
        objects[name] = _compile_object(_yaml(path), ecs_types)
    _cache = {
        "conventions": _yaml(CONVENTIONS_PATH),
        "ecs_types": ecs_types,
        "objects": objects,
        "relationships": _compile_edge(_yaml(RELATIONSHIPS_PATH)),
        "inferred": _compile_edge(_yaml(INFERRED_PATH)),
    }
    return _cache


def known_objects() -> frozenset:
    """The CAR object names the contract projects (13) — the set of
    `car_<object>.jsonl` basenames `byakugan.elastic.load`'s discovery should expect,
    as distinct from `car_relationships.jsonl` / `car_inferred.jsonl`."""
    return frozenset(load_contract()["objects"])


# --------------------------------------------------------------------------- #
# Constants (conventions.yml constants / relationships.yml constants /
# inferred.yml constants): identical shape, `<object>` substituted in object
# streams' values only — the loader-chosen `data_stream.namespace` is not
# one of these (it comes from the caller), applied separately by each of the
# three project_* functions.
# --------------------------------------------------------------------------- #
def _apply_constants(doc: dict, constants: dict, object_name: str | None) -> None:
    for path, val in constants.items():
        if isinstance(val, str) and "<object>" in val:
            val = val.replace("<object>", object_name or "")
        _nest_set(doc, path, val)


# --------------------------------------------------------------------------- #
# The common header (conventions.yml common_header / byakugan/store.py
# HEADER) — 11 fields. 6 are a plain typed copy (read generically off the
# loaded contract, so a future conventions.yml edit to one of their target
# paths needs no code change); the other 5 (timestamp, guid, owning_guid,
# link_confidence, native) are irregular enough (per-object overrides, a
# vocabulary lookup, a verbatim companion render_elastic.py's own comment
# calls a RENDERING convention rather than contract data) that they are
# hard-coded here exactly as conventions.yml's prose states them — timestamp
# itself is handled by the two project_* callers (it decides the whole row's
# fate), not here.
# --------------------------------------------------------------------------- #
_HEADER_SIMPLE = ("car_action", "source_artefact", "source_host",
                  "volume_guid", "mac_address", "device_serial")


def _apply_header(doc: dict, row: dict, name: str, header: dict) -> None:
    for field in _HEADER_SIMPLE:
        raw = row.get(field)
        if _blank(raw):
            continue
        entry = header.get(field) or {}
        ok, val = _coerce(raw, entry.get("type", "keyword"))
        if ok:
            _nest_set(doc, entry["ecs"], val)

    # guid -> event.id, always (the row identity, in every case); on a
    # process row it ALSO wins process.entity_id when owning_guid is absent
    # (conventions.yml common_header.guid.per_object.process — a fallback:
    # true pairing with owning_guid's process.entity_id, but guid's own
    # primary target (event.id) already carries it either way, so there is
    # no separate car.* capture needed when it loses that pairing).
    guid = row.get("guid")
    if not _blank(guid):
        _nest_set(doc, "event.id", guid)
    owning_guid = row.get("owning_guid")
    if not _blank(owning_guid):
        _nest_set(doc, "process.entity_id", owning_guid)
    elif name == "process" and not _blank(guid):
        _nest_set(doc, "process.entity_id", guid)

    # link_confidence -> car.link_confidence (the pipeline word looked up in
    # conventions.yml's own vocabulary -> a float) + labels.link_confidence
    # (the word itself, unconditionally — conventions.yml: "the verbatim word
    # is kept as a label").
    conf = row.get("link_confidence")
    if not _blank(conf):
        _nest_set(doc, "labels.link_confidence", conf)
        values = (header.get("link_confidence") or {}).get("values") or {}
        if conf in values:
            _nest_set(doc, "car.link_confidence", float(values[conf]))

    native = row.get("native")
    if native:
        _nest_set(doc, "car.native", native)


# --------------------------------------------------------------------------- #
# One object's own fields (objects/<object>.yml `fields:`), per rules.
# one_home / fallback / coercion / verbatim.
# --------------------------------------------------------------------------- #
def _apply_object_fields(doc: dict, plan: dict, row: dict, name: str, ecs_types: dict) -> None:
    for target, group in plan["groups"].items():
        ecs_type = _target_type(target, ecs_types)
        order = ([group["primary"]] if group["primary"] else []) + group["fallbacks"]
        filled = False
        for entry in order:
            car_field = entry["car"]
            raw = row.get(car_field)
            if _blank(raw):
                continue
            transform = _VERBATIM_TRANSFORMS.get((name, car_field))
            if transform is not None:
                raw = transform(raw)
            ok, val = _coerce(raw, ecs_type)
            if ok and not filled:
                _nest_set(doc, target, val)
                filled = True
                if entry is not group["primary"]:
                    # a fallback that WON the shared target only because the
                    # primary was absent: preserve verbatim which CAR field
                    # actually supplied it too (the same capture the "loses"
                    # branch below already performs) -- otherwise nothing on
                    # the document distinguishes "the fallback alone had a
                    # value" from "the primary independently held this same
                    # value", which the inverse projection
                    # (byakugan/elastic/inverse_projection.py) needs to tell apart. See that
                    # module's docstring for the one residual case even this
                    # cannot resolve (primary and fallback sharing the exact
                    # same value).
                    _nest_set(doc, f"car.{name}.{car_field}", raw)
                for also in entry.get("also") or []:
                    _apply_also(doc, also, val)
            elif ok:
                # a fallback that parsed fine but lost the target to an
                # earlier entry: "lands verbatim at car.<object>.<field>
                # instead, so nothing is lost" (rules.fallback) — its own
                # also: copies still land (unconditional, rules.one_home).
                _nest_set(doc, f"car.{name}.{car_field}", raw)
                for also in entry.get("also") or []:
                    _apply_also(doc, also, val)
            else:
                # failed its type's coercion (rules.coercion): the ECS
                # target (primary or not) is left unset, also: copies too
                # (same value, same type, same failure) — verbatim capture
                # is the only thing that happens.
                _nest_set(doc, f"car.{name}.{car_field}", raw)

    for entry in plan["natives"]:
        raw = row.get(entry["car"])
        if not _blank(raw):
            _nest_set(doc, f"car.{name}.{entry['car']}", raw)


def _apply_derived(doc: dict, plan: dict, row: dict, name: str) -> None:
    for d in plan["derived"]:
        fn = _DERIVED_TRANSFORMS.get((name, d["ecs"]))
        if fn is None:
            continue
        val = fn(row)
        if val is not None:
            _nest_set(doc, d["ecs"], val)


def _apply_event_defaults(doc: dict, plan: dict, row: dict, name: str) -> None:
    """event.category (constant per object) / event.type (per car_action) /
    event.outcome (from car_action, or from one boolean object field) —
    ECS categorisation, never a plain field copy (rules.event_action)."""
    ed = plan["event_defaults"]
    category = ed.get("category")
    if category:
        _nest_set(doc, "event.category", list(category))
    action = row.get("car_action")
    type_list = (ed.get("type_by_action") or {}).get(action)
    if type_list:
        _nest_set(doc, "event.type", list(type_list))

    outcome = None
    outcome_from_action = ed.get("outcome_from_action") or {}
    if action in outcome_from_action:
        outcome = outcome_from_action[action]
    else:
        field = ed.get("outcome_from_field")
        if field:
            raw = row.get(field)
            if not _blank(raw):
                # the objects/*.yml `fields:` entry naming this CAR field
                # (e.g. socket.yml `success`, user_session.yml
                # `login_successful`) maps `ecs: event.outcome`, but
                # _compile_object excludes every such entry from `groups`
                # (event.outcome is DERIVED here, never a plain field copy —
                # rules.event_action) — so without this capture the raw
                # value has no home anywhere once it collapses to the
                # success/failure word below: preserve it verbatim, exactly
                # like a native: true field (render_elastic.py's
                # object_targets renders car.<object>.<field> concrete for
                # it, never an alias, for the same reason).
                _nest_set(doc, f"car.{name}.{field}", raw)
                ok, val = _coerce_boolean(raw)
                if ok:
                    outcome = "success" if val else "failure"
    if outcome:
        _nest_set(doc, "event.outcome", outcome)


# --------------------------------------------------------------------------- #
# relationships.yml / inferred.yml: one shared engine (both files are shaped
# identically — see _compile_edge). Every field entry already names its own
# `type:` and, where it has one, an `also_type:` that may legitimately DIFFER
# from the primary's — the timestamp/first_seen fields' `also:` (car.rel.
# timestamp keyword, car.inferred.first_seen date) is exactly this: when the
# types differ the also: copy takes the RAW value (the verbatim
# id-reproducibility companion relationships.yml documents); when they match
# (inferred.yml's first_seen, both date) it takes the SAME coerced value as
# the primary — one rule covers both, faithfully, with no special-casing.
# --------------------------------------------------------------------------- #
def _project_edge(row: dict, namespace: str, plan: dict) -> dict | None:
    doc: dict = {}
    _apply_constants(doc, plan["constants"], None)
    _nest_set(doc, "data_stream.namespace", namespace)
    for f in plan["fields"]:
        raw = row.get(f["car"])
        if _blank(raw):
            continue
        ok, val = _coerce(raw, f["type"])
        if not ok:
            continue                                    # no native fallback on an edge stream
        _nest_set(doc, f["ecs"], val)
        also = f["also"]
        if also:
            _nest_set(doc, also, raw if f["also_type"] != f["type"] else val)
    return doc if "@timestamp" in doc else None


# --------------------------------------------------------------------------- #
# The three public entry points.
# --------------------------------------------------------------------------- #
def project_event(ev: dict, namespace: str):
    """A `car_<object>.jsonl` line (byakugan/store.py export_jsonl: header
    fields + the object's own fields flat, `native` a JSON object, `car_object`
    naming the object, no `event_id`) -> `(stream, doc_id, doc)`, or `None`
    when `ev["timestamp"]` does not parse (SKIP_NO_TIMESTAMP)."""
    contract = load_contract()
    name = ev.get("car_object")
    if not name or name not in contract["objects"]:
        raise ValueError(f"no projection contract for CAR object {name!r} "
                         "(byakugan/store.py always sets car_object)")
    dt = parse_ts(ev.get("timestamp"))
    if dt is None:
        return None

    conv = contract["conventions"]
    plan = contract["objects"][name]
    doc: dict = {}
    _apply_constants(doc, conv.get("constants") or {}, name)
    _nest_set(doc, "data_stream.namespace", namespace)
    _nest_set(doc, "@timestamp", _format_iso_z(dt))
    _nest_set(doc, "car.timestamp", ev.get("timestamp"))       # verbatim, id-reproducibility companion
    _apply_header(doc, ev, name, conv.get("common_header") or {})
    _apply_object_fields(doc, plan, ev, name, contract["ecs_types"])
    _apply_derived(doc, plan, ev, name)
    _apply_event_defaults(doc, plan, ev, name)

    recipe = (conv.get("data_stream") or {}).get("document_id", {}).get("recipe", "")
    doc_id = _object_document_id(recipe, ev, name)
    return f"logs-car.{name}-{namespace}", doc_id, doc


def project_relationship(row: dict, namespace: str):
    """A `car_relationships.jsonl` line (byakugan/superset.py _export_table
    over the `relationship` table: every REL_COLUMNS column, `corroborated_by`
    JSON-decoded) -> `(stream, doc_id, doc)`, or `None` when `row["timestamp"]`
    does not parse (SKIP_NO_TIMESTAMP)."""
    plan = load_contract()["relationships"]
    doc = _project_edge(row, namespace, plan)
    if doc is None:
        return None
    doc_id = _edge_document_id(plan["document_id"].get("recipe", ""), row)
    return f"logs-car.rel-{namespace}", doc_id, doc


def project_inferred(row: dict, namespace: str):
    """A `car_inferred.jsonl` line (byakugan/superset.py _export_table over
    the `inferred_node` table: `corroborated_by`/`properties` JSON-decoded)
    -> `(stream, doc_id, doc)`, or `None` when `row["first_seen"]` does not
    parse (SKIP_NO_TIMESTAMP). `document_id` is `node_id` verbatim — already
    deterministic by construction (inferred.yml), never hashed."""
    plan = load_contract()["inferred"]
    doc = _project_edge(row, namespace, plan)
    if doc is None:
        return None
    node_id = row.get("node_id")
    if _blank(node_id):
        raise ValueError("inferred_node row has no node_id (document_id: node_id verbatim)")
    return f"logs-car.inferred-{namespace}", node_id, doc

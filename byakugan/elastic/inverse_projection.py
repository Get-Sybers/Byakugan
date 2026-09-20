"""The ECS->CAR inverse projector: `byakugan.elastic.projection`'s companion,
used only by `byakugan timeline --elastic` (epic #99 phase 5).

`byakugan.elastic.projection` turns a CAR row into an Elasticsearch document.
This module undoes exactly that move — a `logs-car.<object>-*` / `logs-car.rel-*`
document (an ES hit's `_source`) back into the SAME shape
`byakugan/timeline.py`'s own `_object_entries` / `_edge_entries` already
build from the local materialised JSONL tree directly — so a timeline built from
Elastic and a timeline built locally are the same rows, ordered and filtered
by the SAME code (`build_timeline`'s --host/--after/--before, `_sort_key`,
`write_jsonl`), regardless of which tier answered the query.

    invert_object(doc)         a logs-car.<object>-* _source -> the OBJECT
                                timeline entry: {timestamp, kind: "object",
                                object, <car field>: value, ..., native: {...}}
    invert_relationship(doc)   a logs-car.rel-* _source -> the RELATIONSHIP
                                timeline entry: {timestamp, kind: "relationship",
                                source_host, relationship, source_object,
                                source_guid, target_object, target_guid,
                                confidence, method}

Mechanically derived, every time, from `byakugan.elastic.projection.load_contract()`
— the SAME compiled contract `project_event`/`project_relationship` read —
never a second, hand-written field table:

  - every `ecs:` / `also:` / `native: true` home in objects/<object>.yml is
    walked BACKWARDS to its CAR field name (`plan["groups"]`/`plan["natives"]`,
    the exact structures `_apply_object_fields` itself walks forwards);
  - conventions.yml's `common_header` is inverted the same way for the 6
    fields it maps generically (car_action, source_artefact, source_host,
    volume_guid, mac_address, device_serial); guid/owning_guid/link_confidence
    keep the per-field handling `_apply_header` itself gives them (see
    `_header_value` below — a direct mirror, one branch per irregular field);
  - the emitted key ORDER matches `_object_entries`' own (timestamp, kind,
    object, then `byakugan.store.HEADER`'s field order, then the object's own
    MITRE fields in `byakugan.carmodel.fields(object)` order, native last) —
    read off `store.HEADER`/`carmodel.fields()` themselves, not retyped, so a
    round-trip is BYTE-identical (`byakugan/timeline.py`'s `write_jsonl` does
    not sort keys: JSON key order is dict insertion order, and it must match
    exactly what `store.export_jsonl()`'s own car_<object>.jsonl row order is).

Loader-stamped constants (event.kind/module/dataset, data_stream.*,
ecs.version, car.object, event.category/type and every other
event_defaults-derived field, car.link_confidence's float) are never CAR
data — timeline.py's OBJECT entries do not carry them either (the materialised
tree has no field for them), so there is nothing to invert. car.link_confidence (the
float) is specifically NOT the source for `link_confidence`:
labels.link_confidence carries the verbatim pipeline word back, exactly as
the module docstring of `byakugan.elastic.projection` documents.

--------------------------------------------------------------------------- #
Round-trip fidelity, and what stays genuinely irrecoverable
--------------------------------------------------------------------------- #

Two forward-pass gaps (byakugan/elastic/projection.py `_apply_object_fields` /
`_apply_event_defaults`) were CLOSED for this phase precisely so this module
would not have to ship a lossy inverse — see that module's own docstring for
what changed and why. With both fixes in place, every CAR field is
reconstructed EXACTLY, with one residual case that is irrecoverable BY
DESIGN, and one pre-existing (not phase-5-introduced) ECS-typing property
this module does not attempt to undo:

  1. A shared-target primary/fallback PAIR (e.g. objects/process.yml
     hostname (primary) / fqdn (fallback), both -> host.hostname) populated
     with the EXACT SAME STRING on both CAR fields is indistinguishable from
     the fallback alone having that value (primary absent): the document
     carries one ECS value and one car.<object>.<fallback> capture either
     way. This module resolves the ambiguity by assuming the NARROWER case
     (fallback alone) — i.e. it never reconstructs the primary when doing so
     would only be an echo of the fallback's own captured value. Excluded
     from the round-trip test (tests/test_timeline_elastic.py) BY
     CONSTRUCTION: the fixture never gives a primary/fallback pair of one
     object the identical value.
  2. A CAR value for a TYPED ECS target (date/long/float/boolean/ip —
     ecs_types.yml's five coercion buckets) whose JSON TYPE differs from its
     coerced form (e.g. a pid supplied as the STRING "4536" rather than the
     int 4536, or a timestamp not already in `@timestamp`'s own canonical
     'Z'-suffixed rendering) loses that original representation the moment
     coercion succeeds (rules.coercion, conventions.yml) — the coerced value
     is all the document ever carries; there is no overflow capture for a
     SUCCESSFUL coercion (only a failed one lands verbatim, and that case
     round-trips exactly, unaffected). This is a pre-existing, deliberate
     property of the projection contract itself (the whole point of typing
     an ECS field), not something phase 5 introduced or could fix without
     abandoning ECS typing — reversing it is out of scope here. Excluded
     from the round-trip test by construction: every typed field the fixture
     populates is already given in its native coerced Python type/canonical
     string form, so coercion is a byte-exact no-op throughout.
  3. rules.verbatim's handful of ECS-demanded normalisations
     (projection.py's `_VERBATIM_TRANSFORMS`: file.extension's leading dot,
     registry.hive's abbreviation, flow/socket protocol lower-casing,
     network.direction's in/out words) are, in general, MANY-CAR-VALUES-TO-
     ONE-ECS-VALUE (".docx" and "docx" both normalise to "docx"; "tcp" and
     "TCP" both to "tcp") — genuinely ambiguous whenever the ECS value could
     have come from either spelling. `process.env_vars` is the one exception
     (newline-split/joined, a lossless bijection) and IS inverted, below
     (`_VERBATIM_INVERSE_TRANSFORMS`). The other four are reconstructed
     verbatim from the ECS value with NO un-normalising guess (correct
     whenever the original CAR value was already in its post-transform
     canonical form — dot-less, abbreviated, lower-case — and only wrong in
     the narrower case it was not). Excluded from the round-trip test by
     construction: the fixture gives these fields their canonical form to
     begin with, so the forward transform is a byte-exact no-op.
"""
from __future__ import annotations

from .. import carmodel
from ..store import HEADER as _STORE_HEADER
from . import projection

# store.HEADER minus the two fields handled outside this generic pass
# (timestamp decides the row's placement before either entry function is
# called; native is appended last) -- read off store.py, never retyped, so
# the two modules can never drift on the header's own field set or order.
_HEADER_ORDER = tuple(f for f in _STORE_HEADER if f not in ("timestamp", "native"))


# the one rules.verbatim normalisation (projection.py _VERBATIM_TRANSFORMS)
# that IS a lossless bijection -- see point 3 of the docstring above for why
# the other four are deliberately left un-inverted.
def _join_env_vars(v):
    return "\n".join(v) if isinstance(v, list) else v


_VERBATIM_INVERSE_TRANSFORMS = {
    ("process", "env_vars"): _join_env_vars,
}


def _untransform(name: str, car_field: str, value):
    fn = _VERBATIM_INVERSE_TRANSFORMS.get((name, car_field))
    return fn(value) if fn is not None else value


def _doc_get(doc: dict, path: str | None):
    """The value at dotted ECS/car.* `path` in a nested ES `_source`, or None
    when any component is missing — the document-instance analogue of
    projection.py's own `_nest_set`, run backwards."""
    if not path:
        return None
    node = doc
    for p in path.split("."):
        if not isinstance(node, dict) or p not in node:
            return None
        node = node[p]
    return node


# --------------------------------------------------------------------------- #
# The common header, inverted (mirrors byakugan/elastic/projection.py _apply_header).
# --------------------------------------------------------------------------- #
def _header_value(doc: dict, name: str, field: str, header: dict, guid):
    if field == "guid":
        return guid
    if field == "owning_guid":
        owning = _doc_get(doc, "process.entity_id")
        if owning is None:
            return None
        if name == "process" and owning == guid:
            # on a process object event.id IS the guid and process.entity_id
            # merely DUPLICATES it (conventions.yml common_header.guid.
            # per_object.process: guid also wins process.entity_id, but only
            # when owning_guid is absent) -- not an independent owning_guid.
            # On every other object process.entity_id IS owning_guid, always.
            return None
        return owning
    if field == "link_confidence":
        # the verbatim pipeline WORD, not car.link_confidence (the float
        # conventions.yml's vocabulary derives from it) -- see module docstring.
        return _doc_get(doc, "labels.link_confidence")
    ecs_path = (header.get(field) or {}).get("ecs")
    return _doc_get(doc, ecs_path)


# --------------------------------------------------------------------------- #
# One object's own fields, inverted (mirrors _apply_object_fields).
# --------------------------------------------------------------------------- #
def _invert_group(doc: dict, name: str, target: str, group: dict) -> dict:
    """{car field name: value} for every member of one shared-target group
    (one entry for a solo, unshared target). A fallback's own value is
    ALWAYS its car.<object>.<field> capture (byakugan/elastic/projection.py's fix:
    that path is written unconditionally whenever the fallback has a value,
    win or lose, coercion success or failure). The primary's value is the
    ECS target UNLESS a fallback's own capture already accounts for it (the
    residual, documented ambiguity — see module docstring) or the primary's
    OWN coercion failed (its own car.<object>.<field> capture, unambiguous:
    nothing else ever writes that specific path)."""
    out: dict = {}
    fallback_raw: dict[str, object] = {}
    for fb in group["fallbacks"]:
        v = _doc_get(doc, f"car.{name}.{fb['car']}")
        if v is not None:
            fallback_raw[fb["car"]] = v             # pre-untransform, for the equality check below
            out[fb["car"]] = _untransform(name, fb["car"], v)

    primary = group["primary"]
    if primary is None:
        return out
    p_car = primary["car"]
    p_overflow = _doc_get(doc, f"car.{name}.{p_car}")
    if p_overflow is not None:
        out[p_car] = _untransform(name, p_car, p_overflow)   # the primary's own coercion failed
        return out
    t = _doc_get(doc, target)
    if t is not None and not any(v == t for v in fallback_raw.values()):
        out[p_car] = _untransform(name, p_car, t)
    return out


def _invert_object_fields(doc: dict, name: str, plan: dict) -> dict:
    """{car field name: value} for every objects/<object>.yml `fields:` entry
    that is not header-owned: every shared/solo ECS target group, every
    native: true field, and (byakugan/elastic/projection.py's second fix) the
    event_defaults.outcome_from_field driver, when this object has one."""
    out: dict = {}
    for target, group in plan["groups"].items():
        out.update(_invert_group(doc, name, target, group))
    for entry in plan["natives"]:
        v = _doc_get(doc, f"car.{name}.{entry['car']}")
        if v is not None:
            out[entry["car"]] = v
    outcome_field = (plan["event_defaults"] or {}).get("outcome_from_field")
    if outcome_field:
        v = _doc_get(doc, f"car.{name}.{outcome_field}")
        if v is not None:
            out[outcome_field] = v
    return out


def invert_object(doc: dict) -> dict:
    """A logs-car.<object>-* ES `_source` -> the OBJECT timeline entry
    `byakugan/timeline.py`'s `_object_entries` emits from the local
    materialised tree directly.
    Raises ValueError when `doc` does not carry a recognised `car.object`
    (the loader-stamped constant every object stream document has — a
    malformed/foreign document, never a normal projection outcome)."""
    name = _doc_get(doc, "car.object")
    contract = projection.load_contract()
    if not name or name not in contract["objects"]:
        raise ValueError(f"not a recognised logs-car object document (car.object={name!r})")
    conv = contract["conventions"]
    plan = contract["objects"][name]
    header = conv.get("common_header") or {}

    entry: dict = {"timestamp": _doc_get(doc, "car.timestamp"), "kind": "object", "object": name}

    guid = _doc_get(doc, "event.id")
    for field in _HEADER_ORDER:
        val = _header_value(doc, name, field, header, guid)
        if val is not None:
            entry[field] = val

    by_car_field = _invert_object_fields(doc, name, plan)
    for field in carmodel.fields(name):
        if field in _STORE_HEADER:
            continue                                # store.CarStore._cols' own dedupe
        val = by_car_field.get(field)
        if val is not None:
            entry[field] = val

    native = _doc_get(doc, "car.native")
    if native:
        entry["native"] = dict(native)

    return entry


# --------------------------------------------------------------------------- #
# relationships.yml, inverted (mirrors _project_edge).
# --------------------------------------------------------------------------- #
def _invert_edge_fields(doc: dict, plan: dict) -> dict:
    """{car field name: value} for every relationships.yml `fields:` entry.
    The byte-exact ORIGINAL comes from `also:` when it is typed differently
    to the primary (relationships.yml's own verbatim-string companion,
    car.rel.timestamp, alongside the coerced/reformatted @timestamp — the
    same id-reproducibility concern conventions.yml states for the object
    streams' own car.timestamp); the primary `ecs:` target otherwise
    (car.rel.* is keyword-typed verbatim throughout, so it already IS the
    byte-exact value whenever there is no also: to prefer)."""
    row: dict = {}
    for f in plan["fields"]:
        val = None
        if f["also"] and f["also_type"] != f["type"]:
            val = _doc_get(doc, f["also"])
        if val is None:
            val = _doc_get(doc, f["ecs"])
        row[f["car"]] = val
    return row


# byakugan/timeline.py's _edge_entries picks this narrow 9-field subset of
# the relationship table (not class/identity_key/inferred_end/corroborated_by)
# -- kept in step with that dict literal by hand: byakugan.timeline imports
# THIS module (for its --elastic source), so the reverse import that would
# let this module read _edge_entries back is not available without a cycle.
# tests/test_timeline_elastic.py proves the two agree, byte-for-byte, on
# every run -- the enforcement this can't get from a shared import.
RELATIONSHIP_ENTRY_FIELDS = ("source_host", "relationship", "source_object", "source_guid",
                             "target_object", "target_guid", "confidence", "method")


def invert_relationship(doc: dict) -> dict:
    """A logs-car.rel-* ES `_source` -> the RELATIONSHIP timeline entry
    `byakugan/timeline.py`'s `_edge_entries` emits from
    `car_relationships.jsonl` directly -- the same 9 fields (not every
    relationships.yml column: class/identity_key/inferred_end/
    corroborated_by ride along in the document but are not part of the
    timeline's own relationship-entry shape, so they are simply not among
    RELATIONSHIP_ENTRY_FIELDS). Every field is present even when null (the
    dict literal _edge_entries itself builds is unconditional past the
    `timestamp IS NOT NULL` row filter), so this mirrors that exactly."""
    row = _invert_edge_fields(doc, projection.load_contract()["relationships"])
    entry = {"timestamp": row.get("timestamp"), "kind": "relationship"}
    for field in RELATIONSHIP_ENTRY_FIELDS:
        entry[field] = row.get(field)
    return entry

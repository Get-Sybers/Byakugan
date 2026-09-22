"""DERIVED relationships — the data-driven class of the D4 relationship model.

The superset relationship timeline carries two CLASSES of relationship instance:

- **DECLARED** (class=declared): the validated cascade edges enrich.py resolves
  and superset.edges_from_events materializes — rule-driven (relationships.yml,
  cascade_relationships.yml), assessed credible for inference.
- **DERIVED** (class=derived): data-driven 1:1 links THIS module infers where
  two parsed records clearly list the same properties tied to the same event or
  entity, joined on a SHARED STRONG identity — a natively-carried guid, a
  content hash, a real account SID, a memory-object offset. Every row names its
  `identity_key`, its `method` and the guids that corroborate it.

A derived link may RECONSTRUCT a node no source observed — the owner a Sysmon
spoke names by ProcessGuid after the log was cleared, the parent a memory
process names by offset when it was unlinked or reaped (antiforensics / limited
recovery). That node is an `inferred_node` row — flagged, corroborated, exported
to car_inferred.jsonl (its own stream) — and the derived edge points at it via
`inferred_end`. It is NEVER written as a fabricated car_<object> event row.

Content-keyed identities (the same bytes, the same account) become
`content_node` rows, deterministic by content (sha256:<hex>, sid:<S-1-5-21-…>),
with an `entity_ref` from every record carrying them — the attribution layer
the STIX projection derives global-id SCOs from. A record carrying several
hashes references one node per algorithm; a consumer unions the nodes one
record co-references.

The pass is ADDITIVE (the D4 superset cascade). The additive fold of
same-event rows — one CAR entry filling every property any source supplied,
a disagreeing value preserved in the native bag (coalesced_conflicts), never
nulled, the contributors counted — is the pipeline's default fold
(relationships.yml `dedupe.fold`, engine enrich.fold); `coalesce()` here
delegates to it, so a re-derive over a store folds exactly the same way.
The rules are data (relationships.yml `derived:`); this is the engine.

    python -m byakugan.derive <car-dir>     # (re)derive over an existing store
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict

from . import enrich, store, superset

_MISSING = (None, "")
_PROP_CAP = 64          # values kept per content-node property (a hash seen at many paths)
_re_cache: dict[str, re.Pattern] = {}


def rules() -> dict:
    """The `derived:` block of relationships.yml (beside the declared rules).

    YAML 1.1 footgun, absorbed here: an unquoted `on:` key parses as the
    BOOLEAN True (like off/yes/no), which silently voided every reconstruct
    rule's scope until it was quoted. The registry quotes it ("on":) and this
    loader re-keys a boolean-True key back to "on" so a future unquoted edit
    degrades to working, not to scopeless."""
    r = enrich.rules()["derived"]
    for rec in r.get("reconstruct") or []:
        if True in rec and "on" not in rec:
            rec["on"] = rec.pop(True)
    return r


def _get(ev: dict, path: str):
    """A value off an event: a CAR/enrich field, or native.<key>."""
    if path.startswith("native."):
        return (ev.get("_native") or {}).get(path[len("native."):])
    return ev.get(path)


def _accepts(ident: dict, value) -> bool:
    pats = ident.get("accept")
    if not pats:
        return True
    s = str(value).strip()
    for p in pats:
        rx = _re_cache.get(p)
        if rx is None:
            rx = _re_cache[p] = re.compile(p)
        if rx.match(s):
            return True
    return False


def _normalize(ident: dict, value) -> str:
    s = str(value).strip()
    mode = ident.get("normalize")
    return s.lower() if mode == "lower" else s.upper() if mode == "upper" else s


def _values(v) -> list:
    """A join value as a list — a kept Zeek fuids list matches any element; a
    list-valued field usually arrives as a real list, but tolerate JSON text
    too (an older encoding, or a hand-built value)."""
    if v in _MISSING:
        return []
    if isinstance(v, str) and v.startswith("["):
        try:
            v = json.loads(v)
        except ValueError:
            return [v]
    if isinstance(v, (list, tuple)):
        return [x for x in v if x not in _MISSING]
    return [v]


# --------------------------------------------------------------------------- #
# Additive coalescing — the pipeline's fold, by its derive-side name
# --------------------------------------------------------------------------- #
def coalesce(events: list[dict]) -> list[dict]:
    """Rows that are the SAME event (relationships.yml dedupe.key) become ONE
    CAR entry holding every property any source supplied — the additive fold
    (enrich.fold: a later source fills what earlier ones lacked and never
    removes their contribution; conflicts land in native, not in null; the
    contributors are counted). A row with no guid has no identity and never
    collapses. The pipeline folds on every run; this is the same fold for a
    caller that holds events in memory."""
    return enrich.fold(events, enrich.FOLD_ADDITIVE)


# --------------------------------------------------------------------------- #
# Content entities: content_node + entity_ref
# --------------------------------------------------------------------------- #
def _seen(node: dict, ts) -> None:
    if not ts:
        return
    if node["first_seen"] is None or ts < node["first_seen"]:
        node["first_seen"] = ts
    if node["last_seen"] is None or ts > node["last_seen"]:
        node["last_seen"] = ts


def content_entities(events: list[dict]) -> tuple[list[dict], list[dict]]:
    """One content_node per (algorithm/kind, value) any record carries, with
    the context those records give it unioned on (additive, capped), and one
    entity_ref per (record, node) — the record's field is its ROLE (owner_uid,
    target_uid …)."""
    nodes: dict[str, dict] = {}
    refs: list[dict] = []
    for name, ident in rules()["identities"].items():
        if ident.get("kind") != "content":
            continue
        for ev in events:
            for f in ident.get("fields", []):
                v = ev.get(f)
                if v in _MISSING or not _accepts(ident, v):
                    continue
                val = _normalize(ident, v)
                prefix = f[:-len("_hash")] if f.endswith("_hash") else name
                nid = f"{prefix}:{val}"
                node = nodes.get(nid)
                if node is None:
                    node = nodes[nid] = {
                        "node_id": nid, "kind": ident.get("node"), "identity_key": f,
                        "identity_value": val, "properties": {},
                        "first_seen": None, "last_seen": None, "ref_count": 0}
                node["ref_count"] += 1
                _seen(node, ev.get("timestamp"))
                for p in ident.get("properties", []):
                    pv = ev.get(p)
                    if pv in _MISSING:
                        continue
                    lst = node["properties"].setdefault(p, [])
                    if pv not in lst and len(lst) < _PROP_CAP:
                        lst.append(pv)
                if ev.get("guid") is not None:
                    refs.append({"source_host": ev.get("source_host"),
                                 "object": ev["car_object"], "guid": ev["guid"],
                                 "node_id": nid, "identity_key": f,
                                 "timestamp": ev.get("timestamp")})
    return list(nodes.values()), refs


# --------------------------------------------------------------------------- #
# 1:1 links — both ends observed
# --------------------------------------------------------------------------- #
def _edge(rule: dict, s: dict, t: dict, identity_key: str) -> dict:
    return {"timestamp": s.get("timestamp") or t.get("timestamp"),
            "source_host": s.get("source_host"), "relationship": rule["relationship"],
            "source_object": s["car_object"], "source_guid": s["guid"],
            "target_object": t["car_object"], "target_guid": t["guid"],
            "confidence": rule.get("confidence", "definitive"), "method": rule["method"],
            "class": superset.DERIVED, "identity_key": identity_key,
            "inferred_end": None, "corroborated_by": [s["guid"], t["guid"]]}


def _disambiguate(s: dict, cands: list[dict], prefer: dict | None) -> list[dict]:
    """The 1:1 rule: one candidate is it; several are narrowed by the preferred
    field pair (image_path == file_path); still ambiguous means NO edge — the
    content_node carries the many-to-many honestly."""
    if len(cands) == 1:
        return cands
    if prefer:
        sv = s.get(prefer["source"])
        if sv not in _MISSING:
            hit = [t for t in cands
                   if str(t.get(prefer["target"]) or "").lower() == str(sv).lower()]
            if len(hit) == 1:      # exactly one after narrowing is the 1:1 link
                return hit
    return []                      # 0 or >1 after narrowing: still ambiguous, no edge


def link_edges(events: list[dict]) -> list[dict]:
    """The both-ends-observed derived links (relationships.yml derived.links)."""
    idents = rules()["identities"]
    by_obj: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        if ev.get("guid") is not None:
            by_obj[ev["car_object"]].append(ev)
    out, seen = [], set()
    for rule in rules().get("links", []):
        ident = idents[rule["identity"]]
        src_evs, tgt_evs = by_obj.get(rule["source"], []), by_obj.get(rule["target"], [])
        if not src_evs or not tgt_evs:
            continue
        if ident.get("kind") == "content":
            pairs = [(f, f) for f in ident["fields"]]      # strongest first
        else:
            pairs = [(rule["join"]["source"], rule["join"]["target"])]
        for sf, tf in pairs:
            tidx: dict[tuple, list[dict]] = defaultdict(list)
            for t in tgt_evs:
                for v in _values(_get(t, tf)):
                    if _accepts(ident, v):
                        tidx[(t.get("source_host"), _normalize(ident, v))].append(t)
            if not tidx:
                continue
            for s in src_evs:
                for v in _values(_get(s, sf)):
                    if not _accepts(ident, v):
                        continue
                    cands = tidx.get((s.get("source_host"), _normalize(ident, v)))
                    if not cands:
                        continue
                    cands = [t for t in cands if t is not s and t.get("guid") != s.get("guid")]
                    for t in _disambiguate(s, cands, rule.get("prefer")):
                        key = (rule["name"], s["guid"], t["guid"])
                        if key in seen:
                            continue            # a weaker hash already linked this pair
                        seen.add(key)
                        out.append(_edge(rule, s, t, sf))
    return out


# --------------------------------------------------------------------------- #
# Reconstruction — the referenced end is absent
# --------------------------------------------------------------------------- #
def _in_scope(on, ev: dict) -> bool:
    if on in (None, "*"):
        return True
    if on == "spokes":
        return ev["car_object"] != "process"
    obj, _, act = str(on).partition("/")
    return ev["car_object"] == obj and (not act or ev.get("car_action") == act)


def _as_guid(value, ident: dict) -> str | None:
    """The guid the missing node would carry for this identity value: the value
    itself, the identity-normalized value in a form ({value} -> a LUID's
    user_session-<luid>), or the form the artefact mints for it (offset ->
    proc-<hex>)."""
    form = ident.get("guid_form")
    if not form:
        return str(value)
    if "{value}" in form:
        return form.replace("{value}", _normalize(ident, value))
    try:
        return form.replace("{hex}", format(int(value), "x"))
    except (TypeError, ValueError):
        return None


def reconstruct(events: list[dict], observed: set) -> tuple[list[dict], list[dict]]:
    """inferred_node rows + the derived edges that end on them
    (relationships.yml derived.reconstruct). `observed` is the set of
    (host, object, guid) any record in the store carries."""
    idents = rules()["identities"]
    nodes: dict[tuple, dict] = {}
    edges: list[dict] = []
    for rule in rules().get("reconstruct", []):
        ident = idents[rule["identity"]]
        node_obj, end = rule["node"], rule.get("end", "source")
        for ev in events:
            if not _in_scope(rule.get("on"), ev):
                continue
            ref = _get(ev, rule["reference"])
            if ref in _MISSING or ev.get("guid") is None:
                continue
            if not _accepts(ident, ref):
                continue                        # the identity's accept gate (a null/
                                                # well-known LUID never mints a node)
            linked = rule.get("unless_linked")
            if linked and _get(ev, linked) not in _MISSING:
                continue                        # the cascade found it: observed
            host = ev.get("source_host")
            missing = _as_guid(ref, ident)
            if missing is None or missing == str(ev["guid"]):
                continue                        # unusable, or a self-reference
            if (host, node_obj, missing) in observed:
                continue                        # observed: not ours to infer
            obs = rule.get("observed")
            if obs:
                obs_guid, obs_obj = ev.get(obs["field"]), obs["object"]
                if obs_guid in _MISSING:
                    continue
            else:
                obs_guid, obs_obj = ev["guid"], ev["car_object"]
            node = nodes.get((host, missing))
            if node is None:
                node = nodes[(host, missing)] = {
                    "node_id": missing, "source_host": host, "object": node_obj,
                    "identity_key": rule["identity"], "identity_value": str(ref),
                    "method": rule["method"], "corroborated_by": [], "properties": {},
                    "first_seen": None, "last_seen": None, "_rules": []}
            if rule["name"] not in node["_rules"]:
                node["_rules"].append(rule["name"])
            if obs_guid not in node["corroborated_by"]:
                node["corroborated_by"].append(obs_guid)
            _seen(node, ev.get("timestamp"))
            props = node["properties"]
            for nf, ef in (rule.get("properties") or {}).items():
                v = _get(ev, ef)
                if v in _MISSING:
                    continue
                if props.get(nf) in _MISSING:
                    props[nf] = v
                elif str(props[nf]) != str(v):   # additive: keep, never overwrite
                    alts = props.setdefault("conflicts", {}).setdefault(nf, [])
                    if v not in alts:
                        alts.append(v)
            verb = rule["relationship"]
            if verb == "spoke_owner":
                verb = superset._spoke_verb(ev["car_object"], ev.get("car_action"))  # noqa: SLF001
            src = (node_obj, missing) if end == "source" else (obs_obj, obs_guid)
            tgt = (obs_obj, obs_guid) if end == "source" else (node_obj, missing)
            edges.append({"timestamp": ev.get("timestamp"), "source_host": host,
                          "relationship": verb, "source_object": src[0], "source_guid": src[1],
                          "target_object": tgt[0], "target_guid": tgt[1],
                          "confidence": "inferred", "method": rule["method"],
                          "class": superset.DERIVED, "identity_key": rule["identity"],
                          "inferred_end": end, "corroborated_by": [obs_guid]})
    out = []
    for n in nodes.values():
        n["reason"] = (f"{'+'.join(n.pop('_rules'))}: referenced by "
                       f"{len(n['corroborated_by'])} observed record(s) via {n['identity_key']}; "
                       f"no {n['object']} event observed (reconstructed, not evidence)")
        out.append(n)
    return out, edges


# --------------------------------------------------------------------------- #
# The pass
# --------------------------------------------------------------------------- #
def derive(events: list[dict], sup_store: superset.SupersetStore, out_dir: str | None = None) -> dict:
    """Run the derived pass over ONE source's enriched events into `sup_store`
    — an in-memory SupersetStore that already holds the DECLARED edges (e.g.
    from superset.build_from_events); adds the DERIVED layer on top and, with
    `out_dir`, re-exports the relationship timeline (now both classes) and
    car_inferred.jsonl. There is no persistent store to selectively clear a
    stale derived layer from any more: `sup_store` is trusted to be either
    fresh or already derived-free — `run()` below gives it exactly that."""
    observed = {(ev.get("source_host"), ev["car_object"], str(ev["guid"]))
                for ev in events if ev.get("guid") is not None}
    edges = link_edges(events)
    nodes, redges = reconstruct(events, observed)
    cnodes, refs = content_entities(events)
    sup_store.insert_edges(edges + redges)
    sup_store.insert_inferred_nodes(nodes)
    sup_store.insert_content_nodes(cnodes)
    sup_store.insert_entity_refs(refs)
    summary = sup_store.counts()
    if out_dir:
        summary["relationships_exported"] = sup_store.export_jsonl(out_dir)
        summary["inferred_exported"] = sup_store.export_inferred_jsonl(out_dir)
    return summary


def load_events(car_dir: str) -> list[dict]:
    """A materialised source tree's car_<object>.jsonl as the in-memory event
    shape the pass consumes (native -> _native) — store.read_events under its
    derive-side name. Enrich's transient inputs (owning_guid_native,
    owning_offset) are never exported, so a re-derive over a tree sees only
    the natively KEPT references (ParentProcessGuid, TargetProcessGuid, fuids
    …)."""
    return store.read_events(car_dir)


def run(car_dir: str) -> dict:
    """(Re)derive over an existing materialised <car_dir>: read its events
    back from car_<object>.jsonl, recompute BOTH relationship classes fresh
    into a new in-memory store — recompute-fresh-each-run, replacing the old
    clear-just-the-derived-layer contract a persistent superset.db needed —
    and re-export car_relationships.jsonl/car_inferred.jsonl."""
    events = load_events(car_dir)
    if not events:
        raise SystemExit(f"no materialised CAR under {car_dir!r}")
    sup_store = superset.SupersetStore()
    sup_store.insert_edges(superset.edges_from_events(events))
    return derive(events, sup_store, car_dir)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="byakugan.derive",
                                 description="the DERIVED relationship pass over one source's materialised tree")
    ap.add_argument("car_dir", help="a source's car directory (car_<object>.jsonl)")
    args = ap.parse_args(argv)
    json.dump(run(args.car_dir), sys.stdout, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

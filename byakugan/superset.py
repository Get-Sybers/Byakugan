"""The superset relationship timeline — an in-memory edge collection + the
RELATIONSHIP INSTANCES we enter from the artefacts (epic #86, the PURGE
increment).

car.db (now `store.CarStore`, in-memory) holds the OBJECT events (process
create, file write, logon…). This holds the relationship INSTANCES the
cascade produces between those events — each a `source object → relationship
→ target object` edge, timestamped and pointing back at the object events by
guid. That edge collection is a second, more GRANULAR timeline than the
object-level one: it times the *relationships* themselves (P created F,
parent created child, user created logon session, process executed file), and
either LINKS the object events (by guid) or is WATERFALLED (cascaded) from
them.

Held per source alongside the object events, so a source's events and their
relationship timeline stay together for the duration of a build; the ONLY
on-disk product is the materialised JSONL tree (`export_jsonl`/
`export_inferred_jsonl`) — no SQLite is written anywhere in this module. The
former reference-model seed (`model_object`/`relationship_type`, a copy of
build_data_model's own output) is gone: nothing at runtime ever read it back,
so a consumer that wants the superset model calls `build_data_model.build_superset()`
directly.

Relationship instances come in two CLASSES (the D4 relationship model):

- DECLARED (`class=declared`): the validated cascade edges edges_from_events
  materializes from enrich's links — rule-driven, credible for inference.
- DERIVED (`class=derived`): data-driven 1:1 links derive.py infers on a shared
  strong identity (guid / hash / real SID / memory offset), each naming its
  `identity_key`, `method` and the `corroborated_by` guids. A derived edge may
  end on an `inferred_node` — a node reconstructed from what other records
  reference but no source observed (antiforensics / partial recovery); it is
  flagged through `inferred_end` and NEVER written as a car_<object>.jsonl event row.
  Content-keyed identities (a hash, a real SID) become `content_node` rows with
  an `entity_ref` from every record carrying them (the attribution layer).
"""
from __future__ import annotations

import json
import os

# the two relationship classes; every row carries one
DECLARED, DERIVED = "declared", "derived"

# The authoritative row shapes: the exporters write EXACTLY these keys, in
# this order (minus the SQLite `id` autoincrement the old store used — there
# is no surrogate key any more). elastic/projection/relationships.yml and
# inferred.yml declare the SAME column lists (the CAR->ECS boundary contract);
# tests/test_projection_rel_drift.py re-pins the two against each other.
REL_COLUMNS = ("timestamp", "source_host", "relationship", "source_object", "source_guid",
              "target_object", "target_guid", "confidence", "method", "class",
              "identity_key", "inferred_end", "corroborated_by", "properties")
INFERRED_COLUMNS = ("node_id", "source_host", "object", "identity_key", "identity_value",
                    "reason", "method", "corroborated_by", "properties", "first_seen",
                    "last_seen")

# relationship-instance verbs are DATA (cascade_relationships.yml), validated
# against the ATT&CK catalogue by test_superset.
_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "cascade_relationships.yml")
_rules_cache: dict | None = None


def rules() -> dict:
    global _rules_cache
    if _rules_cache is None:
        import yaml
        with open(_RULES_PATH, encoding="utf-8") as fh:
            _rules_cache = yaml.safe_load(fh)
    return _rules_cache


def _spoke_verb(obj: str, act: str) -> str:
    r = rules()
    return (r["spoke_owner"].get(obj) or {}).get(act) or r["default_spoke_verb"]


def _edge_verb(name: str) -> str:
    return rules()["edges"][name]


def _method(ev: dict) -> str | None:
    c = ev.get("link_confidence")
    return {"definitive": "native_guid", "heuristic": "pid_window"}.get(c)


def _edge(ts, host, rel, s_obj, s_guid, t_obj, t_guid, conf, method, properties=None):
    return {"timestamp": ts, "source_host": host, "relationship": rel,
            "source_object": s_obj, "source_guid": s_guid,
            "target_object": t_obj, "target_guid": t_guid,
            "confidence": conf, "method": method, "class": DECLARED,
            "properties": properties or None}


# Association properties carried ON the edge — facts of the relationship
# itself, not of either endpoint object (the #108 file-handle pattern). The
# registry is DATA (cascade_relationships.yml `association_properties`, keyed
# "<object>/<action>" for spoke edges and "edge:<name>" for special edges);
# this is only the mechanics: each property names its sources on the emitting
# event row (a CAR field, or native.<Key>) and the first non-null wins. A
# property is duplicated onto the edge, never moved off the row.
def _edge_properties(key: str, ev: dict, nat: dict) -> dict | None:
    spec = (rules().get("association_properties") or {}).get(key)
    if not spec:
        return None
    props = {}
    for name, sources in spec.items():
        for src in ([sources] if isinstance(sources, str) else sources):
            v = nat.get(src[len("native."):]) if src.startswith("native.") else ev.get(src)
            if v is not None and v != "":
                props[name] = v
                break
    return props or None


def edges_from_events(events: list[dict]) -> list[dict]:
    """The relationship instances (timeline edges) implied by the enriched
    events' cascade links. Typed against the ATT&CK relationship vocabulary."""
    out = []
    for ev in events:
        g, obj, act = ev.get("guid"), ev["car_object"], ev.get("car_action")
        host, ts = ev.get("source_host"), ev.get("timestamp")
        nat = ev.get("_native") or {}
        og = ev.get("owning_guid")
        # SPOKE -> owning process (P --verb--> spoke). Only for non-process
        # spokes: a process event's owning_guid is itself, which would emit a
        # meaningless self-loop; process relationships are handled explicitly
        # below (parent, access).
        if og and g and obj != "process" and og != g:
            out.append(_edge(ts, host, _spoke_verb(obj, act),
                             "process", og, obj, g, ev.get("link_confidence"), _method(ev),
                             _edge_properties(f"{obj}/{act}", ev, nat)))
        # process create -> its parent process
        if obj == "process" and act == "create" and ev.get("parent_guid") \
                and ev["parent_guid"] != g:
            out.append(_edge(ts, host, _edge_verb("parent_process"), "process",
                             ev["parent_guid"], "process", g,
                             ev.get("link_confidence"), _method(ev)))
        # process ACCESS (Sysmon 10): source process -> the target it opened
        # (target_guid is a canonical process field, not the record guid); the
        # access's own facts (granted mask, call trace) ride the edge
        if obj == "process" and act == "access" and og and ev.get("target_guid") \
                and og != ev["target_guid"]:
            out.append(_edge(ts, host, _edge_verb("process_access"), "process", og,
                             "process", ev["target_guid"], ev.get("link_confidence"),
                             _method(ev), _edge_properties("edge:process_access", ev, nat)))
        # process MODIFY (tampering/hollowing): the modifier --modified--> this
        # process, when a source names the modifier (native.modifier_process_guid
        # — the declared native-key contract, like TargetProcessGuid for injection)
        if obj == "process" and act == "modify":
            mg = nat.get("modifier_process_guid")
            if mg and g and mg != g:
                out.append(_edge(ts, host, _edge_verb("process_modify"), "process", mg,
                                 "process", g, nat.get("modifier_process_link"),
                                 "native_guid"))
        # R3 materialised: a zeek spoke (http/file) rides a connection — the
        # flow CONTAINS it (shared capture uid, resolved by enrich into
        # native.flow_guid; Network Traffic Content aliased)
        fg = nat.get("flow_guid")
        if fg and g and obj != "flow" and fg != g:
            out.append(_edge(ts, host, _edge_verb("flow_contains"), "flow", fg,
                             obj, g, nat.get("flow_link"), "capture_uid"))
        # file -> the process that executed it (CAR-2014-02-001, image_path)
        ep = nat.get("executed_as_process_guid")
        if ep and g and ep != g:
            out.append(_edge(ts, host, _edge_verb("file_executed"), "process", ep,
                             "file", g, nat.get("executed_as_process_link"), "image_path"))
        # CreateRemoteThread injection: source process -> target process; where
        # execution begins IN the target (start address/module/function, the
        # created thread id) are facts of the injection — they ride the edge
        tg = nat.get("target_process_guid")
        if tg and og and tg != og:
            out.append(_edge(ts, host, _edge_verb("thread_injection"), "process", og,
                             "process", tg, nat.get("target_process_link"), "native_guid",
                             _edge_properties("edge:thread_injection", ev, nat)))
        # authentication -> the logon session it opened / was requested from
        for gk, lk in (("target_session_guid", "target_session_link"),
                       ("subject_session_guid", "subject_session_link")):
            sg = nat.get(gk)
            if sg and g and sg != g:
                out.append(_edge(ts, host, _edge_verb("auth_session"), obj, g,
                                 "user_session", sg, nat.get(lk), "luid"))
    return out


class SupersetStore:
    """One source's relationship edges, inferred nodes, content nodes and
    entity refs, held in memory for the duration of a build."""

    def __init__(self):
        self.relationships: list[dict] = []
        self.inferred_nodes: dict[str, dict] = {}     # node_id -> row (last write wins)
        self.content_nodes: dict[str, dict] = {}       # node_id -> row (last write wins)
        self.entity_refs: list[dict] = []
        self._entity_ref_seen: set[tuple] = set()      # (source_host, object, guid, node_id, identity_key)

    def insert_edges(self, edges: list[dict]) -> int:
        """Store relationship instances. An edge without a `class` is a DECLARED
        cascade edge; derive.py's edges carry class=derived plus identity_key /
        inferred_end / corroborated_by."""
        for e in edges:
            row = {c: e.get(c) for c in REL_COLUMNS}
            if row["class"] is None:
                row["class"] = DECLARED
            self.relationships.append(row)
        return len(edges)

    def insert_inferred_nodes(self, nodes: list[dict]) -> int:
        for n in nodes:
            row = {c: n.get(c) for c in INFERRED_COLUMNS}
            self.inferred_nodes[row["node_id"]] = row
        return len(nodes)

    def insert_content_nodes(self, nodes: list[dict]) -> int:
        for n in nodes:
            self.content_nodes[n["node_id"]] = dict(n)
        return len(nodes)

    def insert_entity_refs(self, refs: list[dict]) -> int:
        n = 0
        for r in refs:
            key = (r.get("source_host"), r["object"], r["guid"], r["node_id"], r.get("identity_key"))
            if key in self._entity_ref_seen:
                continue
            self._entity_ref_seen.add(key)
            self.entity_refs.append(r)
            n += 1
        return n

    def counts(self) -> dict:
        return {"relationships": len(self.relationships),
                "derived": sum(1 for r in self.relationships if r.get("class") == DERIVED),
                "inferred_nodes": len(self.inferred_nodes),
                "content_nodes": len(self.content_nodes),
                "entity_refs": len(self.entity_refs)}

    def _export(self, out_dir: str, filename: str, rows) -> int:
        os.makedirs(out_dir, exist_ok=True)
        n = 0
        with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, default=str) + "\n")
                n += 1
        return n

    def export_jsonl(self, out_dir: str) -> int:
        """The granular relationship timeline as `car_relationships.jsonl`
        (the downstream-ingest/timeline contract) — ALWAYS written, even
        empty: pipeline.run_batch's idempotency skip re-keys on this file's
        existence, so a source with zero edges still marks itself built."""
        ordered = sorted(self.relationships, key=lambda r: r.get("timestamp") or "")
        return self._export(out_dir, "car_relationships.jsonl", ordered)

    def export_inferred_jsonl(self, out_dir: str) -> int:
        """The reconstructed-but-unobserved nodes as JSONL — car_inferred.jsonl,
        destined for its own stream (logs-car.inferred-*), never a car_<object>."""
        ordered = sorted(self.inferred_nodes.values(), key=lambda n: n.get("first_seen") or "")
        return self._export(out_dir, "car_inferred.jsonl", ordered)

    def close(self) -> None:
        """No-op — an in-memory store holds no file handle. Kept so a caller
        that still treats the store as a closable resource works unchanged."""


def build_from_events(out_dir: str, events: list[dict]) -> SupersetStore:
    """A fresh in-memory SupersetStore for one source: the DECLARED cascade
    edges materialised from `events`'s enrich links, exported as
    `car_relationships.jsonl` under `out_dir` — unconditionally, even when
    empty (see `SupersetStore.export_jsonl`). Returns the open store so
    derive.derive() can layer the DERIVED pass onto the SAME edges before a
    second export."""
    st = SupersetStore()
    st.insert_edges(edges_from_events(events))
    st.export_jsonl(out_dir)
    return st

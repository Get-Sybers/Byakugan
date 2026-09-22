"""The superset relationship timeline (epic #12).

byakugan.store.CarStore holds the object events in memory; byakugan.superset's
SupersetStore holds the relationship INSTANCES the cascade produces between
those events — each a timestamped edge linking the object events by guid (the
granular relationship timeline), exported as car_relationships.jsonl.
"""
import json
import os

from byakugan import superset


def _proc(guid, host="H", ts="2020-01-01T00:00:00Z", **kw):
    return dict({"car_object": "process", "car_action": "create", "guid": guid,
                 "source_host": host, "timestamp": ts}, **kw)


def test_edges_from_cascade_links():
    events = [
        _proc("P1"),
        # spoke owned by P1 (definitive) -> process --loaded--> module
        {"car_object": "module", "car_action": "load", "guid": "M1", "source_host": "H",
         "timestamp": "2020-01-01T00:00:01Z", "owning_guid": "P1",
         "link_confidence": "definitive"},
        # child process with parent -> process --created--> process
        _proc("P2", parent_guid="P1", link_confidence="heuristic"),
        # file executed as a process (image_path) -> process --executed--> file
        {"car_object": "file", "car_action": "create", "guid": "F1", "source_host": "H",
         "timestamp": "2020-01-01T00:00:02Z",
         "_native": {"executed_as_process_guid": "P1", "executed_as_process_link": "heuristic"}},
        # auth -> logon session by LUID
        {"car_object": "authentication", "car_action": "success", "guid": "A1",
         "source_host": "H", "timestamp": "2020-01-01T00:00:03Z",
         "_native": {"target_session_guid": "S1", "target_session_link": "definitive"}},
    ]
    edges = superset.edges_from_events(events)
    triples = {(e["source_object"], e["relationship"], e["target_object"],
                e["source_guid"], e["target_guid"]) for e in edges}
    assert ("process", "loaded", "module", "P1", "M1") in triples
    assert ("process", "created", "process", "P1", "P2") in triples
    assert ("process", "executed", "file", "P1", "F1") in triples
    assert ("authentication", "created", "user_session", "A1", "S1") in triples
    # no edge falls back to a raw action name
    assert all(e["relationship"] not in ("login", "success") for e in edges)
    # no self-loops
    assert all(e["source_guid"] != e["target_guid"] for e in edges)


def test_no_process_owner_self_loops():
    from byakugan import superset
    # a process event's owning_guid is itself -> must NOT emit a self-loop edge
    edges = superset.edges_from_events([
        {"car_object": "process", "car_action": "create", "guid": "P1",
         "source_host": "H", "timestamp": "t", "owning_guid": "P1"},
        {"car_object": "process", "car_action": "terminate", "guid": "P1",
         "source_host": "H", "timestamp": "t", "owning_guid": "P1"},
    ])
    assert edges == []


def test_file_handle_edge_carries_association_properties():
    from byakugan import superset
    # a File handle: process --accessed--> the FILE_OBJECT, the edge carrying the
    # handle's own facts (access mask, handle value) — association properties, not
    # object properties.
    edges = superset.edges_from_events([
        {"car_object": "file", "car_action": "access", "guid": "file-f11e",
         "source_host": "H", "timestamp": "t", "owning_guid": "proc-a",
         "link_confidence": "definitive",
         "_native": {"GrantedAccess": 0x120089, "HandleValue": 4}}])
    assert len(edges) == 1
    e = edges[0]
    assert (e["source_guid"], e["relationship"], e["target_guid"]) == ("proc-a", "accessed", "file-f11e")
    assert e["properties"] == {"access_level": 0x120089, "handle_value": 4}
    # an edge with no association evidence carries no properties
    plain = superset.edges_from_events([
        {"car_object": "file", "car_action": "access", "guid": "file-1",
         "source_host": "H", "timestamp": "t", "owning_guid": "proc-b"}])
    assert plain[0]["properties"] is None


def test_process_access_edges_source_to_target():
    from byakugan import superset
    # Sysmon 10: source --accessed--> TARGET (target_guid), not the record guid
    edges = superset.edges_from_events([
        {"car_object": "process", "car_action": "access", "guid": "REC1",
         "source_host": "H", "timestamp": "t", "owning_guid": "SRC",
         "target_guid": "TGT", "link_confidence": "definitive"}])
    assert len(edges) == 1
    e = edges[0]
    assert (e["source_guid"], e["relationship"], e["target_guid"]) == ("SRC", "accessed", "TGT")


# (object, action) pairs deliberately left to the default verb. EMPTY since
# the owner ratified D1/D2 (docs/research/relationship-model-gaps.md §9-§10):
# email's verbs ground in CAR's own action definitions; pause/close/suspend
# resolved under the vectors/transactions/associations reading. The mechanism
# stays: a pair pinned here is the ONLY legal default — anything else is drift.
_UNDECLARED_BY_DECISION: set[tuple[str, str]] = set()


def test_all_emittable_verbs_are_attack_vocabulary():
    """Every relationship verb the cascade can emit must be a real ATT&CK verb
    (in the seeded catalogue) — the 'typed edge' contract, self-enforcing.
    Sweeps EVERY superset (object, action) pair as a spoke, plus every special
    edge branch, so a new declaration is covered the moment it lands."""
    from byakugan import build_data_model, carmodel, superset
    _, rels = build_data_model.build_superset()
    vocab = {r["relationship"] for r in rels}
    events, i = [], 0
    for obj, spec in carmodel.load().items():
        if obj == "process":
            continue
        for act in spec["actions"]:
            i += 1
            events.append({"car_object": obj, "car_action": act, "guid": f"S{i}",
                           "owning_guid": "P", "source_host": "H", "timestamp": "t"})
    # the special edge branches
    events += [
        {"car_object": "thread", "car_action": "remote_create", "guid": "TH", "owning_guid": "P",
         "source_host": "H", "timestamp": "t", "_native": {"target_process_guid": "PT"}},
        {"car_object": "authentication", "car_action": "success", "guid": "A", "owning_guid": "P",
         "source_host": "H", "timestamp": "t", "_native": {"target_session_guid": "S"}},
        {"car_object": "process", "car_action": "create", "guid": "C", "parent_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "process", "car_action": "access", "guid": "REC", "owning_guid": "P",
         "target_guid": "PT2", "source_host": "H", "timestamp": "t"},
        {"car_object": "process", "car_action": "modify", "guid": "PM", "source_host": "H",
         "timestamp": "t", "_native": {"modifier_process_guid": "P"}},
        {"car_object": "file", "car_action": "create", "guid": "FX", "source_host": "H",
         "timestamp": "t", "_native": {"executed_as_process_guid": "P"}},
        {"car_object": "http", "car_action": "get", "guid": "HT", "source_host": "H",
         "timestamp": "t", "_native": {"flow_guid": "FL", "flow_link": "definitive"}},
    ]
    emitted = {e["relationship"] for e in superset.edges_from_events(events)}
    assert emitted, "no edges emitted"
    assert emitted <= vocab, f"verbs not in ATT&CK vocabulary: {emitted - vocab}"


def test_every_superset_pair_is_declared_or_decision_flagged():
    """The spoke_owner table is COMPLETE: every superset (object, action) pair
    of the 13 CAR objects carries an explicit verb, except the pinned
    decision-flagged pairs (register §9 D1/D2) — the default verb is reserved
    for those and for drift, never a silent home for a legal pair."""
    from byakugan import carmodel, superset
    spoke = superset.rules()["spoke_owner"]
    undeclared = set()
    for obj, spec in carmodel.load().items():
        if obj == "process":        # the hub: its actions are the edges: section
            continue
        for act in spec["actions"]:
            if act not in (spoke.get(obj) or {}):
                undeclared.add((obj, act))
    assert undeclared == _UNDECLARED_BY_DECISION, (
        f"pairs missing a declared verb (declare, or pin as a decision): "
        f"{undeclared - _UNDECLARED_BY_DECISION}; "
        f"decision-pins now declared (unpin): {_UNDECLARED_BY_DECISION - undeclared}")


def test_flow_containment_edge_from_r3_link():
    from byakugan import superset
    # R3 resolved a zeek http/file spoke to its connection (native.flow_guid);
    # the flow CONTAINS the transaction/file-in-transit — materialised edge.
    edges = superset.edges_from_events([
        {"car_object": "http", "car_action": "get", "guid": "http-U-1", "source_host": "H",
         "timestamp": "t", "_native": {"flow_guid": "U", "flow_link": "definitive"}},
        {"car_object": "file", "car_action": "create", "guid": "FdE", "source_host": "H",
         "timestamp": "t", "_native": {"flow_guid": "U", "flow_link": "definitive"}}])
    triples = {(e["source_object"], e["relationship"], e["target_object"],
                e["source_guid"], e["target_guid"], e["confidence"], e["method"])
               for e in edges}
    assert ("flow", "contained", "http", "U", "http-U-1", "definitive", "capture_uid") in triples
    assert ("flow", "contained", "file", "U", "FdE", "definitive", "capture_uid") in triples
    # a flow row never contains itself
    assert not superset.edges_from_events([
        {"car_object": "flow", "car_action": "start", "guid": "U", "source_host": "H",
         "timestamp": "t", "_native": {"flow_guid": "U"}}])


def test_process_modify_edge_from_modifier_contract():
    from byakugan import superset
    # a process/modify row naming its modifier (native.modifier_process_guid)
    # yields modifier --modified--> the tampered process
    edges = superset.edges_from_events([
        {"car_object": "process", "car_action": "modify", "guid": "TGT", "source_host": "H",
         "timestamp": "t",
         "_native": {"modifier_process_guid": "SRC", "modifier_process_link": "definitive"}}])
    assert [(e["source_guid"], e["relationship"], e["target_guid"], e["confidence"])
            for e in edges] == [("SRC", "modified", "TGT", "definitive")]
    # without the native contract key, no edge (the modifier is unknown)
    assert not superset.edges_from_events([
        {"car_object": "process", "car_action": "modify", "guid": "TGT", "source_host": "H",
         "timestamp": "t"}])


def test_association_properties_ride_their_edges():
    from byakugan import superset
    # process ACCESS: the granted mask / call trace are facts of the access
    # itself (CAR field wording: "at which the TARGET process is accessed")
    acc = superset.edges_from_events([
        {"car_object": "process", "car_action": "access", "guid": "REC", "source_host": "H",
         "timestamp": "t", "owning_guid": "SRC", "target_guid": "TGT",
         "access_level": "0x1010", "call_trace": "C:\\W\\a.dll+123"}])
    assert acc[0]["properties"] == {"access_level": "0x1010", "call_trace": "C:\\W\\a.dll+123"}
    # thread INJECTION: where execution begins in the target + the new thread id
    inj = superset.edges_from_events([
        {"car_object": "thread", "car_action": "remote_create", "guid": "TH", "source_host": "H",
         "timestamp": "t", "owning_guid": "SRC", "start_address": "0xFFAA",
         "start_module": "C:\\W\\evil.dll", "start_function": "LoadLibraryA", "tgt_tid": 4242,
         "_native": {"target_process_guid": "TGT"}}])
    by_verb = {e["relationship"]: e for e in inj}
    assert by_verb["accessed"]["properties"] == {
        "start_address": "0xFFAA", "start_function": "LoadLibraryA",
        "start_module": "C:\\W\\evil.dll", "new_thread_id": 4242}
    # the spoke edge for the same thread row carries nothing (no thread/… entry)
    assert by_verb["created"]["properties"] is None
    # module LOAD: the base address is where the image sits in the LOADER
    mod = superset.edges_from_events([
        {"car_object": "module", "car_action": "load", "guid": "M", "source_host": "H",
         "timestamp": "t", "owning_guid": "P", "base_address": "0x7ff0", "tid": 8}])
    assert mod[0]["properties"] == {"base_address": "0x7ff0", "tid": 8}
    # registry VALUE_EDIT: what THIS edit wrote
    reg = superset.edges_from_events([
        {"car_object": "registry", "car_action": "value_edit", "guid": "R", "source_host": "H",
         "timestamp": "t", "owning_guid": "P", "new_content": "evil.exe"}])
    assert reg[0]["properties"] == {"new_content": "evil.exe"}
    # file TIMESTOMP: the pre-tamper creation time (the change is the fact)
    ts = superset.edges_from_events([
        {"car_object": "file", "car_action": "timestomp", "guid": "F", "source_host": "H",
         "timestamp": "t", "owning_guid": "P", "previous_creation_time": "2019-01-01T00:00:00Z"}])
    assert ts[0]["properties"] == {"previous_creation_time": "2019-01-01T00:00:00Z"}


def test_superset_builds_in_memory_and_exports_the_relationship_timeline(tmp_path):
    events = [_proc("P1"),
              {"car_object": "file", "car_action": "create", "guid": "F1",
               "source_host": "H", "timestamp": "2020-01-01T00:00:01Z",
               "owning_guid": "P1", "link_confidence": "definitive"}]
    sup_store = superset.build_from_events(str(tmp_path), events)
    assert sup_store.counts()["relationships"] >= 1
    assert os.path.exists(os.path.join(tmp_path, "car_relationships.jsonl"))
    assert not os.path.exists(os.path.join(tmp_path, "superset.db"))  # no SQLite, ever

    # the process--created-->file relationship instance is stored, linking guids
    row = sup_store.relationships[0]
    assert (row["relationship"], row["source_guid"], row["target_guid"], row["confidence"]) == (
        "created", "P1", "F1", "definitive")
    # and the export round-trips the exact same row (superset.REL_COLUMNS order)
    with open(os.path.join(tmp_path, "car_relationships.jsonl"), encoding="utf-8") as fh:
        exported = json.loads(fh.readline())
    assert list(exported) == list(superset.REL_COLUMNS)
    assert (exported["relationship"], exported["source_guid"], exported["target_guid"],
           exported["confidence"]) == ("created", "P1", "F1", "definitive")

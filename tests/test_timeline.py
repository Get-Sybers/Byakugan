"""The unified CAR timeline: objects (car_<object>.jsonl) + relationship
edges (car_relationships.jsonl) merged into one property-rich, time-ordered
stream (epic #12)."""
import json
import os

import pytest

from byakugan import store, superset, timeline


def _events():
    return [
        {"car_object": "process", "car_action": "create", "guid": "P1",
         "source_host": "H", "timestamp": "2020-01-01T00:00:00Z",
         "exe": r"C:\a.exe", "command_line": "a -x", "_native": {"EventId": 1}},
        {"car_object": "module", "car_action": "load", "guid": "M1",
         "source_host": "H", "timestamp": "2020-01-01T00:00:01Z",
         "owning_guid": "P1", "link_confidence": "definitive",
         "image_path": r"C:\a.exe"},
    ]


def _make(tmp: str):
    st = store.CarStore()
    st.insert_events(_events())
    st.export_jsonl(tmp)
    superset.build_from_events(tmp, _events())


def test_timeline_never_treats_relationships_or_inferred_as_object_streams(tmp_path):
    # car_relationships.jsonl and car_inferred.jsonl sit right beside the
    # object streams and match the SAME car_*.jsonl glob discovery walks —
    # the old car.db equivalent (a producer's own auxiliary table, e.g.
    # Anamnesis's image_context, skipped by its missing timestamp header) is
    # replaced by excluding them BY NAME in _object_entries, never by
    # accident; a stray non-CAR row in car_inferred.jsonl (no full object
    # header at all) must not surface as an "inferred" object either.
    d = str(tmp_path)
    _make(d)
    with open(os.path.join(d, "car_inferred.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"node_id": "X", "object": "process",
                             "first_seen": "2020-01-01T00:00:02Z"}) + "\n")
    rows = timeline.build_timeline(d)                 # must not raise
    objs = {r["object"] for r in rows if r["kind"] == "object"}
    assert "inferred" not in objs and "relationships" not in objs
    assert objs == {"process", "module"}              # the real CAR objects survive


def test_timeline_merges_objects_and_edges_ordered(tmp_path):
    _make(str(tmp_path))
    rows = timeline.build_timeline(str(tmp_path))
    kinds = {r["kind"] for r in rows}
    assert kinds == {"object", "relationship"}
    assert [r["timestamp"] for r in rows] == sorted(r["timestamp"] for r in rows)
    # property-rich: the process entry carries its full CAR props + native
    proc = next(r for r in rows if r["kind"] == "object" and r["object"] == "process")
    assert proc["exe"] == r"C:\a.exe" and proc["command_line"] == "a -x"
    assert proc.get("native", {}).get("EventId") == 1
    # the edge carries the ATT&CK verb + confidence + endpoints
    edge = next(r for r in rows if r["kind"] == "relationship")
    assert edge["relationship"] == "loaded" and edge["confidence"] == "definitive"
    assert (edge["source_object"], edge["target_object"]) == ("process", "module")


def test_timeline_filters_and_writes(tmp_path):
    _make(str(tmp_path))
    assert timeline.build_timeline(str(tmp_path), host="NOPE") == []
    assert all(r["kind"] == "object"
               for r in timeline.build_timeline(str(tmp_path), objects_only=True))
    out = os.path.join(tmp_path, "timeline.jsonl")
    n = timeline.write_jsonl(timeline.build_timeline(str(tmp_path)), out)
    assert n > 0 and len([json.loads(x) for x in open(out)]) == n


def test_timeline_edges_only(tmp_path):
    _make(str(tmp_path))
    rows = timeline.build_timeline(str(tmp_path), edges_only=True)
    assert rows and all(r["kind"] == "relationship" for r in rows)


def test_timeline_excludes_timestamp_less_records(tmp_path):
    # a record with no observation time (a PE's compile stamp is not an event)
    # is still materialised into car_file.jsonl — and stays OFF the timeline
    # rather than mis-placed
    events = _events() + [
        {"car_object": "file", "car_action": "create", "guid": None,
         "source_host": "H", "timestamp": None, "file_path": r"C:\a.exe",
         "_native": {"compile_time": "2019-06-01T00:00:00Z"}}]
    st = store.CarStore()
    st.insert_events(events)
    st.export_jsonl(str(tmp_path))
    superset.build_from_events(str(tmp_path), events)
    rows = timeline.build_timeline(str(tmp_path))
    assert rows and all(r["timestamp"] for r in rows)
    assert not any(r.get("object") == "file" for r in rows)
    file_rows = list(store.read_object_jsonl(str(tmp_path), "file"))
    assert sum(1 for r in file_rows if r["timestamp"] is None) == 1


def test_timeline_after_before_by_instant(tmp_path):
    # fixture: process object @00:00:00, module object + `loaded` edge @00:00:01.
    _make(str(tmp_path))
    mid = "2020-01-01T00:00:00.500Z"          # a Z-suffixed, fractional bound
    after = timeline.build_timeline(str(tmp_path), after=mid)
    assert {(r["kind"], r.get("object", r.get("relationship")))
            for r in after} == {("object", "module"), ("relationship", "loaded")}
    before = timeline.build_timeline(str(tmp_path), before=mid)
    assert [r["kind"] for r in before] == ["object"]
    assert before[0]["object"] == "process"


def test_timeline_bad_bound_is_rejected(tmp_path):
    _make(str(tmp_path))
    with pytest.raises(SystemExit):
        timeline.build_timeline(str(tmp_path), after="not-a-timestamp")


def test_parse_ts_orders_mixed_iso_formats():
    # lexicographic string order would put ".500Z" before the bare second and
    # sort by wall-clock across offsets; the true instant must win.
    p = timeline._parse_ts
    assert p("2020-01-01T00:00:00Z") == p("2020-01-01T00:00:00+00:00")
    assert p("2020-01-01T00:00:00.500Z") > p("2020-01-01T00:00:00Z")
    # 04:00-02:00 == 06:00Z is later than 05:00Z despite sorting earlier as text
    assert p("2020-01-01T04:00:00-02:00") > p("2020-01-01T05:00:00+00:00")
    assert p("garbage") is None and p(None) is None


def test_sort_orders_by_instant_not_string(tmp_path):
    events = [
        {"car_object": "process", "car_action": "create", "guid": "B",
         "source_host": "H", "timestamp": "2020-01-01T00:00:00.500Z"},
        {"car_object": "process", "car_action": "create", "guid": "A",
         "source_host": "H", "timestamp": "2020-01-01T00:00:00Z"},
    ]
    st = store.CarStore()
    st.insert_events(events)
    st.export_jsonl(str(tmp_path))
    rows = timeline.build_timeline(str(tmp_path), objects_only=True)
    assert [r["guid"] for r in rows] == ["A", "B"]   # 00.000 before 00.500

"""The behaviour layer projected into STIX 2.1 (stix.py + analytics.py):
Sightings of ATT&CK Attack-Patterns over the CAR rows, keyed by spindle guids.

A runnable CAR analytic becomes an `indicator` (pattern_type "car"), each
technique / subtechnique it covers an `attack-pattern` (content-keyed, GLOBAL),
the two joined by `indicates` SROs; every matched row becomes a `sighting`
(case-scoped) of the indicator over that row's observed-data. Identity and
behaviour share the one STIX-minted id space: the catalogue is global content
(like the SCOs), the timeline is case-scoped evidence (like the observed-data).
"""
import json
import pathlib
import uuid

from byakugan import derive, enrich, store, stix, superset

_H = "HOSTA"
_T0 = "2020-01-01T00:00:00Z"


def _proc(guid, ts=_T0, **kw):
    return dict({"car_object": "process", "car_action": "create", "guid": guid,
                 "source_host": _H, "timestamp": ts, "source_artefact": "evtx_sysmon"}, **kw)


def _build(d, events):
    """The finished stores the pipeline leaves behind: car.db + superset.db."""
    d.mkdir(parents=True, exist_ok=True)
    events = enrich.enrich(events)
    st = store.CarStore(str(d / "car.db"))
    st.insert_events(events)
    st.close()
    sup = superset.build_superset_db(str(d), events)
    derive.derive(events, sup["superset_db"], str(d))
    return d


def _bundle(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _of(b, t):
    return [o for o in b["objects"] if o["type"] == t]


# --------------------------------------------------------------------------- #
# a matched row -> indicator + attack-pattern + indicates + a sighting over the
# row's observed-data
# --------------------------------------------------------------------------- #
def test_behaviour_hit_projects_indicator_attack_pattern_and_sighting(tmp_path):
    # a bare cmd.exe process create fires exactly CAR-2013-02-003 (exe == "cmd.exe"),
    # which covers T1059 (subtechnique T1059.003, tactic Execution)
    events = [_proc("P1", exe="cmd.exe", image_path=r"C:\Windows\System32\cmd.exe", pid=100)]
    b = _bundle(stix.export(str(_build(tmp_path, events)), case="c")["bundle"])

    # the detection is an indicator, pattern_type "car", the CAR analytic the pattern
    (ind,) = _of(b, "indicator")
    assert ind["pattern_type"] == "car" and ind["name"] == "Processes Spawning cmd.exe"
    assert ind["x_car_analytic"] == "CAR-2013-02-003"
    ext = ind["external_references"][0]
    assert ext == {"source_name": "mitre-car", "external_id": "CAR-2013-02-003",
                   "url": "https://car.mitre.org/analytics/CAR-2013-02-003"}
    # its id is the §2.9 content id keyed by the CAR reference (GLOBAL)
    assert ind["id"] == "indicator--" + str(uuid.uuid5(
        stix.STIX_NS, stix.canonical_json(
            {"external_references": [{"source_name": "mitre-car", "external_id": "CAR-2013-02-003"}]})))

    # the technique's attack-pattern is present (GLOBAL, content-keyed by the ATT&CK id)
    aps = {a["name"]: a for a in _of(b, "attack-pattern")}
    assert {"T1059", "T1059.003"} <= set(aps)
    t1059 = aps["T1059"]
    assert t1059["external_references"][0] == {"source_name": "mitre-attack", "external_id": "T1059",
                                               "url": "https://attack.mitre.org/techniques/T1059"}
    assert {"kill_chain_name": "mitre-attack", "phase_name": "execution"} in t1059["kill_chain_phases"]
    # a subtechnique keeps the T1059/003 url path and inherits the entry's tactic
    assert aps["T1059.003"]["external_references"][0]["url"] == \
        "https://attack.mitre.org/techniques/T1059/003"
    assert t1059["id"] == "attack-pattern--" + str(uuid.uuid5(
        stix.STIX_NS, stix.canonical_json(
            {"external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}]})))

    # indicator --indicates--> attack-pattern, one per covered technique
    indicates = [r for r in _of(b, "relationship") if r["relationship_type"] == "indicates"]
    assert {r["target_ref"] for r in indicates} == {aps["T1059"]["id"], aps["T1059.003"]["id"]}
    assert all(r["source_ref"] == ind["id"] for r in indicates)

    # the sighting: of the indicator, over THIS row's observed-data, where sighted the host
    (obs,) = _of(b, "observed-data")
    (sight,) = _of(b, "sighting")
    assert sight["sighting_of_ref"] == ind["id"] and sight["count"] == 1
    assert sight["observed_data_refs"] == [obs["id"]]
    assert sight["first_seen"] == sight["last_seen"] == "2020-01-01T00:00:00.000Z"
    assert sight["x_car_analytic"] == "CAR-2013-02-003" and sight["x_car_event_id"] == "P1"
    assert set(sight["x_car_techniques"]) == {"T1059", "T1059.003"}
    # where_sighted_refs -> a host identity SDO (not the producer)
    (host_id,) = [o for o in _of(b, "identity") if o["id"] != stix.PRODUCER["id"]]
    assert host_id["name"] == _H and host_id["identity_class"] == "system"
    assert sight["where_sighted_refs"] == [host_id["id"]]

    # every embedded reference resolves inside the bundle
    known = {o["id"] for o in b["objects"]}
    for o in b["objects"]:
        for k, v in o.items():
            refs = v if k.endswith("_refs") else [v] if k.endswith("_ref") else []
            assert all(x in known for x in refs), (o["type"], k, v)


# --------------------------------------------------------------------------- #
# the catalogue is GLOBAL (same in every case); the sightings are CASE-SCOPED
# --------------------------------------------------------------------------- #
def test_catalogue_is_global_and_sightings_are_case_scoped(tmp_path):
    events = [_proc("P1", exe="cmd.exe", pid=100)]
    a = _build(tmp_path / "a", events)
    b1 = _bundle(stix.export(str(a), case="case-one")["bundle"])
    b2 = _bundle(stix.export(str(_build(tmp_path / "b", events)), case="case-two")["bundle"])

    # the indicator and the attack-patterns are the SAME objects in both cases
    assert {o["id"] for o in _of(b1, "indicator")} == {o["id"] for o in _of(b2, "indicator")}
    assert {o["id"] for o in _of(b1, "attack-pattern")} == {o["id"] for o in _of(b2, "attack-pattern")}
    ind_rel1 = {r["id"] for r in _of(b1, "relationship") if r["relationship_type"] == "indicates"}
    ind_rel2 = {r["id"] for r in _of(b2, "relationship") if r["relationship_type"] == "indicates"}
    assert ind_rel1 == ind_rel2 and ind_rel1
    # the sighting is case-scoped: same analytic + guid, a DIFFERENT id per case
    (s1,), (s2,) = _of(b1, "sighting"), _of(b2, "sighting")
    assert s1["x_car_analytic"] == s2["x_car_analytic"] == "CAR-2013-02-003"
    assert s1["x_car_event_id"] == s2["x_car_event_id"] == "P1"
    assert s1["id"] != s2["id"]
    assert s1["sighting_of_ref"] == s2["sighting_of_ref"]      # same (global) indicator


# --------------------------------------------------------------------------- #
# re-export of the same case is byte-identical (determinism)
# --------------------------------------------------------------------------- #
def test_behaviour_re_export_is_byte_identical(tmp_path):
    events = [_proc("P1", exe="cmd.exe", pid=100),
              _proc("P2", ts="2020-01-01T00:00:05Z", exe="wsmprovhost.exe", parent_exe="svchost.exe")]
    d = _build(tmp_path, events)
    first = stix.export(str(d), case="c")
    again = tmp_path / "again.json"
    stix.export(str(d), out_path=str(again), case="c")
    assert again.read_bytes() == pathlib.Path(first["bundle"]).read_bytes()
    # two analytics fired -> two indicators, two sightings, both classes reachable
    b = _bundle(first["bundle"])
    assert {i["x_car_analytic"] for i in _of(b, "indicator")} == {"CAR-2013-02-003", "CAR-2014-11-004"}
    assert {s["x_car_event_id"] for s in _of(b, "sighting")} == {"P1", "P2"}


# --------------------------------------------------------------------------- #
# a sighting still stands when the row produced no observed-data (no ts), the
# observed_data_refs simply omitted
# --------------------------------------------------------------------------- #
def test_sighting_without_observed_data_when_row_has_no_time(tmp_path):
    # a timestamp that does not parse -> the row gets its SCOs but NO observed-data;
    # the analytic still fires and the sighting still stands, without observed_data_refs
    events = [_proc("P1", ts="not-a-timestamp", exe="cmd.exe", pid=100)]
    b = _bundle(stix.export(str(_build(tmp_path, events)), case="c")["bundle"])
    assert _of(b, "observed-data") == []
    (sight,) = _of(b, "sighting")
    assert sight["x_car_analytic"] == "CAR-2013-02-003"
    assert "observed_data_refs" not in sight            # no observed-data to point at
    assert "first_seen" not in sight                    # an unparseable time is never invented
    # the indicator it sights still resolves
    assert sight["sighting_of_ref"] in {o["id"] for o in _of(b, "indicator")}


# --------------------------------------------------------------------------- #
# evidence-driven: a row matching nothing yields no behaviour objects at all
# --------------------------------------------------------------------------- #
def test_no_behaviour_objects_without_a_hit(tmp_path):
    events = [_proc("P1", exe="benign-unmatched.exe", image_path=r"C:\Users\a\benign-unmatched.exe")]
    b = _bundle(stix.export(str(_build(tmp_path, events)), case="c")["bundle"])
    assert _of(b, "sighting") == [] and _of(b, "indicator") == [] and _of(b, "attack-pattern") == []
    assert [r for r in _of(b, "relationship") if r["relationship_type"] == "indicates"] == []
    # the ordinary SCO / observation projection is unchanged
    assert len(_of(b, "process")) == 1 and len(_of(b, "observed-data")) == 1


# --------------------------------------------------------------------------- #
# the catalogue helper: one attack-pattern per ATT&CK id, one indicator per
# runnable analytic, tactics unioned so kill_chain_phases are case-independent
# --------------------------------------------------------------------------- #
def test_behaviour_catalogue_over_the_pinned_corpus():
    from byakugan import analytics as A
    ans = A.load_analytics()
    cat = stix.behaviour_catalogue(ans)
    runnable = [a for a in ans if a.runnable]
    assert len(cat["indicators"]) == len(runnable)               # one per runnable analytic
    assert "T1059" in cat["attack_patterns"] and "T1059.003" in cat["attack_patterns"]
    # every id an indicator covers has an attack-pattern to indicate
    for anid, techs in cat["covers"].items():
        assert techs and all(t in cat["attack_patterns"] for t in techs)
    # the phases are ATT&CK shortnames, stable and de-duplicated
    t1059 = cat["attack_patterns"]["T1059"]
    phases = [p["phase_name"] for p in t1059["kill_chain_phases"]]
    assert "execution" in phases and len(phases) == len(set(phases))

"""Cross-source convergence (crosssource.py) — the same entity seen across
sources folds into one property view, tagged with which artefact supplied each
field and the confidence it was joined at. The per-source stores are untouched.

This is the 'grab different properties from different artefacts' payoff: a log
gives the command line + hash, memory the pid + recovered command line, a disk
execution artefact the run — converged into more than any one source held.
"""
import os

from piiat_mitrecar import crosssource, store


def _store(case_dir, source, events):
    d = os.path.join(case_dir, source)
    os.makedirs(d, exist_ok=True)
    st = store.CarStore(os.path.join(d, "car.db"))
    st.insert_events(events)
    st.close()


def _proc(guid, host="WIN10", **kw):
    return dict({"car_object": "process", "car_action": "create", "guid": guid,
                 "source_host": host, "timestamp": "2026-01-01T00:00:00Z"}, **kw)


def _one(conv, obj="process"):
    got = [c for c in conv if c["car_object"] == obj]
    assert got, f"expected a {obj} convergence, got {conv}"
    return got[0]


# --------------------------------------------------------------------------- #
# heuristic_image: one binary, three artefacts, one merged view
# --------------------------------------------------------------------------- #
def test_heuristic_image_merges_properties_with_provenance(tmp_path):
    d = str(tmp_path)
    # a log: full-path image, the command line, the binary hash, the user
    _store(d, "evtx", [_proc("log-1", image_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                             exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                             command_line="powershell -enc SQBFAFgA", sha256_hash="ABC123",
                             user="WIN10\\jdh")])
    # memory: basename exe, recovered command line, a live pid (the log lacks it here)
    _store(d, "memory", [_proc("mem-1", exe="powershell.exe",
                               command_line="powershell -enc SQBFAFgA", pid=4242)])
    # a disk execution artefact (prefetch): just proves it RAN
    _store(d, "disk", [_proc("pf-1", exe="POWERSHELL.EXE")])

    c = _one(crosssource.converge(d))
    assert c["tier"] == "heuristic_image"                     # a lead, honestly labelled
    assert set(c["sources"]) == {"evtx", "memory", "disk"}
    # the binary basename joined a full path, a basename and an upper-case name
    assert c["join_key"][-1] == "powershell.exe"
    # each property records the artefact(s) that supplied it — the whole point
    assert c["property_sources"]["sha256_hash"] == ["evtx"]   # only the log had the hash
    assert c["property_sources"]["pid"] == ["memory"]         # only memory had the live pid
    assert set(c["property_sources"]["command_line"]) == {"evtx", "memory"}  # both agreed
    # the merged view holds more than any single source did
    for f in ("sha256_hash", "pid", "command_line", "user"):
        assert f in c["properties"]


# --------------------------------------------------------------------------- #
# definitive_content: same bytes across sources outranks a mere image lead
# --------------------------------------------------------------------------- #
def test_content_hash_convergence_is_host_independent(tmp_path):
    d = str(tmp_path)
    # the SAME file (by hash) on two different hosts — content identity is definitive
    _store(d, "amcache", [dict({"car_object": "file", "car_action": "create", "guid": "am-1",
                                "source_host": "HOSTA", "timestamp": "2026-01-01T00:00:00Z",
                                "file_path": r"C:\evil.exe", "sha256_hash": "DEADBEEF"})])
    _store(d, "memory-b", [dict({"car_object": "file", "car_action": "create", "guid": "mem-2",
                                 "source_host": "HOSTB", "timestamp": "2026-01-01T00:00:00Z",
                                 "file_name": "evil.exe", "sha256_hash": "DEADBEEF"})])
    c = _one(crosssource.converge(d), obj="file")
    assert c["tier"] == "definitive_content"
    assert set(c["sources"]) == {"amcache", "memory-b"}
    # both a path (amcache) and a name (memory) survive in the merged view
    assert "file_path" in c["properties"] and "file_name" in c["properties"]


# --------------------------------------------------------------------------- #
# a single-source group is NOT a convergence; no cross-source noise
# --------------------------------------------------------------------------- #
def test_single_source_is_not_a_convergence(tmp_path):
    d = str(tmp_path)
    _store(d, "only", [_proc("a", exe="cmd.exe"), _proc("b", exe="cmd.exe")])
    assert crosssource.converge(d) == []


# --------------------------------------------------------------------------- #
# different hosts never image-converge (instance identity is host-scoped)
# --------------------------------------------------------------------------- #
def test_image_lead_never_crosses_hosts(tmp_path):
    d = str(tmp_path)
    _store(d, "s1", [_proc("x", host="HOSTA", exe="cmd.exe")])
    _store(d, "s2", [_proc("y", host="HOSTB", exe="cmd.exe")])
    # no shared hash, different hosts -> no image convergence
    assert [c for c in crosssource.converge(d) if c["tier"] == "heuristic_image"] == []

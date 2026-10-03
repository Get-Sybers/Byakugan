"""`byakugan timeline --elastic`: the SAME timeline.jsonl, byte-for-byte,
whether it is built from car.db/superset.db or from the logs-car.* data
streams `byakugan load` populated (epic #99 phase 5) — the correctness
anchor for byakugan/elastic/inverse_projection.py + timeline.py's Elastic
source.

A: the LOCAL timeline (build_timeline + write_jsonl) over a synthetic
   materialised tree.
B: `byakugan.elastic.load` bundle mode over the SAME tree, served from a
   stdlib http.server ES stub (point-in-time + search_after, 2+ pages),
   fetched with `timeline.build_timeline_from_elastic` + write_jsonl.

A == B, byte-for-byte — ordering, filtering and JSON rendering all come from
the exact same shared code (timeline._filter_and_sort / _sort_key /
write_jsonl) regardless of which tier answered the query.
"""
from __future__ import annotations

import fnmatch
import http.server
import json
import os
import threading

import pytest

from byakugan import derive, store, superset, timeline
from byakugan.elastic import load

NAMESPACE = "default"


# --------------------------------------------------------------------------- #
# A real materialised tree: CarStore + SupersetStore over 2 synthetic sources
# (mirrors tests/test_load.py's own _build_tree). Every value is deliberately
# given in a form that round-trips byte-exactly through ECS coercion/
# normalisation (native Python types for typed fields, canonical-form
# strings for the rules.verbatim normalisations) — see
# byakugan/elastic/inverse_projection.py's own docstring for exactly which cases
# that sidesteps and why they are not phase-5's to fix.
# --------------------------------------------------------------------------- #
def _events(host: str, prefix: str) -> list[dict]:
    return [
        {"car_object": "process", "car_action": "create", "guid": f"{prefix}P1",
         "source_host": host, "timestamp": "2020-01-01T00:00:00Z",
         "source_artefact": "evtx_sysmon", "link_confidence": "definitive",
         "volume_guid": "Volume{abc}", "mac_address": "aa:bb:cc:dd:ee:ff",
         "device_serial": "SN1", "exe": "a.exe", "command_line": "a -x",
         "image_path": r"C:\a.exe", "pid": 100, "sid": "S-1-5-18",
         "hostname": host, "integrity_level": "System",
         # the hash mints a content node -> a logs-car.content-* bundle, the
         # OTHER non-timeline stream the elastic fetch must exclude
         "sha256_hash": "c1" * 32,
         "env_vars": "A=1\nB=2", "_native": {"EventId": 1}},
        # owning_guid ABSENT: process.entity_id will duplicate event.id on the
        # ECS side (the header's own per_object.process fallback) -- proves
        # the inverse's duplicate-collapse rule, not just the plain case.
        {"car_object": "process", "car_action": "create", "guid": f"{prefix}P2",
         "source_host": host, "timestamp": "2020-01-01T00:00:01Z",
         "parent_guid": f"{prefix}P1", "fqdn": f"only-fqdn.{prefix}.example",
         "source_artefact": "evtx_sysmon"},
        {"car_object": "module", "car_action": "load", "guid": f"{prefix}M1",
         "source_host": host, "timestamp": "2020-01-01T00:00:02Z",
         "owning_guid": f"{prefix}P1", "link_confidence": "definitive",
         "source_artefact": "evtx_sysmon", "module_path": r"C:\a.dll",
         "module_name": "a.dll", "md5_hash": "deadbeef"},
        {"car_object": "socket", "car_action": "bind", "guid": f"{prefix}S1",
         "source_host": host, "timestamp": "2020-01-01T00:00:03Z",
         "owning_guid": f"{prefix}P1", "success": 1, "local_address": "10.0.0.5",
         "local_port": 80, "protocol": "tcp", "family": "AF_INET"},
        {"car_object": "socket", "car_action": "bind", "guid": f"{prefix}S2",
         "source_host": host, "timestamp": "2020-01-01T00:00:04Z",
         "owning_guid": f"{prefix}P1", "success": 0, "local_address": "10.0.0.6",
         "local_port": 81},
        {"car_object": "registry", "car_action": "create", "guid": f"{prefix}R1",
         "source_host": host, "timestamp": "2020-01-01T00:00:05Z",
         "owning_guid": f"{prefix}P1", "hive": "HKLM", "key": r"HKLM\Software\X"},
        {"car_object": "flow", "car_action": "start", "guid": f"{prefix}F1",
         "source_host": host, "timestamp": "2020-01-01T00:00:06Z",
         "owning_guid": f"{prefix}P1", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
         "src_port": 4444, "dest_port": 80, "application_protocol": "http",
         "network_direction": "outbound", "out_bytes": 500},
    ]


def _build_tree(root: str, sources=("sysmon1", "sysmon2")) -> str:
    """<root>/<source>/car_<object>.jsonl + car_relationships.jsonl +
    car_inferred.jsonl for each of `sources`, via the real engine stores —
    exactly as `byakugan build` would leave them."""
    for i, name in enumerate(sources):
        d = os.path.join(root, name)
        os.makedirs(d, exist_ok=True)
        events = _events(f"HOST{i}", f"{name}-")
        st = store.CarStore()
        st.insert_events(events)
        st.export_jsonl(d)
        sup = superset.SupersetStore()
        sup.insert_edges(superset.edges_from_events(events))
        sup.insert_inferred_nodes([
            {"node_id": f"{name}-inferred-1", "source_host": f"HOST{i}", "object": "process",
             "identity_key": "guid", "identity_value": f"{name}-ghost",
             "reason": "reconstructed", "method": "native_guid",
             "corroborated_by": [f"{name}-P1"], "properties": {"pid": 42},
             "first_seen": "2020-01-01T00:00:07Z", "last_seen": "2020-01-01T00:00:07Z"}])
        cnodes, _refs = derive.content_entities(events)
        sup.insert_content_nodes(cnodes)
        sup.export_jsonl(d)
        sup.export_inferred_jsonl(d)
        sup.export_content_jsonl(d)
        sup.close()
    return root


# --------------------------------------------------------------------------- #
# The ES stub: point-in-time open/close + search_after paging, serving the
# EXACT (doc_id, doc) pairs `byakugan.elastic.load` bundle mode rendered (no _bulk
# round-trip needed -- bundle mode already produced the real projected
# bytes; this just loads them into the stub's per-stream store).
# --------------------------------------------------------------------------- #
def _read_bundle(path: str) -> list[tuple[str, dict]]:
    with open(path, encoding="utf-8") as fh:
        lines = [json.loads(x) for x in fh if x.strip()]
    return [(a["create"]["_id"], d) for a, d in zip(lines[0::2], lines[1::2])]


def _seed_from_bundles(elastic_dir: str) -> dict:
    indices: dict[str, dict[str, dict]] = {}
    for fn in sorted(os.listdir(elastic_dir)):
        if not fn.endswith(".ndjson"):
            continue
        stream = fn[: -len(".ndjson")]
        indices[stream] = dict(_read_bundle(os.path.join(elastic_dir, fn)))
    return indices


def _excluded_datasets(query: dict) -> set:
    """The event.dataset values the query's must_not excludes — both the
    single `term` shape and the `terms` list shape the engine sends."""
    out: set = set()
    for clause in ((query or {}).get("bool") or {}).get("must_not") or []:
        t = (clause.get("term") or {}).get("event.dataset")
        if t:
            out.add(t)
        out.update((clause.get("terms") or {}).get("event.dataset") or [])
    return out


class _StubES(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):                            # noqa: A003 — silence the stub
        pass

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _json(self, status: int, obj) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _matching_triples(self, pattern: str, query: dict):
        st = self.server.state
        excluded = _excluded_datasets(query)
        out = []
        for stream, docs in st["indices"].items():
            if not fnmatch.fnmatch(stream, pattern):
                continue
            for doc_id, doc in docs.items():
                if (doc.get("event") or {}).get("dataset") in excluded:
                    continue
                out.append((stream, doc_id, doc))
        out.sort(key=lambda t: (t[2].get("@timestamp") or "", t[1]))
        return out

    def do_POST(self):
        st = self.server.state
        path = self.path.split("?", 1)[0].strip("/")
        parts = path.split("/")
        raw = self._body()

        if len(parts) == 2 and parts[1] == "_pit":
            pit_id = f"pit-{len(st['pits']) + 1}"
            st["pits"][pit_id] = parts[0]
            st["pit_opens"] += 1
            self._json(200, {"id": pit_id})
            return

        if parts == ["_search"]:
            body = json.loads(raw or b"{}")
            pit_id = (body.get("pit") or {}).get("id")
            if pit_id not in st["pits"]:
                self._json(404, {"error": {"type": "not_found", "reason": "unknown pit"}})
                return
            st["search_calls"] += 1
            triples = self._matching_triples(st["pits"][pit_id], body.get("query") or {})
            search_after = body.get("search_after")
            if search_after:
                sa = tuple(search_after)
                start = len(triples)
                for i, (_s, doc_id, doc) in enumerate(triples):
                    if (doc.get("@timestamp"), doc_id) > sa:
                        start = i
                        break
                triples = triples[start:]
            size = body.get("size") or 10
            page = triples[:size]
            hits = []
            for stream, doc_id, doc in page:
                st["streams_seen"].add(stream)
                hits.append({"_index": stream, "_id": doc_id, "_source": doc,
                            "sort": [doc.get("@timestamp"), doc_id]})
            self._json(200, {"pit_id": pit_id, "hits": {"hits": hits}})
            return

        self._json(404, {"error": "not_found"})

    def do_DELETE(self):
        st = self.server.state
        path = self.path.split("?", 1)[0].strip("/")
        if path == "_pit":
            body = json.loads(self._body() or b"{}")
            pid = body.get("id")
            if st["pits"].pop(pid, None) is not None:
                st["pit_closes"] += 1
            self._json(200, {"succeeded": True, "num_freed": 1})
            return
        self._json(404, {"error": "not_found"})


@pytest.fixture
def es_stub():
    state = {"indices": {}, "pits": {}, "search_calls": 0, "pit_opens": 0,
             "pit_closes": 0, "streams_seen": set()}
    server = http.server.HTTPServer(("127.0.0.1", 0), _StubES)
    server.state = state
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        t.join(timeout=5)


# --------------------------------------------------------------------------- #
# The anchor: A == B, byte-for-byte.
# --------------------------------------------------------------------------- #
def test_elastic_timeline_matches_local_byte_for_byte(tmp_path, es_stub, monkeypatch):
    es_url, state = es_stub
    # a small page size over ~30+ documents forces several search_after pages
    # ("2+ pages to prove paging") without a large fixture.
    monkeypatch.setattr(timeline, "PAGE_SIZE", 3)

    car = str(tmp_path / "car")
    _build_tree(car)

    # A: local.
    rows_a = timeline.build_timeline(car)
    out_a = str(tmp_path / "local.jsonl")
    timeline.write_jsonl(rows_a, out_a)

    # B: byakugan.elastic.load bundle mode over the SAME tree -> the exact
    # bulk (doc_id, doc) pairs a push would have sent -> the stub's own indices.
    out_dir = str(tmp_path / "out")
    summary = load.run(car, out_dir, NAMESPACE)
    assert summary["status"] == "ok"
    state["indices"] = _seed_from_bundles(os.path.join(out_dir, "elastic"))
    assert state["indices"], "byakugan.elastic.load produced no bundles to seed the stub with"

    rows_b = timeline.build_timeline_from_elastic(es_url, NAMESPACE)
    out_b = str(tmp_path / "elastic.jsonl")
    timeline.write_jsonl(rows_b, out_b)

    with open(out_a, "rb") as fh:
        bytes_a = fh.read()
    with open(out_b, "rb") as fh:
        bytes_b = fh.read()
    assert bytes_a == bytes_b
    assert rows_a and rows_b                            # not a vacuous match

    # paging actually happened (PAGE_SIZE=3 over 2 sources x (6 objects + N
    # relationships) documents is well over one page).
    assert state["search_calls"] >= 2
    assert state["pit_opens"] == 1 and state["pit_closes"] == 1

    # the non-timeline streams were never served: the stub applies the query
    # filter this module's fetch sends (event.dataset car.inferred and
    # car.content), and this proves it by observing what the stub actually
    # returned across the whole fetch, not just by construction.
    assert f"logs-car.inferred-{NAMESPACE}" not in state["streams_seen"]
    assert f"logs-car.content-{NAMESPACE}" not in state["streams_seen"]
    assert any(s.startswith("logs-car.rel-") for s in state["streams_seen"])
    assert any(s.startswith("logs-car.process-") for s in state["streams_seen"])


def test_elastic_timeline_host_filter_matches_local(tmp_path, es_stub, monkeypatch):
    monkeypatch.setattr(timeline, "PAGE_SIZE", 3)
    es_url, state = es_stub
    car = str(tmp_path / "car")
    _build_tree(car)

    rows_local = timeline.build_timeline(car, host="HOST0")
    out_dir = str(tmp_path / "out")
    load.run(car, out_dir, NAMESPACE)
    state["indices"] = _seed_from_bundles(os.path.join(out_dir, "elastic"))

    rows_elastic = timeline.build_timeline_from_elastic(es_url, NAMESPACE, host="HOST0")
    assert rows_local == rows_elastic
    assert rows_local                                    # not a vacuous match
    assert all(r.get("source_host", "HOST0") == "HOST0" for r in rows_local)
    # the filter genuinely excluded the other host, proving this isn't
    # trivially true because both sides returned everything
    assert not any(e.get("source_host") == "HOST1" for e in rows_elastic)


def test_elastic_fetch_never_touches_the_non_timeline_streams_even_populated(tmp_path, es_stub):
    """byakugan.elastic.projection.SKIP_NO_TIMESTAMP-independent sanity check: the
    inferred AND content streams genuinely hold documents in this fixture
    (so their absence from streams_seen in the tests above is not just
    because there was nothing there to find)."""
    es_url, state = es_stub
    car = str(tmp_path / "car")
    _build_tree(car)
    out_dir = str(tmp_path / "out")
    load.run(car, out_dir, NAMESPACE)
    bundles = os.path.join(out_dir, "elastic")
    for stream in (f"logs-car.inferred-{NAMESPACE}", f"logs-car.content-{NAMESPACE}"):
        assert os.path.isfile(os.path.join(bundles, f"{stream}.ndjson"))
    state["indices"] = _seed_from_bundles(bundles)
    for stream in (f"logs-car.inferred-{NAMESPACE}", f"logs-car.content-{NAMESPACE}"):
        assert state["indices"][stream]                  # genuinely non-empty

    timeline.build_timeline_from_elastic(es_url, NAMESPACE)
    assert f"logs-car.inferred-{NAMESPACE}" not in state["streams_seen"]
    assert f"logs-car.content-{NAMESPACE}" not in state["streams_seen"]


def test_elastic_connection_failure_is_a_clean_system_exit_not_a_traceback():
    """A connection failure (here: nothing listening) is reported the same
    way build_timeline's own --after/--before checks are: SystemExit, which
    byakugan/cli.py's run_engine already turns into a clean config_error
    summary — never an uncaught OSError crashing the container sub-tool."""
    with pytest.raises(SystemExit, match="--elastic"):
        timeline.build_timeline_from_elastic("http://127.0.0.1:1", NAMESPACE)


def test_sort_rows_matches_sort_key():
    """_sort_rows (the collision-only tiebreak path) orders exactly as the
    per-row composite _sort_key: tied instants, tied instant+kind, an
    object/edge tie at one instant, unparseable and absent timestamps."""
    rows = [
        {"timestamp": "2024-01-01T00:00:01", "kind": "object", "object": "b"},
        {"timestamp": "2024-01-01T00:00:01", "kind": "object", "object": "a"},
        {"timestamp": "2024-01-01T00:00:01", "kind": "relationship",
         "relationship": "created", "source_guid": "s", "target_guid": "t"},
        {"timestamp": "2024-01-01T00:00:00", "kind": "object", "object": "z"},
        {"timestamp": "not-a-time", "kind": "object", "object": "y"},
        {"timestamp": "not-a-time", "kind": "object", "object": "x"},
        {"timestamp": None, "kind": "object", "object": "w"},
        {"timestamp": "2024-01-01T00:00:01", "kind": "object", "object": "a"},
    ]
    expect = sorted(rows, key=timeline._sort_key)
    assert timeline._sort_rows(list(rows)) == expect

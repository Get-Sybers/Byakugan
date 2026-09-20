"""`byakugan load` — a materialised CAR tree -> Elasticsearch `_bulk` NDJSON
bundles (bundle mode) or pushed data streams (push mode) (epic #99 phase 2)."""
import hashlib
import http.server
import json
import os
import threading

import pytest

from byakugan import cli, store, superset
from byakugan.elastic import load, projection


# --------------------------------------------------------------------------- #
# A real materialised tree: CarStore + SupersetStore over 2 synthetic sources.
# --------------------------------------------------------------------------- #
def _events(host, prefix):
    return [
        {"car_object": "process", "car_action": "create", "guid": f"{prefix}P1",
         "source_host": host, "timestamp": "2020-01-01T00:00:00Z",
         "source_artefact": "evtx_sysmon", "link_confidence": "definitive",
         "exe": "a.exe", "command_line": "a -x", "_native": {"EventId": 1}},
        {"car_object": "module", "car_action": "load", "guid": f"{prefix}M1",
         "source_host": host, "timestamp": "2020-01-01T00:00:01Z",
         "owning_guid": f"{prefix}P1", "link_confidence": "definitive",
         "source_artefact": "evtx_sysmon", "image_path": r"C:\a.exe"},
        # a row with no timestamp: materialised (car.db allows it), never bundled
        {"car_object": "file", "car_action": "create", "guid": None,
         "source_host": host, "timestamp": None, "source_artefact": "evtx_sysmon",
         "file_path": r"C:\x"},
    ]


def _build_tree(root, sources=("sysmon1", "sysmon2")):
    """<root>/<source>/car_<object>.jsonl + car_relationships.jsonl +
    car_inferred.jsonl for each of `sources` — via the real engine stores,
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
             "first_seen": "2020-01-01T00:00:02Z", "last_seen": "2020-01-01T00:00:02Z"}])
        sup.export_jsonl(d)
        sup.export_inferred_jsonl(d)
        sup.close()
    return root


def _read_ndjson(path):
    with open(path, encoding="utf-8") as fh:
        lines = [json.loads(x) for x in fh if x.strip()]
    return list(zip(lines[0::2], lines[1::2]))          # [(action, doc), ...]


# --------------------------------------------------------------------------- #
# Bundle mode.
# --------------------------------------------------------------------------- #
def test_bundle_mode_streams_ids_and_manifest(tmp_path):
    car = _build_tree(str(tmp_path / "car"))
    out = str(tmp_path / "out")
    summary = load.run(car, out, "default")

    assert summary["status"] == "ok" and summary["mode"] == "bundle"
    # process + module + rel + inferred populated (2 sources each); file has
    # no timestamp anywhere, so logs-car.file-default is never created
    elastic = os.path.join(out, "elastic")
    files = sorted(os.listdir(elastic))
    assert files == sorted([
        "logs-car.inferred-default.ndjson", "logs-car.module-default.ndjson",
        "logs-car.process-default.ndjson", "logs-car.rel-default.ndjson",
        "manifest.json"])

    manifest = json.load(open(os.path.join(elastic, "manifest.json"), encoding="utf-8"))
    assert manifest["namespace"] == "default" and manifest["mode"] == "bundle"
    assert manifest["contract"]["version"] == 3
    proc = manifest["streams"]["logs-car.process-default"]
    assert proc["documents"] == 2                        # one process row per source
    # per-line create ids: match project_event's own id for each row, and
    # the manifest's sha256 matches the actual bundle bytes
    pairs = _read_ndjson(os.path.join(out, proc["bundle"]))
    assert len(pairs) == 2
    for action, doc in pairs:
        assert set(action) == {"create"} and set(action["create"]) == {"_id"}
        assert doc["car"]["object"] == "process"
    actual_sha = hashlib.sha256(open(os.path.join(out, proc["bundle"]), "rb").read()).hexdigest()
    assert actual_sha == proc["sha256"]
    # a source's record/skip counts: 2 records (process, module) + 1 skip (file)
    # + whatever the rel/inferred rows contribute
    for name in ("sysmon1", "sysmon2"):
        s = manifest["sources"][name]
        assert s["skipped"] == 1 and s["failed"] == 0
        assert s["records"] >= 2

    # file (no timestamp anywhere) never got a stream at all
    assert "logs-car.file-default" not in manifest["streams"]
    assert summary["skip_reasons"] == {projection.SKIP_NO_TIMESTAMP: 2}


def test_bundle_mode_second_run_skips_without_force(tmp_path):
    car = _build_tree(str(tmp_path / "car"))
    out = str(tmp_path / "out")
    load.run(car, out, "default")
    bundle = os.path.join(out, "elastic", "logs-car.process-default.ndjson")
    mtime1 = os.path.getmtime(bundle)

    again = load.run(car, out, "default")
    assert again["status"] == "ok" and again.get("skipped_run") is True
    assert again["processed"] == 0 and again["skipped"] > 0
    assert os.path.getmtime(bundle) == mtime1             # untouched


def test_bundle_mode_force_rerenders_byte_identical(tmp_path):
    car = _build_tree(str(tmp_path / "car"))
    out = str(tmp_path / "out")
    load.run(car, out, "default")
    bundle = os.path.join(out, "elastic", "logs-car.process-default.ndjson")
    before = open(bundle, "rb").read()

    forced = load.run(car, out, "default", force=True)
    assert forced["status"] == "ok" and not forced.get("skipped_run")
    after = open(bundle, "rb").read()
    assert before == after


def test_bundle_mode_empty_tree_is_nothing_and_writes_no_output(tmp_path):
    empty = str(tmp_path / "empty")
    os.makedirs(empty)
    out = str(tmp_path / "out")
    with pytest.raises(SystemExit, match="no materialised CAR"):
        load.run(empty, out, "default")
    assert not os.path.exists(out)


def test_find_sources_mirrors_timeline_find_stores(tmp_path):
    root = str(tmp_path)
    assert load.find_sources(root) == []
    a = os.path.join(root, "a")
    os.makedirs(a)
    open(os.path.join(a, "car_process.jsonl"), "w").close()
    assert load.find_sources(root) == [a]
    b = os.path.join(root, "nested", "b")
    os.makedirs(b)
    open(os.path.join(b, "car_relationships.jsonl"), "w").close()
    # once the ROOT itself holds no car_*.jsonl, every dir beneath it that does
    root2 = str(tmp_path / "tree")
    for name in ("s1", "s2/sub"):
        d = os.path.join(root2, name)
        os.makedirs(d)
        open(os.path.join(d, "car_file.jsonl"), "w").close()
    assert load.find_sources(root2) == sorted([os.path.join(root2, "s1"), os.path.join(root2, "s2", "sub")])


def test_a_bad_row_is_a_failure_not_a_crash(tmp_path):
    src = tmp_path / "car" / "s1"
    src.mkdir(parents=True)
    (src / "car_process.jsonl").write_text(
        "not json at all\n"
        + json.dumps({"car_object": "process", "timestamp": "2020-01-01T00:00:00Z",
                     "car_action": "create", "guid": "P1", "source_host": "H"}) + "\n")
    summary = load.run(str(tmp_path / "car"), str(tmp_path / "out"), "default")
    assert summary["failed"] == 1 and summary["records"] == 1
    assert summary["failures"][0]["line"] == 1


# --------------------------------------------------------------------------- #
# Push mode: a stdlib http.server stand-in for Elasticsearch/Kibana.
# --------------------------------------------------------------------------- #
class _StubES(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):                            # noqa: A003 — silence the stub
        pass

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        st = self.server.state
        parts = self.path.split("?", 1)[0].strip("/").split("/")
        if len(parts) == 2 and parts[0] in ("_component_template", "_index_template"):
            store_ = st["component"] if parts[0] == "_component_template" else st["index"]
            if parts[1] in store_:
                key = parts[0][1:] + "s"
                inner = parts[0][1:]
                self._json(200, {key: [{"name": parts[1], inner: store_[parts[1]]}]})
            else:
                self._json(404, {"error": "not_found"})
            return
        self._json(404, {"error": "not_found"})

    def do_PUT(self):
        st = self.server.state
        parts = self.path.split("?", 1)[0].strip("/").split("/")
        body = json.loads(self._body() or b"{}")
        if len(parts) == 2 and parts[0] in ("_component_template", "_index_template"):
            store_ = st["component"] if parts[0] == "_component_template" else st["index"]
            store_[parts[1]] = body
            st["puts"].append(f"{parts[0]}/{parts[1]}")
            self._json(200, {"acknowledged": True})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        st = self.server.state
        path = self.path.split("?", 1)[0].strip("/")
        parts = path.split("/")
        raw = self._body()
        if len(parts) == 2 and parts[1] == "_bulk":
            stream = parts[0]
            st["bulk_calls"].append(stream)
            index = st["indices"].setdefault(stream, {})
            lines = raw.decode("utf-8").splitlines()
            items = []
            for i in range(0, len(lines), 2):
                action, doc = json.loads(lines[i]), json.loads(lines[i + 1])
                doc_id = action["create"]["_id"]
                if stream in st["fail_streams"]:
                    items.append({"create": {"status": 500, "error": {"type": "stub_forced_failure"}}})
                elif doc_id in index:
                    items.append({"create": {"status": 409,
                                             "error": {"type": "version_conflict_engine_exception"}}})
                else:
                    index[doc_id] = doc
                    items.append({"create": {"status": 201}})
            self._json(200, {"errors": any(it["create"]["status"] >= 300 for it in items), "items": items})
            return
        if len(parts) == 2 and parts[1] == "_search":
            stream = parts[0]
            index = st["indices"].get(stream, {})
            q = json.loads(raw or b"{}")
            ids = ((q.get("query") or {}).get("ids") or {}).get("values") or []
            total = sum(1 for i in ids if i in index)
            self._json(200, {"hits": {"total": {"value": total}}})
            return
        if path == "api/saved_objects/_import":
            st["kibana_imports"].append(raw)
            self._json(200, {"success": True, "successCount": 2})
            return
        self._json(404, {"error": "not_found"})


@pytest.fixture
def es_stub():
    state = {"component": {}, "index": {}, "indices": {}, "bulk_calls": [], "puts": [],
            "kibana_imports": [], "fail_streams": set()}
    server = http.server.HTTPServer(("127.0.0.1", 0), _StubES)
    server.state = state
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        t.join(timeout=5)


def _big_tree(root, n=2500):
    """One source, `n` synthetic process rows — enough to force several
    _bulk chunks at BULK_MAX_ACTIONS=1000."""
    d = os.path.join(root, "big")
    os.makedirs(d)
    with open(os.path.join(d, "car_process.jsonl"), "w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(json.dumps({
                "car_object": "process", "car_action": "create", "guid": f"P{i}",
                "source_host": "H", "timestamp": f"2020-01-01T00:00:{i % 60:02d}Z",
                "source_artefact": "evtx_sysmon", "link_confidence": "definitive",
                "exe": "a.exe"}) + "\n")
    return d


def test_push_mode_chunks_and_verifies(tmp_path, es_stub):
    es_url, state = es_stub
    car = str(tmp_path / "car")
    _big_tree(car, 2500)
    out = str(tmp_path / "out")
    summary = load.run(car, out, "default", es_url=es_url)

    assert summary["status"] == "ok" and summary["mode"] == "push"
    stream = "logs-car.process-default"
    assert summary["streams"][stream]["documents"] == 2500
    assert summary["streams"][stream]["created"] == 2500
    assert summary["streams"][stream]["failed"] == 0
    assert summary["streams"][stream]["verified"] is True
    assert summary["streams"][stream]["verify_total"] == 2500
    # chunking observed: 2500 actions at <=1000/chunk needs >= 3 _bulk calls
    assert state["bulk_calls"].count(stream) >= 3
    assert len(state["indices"][stream]) == 2500


def test_push_mode_es_url_scheme_is_plain_http_not_https(tmp_path, es_stub):
    """`--es-url` takes the URL's OWN scheme — push mode never requires or
    assumes https. The standalone lab stack (elastic/, HTTP TLS off — see
    elastic/README.md) is reached over plain http://127.0.0.1:9201, so this
    makes that contract explicit rather than incidental: every `es_stub` push
    test above already runs over http (the stub only ever serves plain HTTP),
    proving it end to end; this test just names why that is safe. `load.run`
    always builds a TLS `ssl_context` (`byakugan.elastic._http.ssl_context`, shared
    with `byakugan.timeline --elastic`) regardless of `--es-url`'s scheme —
    `urllib` simply never consults an SSL context for a plain http:// request,
    so passing one is harmless and pushing to an http:// stack works exactly
    like pushing to an https:// one would."""
    es_url, _state = es_stub
    assert es_url.startswith("http://") and not es_url.startswith("https://")
    car = str(tmp_path / "car")
    _build_tree(car, sources=("s1",))
    out = str(tmp_path / "out")
    summary = load.run(car, out, "default", es_url=es_url)
    assert summary["status"] == "ok" and summary["mode"] == "push"
    assert summary["streams"]["logs-car.process-default"]["created"] == 1


def test_push_mode_conflict_is_already_present(tmp_path, es_stub):
    es_url, state = es_stub
    car = str(tmp_path / "car")
    _build_tree(car, sources=("s1",))
    out = str(tmp_path / "out")
    first = load.run(car, out, "default", es_url=es_url)
    assert first["streams"]["logs-car.process-default"]["created"] == 1

    again = load.run(car, out, "default", es_url=es_url, force=True)
    st = again["streams"]["logs-car.process-default"]
    assert st["created"] == 0 and st["already_present"] == 1 and st["failed"] == 0
    assert st["verified"] is True


def test_push_mode_one_stream_failing_is_partial(tmp_path, es_stub):
    es_url, state = es_stub
    car = str(tmp_path / "car")
    _build_tree(car, sources=("s1",))
    state["fail_streams"] = {"logs-car.module-default"}
    out = str(tmp_path / "out")
    summary = load.run(car, out, "default", es_url=es_url)

    assert summary["status"] == "partial"
    assert summary["streams"]["logs-car.process-default"]["failed"] == 0
    assert summary["streams"]["logs-car.module-default"]["failed"] > 0
    assert summary["streams"]["logs-car.module-default"]["verified"] is False


def test_push_mode_every_stream_failing_is_failed(tmp_path, es_stub):
    es_url, state = es_stub
    car = str(tmp_path / "car")
    _build_tree(car, sources=("s1",))
    state["fail_streams"] = {"logs-car.process-default", "logs-car.module-default",
                             "logs-car.rel-default", "logs-car.inferred-default"}
    out = str(tmp_path / "out")
    summary = load.run(car, out, "default", es_url=es_url)
    assert summary["status"] == "failed"
    assert summary["processed"] == 0 and summary["failed"] > 0


def test_setup_applies_templates_then_reports_unchanged(tmp_path, es_stub):
    es_url, state = es_stub
    ctx = load.ssl_context(None)
    result1 = load.run_setup(es_url, {}, None, kibana_url=None)
    assert result1["ok"] and result1["unchanged"] == []
    assert len(result1["applied"]) == len(state["puts"])
    assert any(p.startswith("_component_template/") for p in state["puts"])
    assert any(p.startswith("_index_template/") for p in state["puts"])
    n_applied = len(result1["applied"])
    puts_after_first = list(state["puts"])

    result2 = load.run_setup(es_url, {}, None, kibana_url=None)
    assert result2["applied"] == [] and len(result2["unchanged"]) == n_applied
    assert state["puts"] == puts_after_first                # no new PUTs on the no-op pass


def test_setup_with_kibana_url_imports_the_bundle(tmp_path, es_stub):
    es_url, state = es_stub
    result = load.run_setup(es_url, {}, None, kibana_url=es_url)
    assert result["ok"] is True
    assert result["kibana"]["ok"] is True
    assert len(state["kibana_imports"]) == 1
    assert b"multipart" not in state["kibana_imports"][0]   # the raw ndjson content itself


def test_run_with_setup_true_runs_setup_before_loading(tmp_path, es_stub):
    es_url, state = es_stub
    car = str(tmp_path / "car")
    _build_tree(car, sources=("s1",))
    summary = load.run(car, str(tmp_path / "out"), "default", es_url=es_url, setup=True)
    assert "setup" in summary and summary["setup"]["ok"]
    assert state["puts"]                                     # templates really were applied


# --------------------------------------------------------------------------- #
# cli.py wiring.
# --------------------------------------------------------------------------- #
def _write(car_dir, source, obj, rows):
    d = car_dir / source
    d.mkdir(parents=True, exist_ok=True)
    (d / f"car_{obj}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


def _row(obj, action, **fields):
    return {"car_object": obj, "timestamp": "2020-01-01T00:00:00Z", "car_action": action,
           "guid": f"{obj}-1", "owning_guid": None, "link_confidence": "definitive",
           "source_artefact": "evtx_sysmon", "source_host": "PC1", "native": {}, **fields}


def _summary(capsys):
    captured = capsys.readouterr()
    lines = [line for line in captured.out.splitlines() if line.strip()]
    assert len(lines) == 1, captured.out
    return json.loads(lines[0]), captured.err


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "DEFAULT_OUT_DIR", str(tmp_path / "no-such-output"))
    for key in list(os.environ):
        if key.startswith("BYAKUGAN_"):
            monkeypatch.delenv(key)
    return monkeypatch


def test_cli_load_bad_log_level_is_config_error_before_input_scan(tmp_path, env, capsys):
    # the input dir does not exist — if LOG_LEVEL were checked AFTER the input
    # scan this would fail on BYAKUGAN_LOAD_INPUT_DIR instead
    env.setenv("BYAKUGAN_LOAD_INPUT_DIR", str(tmp_path / "does-not-exist"))
    env.setenv("BYAKUGAN_LOAD_LOG_LEVEL", "bogus")
    assert cli.main(["load"]) == 2
    s, _err = _summary(capsys)
    assert s["status"] == "config_error"
    assert "BYAKUGAN_LOAD_LOG_LEVEL" in s["error"]


def test_cli_load_empty_tree_is_nothing_with_no_elastic_dir(tmp_path, env, capsys):
    car, out = tmp_path / "car", tmp_path / "out"
    car.mkdir()
    env.setenv("BYAKUGAN_LOAD_INPUT_DIR", str(car))
    env.setenv("BYAKUGAN_LOAD_OUT_DIR", str(out))
    assert cli.main(["load"]) == 1
    s, _err = _summary(capsys)
    assert (s["subtool"], s["status"], s["exit"]) == ("load", "nothing", 1)
    assert not os.path.exists(out / "elastic")


def test_cli_load_a_populated_tree(tmp_path, env, capsys):
    car, out = tmp_path / "car", tmp_path / "out"
    _write(car, "sysmon", "process", [_row("process", "create", exe="a.exe")])
    env.setenv("BYAKUGAN_LOAD_INPUT_DIR", str(car))
    env.setenv("BYAKUGAN_LOAD_OUT_DIR", str(out))
    env.setenv("BYAKUGAN_LOAD_NAMESPACE", "Case 42")
    assert cli.main(["load"]) == 0
    s, _err = _summary(capsys)
    assert s["status"] == "ok" and s["records"] == 1 and s["processed"] == 1
    assert s["outputs"] == [str(out / "elastic")]
    assert (out / "elastic" / "logs-car.process-case-42.ndjson").is_file()
    assert (out / "load.txt").is_file()

    # rerun without FORCE: skipped, still ok
    assert cli.main(["load"]) == 0
    s2, _err = _summary(capsys)
    assert s2["status"] == "ok" and s2["skipped"] == 1 and s2["processed"] == 0


def test_cli_load_namespace_slugify_and_empty_slug_is_config_error(tmp_path, env, capsys):
    car, out = tmp_path / "car", tmp_path / "out"
    _write(car, "sysmon", "process", [_row("process", "create")])
    env.setenv("BYAKUGAN_LOAD_INPUT_DIR", str(car))
    env.setenv("BYAKUGAN_LOAD_OUT_DIR", str(out))
    env.setenv("BYAKUGAN_LOAD_NAMESPACE", "!!!")
    assert cli.main(["load"]) == 2
    s, _err = _summary(capsys)
    assert s["status"] == "config_error" and "BYAKUGAN_LOAD_NAMESPACE" in s["error"]


def test_cli_load_is_dispatchable_as_pass_through(tmp_path, env):
    car = tmp_path / "car"
    _write(car, "sysmon", "process", [_row("process", "create")])
    out = tmp_path / "out"
    assert cli.main(["load", str(car), "--out", str(out), "--namespace", "default"]) == 0
    assert (out / "elastic" / "logs-car.process-default.ndjson").is_file()

#!/usr/bin/env python3
"""The live-Elasticsearch end-to-end gate (epic #99 phase 8): the one claim
unit tests cannot make — that a real Elasticsearch + Kibana, driven only
through `byakugan.elastic.load`/`byakugan.timeline`'s own public surface,
actually behaves the way the projection contract and the standalone stack's
README promise. `tests/test_load.py` (a stdlib `http.server` stand-in) and
`tests/test_timeline_elastic.py` already prove the WIRE PROTOCOL against a
stub; this proves the CLUSTER — real templates, real aliases, a real least-
privilege identity, a real re-push — which only CI (GitHub's ubuntu-latest,
`.github/workflows/elastic-e2e.yml`, `elastic/docker-compose.yml`) can run,
since this sandbox has no Docker daemon.

Five steps, run in order against one namespace:

  A. Materialise a small, honest CAR tree — 2 sources, run through the ACTUAL
     engine surfaces (`byakugan.store.CarStore`, `byakugan.superset.build_from_events`,
     `byakugan.derive.derive` — the exact sequence `byakugan/pipeline.py`'s own
     `_process_one` runs), never hand-built JSON pretending to be one.
  B. First load, push mode, as the `elastic` superuser: `--setup` (templates +
     Kibana import) + a genuine push; assert per-stream created == bundled,
     every stream verified, the composed `logs-car-process` index template
     exists, and the `car-timeline-dashboard` Kibana saved object was imported.
  C. Prove the CAR-name field ALIASES are live: a term query on
     `car.process.command_line` (an Elasticsearch field alias onto
     `process.command_line` — see `elastic/projection/render_elastic.py`)
     finds the one process row seeded with it; a `logs-car.rel-*` document
     carries `car.rel.relationship`.
  D. Re-push the SAME tree, `--force`, authenticated as `byakugan_loader`
     (created by `elastic/config/setup.sh`, role `logs_car_writer`:
     create_doc/create_index/read/view_index_metadata on `logs-car.*` only —
     no template/cluster privileges) — proves both idempotency (100%
     already_present against a live cluster) and that this identity's
     narrower grant is sufficient for the steady-state path.
  E. `byakugan.timeline.build_timeline` (local) vs `--elastic` (the same
     namespace) — byte-compare `timeline.jsonl`.

`--offline-selftest` runs only step A plus the LOCAL half of step E (build
the tree, build+write the local timeline, check the tree/count invariants)
and touches no network — this is what this script's own logic can be proven
against without a live cluster, e.g. in this repo's own sandboxes; steps
B-E's Elasticsearch/Kibana calls only run in CI.

    python scripts/e2e_elastic.py --offline-selftest
    python scripts/e2e_elastic.py --es-url http://127.0.0.1:9201 --kibana-url http://127.0.0.1:5602 \
        --es-user elastic --es-password "$ELASTIC_PASSWORD" \
        --loader-user byakugan_loader --loader-password "$BYAKUGAN_LOADER_PASSWORD" \
        --namespace e2e

Every assertion failure prints exactly what differed (to stderr) and exits
non-zero; success prints a compact proof summary and exits 0.

Dependencies: the standard library + the `byakugan` package only (no
`requests`, no elasticsearch client — the same stdlib-`urllib` posture as
`byakugan.elastic.load` itself, via `byakugan.elastic.load`'s own re-exported
`_http` helpers).
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sys
import tempfile
import uuid

from byakugan import derive, store, superset, timeline
from byakugan.elastic import load

# --------------------------------------------------------------------------- #
# The fixture: 2 sources, replicated (not imported) from tests/test_load.py's
# own `_events`/`_build_tree` approach. Replicated rather than imported
# because tests/ is not an importable package outside pytest collection
# (pyproject.toml's `[tool.pytest.ini_options] pythonpath = ["tests"]` only
# takes effect under pytest itself; this script runs standalone, in CI and
# under --offline-selftest alike) — see the module docstring above for what
# this extends test_load.py's fixture WITH (a parent link, an owned file, an
# authentication<->user_session LUID pair, a trivial derived edge).
# --------------------------------------------------------------------------- #
SOURCES = (("hostA", "srcA-"), ("hostB", "srcB-"))
N_SOURCES = len(SOURCES)
OBJECTS_PER_SOURCE = 5             # 2 process + file + authentication + user_session
# per source: parent->child (declared), owner->file (declared), auth->session
# (declared, the LUID pair) + the process<->file sha256 match (derived) —
# see _make_events's comments for exactly which row produces which edge.
DECLARED_EDGES_PER_SOURCE = 3
DERIVED_EDGES_PER_SOURCE = 1
EDGES_PER_SOURCE = DECLARED_EDGES_PER_SOURCE + DERIVED_EDGES_PER_SOURCE
STREAM_OBJECTS = ("process", "file", "authentication", "user_session")


def _make_events(host: str, prefix: str, seeded_command_line: str | None) -> list[dict]:
    """One source's events — plain dicts, already-resolved links, exactly the
    shape tests/test_load.py's own `_events()` constructs (car_object/
    car_action/guid/source_host/timestamp/source_artefact/link_confidence +
    the object's own fields + `_native` for the header's native-only bag) —
    fed straight to CarStore/build_from_events/derive, never through enrich
    (which resolves those links FROM raw pid/offset windows; here they are
    already known, as a finished pipeline run would have left them)."""
    sha256 = hashlib.sha256(f"{prefix}payload".encode("utf-8")).hexdigest()
    luid = f"{prefix}LUID-1"
    image_path = rf"C:\Users\a\{prefix}payload.exe"
    return [
        # process: the parent (create; no parent link of its own).
        {"car_object": "process", "car_action": "create", "guid": f"{prefix}P-parent",
         "source_host": host, "timestamp": "2024-01-01T00:00:00Z",
         "source_artefact": "evtx_sysmon", "link_confidence": "definitive",
         "exe": "explorer.exe", "command_line": r"C:\Windows\explorer.exe",
         "image_path": r"C:\Windows\explorer.exe"},
        # process: the child — create WITH a parent link (superset.edges_from_events
        # -> a declared "parent_process" edge parent--created-->child) and a
        # sha256_hash shared with the file row below (-> derive.py's
        # process_image_content DERIVED edge, class=derived, method=shared_hash).
        # The FIRST source's child also carries the seeded command_line step C
        # searches for via the car.process.command_line alias.
        {"car_object": "process", "car_action": "create", "guid": f"{prefix}P-child",
         "parent_guid": f"{prefix}P-parent", "source_host": host, "timestamp": "2024-01-01T00:00:01Z",
         "source_artefact": "evtx_sysmon", "link_confidence": "definitive",
         "exe": "payload.exe",
         "command_line": seeded_command_line if seeded_command_line else f"payload.exe --host {host}",
         "image_path": image_path, "sha256_hash": sha256},
        # file: owned by the child process (owning_guid -> a declared
        # spoke_owner "created" edge, process--created-->file) and sharing the
        # child's sha256_hash + path (-> the derived edge above).
        {"car_object": "file", "car_action": "create", "guid": f"{prefix}F-1",
         "owning_guid": f"{prefix}P-child", "source_host": host, "timestamp": "2024-01-01T00:00:02Z",
         "source_artefact": "evtx_sysmon", "link_confidence": "definitive",
         "file_path": image_path, "file_name": f"{prefix}payload.exe", "sha256_hash": sha256},
        # authentication: names the logon session it opened by LUID, native
        # (target_session_guid — not a CAR schema field, so it lives in the
        # header's own native bag, same as superset.edges_from_events reads it).
        {"car_object": "authentication", "car_action": "success", "guid": f"{prefix}A-1",
         "source_host": host, "timestamp": "2024-01-01T00:00:03Z",
         "source_artefact": "evtx_security", "link_confidence": "definitive",
         "app_name": "winlogon.exe", "auth_service": "Active Directory", "method": "Kerberos",
         "target_ad_domain": "CORP", "hostname": host, "target_uid": "U-1001", "target_user": "alice",
         "_native": {"target_session_guid": luid, "target_session_link": "definitive"}},
        # user_session: the session the authentication above names — guid ==
        # that same LUID (-> a declared "auth_session" edge, authentication
        # --created--> user_session; the "LUID pair" the task names).
        {"car_object": "user_session", "car_action": "login", "guid": luid,
         "source_host": host, "timestamp": "2024-01-01T00:00:04Z",
         "source_artefact": "evtx_security", "link_confidence": "definitive",
         "hostname": host, "user": "alice", "uid": "U-1001",
         "login_id": luid, "login_type": "interactive", "login_successful": True},
    ]


def build_tree(work_dir: str, marker: str) -> tuple[str, dict]:
    """Step A: a materialised CAR tree over N_SOURCES synthetic sources,
    through the ACTUAL engine surfaces — CarStore.export_jsonl, then
    superset.build_from_events, then derive.derive re-exporting both
    relationship classes over the SAME in-memory events/store — exactly the
    sequence byakugan/pipeline.py's own `_process_one` runs (CarStore export,
    then `superset.build_from_events`, then, with the derive pass,
    `derive.derive(events, sup_store, out_dir)`), so the tree this produces
    is exactly what a real build would leave on disk. Returns
    (car_dir, {"seeded_command_line": ...})."""
    car_dir = os.path.join(work_dir, "car")
    seeded_command_line = f"payload.exe --e2e-mark {marker}"
    for i, (host, prefix) in enumerate(SOURCES):
        d = os.path.join(car_dir, host)
        os.makedirs(d, exist_ok=True)
        events = _make_events(host, prefix, seeded_command_line if i == 0 else None)
        st = store.CarStore()
        st.insert_events(events)
        st.export_jsonl(d)
        sup = superset.build_from_events(d, events)      # DECLARED edges, exported
        derive.derive(events, sup, d)                    # + DERIVED edges, re-exported (both classes)

    db_files = sorted(glob.glob(os.path.join(car_dir, "**", "*.db"), recursive=True))
    _check(not db_files, f"materialised tree holds .db file(s) (the engine is JSONL-only): {db_files}")
    return car_dir, {"seeded_command_line": seeded_command_line}


# --------------------------------------------------------------------------- #
# Small helpers: fail loud, diff loud.
# --------------------------------------------------------------------------- #
def _proof(msg: str) -> None:
    print(f"[e2e] {msg}")


def _fail(msg: str) -> None:
    sys.stderr.write(f"E2E FAIL: {msg}\n")
    raise SystemExit(1)


def _check(cond: bool, msg: str) -> None:
    if not cond:
        _fail(msg)


def _first_difference(path_a: str, path_b: str, label_a: str, label_b: str) -> str | None:
    """None when the two files are byte-identical; else exactly what
    differed — the first differing line (or a line-count mismatch)."""
    a = open(path_a, "rb").read()
    b = open(path_b, "rb").read()
    if a == b:
        return None
    la = a.decode("utf-8", "replace").splitlines()
    lb = b.decode("utf-8", "replace").splitlines()
    for i, (x, y) in enumerate(zip(la, lb), 1):
        if x != y:
            return (f"first difference at line {i}:\n"
                    f"  {label_a}:   {x}\n  {label_b}: {y}")
    return f"identical for {min(len(la), len(lb))} lines, but line counts differ: " \
          f"{label_a}={len(la)} {label_b}={len(lb)}"


# --------------------------------------------------------------------------- #
# HTTP: byakugan.elastic.load's own stdlib-urllib helpers (auth/TLS/request),
# re-exported off `load` — no separate client, no separate auth code path.
# --------------------------------------------------------------------------- #
def _get(url: str, user: str, password: str):
    return load.http_json(url, "GET", None, load.auth_headers("", user, password), load.ssl_context(None))


def _search(args, stream: str, body: dict, user: str, password: str):
    headers = {**load.auth_headers("", user, password), "Content-Type": "application/json"}
    url = f"{args.es_url.rstrip('/')}/{stream}/_search"
    return load.http_json(url, "POST", json.dumps(body, separators=(",", ":")), headers, load.ssl_context(None))


# --------------------------------------------------------------------------- #
# Step B: first load, push mode, as the elastic superuser.
# --------------------------------------------------------------------------- #
def step_b_first_load(args, car_dir: str, out_dir: str) -> dict:
    _proof("step B: first load, push mode, as the elastic superuser (--setup --kibana-url)")
    summary = load.run(car_dir, out_dir, args.namespace, es_url=args.es_url,
                       es_user=args.es_user, es_password=args.es_password,
                       kibana_url=args.kibana_url, setup=True, force=True)
    _check(summary["status"] == "ok",
          f"step B: load status={summary['status']!r} (expected 'ok'); "
          f"failures={summary.get('failures')}; setup={summary.get('setup')}")

    # "rel" = the relationship timeline; "content" = the attribution layer
    # (the seeded hashes mint content nodes — global by content key — so
    # car_content.jsonl populates logs-car.content-* since the D5 stream landed)
    expected_streams = {f"logs-car.{o}-{args.namespace}" for o in (*STREAM_OBJECTS, "rel", "content")}
    got_streams = set(summary["streams"])
    _check(got_streams == expected_streams,
          f"step B: populated streams {sorted(got_streams)} != expected {sorted(expected_streams)}")

    for name, st in sorted(summary["streams"].items()):
        _check(st["created"] == st["documents"],
              f"step B: stream {name}: created={st['created']} != bundled documents={st['documents']}")
        _check(st["failed"] == 0, f"step B: stream {name}: failed={st['failed']} (expected 0)")
        _check(st["verified"] is True and st.get("verify_total") == st["documents"],
              f"step B: stream {name}: verified={st['verified']} verify_total={st.get('verify_total')} "
              f"documents={st['documents']} (expected verified=True, verify_total==documents)")

    setup = summary.get("setup") or {}
    _check(setup.get("ok") is True, f"step B: --setup did not report ok: {setup}")
    _check((setup.get("kibana") or {}).get("ok") is True,
          f"step B: Kibana import did not report ok: {setup.get('kibana')}")

    status, parsed, raw = _get(f"{args.es_url.rstrip('/')}/_index_template/logs-car-process",
                               args.es_user, args.es_password)
    templates = (parsed or {}).get("index_templates") or []
    _check(status == 200 and any(t.get("name") == "logs-car-process" for t in templates),
          f"step B: GET _index_template/logs-car-process: HTTP {status}, body={raw[:300]!r}")

    kheaders = {**load.auth_headers("", args.es_user, args.es_password), "kbn-xsrf": "true"}
    kurl = f"{args.kibana_url.rstrip('/')}/api/saved_objects/_find?type=dashboard"
    kstatus, kparsed, kraw = load.http_json(kurl, "GET", None, kheaders, load.ssl_context(None))
    ids = [o.get("id") for o in (kparsed or {}).get("saved_objects") or []]
    _check(kstatus == 200 and "car-timeline-dashboard" in ids,
          f"step B: Kibana GET {kurl}: HTTP {kstatus}, dashboard ids={ids}, body={kraw[:300]!r}")

    total_docs = sum(s["documents"] for s in summary["streams"].values())
    _proof(f"step B OK: {total_docs} documents created across {len(summary['streams'])} streams "
          f"(as {args.es_user}); logs-car-process index template + car-timeline-dashboard confirmed")
    return summary


# --------------------------------------------------------------------------- #
# Step C: the CAR-name alias + the rel edge, both live.
# --------------------------------------------------------------------------- #
def step_c_alias_and_field_proof(args, info: dict) -> None:
    _proof("step C: live alias + field proof")
    seeded = info["seeded_command_line"]
    stream = f"logs-car.process-{args.namespace}"
    status, parsed, raw = _search(args, stream, {"query": {"term": {"car.process.command_line": seeded}}},
                                  args.es_user, args.es_password)
    total = (((parsed or {}).get("hits") or {}).get("total") or {}).get("value")
    _check(status == 200 and total == 1,
          f"step C: term car.process.command_line={seeded!r} on {stream}: HTTP {status}, "
          f"hits.total.value={total} (expected exactly 1); body={raw[:300]!r}")
    hit_source = parsed["hits"]["hits"][0]["_source"]
    actual_cmd = (hit_source.get("process") or {}).get("command_line")
    _check(actual_cmd == seeded,
          f"step C: the one hit's process.command_line={actual_cmd!r} != seeded {seeded!r} "
          "(the car.process.command_line alias resolved to the wrong concrete field)")

    rel_stream = f"logs-car.rel-{args.namespace}"
    rstatus, rparsed, rraw = _search(args, rel_stream, {"query": {"match_all": {}}, "size": 1},
                                     args.es_user, args.es_password)
    hits = ((rparsed or {}).get("hits") or {}).get("hits") or []
    _check(rstatus == 200 and hits,
          f"step C: {rel_stream} _search match_all: HTTP {rstatus}, 0 hits; body={rraw[:300]!r}")
    rel_value = ((hits[0].get("_source") or {}).get("car") or {}).get("rel", {}).get("relationship")
    _check(bool(rel_value),
          f"step C: {rel_stream} hit carries no car.rel.relationship: _source={hits[0].get('_source')}")

    event_id = (hit_source.get("event") or {}).get("id")
    _proof(f"step C OK: car.process.command_line={seeded!r} -> 1 hit (event.id={event_id}); "
          f"{rel_stream} doc car.rel.relationship={rel_value!r} present")


# --------------------------------------------------------------------------- #
# Step D: idempotent re-push, as the least-privilege byakugan_loader.
# --------------------------------------------------------------------------- #
def step_d_idempotent_least_priv(args, car_dir: str, out_dir: str) -> dict:
    _proof("step D: idempotent re-push, as byakugan_loader (no --setup, --force)")
    summary = load.run(car_dir, out_dir, args.namespace, es_url=args.es_url,
                       es_user=args.loader_user, es_password=args.loader_password, force=True)
    _check(summary["status"] == "ok",
          f"step D: load status={summary['status']!r} (expected 'ok'); "
          f"failures={summary.get('failures')}; setup={summary.get('setup')}")
    for name, st in sorted(summary["streams"].items()):
        _check(st["created"] == 0, f"step D: stream {name}: created={st['created']} (expected 0)")
        _check(st["failed"] == 0, f"step D: stream {name}: failed={st['failed']} (expected 0)")
        _check(st["already_present"] == st["documents"],
              f"step D: stream {name}: already_present={st['already_present']} != "
              f"documents={st['documents']} (expected 100% already_present)")
    total_docs = sum(s["documents"] for s in summary["streams"].values())
    _proof(f"step D OK: {total_docs}/{total_docs} documents already_present via {args.loader_user} "
          "(create_doc/create_index/read/view_index_metadata only) — 0 created, 0 failed")
    return summary


# --------------------------------------------------------------------------- #
# Step E: local timeline vs --elastic, byte-compared.
# --------------------------------------------------------------------------- #
def step_e_timeline_bytecompare(args, car_dir: str, work_dir: str) -> None:
    _proof("step E: timeline byte-compare (local build vs --elastic)")
    local_rows = timeline.build_timeline(car_dir)
    local_path = os.path.join(work_dir, "timeline.local.jsonl")
    timeline.write_jsonl(local_rows, local_path)

    try:
        remote_rows = timeline.build_timeline_from_elastic(
            args.es_url, args.namespace, es_user=args.es_user, es_password=args.es_password)
    except SystemExit as e:
        raise RuntimeError(f"build_timeline_from_elastic failed (exit {e.code})") from e
    remote_path = os.path.join(work_dir, "timeline.elastic.jsonl")
    timeline.write_jsonl(remote_rows, remote_path)

    diff = _first_difference(local_path, remote_path, "local", "elastic")
    _check(diff is None, f"step E: timeline.jsonl differs, local ({local_path}) vs --elastic "
          f"({remote_path}): {diff}")
    _proof(f"step E OK: timeline byte-identical — {len(local_rows)} entries, "
          f"{os.path.getsize(local_path)} bytes, local == --elastic")


# --------------------------------------------------------------------------- #
# Orchestration.
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="scripts/e2e_elastic.py",
        description="the live-Elasticsearch end-to-end gate: a real byakugan.elastic.load push, "
                    "the CAR-name aliases, the byakugan_loader least-privilege identity, an "
                    "idempotent re-push and a byte-identical byakugan.timeline --elastic, against "
                    "a real Elasticsearch + Kibana (elastic/docker-compose.yml, in CI).")
    ap.add_argument("--es-url", default="", help="Elasticsearch base URL (e.g. http://127.0.0.1:9201)")
    ap.add_argument("--kibana-url", default="", help="Kibana base URL (e.g. http://127.0.0.1:5602)")
    ap.add_argument("--es-user", default="elastic", help="superuser for --setup + the first push (step B)")
    ap.add_argument("--es-password", default="")
    ap.add_argument("--loader-user", default="byakugan_loader",
                    help="the least-privilege identity for the routine re-push (step D)")
    ap.add_argument("--loader-password", default="")
    ap.add_argument("--namespace", default="e2e", help="the Elastic data-stream namespace to use")
    ap.add_argument("--work", default="", help="working directory (default: a fresh tempdir)")
    ap.add_argument("--offline-selftest", action="store_true",
                    help="build the tree + the local timeline only, assert tree/count invariants, "
                        "and exit — no network. Proves this script's own logic without a live cluster.")
    args = ap.parse_args(argv)

    work_dir = args.work or tempfile.mkdtemp(prefix="byakugan-e2e-")
    os.makedirs(work_dir, exist_ok=True)
    marker = uuid.uuid4().hex[:12]

    _proof(f"step A: materialising a synthetic CAR tree ({N_SOURCES} sources) under {work_dir}")
    car_dir, info = build_tree(work_dir, marker)
    _proof(f"step A OK: {N_SOURCES} sources, {N_SOURCES * OBJECTS_PER_SOURCE} objects, "
          f"{N_SOURCES * EDGES_PER_SOURCE} relationship edges, no .db files under {car_dir}")

    if args.offline_selftest:
        local_rows = timeline.build_timeline(car_dir)
        local_path = os.path.join(work_dir, "timeline.local.jsonl")
        timeline.write_jsonl(local_rows, local_path)
        n_obj = sum(1 for r in local_rows if r["kind"] == "object")
        n_rel = sum(1 for r in local_rows if r["kind"] == "relationship")
        _check(n_obj == N_SOURCES * OBJECTS_PER_SOURCE,
              f"offline-selftest: {n_obj} local object entries, expected {N_SOURCES * OBJECTS_PER_SOURCE}")
        _check(n_rel == N_SOURCES * EDGES_PER_SOURCE,
              f"offline-selftest: {n_rel} local relationship entries, expected {N_SOURCES * EDGES_PER_SOURCE}")
        _proof(f"offline-selftest OK: local timeline {local_path} — {len(local_rows)} entries "
              f"({n_obj} objects, {n_rel} relationships); no network used")
        return 0

    _check(bool(args.es_url), "--es-url is required outside --offline-selftest")
    _check(bool(args.kibana_url), "--kibana-url is required outside --offline-selftest (step B imports Kibana assets)")
    _check(bool(args.es_password), "--es-password is required outside --offline-selftest (the superuser password)")
    _check(bool(args.loader_password),
          "--loader-password is required outside --offline-selftest (the byakugan_loader password)")

    out_dir = os.path.join(work_dir, "out")
    try:
        b_summary = step_b_first_load(args, car_dir, out_dir)
        step_c_alias_and_field_proof(args, info)
        d_summary = step_d_idempotent_least_priv(args, car_dir, out_dir)
        step_e_timeline_bytecompare(args, car_dir, work_dir)
    except (OSError, RuntimeError) as e:
        _fail(f"network/Elasticsearch error: {e}")

    total_docs = sum(s["documents"] for s in b_summary["streams"].values())
    already = sum(s["already_present"] for s in d_summary["streams"].values())
    print("")
    print("E2E OK — the live Elasticsearch loop is proven end to end")
    print(f"  namespace:               {args.namespace}")
    print(f"  sources:                 {N_SOURCES}")
    print(f"  streams:                 {', '.join(sorted(b_summary['streams']))}")
    print(f"  documents (1st load):    {total_docs} created, as {args.es_user}")
    print(f"  alias hit:               car.process.command_line == {info['seeded_command_line']!r} -> 1")
    print(f"  re-push (2nd load):      {already}/{total_docs} already_present, as {args.loader_user} "
         "(least privilege)")
    print("  timeline:                byte-identical, local build vs --elastic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

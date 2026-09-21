"""`byakugan load` — a materialised CAR tree -> an Elastic stack's
`logs-car.*` data streams (epic #99 phase 2), per the projection contract
`byakugan.elastic.projection` implements — the DX_DFIR-integrated stack,
Byakugan's own standalone one (`elastic/`), or any other Elasticsearch that
serves the same contract; push mode dials whatever `--es-url` names, over
that URL's own scheme (http or https). Runtime dependencies stay stdlib +
pyyaml (via `byakugan.elastic.projection`) only — no elasticsearch client
library; every network call is stdlib `urllib`.

    python -m byakugan.elastic.load <car-tree> [--out DIR] [--namespace NS] [--force]
        [--es-url URL] [--es-api-key KEY] [--es-user USER]
        [--es-password PASS | --es-password-file FILE] [--es-ca-file FILE]
        [--setup] [--kibana-url URL]

Two modes, selected by `--es-url` (empty = bundle, the default — no network
is ever opened without it, the same opt-in shape as ANAMNESIS_SYMBOLS_ONLINE):

  bundle  render `<out>/elastic/logs-car.<stream>-<ns>.ndjson` (one file per
          data stream actually populated — 13 CAR objects + rel + inferred,
          Elasticsearch `_bulk` NDJSON: a `{"create": {"_id": ...}}` line then
          the document, compact + sorted-key JSON for byte-determinism) plus
          `elastic/manifest.json` (contract version, namespace, per-stream
          doc count/filename/sha256, per-source record/skip counts) and
          `<out>/load.txt` (the same, human-readable, also echoed to stderr).
  push    everything bundle mode does, then POSTs each bundle to
          `<es>/<stream>/_bulk` in chunks, treats 409 (version_conflict) as
          already-present, and verifies per-stream document counts with an
          `_search` ids query. `--setup` additionally PUTs the rendered
          component/index templates (elastic/projection/rendered/) before
          loading, and — with `--kibana-url` — imports the Kibana bundle.

Discovery mirrors byakugan/timeline.py's `_find_stores`, keyed on the JSONL
export (`car_*.jsonl` — the engine's only on-disk product, no SQLite anywhere):
the input dir itself if it holds any, else every directory beneath it that
does. A row with no parseable
timestamp, or a stream this contract has no home for, is what
`byakugan.elastic.projection` already decides (SKIP_NO_TIMESTAMP / a raised
exception) — this module just counts the outcome.

Deterministic by construction: the same input tree renders byte-identical
bundles every time (the projection is pure, ids are content-derived — see
projection.sha1_id — and every JSON dump here is compact + sort_keys). A
complete previous run (an existing, covering `elastic/manifest.json`, and —
in push mode — one whose push itself succeeded) is a no-op unless `--force`,
mirroring `byakugan build`'s own per-source skip.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import ssl
import sys

from . import projection
from ._http import auth_headers, http_json, ssl_context

BULK_MAX_ACTIONS = 1000
BULK_MAX_BYTES = 4 * 1024 * 1024
VERIFY_BATCH = 1000
_TEMPLATE_META_KEYS = ("template", "composed_of", "index_patterns", "data_stream",
                       "priority", "ignore_missing_component_templates", "_meta")


# --------------------------------------------------------------------------- #
# Discovery (mirrors byakugan/timeline.py's _find_stores, keyed on the JSONL).
# --------------------------------------------------------------------------- #
def find_sources(path: str) -> list[str]:
    """Source directories under `path`: `path` itself if it holds any
    `car_*.jsonl`, else every directory beneath it that does."""
    if glob.glob(os.path.join(path, "car_*.jsonl")):
        return [path]
    return sorted({os.path.dirname(p)
                   for p in glob.glob(os.path.join(path, "**", "car_*.jsonl"), recursive=True)})


# --------------------------------------------------------------------------- #
# Projection: every row of every source -> its stream's (doc_id, doc) list.
# --------------------------------------------------------------------------- #
def _consume(path: str, source_key: str, project, namespace: str, streams: dict,
            stats: dict, skip_reasons: dict, failures: list) -> None:
    if not os.path.isfile(path):
        return
    basename = os.path.basename(path)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                result = project(row, namespace)
            except Exception as e:                                  # noqa: BLE001 — one bad row never aborts the load
                stats["failed"] += 1
                failures.append({"source": source_key, "file": basename, "line": lineno,
                                 "error": str(e)})
                continue
            if result is None:
                stats["skipped"] += 1
                skip_reasons[projection.SKIP_NO_TIMESTAMP] = skip_reasons.get(
                    projection.SKIP_NO_TIMESTAMP, 0) + 1
                continue
            stream, doc_id, doc = result
            streams.setdefault(stream, []).append((doc_id, doc))
            stats["records"] += 1


def project_tree(car_dir: str, sources: list[str], namespace: str) -> dict:
    """Every row of every `car_*.jsonl` under `sources`, projected — streams
    (in first-contributing-source order: sources sorted, then file order
    within a source, per stream — a re-render is byte-identical), per-source
    record/skip/failed counts, skip reasons and failures (JSON parse errors,
    an unrecognised car_object, a node_id-less inferred row — see
    byakugan.elastic.projection's per-function docstrings)."""
    streams: dict[str, list] = {}
    per_source: dict[str, dict] = {}
    skip_reasons: dict[str, int] = {}
    failures: list[dict] = []
    for source in sorted(sources):
        key = os.path.relpath(source, car_dir)
        stats = {"records": 0, "skipped": 0, "failed": 0}
        for obj in sorted(projection.known_objects()):
            _consume(os.path.join(source, f"car_{obj}.jsonl"), key, projection.project_event,
                     namespace, streams, stats, skip_reasons, failures)
        _consume(os.path.join(source, "car_relationships.jsonl"), key,
                 projection.project_relationship, namespace, streams, stats, skip_reasons, failures)
        _consume(os.path.join(source, "car_inferred.jsonl"), key,
                 projection.project_inferred, namespace, streams, stats, skip_reasons, failures)
        per_source[key] = stats
    return {"streams": streams, "per_source": per_source, "skip_reasons": skip_reasons,
           "failures": failures}


# --------------------------------------------------------------------------- #
# Bundle rendering: NDJSON files + manifest.json.
# --------------------------------------------------------------------------- #
def _bulk_pair(doc_id: str, doc: dict) -> tuple[str, str]:
    action = json.dumps({"create": {"_id": doc_id}}, separators=(",", ":"), sort_keys=True)
    body = json.dumps(doc, separators=(",", ":"), sort_keys=True)
    return action, body


def _bundle_text(docs: list[tuple[str, dict]]) -> str:
    parts = []
    for doc_id, doc in docs:
        action, body = _bulk_pair(doc_id, doc)
        parts.append(action)
        parts.append(body)
    return "".join(p + "\n" for p in parts)


def write_bundles(projected: dict, out_dir: str, namespace: str, mode: str,
                  push_ok: bool | None = None) -> dict:
    """`<out_dir>/elastic/logs-car.<stream>-<ns>.ndjson` (one per populated
    stream) + `elastic/manifest.json`. Returns the manifest dict actually
    written (the same shape `read_manifest` reads back)."""
    elastic_dir = os.path.join(out_dir, "elastic")
    os.makedirs(elastic_dir, exist_ok=True)
    stream_manifest = {}
    for stream in sorted(projected["streams"]):
        docs = projected["streams"][stream]
        filename = f"{stream}.ndjson"
        text = _bundle_text(docs)
        with open(os.path.join(elastic_dir, filename), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        stream_manifest[stream] = {"bundle": f"elastic/{filename}", "documents": len(docs),
                                   "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    contract = projection.load_contract()["conventions"].get("contract") or {}
    manifest = {
        "contract": {"name": contract.get("name"), "version": contract.get("version")},
        "namespace": namespace,
        "mode": mode,
        "streams": stream_manifest,
        "sources": projected["per_source"],
    }
    if push_ok is not None:
        manifest["push_ok"] = push_ok
    with open(os.path.join(elastic_dir, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def read_manifest(out_dir: str) -> dict | None:
    path = os.path.join(out_dir, "elastic", "manifest.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _manifest_covers(manifest: dict, sources: list[str], car_dir: str) -> bool:
    have = set((manifest.get("sources") or {}))
    want = {os.path.relpath(s, car_dir) for s in sources}
    return have == want


def _manifest_is_reusable(manifest: dict | None, sources: list[str], car_dir: str, mode: str) -> bool:
    """A previous run this run can skip entirely (mirrors `byakugan build`'s
    per-source skip-if-already-built): the manifest covers exactly today's
    source set, and — in push mode — that previous run's push itself
    succeeded (a bundle-only manifest, or one whose push failed, never
    silently stands in for a real push)."""
    if manifest is None or not _manifest_covers(manifest, sources, car_dir):
        return False
    if mode == "bundle":
        return True
    return manifest.get("mode") == "push" and manifest.get("push_ok") is True


# --------------------------------------------------------------------------- #
# HTTP: auth, TLS, the one request primitive every ES/Kibana call in this
# module goes through — `byakugan.elastic._http` (shared with byakugan.timeline's
# own --elastic fetch; imported above, re-exported here unchanged).
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Push: chunked _bulk, 409 -> already_present, then an ids-query verification.
# --------------------------------------------------------------------------- #
def _chunk_docs(docs: list[tuple[str, dict]], max_actions: int, max_bytes: int):
    chunk: list[tuple[str, str, str]] = []
    size = 0
    for doc_id, doc in docs:
        action, body = _bulk_pair(doc_id, doc)
        pair_bytes = len(action) + len(body) + 2
        if chunk and (len(chunk) >= max_actions or size + pair_bytes > max_bytes):
            yield chunk
            chunk, size = [], 0
        chunk.append((doc_id, action, body))
        size += pair_bytes
    if chunk:
        yield chunk


def push_stream(es_url: str, stream: str, docs: list[tuple[str, dict]], headers: dict,
                context: ssl.SSLContext | None) -> dict:
    created = already_present = failed = 0
    errors: list[str] = []
    for chunk in _chunk_docs(docs, BULK_MAX_ACTIONS, BULK_MAX_BYTES):
        # refresh=wait_for: a bulk write is not SEARCHABLE until a refresh,
        # and the ids-query verification runs immediately after the push —
        # without this it undercounts and books the shortfall as failed (the
        # live e2e gate caught exactly that). wait_for guarantees searchability
        # before the next request without forcing an immediate segment flush,
        # keeping the loader inside the least-privilege writer role (a
        # standalone refresh needs the `maintenance` privilege logs_car_writer
        # deliberately does not have).
        url = f"{es_url}/{stream}/_bulk?refresh=wait_for"
        body = "".join(f"{action}\n{doc_body}\n" for _id, action, doc_body in chunk)
        try:
            status, parsed, raw = http_json(
                url, "POST", body, {**headers, "Content-Type": "application/x-ndjson"}, context)
        except OSError as e:
            failed += len(chunk)
            errors.append(f"chunk of {len(chunk)}: {e}")
            continue
        items = (parsed or {}).get("items") or []
        if len(items) != len(chunk):
            failed += len(chunk)
            errors.append(f"HTTP {status}: unexpected response {raw[:200]!r}")
            continue
        for (doc_id, _a, _b), item in zip(chunk, items):
            result = (item or {}).get("create") or {}
            st = result.get("status")
            if st == 409:
                already_present += 1
            elif isinstance(st, int) and 200 <= st < 300:
                created += 1
            else:
                failed += 1
                if len(errors) < 5:
                    errors.append(f"{doc_id}: {result.get('error') or st}")
    return {"created": created, "already_present": already_present, "failed": failed,
           "errors": errors[:5]}


def verify_stream(es_url: str, stream: str, doc_ids: list[str], headers: dict,
                  context: ssl.SSLContext | None) -> int:
    """The number of `doc_ids` actually present in `stream` (an ids query,
    batched, `size: 0`/`track_total_hits` — the count only, no _source)."""
    total = 0
    for i in range(0, len(doc_ids), VERIFY_BATCH):
        batch = doc_ids[i:i + VERIFY_BATCH]
        body = json.dumps({"query": {"ids": {"values": batch}}, "size": 0,
                           "track_total_hits": True}, separators=(",", ":"))
        status, parsed, raw = http_json(f"{es_url}/{stream}/_search", "POST", body,
                                        {**headers, "Content-Type": "application/json"}, context)
        if status >= 300 or not parsed:
            raise RuntimeError(f"verify {stream}: HTTP {status}: {raw[:200]!r}")
        total += ((parsed.get("hits") or {}).get("total") or {}).get("value") or 0
    return total


def push_all(es_url: str, streams: dict, headers: dict, context: ssl.SSLContext | None) -> dict:
    """Push + verify every stream; per-stream `{created, already_present,
    failed, errors, verified, verify_total}`."""
    out = {}
    for stream in sorted(streams):
        docs = streams[stream]
        result = push_stream(es_url, stream, docs, headers, context)
        try:
            total = verify_stream(es_url, stream, [d for d, _ in docs], headers, context)
        except (RuntimeError, OSError) as e:
            result["verified"] = False
            result["verify_error"] = str(e)
        else:
            result["verify_total"] = total
            result["verified"] = total == len(docs)
            if not result["verified"]:
                result["failed"] += max(0, len(docs) - total)
        out[stream] = result
    return out


# --------------------------------------------------------------------------- #
# Setup: rendered component/index templates + the Kibana bundle.
# --------------------------------------------------------------------------- #
def _template_shape(stored: dict) -> dict:
    return {k: stored[k] for k in _TEMPLATE_META_KEYS if k in stored}


def _apply_template(es_url: str, url_prefix: str, name: str, body: dict, headers: dict,
                    context: ssl.SSLContext | None) -> tuple[bool, str]:
    """(ok, "applied"|"unchanged"|an error message). GET first: a stored
    template whose relevant body already deep-equals `body` is left alone —
    re-setup is then a no-op, which is what makes `SETUP` safe to leave on."""
    url = f"{es_url}/{url_prefix}/{name}"
    status, parsed, _raw = http_json(url, "GET", None, headers, context)
    if status == 200 and parsed:
        entries = parsed.get("component_templates") or parsed.get("index_templates") or []
        if entries:
            stored = entries[0].get("component_template") or entries[0].get("index_template") or {}
            if _template_shape(stored) == _template_shape(body):
                return True, "unchanged"
    status, _parsed, raw = http_json(url, "PUT", json.dumps(body, separators=(",", ":")),
                                     {**headers, "Content-Type": "application/json"}, context)
    if status >= 300:
        return False, f"PUT {url_prefix}/{name} failed: HTTP {status}: {raw[:200]!r}"
    return True, "applied"


def _import_kibana(kibana_url: str, ndjson_path: str, headers: dict,
                   context: ssl.SSLContext | None) -> dict:
    with open(ndjson_path, "rb") as fh:
        content = fh.read()
    boundary = "byakuganload" + hashlib.sha1(content).hexdigest()[:16]
    body = (f"--{boundary}\r\n"
           'Content-Disposition: form-data; name="file"; filename="logs-car-views.ndjson"\r\n'
           "Content-Type: application/ndjson\r\n\r\n").encode("utf-8") + content + \
          f"\r\n--{boundary}--\r\n".encode("utf-8")
    url = f"{kibana_url}/api/saved_objects/_import?overwrite=true"
    try:
        status, parsed, raw = http_json(
            url, "POST", body,
            {**headers, "kbn-xsrf": "true", "Content-Type": f"multipart/form-data; boundary={boundary}"},
            context)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    ok = status < 300 and isinstance(parsed, dict) and parsed.get("success") is True
    out = {"ok": ok, "status": status}
    if not ok:
        out["error"] = (parsed if parsed is not None else raw[:500].decode("utf-8", "replace"))
    return out


def run_setup(es_url: str, headers: dict, context: ssl.SSLContext | None,
             kibana_url: str | None) -> dict:
    """PUT every rendered component template then index template
    (elastic/projection/rendered/), skipping any already applied unchanged;
    with `kibana_url`, also import the rendered Kibana bundle."""
    rendered = os.path.join(projection.MODEL_DIR, "rendered")
    applied: list[str] = []
    unchanged: list[str] = []
    errors: list[str] = []
    for kind, prefix in (("component_templates", "_component_template"),
                         ("index_templates", "_index_template")):
        for path in sorted(glob.glob(os.path.join(rendered, kind, "*.json"))):
            name = os.path.splitext(os.path.basename(path))[0]
            with open(path, encoding="utf-8") as fh:
                body = json.load(fh)
            try:
                ok, action = _apply_template(es_url, prefix, name, body, headers, context)
            except OSError as e:
                ok, action = False, f"PUT {prefix}/{name}: {e}"
            if not ok:
                errors.append(action)
            elif action == "applied":
                applied.append(f"{prefix}/{name}")
            else:
                unchanged.append(f"{prefix}/{name}")
    result = {"applied": applied, "unchanged": unchanged, "ok": not errors}
    if errors:
        result["errors"] = errors
    if kibana_url:
        kibana = _import_kibana(kibana_url, os.path.join(rendered, "kibana", "logs-car-views.ndjson"),
                                headers, context)
        result["kibana"] = kibana
        result["ok"] = result["ok"] and kibana["ok"]
    return result


# --------------------------------------------------------------------------- #
# The human-readable report (load.txt / stderr).
# --------------------------------------------------------------------------- #
def render_report(summary: dict) -> str:
    lines = [f"byakugan load: {summary['car_dir']} -> {summary['out_dir']}/elastic "
            f"(namespace={summary['namespace']}, mode={summary['mode']}, status={summary['status']})"]
    if summary.get("skipped_run"):
        lines.append(f"skipped: a complete manifest already covers this tree "
                     f"({os.path.join(summary['out_dir'], 'elastic', 'manifest.json')}); "
                     "set FORCE to re-render/re-push")
    streams = summary.get("streams") or {}
    if streams:
        lines.append("")
        lines.append("streams:")
        for name in sorted(streams):
            st = streams[name]
            extra = ""
            if summary["mode"] == "push" and "created" in st:
                extra = (f" (created {st['created']}, already_present {st['already_present']}, "
                        f"push_failed {st['failed']}, verified {st['verified']})")
            lines.append(f"  {name}: {st['documents']} document(s){extra}")
    per_source = summary.get("per_source") or {}
    if per_source:
        lines.append("")
        lines.append("sources:")
        for name in sorted(per_source):
            s = per_source[name]
            lines.append(f"  {name}: {s['records']} record(s), {s['skipped']} skipped, "
                        f"{s['failed']} failed")
    skip_reasons = summary.get("skip_reasons") or {}
    if skip_reasons:
        lines.append("")
        lines.append("skips:")
        for reason in sorted(skip_reasons):
            lines.append(f"  {reason}: {skip_reasons[reason]}")
    failures = summary.get("failures") or []
    if failures:
        lines.append("")
        lines.append(f"failures ({len(failures)}):")
        for f in failures[:20]:
            lines.append(f"  {f.get('source', '?')}/{f.get('file', '?')}:{f.get('line', '?')}: "
                        f"{f.get('error', '?')}")
        if len(failures) > 20:
            lines.append(f"  ... and {len(failures) - 20} more")
    setup = summary.get("setup")
    if setup:
        lines.append("")
        lines.append(f"setup: {len(setup.get('applied', []))} applied, "
                    f"{len(setup.get('unchanged', []))} unchanged"
                    + ("" if setup.get("ok", True) else f", errors: {setup.get('errors')}"))
        if "kibana" in setup:
            k = setup["kibana"]
            lines.append(f"  kibana import: {'ok' if k.get('ok') else 'FAILED: ' + str(k.get('error'))}")
    lines.append("")
    lines.append(f"records={summary['records']} processed={summary['processed']} "
                f"skipped={summary['skipped']} failed={summary['failed']}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Orchestration.
# --------------------------------------------------------------------------- #
def run(car_dir: str, out_dir: str, namespace: str, *, es_url: str = "", es_api_key: str = "",
       es_user: str = "", es_password: str = "", es_ca_file: str | None = None,
       kibana_url: str = "", setup: bool = False, force: bool = False) -> dict:
    """The whole `byakugan load` run: discovery (raises `SystemExit` when the
    tree is empty — never touches `out_dir`), the manifest skip-shortcut,
    projection + bundle rendering, and — in push mode — the push/verify and
    optional setup. Returns the summary dict `main()` prints and reports."""
    sources = find_sources(car_dir)
    if not sources:
        raise SystemExit(f"no materialised CAR under {car_dir!r}")

    mode = "push" if es_url else "bundle"
    headers = auth_headers(es_api_key, es_user, es_password) if mode == "push" else {}
    context = ssl_context(es_ca_file) if mode == "push" else None

    setup_result = None
    if mode == "push" and setup:
        setup_result = run_setup(es_url.rstrip("/"), headers, context, kibana_url or None)

    if not force:
        existing = read_manifest(out_dir)
        if _manifest_is_reusable(existing, sources, car_dir, mode):
            streams = existing.get("streams") or {}
            total_docs = sum(s["documents"] for s in streams.values())
            summary = {
                "car_dir": car_dir, "out_dir": out_dir, "namespace": namespace, "mode": mode,
                "sources": sorted(os.path.relpath(s, car_dir) for s in sources),
                "streams": streams, "per_source": existing.get("sources") or {},
                "skip_reasons": {}, "failures": [],
                "records": 0, "processed": 0, "skipped": total_docs, "failed": 0,
                "status": "ok", "skipped_run": True,
            }
            if setup_result is not None:
                summary["setup"] = setup_result
            return summary

    projected = project_tree(car_dir, sources, namespace)
    push_results = None
    if mode == "push":
        push_results = push_all(es_url.rstrip("/"), projected["streams"], headers, context)
        # all([]) is vacuously True: a push with nothing to push (every row
        # skipped for lacking a timestamp) is trivially a clean push, and
        # stays eligible for a later skip-shortcut.
        push_ok = all(r["failed"] == 0 and r.get("verified", True) for r in push_results.values())
    else:
        push_ok = None
    manifest = write_bundles(projected, out_dir, namespace, mode, push_ok=push_ok)

    streams_summary = {}
    for name, info in manifest["streams"].items():
        entry = dict(info)
        if push_results is not None:
            entry.update(push_results.get(name, {}))
        streams_summary[name] = entry

    records = sum(s["documents"] for s in manifest["streams"].values())
    if mode == "bundle":
        processed, failed = records, 0
        status = "ok"
    else:
        failed = sum(r.get("failed", 0) for r in (push_results or {}).values())
        processed = max(0, records - failed)
        status = "ok" if failed == 0 else ("failed" if processed == 0 else "partial")

    summary = {
        "car_dir": car_dir, "out_dir": out_dir, "namespace": namespace, "mode": mode,
        "sources": sorted(os.path.relpath(s, car_dir) for s in sources),
        "streams": streams_summary, "per_source": projected["per_source"],
        "skip_reasons": projected["skip_reasons"], "failures": projected["failures"],
        "records": records, "processed": processed, "skipped": sum(
            s["skipped"] for s in projected["per_source"].values()),
        "failed": failed + sum(s["failed"] for s in projected["per_source"].values()),
        "status": status,
    }
    if setup_result is not None:
        summary["setup"] = setup_result
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="byakugan.elastic.load",
        description="project a materialised CAR tree into Elasticsearch _bulk NDJSON bundles "
                    "(bundle mode), or also push them (push mode, --es-url)")
    ap.add_argument("car_dir", help="a source's car directory, or a tree to aggregate")
    ap.add_argument("--out", help="output directory (default: <car_dir>)")
    ap.add_argument("--namespace", default="default", help="the Elastic data-stream namespace")
    ap.add_argument("--force", action="store_true", help="re-render/re-push even if already complete")
    ap.add_argument("--es-url", default="", help="Elasticsearch base URL (push mode; empty = bundle only)")
    ap.add_argument("--es-api-key", default="")
    ap.add_argument("--es-user", default="")
    ap.add_argument("--es-password", default="")
    ap.add_argument("--es-password-file", default="")
    ap.add_argument("--es-ca-file", default="", help="CA bundle for the Elasticsearch TLS certificate")
    ap.add_argument("--kibana-url", default="", help="also import the Kibana bundle (--setup only)")
    ap.add_argument("--setup", action="store_true",
                    help="apply the rendered index/component templates before loading (push mode only)")
    a = ap.parse_args(argv)

    password = a.es_password
    if a.es_password_file:
        with open(a.es_password_file, encoding="utf-8") as fh:
            password = fh.read().strip()

    summary = run(a.car_dir, a.out or a.car_dir, a.namespace, es_url=a.es_url,
                 es_api_key=a.es_api_key, es_user=a.es_user, es_password=password,
                 es_ca_file=a.es_ca_file or None, kibana_url=a.kibana_url, setup=a.setup,
                 force=a.force)

    report = render_report(summary)
    sys.stderr.write(report)
    with open(os.path.join(summary["out_dir"], "load.txt"), "w", encoding="utf-8") as fh:
        fh.write(report)

    json.dump(summary, sys.stdout, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Build one property-rich, time-ordered CAR timeline from the stores.

Unions the OBJECT events (car.db — every populated CAR field plus the `native`
evidence) and the RELATIONSHIP instances (superset.db — source→verb→target with
confidence/method) into a single timestamp-ordered stream, written as
timeline.jsonl. Point it at one source's car directory, or at a parent tree to
aggregate every source under it.

  python -m byakugan.timeline <car-dir-or-tree> [--out FILE]
         [--host H] [--after ISO] [--before ISO] [--objects-only | --edges-only]

SOURCE (epic #99 phase 5): the same rows can come from Elasticsearch instead
of car.db/superset.db — `--elastic <es-url>` (with `--namespace`, default
"default") builds the timeline from the `logs-car.*-<namespace>` data
streams `byakugan load` populated, via `byakugan.inverse_projection`'s
ECS->CAR inverse of the SAME projection contract `byakugan.load` projects
forward. `<car_dir>` is then only the default --out directory (no car.db is
read). Auth/TLS: `--es-api-key`, or `--es-user` with `--es-password` /
`--es-password-file`, and `--es-ca-file` for the server's CA bundle — the
same flags/shapes `byakugan.load`'s push mode takes, via the same shared
`byakugan._http` helpers. --host/--after/--before, --objects-only/
--edges-only, the output ordering and timeline.jsonl bytes are unchanged
either way: an Elastic-sourced row is converted to the exact same entry
shape a local row already has, then handed to the SAME filter/sort/write
code (`_sort_key`, `write_jsonl`) — this module does not know or care
afterward which tier answered the query.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sqlite3
import sys

from . import inverse_projection
from ._http import auth_headers, http_json, ssl_context
# the one tolerant ISO-8601 parser (mixed renderings, any fraction width) —
# shared with the engine's ts_before marker and the STIX projection
from .normalize import parse_ts as _parse_ts

# ~1000 documents/page (module constant, not a CLI flag — tests lower it via
# monkeypatch to prove multi-page search_after paging on a small fixture; read
# fresh inside _fetch_hits rather than bound as a def-time default, so that
# monkeypatch actually takes effect).
PAGE_SIZE = 1000
_PIT_KEEP_ALIVE = "2m"


def _find_stores(path: str) -> list[str]:
    """The store directories under `path`: `path` itself if it holds a car.db,
    else every directory beneath it that does (aggregate mode)."""
    if os.path.isfile(os.path.join(path, "car.db")):
        return [path]
    return sorted({os.path.dirname(p)
                   for p in glob.glob(os.path.join(path, "**", "car.db"),
                                      recursive=True)})


def _object_entries(car_db: str):
    """One entry per object event, carrying every populated CAR field + native."""
    c = sqlite3.connect(car_db)
    c.row_factory = sqlite3.Row
    try:
        tables = [r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            qt = '"' + t.replace('"', '""') + '"'    # escape the identifier quote
            # only CAR object tables carry the event header; a producer may add
            # its own auxiliary table (Anamnesis's car.db has `image_context`:
            # source_image/source_plugin/record, no timestamp) — skip anything
            # without the header rather than crashing the whole timeline on it
            cols = {r[1] for r in c.execute(f'PRAGMA table_info({qt})')}
            if "timestamp" not in cols:
                continue
            for r in c.execute(f'SELECT * FROM {qt} WHERE timestamp IS NOT NULL'):
                entry = {"timestamp": r["timestamp"], "kind": "object", "object": t}
                for k in r.keys():
                    if k in ("event_id", "native", "timestamp"):
                        continue
                    if r[k] not in (None, ""):
                        entry[k] = r[k]
                if r["native"]:
                    try:
                        nat = {k: v for k, v in json.loads(r["native"]).items()
                               if v not in (None, "")}
                        if nat:
                            entry["native"] = nat
                    except (ValueError, TypeError):
                        pass
                yield entry
    finally:
        c.close()


def _edge_entries(superset_db: str):
    """One entry per relationship instance (source→verb→target, confidence)."""
    if not os.path.exists(superset_db):
        return
    c = sqlite3.connect(superset_db)
    c.row_factory = sqlite3.Row
    try:
        if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                         "AND name='relationship'").fetchone():
            return
        for r in c.execute("SELECT * FROM relationship WHERE timestamp IS NOT NULL"):
            yield {
                "timestamp": r["timestamp"], "kind": "relationship",
                "source_host": r["source_host"],
                "relationship": r["relationship"],
                "source_object": r["source_object"], "source_guid": r["source_guid"],
                "target_object": r["target_object"], "target_guid": r["target_guid"],
                "confidence": r["confidence"], "method": r["method"],
            }
    finally:
        c.close()


def build_timeline(path: str, host: str | None = None, after: str | None = None,
                   before: str | None = None, objects_only: bool = False,
                   edges_only: bool = False) -> list[dict]:
    """The merged, time-ordered timeline (objects + relationship edges)."""
    stores = _find_stores(path)
    if not stores:
        raise SystemExit(f"no car.db found under {path!r}")
    rows: list[dict] = []
    for d in stores:
        if not edges_only:
            rows.extend(_object_entries(os.path.join(d, "car.db")))
        if not objects_only:
            rows.extend(_edge_entries(os.path.join(d, "superset.db")))
    return _filter_and_sort(rows, host, after, before)


def _filter_and_sort(rows: list[dict], host: str | None, after: str | None,
                     before: str | None) -> list[dict]:
    """--host/--after/--before + the canonical ordering — shared by every
    SOURCE (car.db/superset.db locally, or Elasticsearch — see
    build_timeline_from_elastic), so which tier answered the query decides
    nothing about filtering, ordering or (via write_jsonl) the output bytes."""
    if host is not None:
        rows = [e for e in rows if e.get("source_host") == host]
    lo = _parse_ts(after) if after is not None else None
    hi = _parse_ts(before) if before is not None else None
    if after is not None and lo is None:
        raise SystemExit(f"--after: not an ISO-8601 timestamp: {after!r}")
    if before is not None and hi is None:
        raise SystemExit(f"--before: not an ISO-8601 timestamp: {before!r}")
    if lo is not None or hi is not None:
        # a bounded window compares the true instant; an unparseable event
        # timestamp can't be placed, so it's excluded rather than mis-sorted.
        rows = [e for e in rows
                if (dt := _parse_ts(e.get("timestamp"))) is not None
                and (lo is None or dt >= lo) and (hi is None or dt <= hi)]
    return _sort_rows(rows)


# --------------------------------------------------------------------------- #
# SOURCE: Elasticsearch (epic #99 phase 5) — point-in-time + search_after over
# logs-car.*-<namespace>, excluding event.dataset car.inferred (never part of
# the timeline: an inferred_node is reconstructed evidence about an object,
# never a car.db event row — see model/projection/inferred.yml), each hit
# inverted back to the local entry shape (byakugan.inverse_projection), then
# handed to the exact same _filter_and_sort/write_jsonl as the local source.
# --------------------------------------------------------------------------- #
def _pit_open(es_url: str, namespace: str, headers: dict, context) -> str:
    status, parsed, raw = http_json(
        f"{es_url}/logs-car.*-{namespace}/_pit?keep_alive={_PIT_KEEP_ALIVE}",
        "POST", None, headers, context)
    if status >= 300 or not parsed or "id" not in parsed:
        raise RuntimeError(f"open PIT on logs-car.*-{namespace}: HTTP {status}: {raw[:200]!r}")
    return parsed["id"]


def _pit_close(es_url: str, pit_id: str, headers: dict, context) -> None:
    try:
        http_json(f"{es_url}/_pit", "DELETE", json.dumps({"id": pit_id}, separators=(",", ":")),
                 {**headers, "Content-Type": "application/json"}, context)
    except OSError:
        pass                 # best-effort close; an unclosed PIT just expires on its keep_alive


def _fetch_hits(es_url: str, namespace: str, headers: dict, context, page_size: int | None = None):
    """Every logs-car.*-<namespace> document's `_source`, EXCEPT
    event.dataset car.inferred — sorted `@timestamp` asc with the PIT
    tiebreak (`_shard_doc`), `page_size` (default: the module's PAGE_SIZE,
    looked up fresh so a test's monkeypatch takes effect) per `_search`."""
    if page_size is None:
        page_size = PAGE_SIZE
    headers = {**headers, "Content-Type": "application/json"}
    query = {"bool": {"must_not": [{"term": {"event.dataset": "car.inferred"}}]}}
    sort = [{"@timestamp": "asc"}, {"_shard_doc": "asc"}]
    pit_id = _pit_open(es_url, namespace, headers, context)
    try:
        search_after = None
        while True:
            body = {"size": page_size, "pit": {"id": pit_id, "keep_alive": _PIT_KEEP_ALIVE},
                    "sort": sort, "query": query}
            if search_after is not None:
                body["search_after"] = search_after
            status, parsed, raw = http_json(f"{es_url}/_search", "POST",
                                            json.dumps(body, separators=(",", ":")), headers, context)
            if status >= 300 or not parsed:
                raise RuntimeError(f"search logs-car.*-{namespace}: HTTP {status}: {raw[:200]!r}")
            pit_id = parsed.get("pit_id") or pit_id
            hits = (parsed.get("hits") or {}).get("hits") or []
            if not hits:
                return
            for hit in hits:
                yield hit["_source"]
            search_after = hits[-1].get("sort")
            if not search_after:
                return
    finally:
        _pit_close(es_url, pit_id, headers, context)


def _invert_hit(source: dict) -> tuple[bool, dict]:
    """(is_relationship, entry) — the one place a hit's `event.dataset` is
    read to pick which inverse projector (byakugan.inverse_projection) owns
    it."""
    if (source.get("event") or {}).get("dataset") == "car.rel":
        return True, inverse_projection.invert_relationship(source)
    return False, inverse_projection.invert_object(source)


def build_timeline_from_elastic(es_url: str, namespace: str = "default", *,
                                host: str | None = None, after: str | None = None,
                                before: str | None = None, objects_only: bool = False,
                                edges_only: bool = False, es_api_key: str = "", es_user: str = "",
                                es_password: str = "", es_ca_file: str | None = None,
                                page_size: int | None = None) -> list[dict]:
    """The merged, time-ordered timeline built from `logs-car.*-<namespace>`
    instead of car.db/superset.db — same rows, same filters, same order, same
    write_jsonl bytes as `build_timeline` (see module docstring)."""
    headers = auth_headers(es_api_key, es_user, es_password)
    context = ssl_context(es_ca_file)
    rows: list[dict] = []
    try:
        for source in _fetch_hits(es_url.rstrip("/"), namespace, headers, context, page_size):
            is_rel, entry = _invert_hit(source)
            if is_rel and objects_only:
                continue
            if not is_rel and edges_only:
                continue
            rows.append(entry)
    except (OSError, RuntimeError) as e:
        # a connection failure (DNS, refused, TLS, timeout — OSError) or a
        # non-2xx ES response (RuntimeError, see _pit_open/_fetch_hits): the
        # same SystemExit-is-a-config-error contract build_timeline's own
        # --after/--before checks already use, so `byakugan timeline`
        # (byakugan/cli.py's run_engine) reports it cleanly instead of a
        # raw traceback.
        raise SystemExit(f"--elastic {es_url}: {e}") from e
    return _filter_and_sort(rows, host, after, before)


def _primary_key(e: dict):
    """The cheap ordering component: the true instant (unparseable timestamps
    sort last, by their raw string); within one instant an object precedes
    its relationships."""
    dt = _parse_ts(e.get("timestamp"))
    edge = e.get("kind") == "relationship"
    if dt is not None:
        return (0, dt, edge)
    return (1, e.get("timestamp") or "", edge)


def _tie(e: dict) -> str:
    """The collision tiebreak: the entry's own canonical JSON, which makes
    the order (and so, via write_jsonl, the output BYTES) depend only on each
    row's own DATA — never on which tier produced it (car.db/superset.db's
    SQLite enumeration order, or the arbitrary order Elasticsearch's
    search_after pagination happens to return hits in — the --elastic source,
    epic #99 phase 5) or on the otherwise-implementation-defined order rows
    were appended in before the sort. A genuine, byte-identical duplicate row
    ties even on this — the two are interchangeable, so which one sorts first
    is moot."""
    return json.dumps(e, default=str, sort_keys=True)


def _sort_key(e: dict):
    """_primary_key + _tie as one composite — the full canonical ordering of
    a single entry. The bulk path is _sort_rows, which pays _tie's whole-row
    serialisation only for entries that actually collide on _primary_key
    (routine: independent sources sharing whole-second evidence timestamps,
    or two edges off the same event) instead of for every row."""
    return (*_primary_key(e), _tie(e))


def _sort_rows(rows: list[dict]) -> list[dict]:
    """Sort by _primary_key, then re-order only the runs that tied on it by
    _tie — the same ordering as sorting every row by _sort_key (asserted by
    tests), without serialising every row's JSON when few or none collide."""
    keyed = sorted(((_primary_key(e), e) for e in rows), key=lambda ke: ke[0])
    out: list[dict] = []
    i, n = 0, len(keyed)
    while i < n:
        j = i + 1
        while j < n and keyed[j][0] == keyed[i][0]:
            j += 1
        if j - i > 1:
            out.extend(sorted((ke[1] for ke in keyed[i:j]), key=_tie))
        else:
            out.append(keyed[i][1])
        i = j
    return out


def write_jsonl(rows: list[dict], out: str) -> int:
    with open(out, "w", encoding="utf-8") as fh:
        for e in rows:
            fh.write(json.dumps(e, default=str) + "\n")
    return len(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="byakugan.timeline",
        description="one property-rich, time-ordered CAR timeline from car.db + superset.db, "
                    "or (--elastic) from the logs-car.* data streams")
    ap.add_argument("car_dir", help="a source's car directory, or a tree to aggregate "
                    "(--elastic: only the default --out directory; no car.db is read)")
    ap.add_argument("--out", help="output path (default: <car_dir>/timeline.jsonl)")
    ap.add_argument("--host", help="only events whose source_host matches")
    ap.add_argument("--after", help="only events at/after this ISO timestamp")
    ap.add_argument("--before", help="only events at/before this ISO timestamp")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--objects-only", action="store_true")
    g.add_argument("--edges-only", action="store_true")
    ap.add_argument("--elastic", default="",
                    help="Elasticsearch base URL: build the timeline from "
                        "logs-car.*-<namespace> instead of car_dir")
    ap.add_argument("--namespace", default="default", help="the Elastic data-stream namespace "
                    "(--elastic only)")
    ap.add_argument("--es-api-key", default="")
    ap.add_argument("--es-user", default="")
    ap.add_argument("--es-password", default="")
    ap.add_argument("--es-password-file", default="")
    ap.add_argument("--es-ca-file", default="", help="CA bundle for the Elasticsearch TLS certificate")
    a = ap.parse_args(argv)

    if a.elastic:
        password = a.es_password
        if a.es_password_file:
            with open(a.es_password_file, encoding="utf-8") as fh:
                password = fh.read().strip()
        rows = build_timeline_from_elastic(
            a.elastic, a.namespace, host=a.host, after=a.after, before=a.before,
            objects_only=a.objects_only, edges_only=a.edges_only, es_api_key=a.es_api_key,
            es_user=a.es_user, es_password=password, es_ca_file=a.es_ca_file or None)
    else:
        rows = build_timeline(a.car_dir, a.host, a.after, a.before,
                              a.objects_only, a.edges_only)
    out = a.out or os.path.join(a.car_dir, "timeline.jsonl")
    write_jsonl(rows, out)
    json.dump({"car_dir": a.car_dir, "timeline": out, "entries": len(rows),
               "objects": sum(1 for e in rows if e["kind"] == "object"),
               "relationships": sum(1 for e in rows if e["kind"] == "relationship")},
              sys.stdout, default=str)
    sys.stdout.write("\n")
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())

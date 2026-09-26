"""The per-file CAR pipeline — one ingested file, one CAR database (epic #86).

Owner's isolation rule: **each ingested file gets its OWN car database for
enrichment** — enrichment runs only within that file's events, so no source
ever depends on another source being present, and nothing is mixed. Cross-source
("final") enrichment is a separate, optional end-stage over the aggregate,
gated behind the capability determination — never part of the per-file product.

    python -m byakugan --in <file> --out <dir> [--artefacts k1,k2]

One input file -> route to its artefact map(s) -> normalize -> enrich
(self-contained, in memory) -> <out>/car_<object>.jsonl + car_relationships.jsonl
(the downstream ingest contract — DX_DFIR ships the JSONL to Elastic). No
SQLite is written anywhere in this pipeline; the materialised JSONL tree is
the only on-disk product of a build.
An Anamnesis car.db input passes through 1:1 (already finished CAR) — the one
place this repo still reads a `car.db`, because that file is Anamnesis's own
output format, not Byakugan's store (see byakugan/readers.py).

Routing is by filename when --artefacts is not given; a Security log feeds BOTH
its authentication and its user_session maps (same file — the in-file LUID join
between them is legitimately self-contained).

**The parse stage is the Go engine.** Everything from a raw processor file to
the pre-enrichment CAR event stream — line reading, raw-l2t container splitting,
the winevt/jlecmd format adapters, the marker resolver and the spindle identity
— runs in `go/bin/byakugan-parse` (build: `make -C go build`); the CAR map
tests (tests/test_car_*.py, via tests/go_engine.py) drive this engine directly.
Routing, the
per-source layout, enrichment and everything after it stay here in Python; the
Anamnesis car.db passthrough is Python too (it never parsed anything).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from . import enrich, readers, store

# EvtxECmd output is ONE uniform shape across all ~110 Windows channels, so it
# is CONTENT-routed, not filename-routed: every *_EvtxECmd_Output.json feeds the
# whole evtx map family and each map's (Channel, EventId) predicate decides which
# rows it claims (a row matching none is dropped). Adding a channel/EventId is a
# map change, never a routing change.
EVTX_MAPS = ["evtx_security",           # Security 4624/4625/4672 -> authentication
             "evtx_security_sessions",  # Security 4624/4634/4647/4778/4779 -> user_session
             "evtx_process",            # Security 4688 -> process
             "evtx_services",           # System 7045 / Security 4697 -> service
             "evtx_sysmon",             # Sysmon EIDs -> process/flow/file/registry/module/driver/thread
             "evtx_bits",               # BITS-Client 59/60 -> http
             "evtx_rdp",                # TerminalServices 21/24/25 -> user_session
             "evtx_more"]               # 4907/5857/20003/30803/7001/7002/7034 -> file/module/service/flow/user_session
# NB: the Security-audit families (4663/4657/4660/4670/4689/5140/5145/5156/5157/
# 5158/5058 -> file/registry/process/flow/socket) are NOT active — their mappings
# are unvalidated inferences quarantined in ../to-be-validated/evtx_audit.yml
# until confirmed against an audit-enabled capture. Promote from there.

# filename-pattern -> artefact map keys (explicit, first match wins)
ROUTES = [
    ("_EvtxECmd_Output", EVTX_MAPS),
    ("goevtx.jsonl", EVTX_MAPS),        # goevtx (the evtx lane): the same record shape, one file per log
    ("conn.json", ["zeek_conn"]),
    ("dns.json", ["zeek_dns"]),
    ("http.json", ["zeek_http"]),
    ("smtp.json", ["zeek_smtp"]),
    ("files.json", ["zeek_files"]),
    ("ssl.json", ["zeek_ssl"]),        # TLS handshake -> flow (SNI in dest_fqdn)
    ("x509.json", ["zeek_x509"]),      # TLS certificate -> file (fingerprint = sha256)
    # Zeek logs with no dedicated CAR object — routed to nothing EXPLICITLY (known,
    # not unknown): their per-flow detail can enrich the flow by uid at the
    # cascade stage, but they are not CAR objects.
    ("dhcp.json", []),
    ("ntp.json", []), ("snmp.json", []), ("ocsp.json", []), ("weird.json", []),
    ("pe.json", []), ("packet_filter.json", []),
    (".L2tPrefetch", ["plaso_exec_prefetch"]),
    (".L2tWinreg", ["plaso_exec_winreg", "plaso_registry", "plaso_shellitem"]),
    (".L2tSyslog", ["plaso_exec_cron", "l2t_text"]),
    (".L2tCron", ["plaso_exec_cron"]),
    (".L2tFilestat", ["l2t_filestat"]),
    (".L2tMft", ["l2t_mft"]),
    (".L2tUsnjrnl", ["l2t_usnjrnl"]),
    (".L2tWinevt", ["l2t_winevt"]),     # Plaso legacy EVT  -> the winevtx CAR maps
    (".L2tWinevtx", ["l2t_winevt"]),    # Plaso modern EVTX -> the winevtx CAR maps
    (".L2tMsiecf", ["l2t_msiecf"]),     # IE index.dat visits -> http
    (".L2tFirefoxCache", ["l2t_firefox_cache"]),  # -> http (recorded method/status)
    (".L2tSqlite", ["l2t_firefox_places"]),       # firefox page visits -> http (gated by data_type)
    (".L2tJavaIdx", ["l2t_javaidx"]),   # Java download cache -> http
    (".L2tLnk", ["l2t_lnk", "plaso_shellitem"]),  # shortcut target MAC times -> file (+ embedded shell items)
    (".L2tRecycleBinInfo2", ["l2t_recyclebin"]),  # deletion events -> file/delete
    (".L2tRecycleBin", ["l2t_recyclebin"]),
    # l2t tables with NO CAR object — routed to [] EXPLICITLY (known, not
    # unknown): pe = compilation times (no CAR file action); olecf = document
    # internal streams; rplog = restore-point info; fseventsd = macOS flags
    # (2 rows, undecoded). Their rows stay raw.
    (".L2tPe", ["plaso_pecoff"]),        # pe_coff:file -> timestamp-less file record (path + sha256 + PE meta, compile_time native); dll_import/resource -> raw
    (".L2tOlecf", ["plaso_olecf"]),      # olecf:summary_info -> file (doc + authoring meta); olecf:item -> raw
    (".L2tRplog", []),
    (".L2tFseventsd", ["plaso_fseventsd"]),  # macOS FSEvents -> file/modify (never dropped)
    (".L2tEsedb", ["l2t_srum"]),        # Plaso esedb/srum -> flow + process (SRUM)
    ("_RECmd_Batch_", ["recmd_batch"]), # RECmd --json batch output -> registry
    ("jlecmd_AutomaticDestinations", ["jlecmd_dest"]),  # jump lists -> file (via adapter)
    ("jlecmd_CustomDestinations", []),  # pin-centric, no interaction times -> raw
    ("_LECmd_Output", []),              # lnk: the l2t lnk map is canonical (artefact != processor)
    ("recmd_batch.json", ["recmd_batch"]),
    # Get-Sybers Go parsers (DX_DFIR's godfir-toolz lane): ese_dump writes one
    # JSONL per SRUM provider table (only Network/Application usage carry a CAR
    # object — the map leaves the rest raw); prefetch_dump writes one output file.
    ("NetworkDataUsage", ["esedump_srum"]),        # ese_dump SRUM -> flow (network usage)
    ("ApplicationResourceUsage", ["esedump_srum"]),  # ese_dump SRUM -> process (app usage)
    ("PrefetchDump_Output", ["prefetch_dump"]),    # prefetch_dump -> process (execution)
    # The GoDFIR-toolz framework layout (godfir-toolz/<tool>/<item>/<tool>.jsonl,
    # the tools in GODFIR_TOOLS): every Go tool writes one <tool>.jsonl per
    # item, in the record shape the map above already consumes — the file name
    # is the route.
    ("gore.jsonl", ["recmd_batch"]),           # gore registry batch (recmd_batch shape) -> registry
    ("goprefetch.jsonl", ["prefetch_dump"]),   # goprefetch -> process (execution)
    ("gojle.jsonl", ["jlecmd_dest"]),          # gojle jump lists (jlecmd_dest shape) -> file (via adapter)
    # goese writes one <table>.jsonl per SRUM provider table (NetworkDataUsage /
    # ApplicationResourceUsage route above) plus goese.jsonl, its per-table
    # index; the other provider tables (NetworkConnectivityUsage, EnergyUsage,
    # PushNotifications, ...) are SRUM-internal telemetry with no CAR object.
    ("goese.jsonl", []),
    # Go tools with no CAR map yet — routed to nothing EXPLICITLY (known, not
    # unknown): a raw $MFT entry, a shortcut, a $I record, a shellbag, an
    # Amcache/ShimCache entry, a Timeline activity. Their records stay raw.
    ("gomft.jsonl", []), ("gole.jsonl", []), ("gorb.jsonl", []), ("gosbe.jsonl", []),
    ("goamcache.jsonl", []), ("goappcompat.jsonl", []), ("gowxt.jsonl", []),
    (".L2tUtmp", ["l2t_utmp"]),
    (".L2tUtmpx", ["l2t_utmpx"]),
    (".L2tText", ["l2t_text"]),
]

# The GoDFIR-toolz Go tools: each has a godfir-toolz/<tool>/ output dir and a
# <tool>.jsonl route above (mapped, or explicitly to nothing).
GODFIR_TOOLS = ("gore", "gojle", "gole", "goamcache", "goappcompat", "gosbe",
                "gorb", "gomft", "goese", "goprefetch", "gowxt")


def route(path: str) -> list[str]:
    name = os.path.basename(path)
    for pattern, keys in ROUTES:
        if pattern in name:
            return keys
    return []


def _is_raw_l2t(path: str) -> bool:
    """A raw log2timeline json_line file: unwrapped Plaso records (top-level
    data_type + parser, no `Record`), as opposed to the split per-table files
    the l2t maps consume."""
    if not path.endswith(".jsonl"):
        return False
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                r = json.loads(line)
                return isinstance(r, dict) and "data_type" in r and "Record" not in r
    except (OSError, ValueError):
        return False
    return False


# --------------------------------------------------------------------------- #
# the Go parse engine
# --------------------------------------------------------------------------- #
PARSE_BIN_ENV = "BYAKUGAN_PARSE_BIN"


def _repo_parse_bin() -> str:
    """<repo>/go/bin/byakugan-parse, relative to this package."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(repo, "go", "bin", "byakugan-parse")


def parse_binary() -> str:
    """The byakugan-parse binary: $BYAKUGAN_PARSE_BIN, else the repo's own
    go/bin/byakugan-parse, else one on PATH. Missing is fatal and says so —
    file ingestion has no Python fallback any more."""
    env = os.environ.get(PARSE_BIN_ENV)
    if env:
        if os.path.isfile(env) and os.access(env, os.X_OK):
            return env
        raise SystemExit(
            f"{PARSE_BIN_ENV}={env!r} is not an executable file — build the Go "
            f"parse engine with: make -C go build (-> {_repo_parse_bin()}), or "
            f"unset {PARSE_BIN_ENV} to use the repo's own binary / PATH")
    local = _repo_parse_bin()
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    found = shutil.which("byakugan-parse")
    if found:
        return found
    raise SystemExit(
        "byakugan-parse (the Go parse engine) not found — every file source is "
        "parsed by it. Build it with: make -C go build "
        f"(-> {local}), or set {PARSE_BIN_ENV} to an existing binary")


def _run_parse(argv: list[str]) -> subprocess.Popen:
    return subprocess.Popen([parse_binary(), *argv], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)


def _engine_failed(argv: list[str], code: int, err: bytes) -> RuntimeError:
    return RuntimeError(f"byakugan-parse {' '.join(argv)}: exited {code}: "
                        f"{err.decode('utf-8', 'replace').strip()}")


def parse_events(path: str, artefacts: list[str], adapter: str = "none",
                 default_host: str | None = None) -> list[dict]:
    """One file -> its CAR events, in input order (records × artefacts, the
    engine running every map per record — the file is read ONCE).

    The engine emits one `json.dumps(event)` line per event, so `json.loads`
    rebuilds a plain CAR event dict — the shape the CAR map tests assert on
    (tests/test_car_*.py drive this same engine through tests/go_engine.py)."""
    argv = ["parse", "--in", path, "--artefacts", ",".join(artefacts),
            "--adapter", adapter]
    if default_host:
        argv += ["--host", default_host]
    proc = _run_parse(argv)
    events = []
    try:
        for line in proc.stdout:
            ev = json.loads(line)
            # the engine already applied it; re-assert the pipeline's own rule
            # so a falsy-but-not-None fallback host behaves exactly as before
            if not ev.get("source_host"):
                ev["source_host"] = default_host
            events.append(ev)
    finally:
        proc.stdout.close()
        err = proc.stderr.read()
        proc.stderr.close()
        code = proc.wait()
    if code != 0:
        raise _engine_failed(argv, code, err)
    return events


def split_l2t(path: str, out_dir: str) -> dict[str, str]:
    """A raw log2timeline json_line CONTAINER -> {table: file}, split into
    `out_dir` by the engine (same wrapped rows, same physical-line RecordId).
    Insertion order is the order each table's first record appeared."""
    argv = ["split-l2t", "--in", path, "--out-dir", out_dir]
    proc = _run_parse(argv)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise _engine_failed(argv, proc.returncode, err)
    return json.loads(out)["tables"]


def _iter_source_files(in_path: str):
    """The files that make up ONE source. A directory (a Zeek capture, a host's
    event-log export) is a single source: every file under it is routed and
    merged into ONE in-memory working store, so within-source cross-log
    enrichment can run and no other source is depended on. A single file is a
    one-file source."""
    if os.path.isdir(in_path):
        for root, _dirs, files in os.walk(in_path):
            for fn in sorted(files):
                yield os.path.join(root, fn)
    else:
        yield in_path


def process_file(in_path: str, out_dir: str, artefacts: list[str] | None = None,
                 default_host: str | None = None, derive_pass: bool = False) -> dict:
    """One SOURCE -> its own enriched CAR database + JSON export. The source is a
    single file, or a directory whose files together are one source (Zeek's per-
    protocol logs; a host's event-log channels) — same isolation either way.

    `derive_pass` (optional, off by default) adds the DERIVED relationship stage
    (derive.py): data-driven 1:1 links, inferred nodes and content entities,
    exported into car_relationships.jsonl/car_inferred.jsonl beside the object
    JSONL. The additive fold of same-event rows is not part of it — enrich
    folds on every run (relationships.yml dedupe.fold)."""
    os.makedirs(out_dir, exist_ok=True)
    name = os.path.basename(in_path.rstrip("/"))

    if name == "car.db":                       # Anamnesis finished CAR: passthrough
        events = readers.load_anamnesis_car(in_path)
        used = ["memory (passthrough)"]
    else:
        events, used = [], []

        def _consume(arts, path):
            """Hand `path` to the parse engine ONCE with every routed map: it
            runs them per record (content-routing sends an evtx file to all evtx
            maps — re-reading the file per map is what made this O(maps × file))."""
            arts = [a for a in arts if a]
            if not arts:
                return
            for a in arts:
                if a not in used:
                    used.append(a)
            # jlecmd_dest and l2t_winevt are ADAPTER route keys, not plain maps:
            # a jump-list record is flattened per DestListEntry, and a Plaso
            # winevt table is PORTED to the evtx maps (each record reshaped to
            # the EvtxECmd shape, then the whole EVTX_MAPS family run over it —
            # the engine fans the route key out, ir.adapters carries the pair).
            adapter = "none"
            if arts == ["jlecmd_dest"]:
                adapter = "jlecmd"
            elif arts == ["l2t_winevt"]:
                adapter = "winevt"
                for a in EVTX_MAPS:
                    if a not in used:
                        used.append(a)
            events.extend(parse_events(path, arts, adapter=adapter,
                                       default_host=default_host))

        for f in _iter_source_files(in_path):
            if artefacts:
                _consume(artefacts, f)
            elif _is_raw_l2t(f):
                # a raw log2timeline json_line file is a CONTAINER of many
                # parsers; wrap+split it into per-parser tables (the shape the
                # l2t maps expect) and route each table by its name.
                # split under the (disk-backed) output dir — a big container's
                # per-parser tables overflow a tmpfs /tmp (hit for real: 15G
                # tmpfs at 98% killed the two largest sources)
                tmp = tempfile.mkdtemp(prefix=".car_l2t_", dir=out_dir)
                try:
                    for tpath in split_l2t(f, tmp).values():
                        _consume(route(tpath), tpath)
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
            else:
                _consume(route(f), f)

    # enrichment is SELF-CONTAINED: only THIS source's events are in scope; it
    # begins with the fold (D4, additive by default): rows that are the same
    # event become ONE entry holding every contributor's properties
    events = enrich.enrich(events)

    # the engine's working store is IN MEMORY for the duration of this build;
    # export_jsonl is the only on-disk product (car_<object>.jsonl, re-written
    # fresh from this file each run — nothing is ever appended to a stale tree)
    st = store.CarStore()
    st.insert_events(events)
    counts = st.counts()
    written = st.export_jsonl(out_dir)

    # USE the source-manifest structure: emit the manifest for every source that
    # actually contributed (traceability — the materialised tree is paired with
    # a hard file saying "this source gives these objects/actions/properties,
    # derived by this wrapper"), and CAR-validity-check what those sources emit.
    source_ids, source_issues = _write_source_manifests(out_dir, used)

    # the SUPERSET relationship timeline beside the object events: the
    # relationship INSTANCES the cascade produced between these events — a
    # second, granular relationship timeline linking the object rows by guid.
    # car_relationships.jsonl is written unconditionally (below), even when
    # empty — it is the build's done-marker (run_batch's idempotency skip).
    from . import superset
    sup_store = superset.build_from_events(out_dir, events)
    result = {"input": in_path, "artefacts": used, "events": sum(counts.values()),
              "objects": counts, "exported": written, "car_dir": out_dir,
              "sources": source_ids, "source_manifests": os.path.join(out_dir, "sources.yaml"),
              "source_issues": source_issues,
              "relationships": sup_store.counts()["relationships"],
              "relationships_exported": sup_store.counts()["relationships"]}
    if derive_pass:
        # the DERIVED class: strong-identity 1:1 links, reconstructed (flagged)
        # nodes, content entities — recomputed fresh into the SAME in-memory
        # store, then re-exported (both classes) over the declared-only file
        from . import derive
        result.update(derive.derive(events, sup_store, out_dir))
    return result


def _write_source_manifests(out_dir: str, used: list[str]) -> tuple[list[str], list[str]]:
    """Write the source (sensor) manifests for the artefacts that contributed to
    this source's materialised tree, and return (source_ids, CAR-validity
    problems). Makes each source traceable to how it was derived; the manifests
    are generated from the maps."""
    import yaml
    from . import mappings, sources_model
    docs, ids = [], []
    for u in used:
        key = "memory" if u.startswith("memory") else u
        if key in mappings.MAPPINGS:
            docs.append(sources_model.build_source_doc(key)); ids.append(key)
        elif key in sources_model._PASSTHROUGH:      # noqa: SLF001
            docs.append(sources_model.build_passthrough_doc(key)); ids.append(key)
    with open(os.path.join(out_dir, "sources.yaml"), "w", encoding="utf-8") as fh:
        yaml.safe_dump_all(docs, fh, sort_keys=False, allow_unicode=True)
    # a source must never claim coverage outside the CAR data model
    problems = [p for p in sources_model.validate_against_car_model()
                if any(p.startswith(i + ":") for i in ids)]
    return ids, problems


# --------------------------------------------------------------------------- #
# source discovery over a processed tree
# --------------------------------------------------------------------------- #
# A lane's staging directory — `_`-prefixed: processed/_extracted (the shared
# image export the tools parse), windows_logs/_extracted_evtx and
# godfir-toolz/_extracted of the older layouts — holds raw artefacts, never
# processed output, and is not walked. Neither is anything the engine itself
# writes (byakugan/, byakugan-load/, exchange/) nor the detection lane's tree
# (detections/ — the exchange's behaviour bridge reads it, not the CAR build).
def _is_staging(name: str) -> bool:
    return name.startswith("_")


# processed/<leaf> -> (source-name prefix, discoverer). The leaf is the TOOL
# (DX_DFIR's `processed/<tool>/[<collection>/]…` layout); the older leaves stay
# so a tree written before the rename keeps building.
_ENGINE_LEAVES = ("byakugan", "byakugan-load", "exchange", "detections")


def _subdirs(path: str) -> list[str]:
    """The non-staging subdirectory names of `path`, sorted (none when it is
    not a directory)."""
    if not os.path.isdir(path):
        return []
    return sorted(n for n in os.listdir(path)
                  if os.path.isdir(os.path.join(path, n)) and not _is_staging(n))


def _walk(root: str):
    """os.walk over `root`, staging directories pruned, entries sorted so the
    discovery order (and the source names it yields) is deterministic."""
    for cur, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not _is_staging(d))
        yield cur, dirs, sorted(files)


def _fold(rel: str) -> str:
    """A path relative to a lane root, folded to one source-name segment: the
    same `/`->`_` rule the tools use for their item folders, so a
    collection-scoped tree (`<collection>/<host>/<item>`) names its source
    `<collection>_<host>_<item>`."""
    return rel.replace(os.sep, "_")


# One directory holding any of these is one event-log source: an EvtxECmd
# export (a host's channels, one file each) or a goevtx item (one log:
# <…>/goevtx.jsonl).
_EVTX_SOURCE_FILES = ("_EvtxECmd_Output.json", "goevtx.jsonl")
# per-item index files the plaso image writes beside its output — never a
# raw json_line container
_PLASO_INDEXES = ("timeline.jsonl", "psort.jsonl", "log2timeline.jsonl", "image_export.jsonl")


def _evtx_sources(wl: str, prefix: str):
    """(name, path, host) for every directory under an event-log lane root
    that holds event-log output, at any depth (`<collection>/<host>/<log>/`
    or the flat `<item>/`)."""
    for cur, _dirs, files in _walk(wl):
        if any(f.endswith(_EVTX_SOURCE_FILES) for f in files):
            yield f"{prefix}_{_fold(os.path.relpath(cur, wl))}", cur, None


def _zeek_sources(zk: str):
    """(name, path, host) for every capture directory under zeek/: a directory
    holding Zeek's JSON logs (the `zeek.jsonl` index, or any `*.json`), at any
    depth — `zeek/<capture>/` flat, `zeek/<collection>/<capture>/` scoped. The
    capture directory's own name is the fallback host."""
    for cur, _dirs, files in _walk(zk):
        if cur == zk:
            continue
        if "zeek.jsonl" in files or any(f.endswith(".json") for f in files):
            yield f"zeek_{_fold(os.path.relpath(cur, zk))}", cur, os.path.basename(cur)


def _plaso_sources(root: str, strip_first: bool):
    """(name, path, host) under a plaso lane root: every psort per-item folder
    (`<…>/timeline.jsonl`, at any depth — `jsonl/<source>/` of the older
    layout, `<host>/` or `<collection>/<host>/` of the current one where the
    rendered timeline sits beside the storage file) and every raw
    `<image>.jsonl` json_line container beside the folders — one source each;
    the l2t maps derive the host from the records. `strip_first` drops the
    older layout's `jsonl/` / `storage/` level from the name."""
    if not os.path.isdir(root):
        return
    for cur, _dirs, files in _walk(root):
        rel = os.path.relpath(cur, root)
        parts = [] if rel == "." else rel.split(os.sep)
        if strip_first and parts and parts[0] in ("jsonl", "storage"):
            parts = parts[1:]
        if "timeline.jsonl" in files and parts:
            yield f"l2t_{'_'.join(parts)}", os.path.join(cur, "timeline.jsonl"), None
        for f in files:
            if f.endswith(".jsonl") and f not in _PLASO_INDEXES:
                yield f"l2t_{'_'.join(parts + [f[:-6]])}", os.path.join(cur, f), None


def _framework_sources(gt: str, prefix: str, legacy_hosts: bool):
    """(name, path, host) under a GoDFIR-toolz framework lane root. An ITEM is
    a directory holding `<tool>.jsonl` where `<tool>` names one of its
    ancestor directories beneath the root (the sub-tool level:
    `<tool>/<item>/` flat, `<collection>/<tool>/<host>/<item>/` scoped) or one
    of GODFIR_TOOLS — one source each, and no host is claimed (the item is a
    path, not a host; the maps carry what the records say). An `<item>.part`
    still being written is not an item. With `legacy_hosts`, an immediate
    subdirectory that is neither a tool directory nor holds items is the
    older `godfir-toolz/<host>/` tree: one source per host directory,
    upper-cased name as the fallback host."""
    seen_item = set()
    for cur, _dirs, files in _walk(gt):
        rel = os.path.relpath(cur, gt)
        if rel == ".":
            continue
        ancestors = set(rel.split(os.sep)[:-1])
        if any(f.endswith(".jsonl") and (f[:-6] in ancestors or f[:-6] in GODFIR_TOOLS)
               for f in files):
            seen_item.add(rel.split(os.sep)[0])
            yield f"{prefix}_{_fold(rel)}", cur, None
    if not legacy_hosts:
        return
    for name in _subdirs(gt):
        d = os.path.join(gt, name)
        if name in seen_item or name in GODFIR_TOOLS:
            continue
        # a tool directory by shape (`<item>/<name>.jsonl`, finished or not) is never a host
        if any(os.path.exists(os.path.join(d, it, f"{name}.jsonl{sfx}"))
               for it in _subdirs(d) for sfx in ("", ".part")):
            continue
        yield f"{prefix}_{name}", d, name.upper()


def _memory_sources(mem: str, prefix: str):
    """(name, path, host) for every finished anamnesis image under a memory
    lane root: a directory holding `car.db`, at any depth."""
    for cur, _dirs, files in _walk(mem):
        if "car.db" in files and cur != mem:
            yield f"{prefix}_{_fold(os.path.relpath(cur, mem))}", os.path.join(cur, "car.db"), None


def discover_sources(processed_dir: str) -> list[tuple[str, str, str | None]]:
    """The CAR sources under a processed tree, honouring the isolation rule
    (one source -> one working store). Returns (source_name, in_path, default_host).

    The tree is `processed/<tool>/[<collection>/]…` — one leaf per tool, a
    collection-scoped run one level below it, the tool's own per-item
    folders under that (DX_DFIR's `dxdfir process`). Discovery is by the
    files each tool writes, at any depth, so the older flat leaves keep
    building beside the current ones:

    - windowlicker/ (and the older windows_logs/): every directory holding
      goevtx.jsonl (one event log) or *_EvtxECmd_Output.json (a host's
      export) is one source;
    - zeek/: every capture directory (Zeek's JSON logs) is one source;
    - log2timeline/: every psort per-item folder (timeline.jsonl beside the
      storage file, or the older jsonl/<source>/) and every raw <image>.jsonl
      container — one source each; likewise under a top-level jsonl/ (a
      psort output root mounted directly);
    - windowlicker/, daemonhunter/ (and the older godfir-toolz/): every
      Go-tool item directory (`<tool>.jsonl` under its sub-tool level) is one
      source; godfir-toolz/<host>/ (not a tool dir): one source per host
      directory, upper-cased dir name as the fallback host;
    - anamnesis/ (and the older memory/): every <image>/car.db, Anamnesis'
      finished CAR (passthrough).

    A `_`-prefixed staging directory (the image exports the tools parse) is
    never a source, nor is anything under the engine's own leaves
    (byakugan/, byakugan-load/, exchange/) or detections/.
    """
    out: list[tuple[str, str, str | None]] = []
    j = lambda *p: os.path.join(processed_dir, *p)  # noqa: E731
    for leaf, prefix in (("windows_logs", "windows_logs"), ("windowlicker", "windowlicker")):
        out.extend(sorted(_evtx_sources(j(leaf), prefix)))
    out.extend(sorted(_zeek_sources(j("zeek"))))
    out.extend(_plaso_sources(j("log2timeline"), strip_first=True))
    out.extend(_plaso_sources(j("jsonl"), strip_first=False))
    out.extend(_framework_sources(j("godfir-toolz"), "godfir_toolz", legacy_hosts=True))
    out.extend(_framework_sources(j("windowlicker"), "windowlicker", legacy_hosts=False))
    out.extend(_framework_sources(j("daemonhunter"), "daemonhunter", legacy_hosts=False))
    for leaf in ("memory", "anamnesis"):
        out.extend(sorted(_memory_sources(j(leaf), leaf)))
    # one source, one name: the evtx and framework walks of windowlicker/ can
    # both see a goevtx item (goevtx is a gowindowlicker sub-tool)
    uniq, seen = [], set()
    for src in out:
        if src[0] not in seen:
            seen.add(src[0])
            uniq.append(src)
    return uniq


def run_batch(processed_dir: str, out_root: str, force: bool = False,
              derive_pass: bool = False, stix_export: bool = False) -> list[dict]:
    """Every discovered source -> <out_root>/<source_name>/car_*.jsonl.
    Idempotent: a source whose output car_relationships.jsonl already exists
    (the build's done-marker — written unconditionally, even empty, by
    superset.build_from_events) is skipped unless `force`. Sources run
    SEQUENTIALLY (bounded load); one failing source never stops the rest.
    `stix_export` adds the STIX projection step (stix.py) over each finished
    tree, case-scoped by the source name."""
    results = []
    for name, in_path, host in discover_sources(processed_dir):
        dst = os.path.join(out_root, name)
        if not force and os.path.isfile(os.path.join(dst, "car_relationships.jsonl")):
            results.append({"source": name, "skipped": "exists"})
            continue
        try:
            s = process_file(in_path, dst, default_host=host, derive_pass=derive_pass)
            s["source"] = name
            if stix_export:
                from . import stix
                s["stix"] = stix.export(dst, case=name)
            results.append(s)
        except Exception as exc:                       # noqa: BLE001 — batch isolation
            results.append({"source": name, "error": f"{type(exc).__name__}: {exc}"})
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="byakugan",
        description="one ingested source -> its own enriched, in-memory CAR event collection "
                    "+ per-object JSONL for downstream ingestion")
    ap.add_argument("--in", dest="in_path", help="one processed artefact file/dir (single-source mode)")
    ap.add_argument("--out", dest="out_dir", help="output dir (single-source: this source's materialised "
                    "car_<object>.jsonl tree; batch: the car/ root)")
    ap.add_argument("--artefacts", default=None, help="comma-separated artefact map keys (default: route by filename)")
    ap.add_argument("--host", default=None, help="fallback source_host where the map derives none")
    ap.add_argument("--batch", dest="batch_dir", default=None,
                    help="discover every source under this processed dir and run each (idempotent)")
    ap.add_argument("--force", action="store_true",
                    help="batch: rebuild sources whose car_relationships.jsonl already exists")
    ap.add_argument("--derive", action="store_true",
                    help="also run the DERIVED relationship pass (strong-identity 1:1 links, "
                         "inferred nodes, content entities) into car_relationships.jsonl/car_inferred.jsonl")
    ap.add_argument("--stix", action="store_true",
                    help="also derive the STIX 2.1 bundle (stix_bundle.json) from the finished "
                         "stores (python -m byakugan.stix export)")
    args = ap.parse_args(argv)

    if args.batch_dir:
        out_root = args.out_dir or os.path.join(args.batch_dir, "car")
        results = run_batch(args.batch_dir, out_root, force=args.force,
                            derive_pass=args.derive, stix_export=args.stix)
        json.dump(results, sys.stdout, default=str)
        sys.stdout.write("\n")
        return 0 if any("error" not in r for r in results) else 1

    if not (args.in_path and args.out_dir):
        ap.error("--in/--out (single source) or --batch required")
    arts = [a.strip() for a in args.artefacts.split(",") if a.strip()] if args.artefacts else None
    summary = process_file(args.in_path, args.out_dir, artefacts=arts, default_host=args.host,
                           derive_pass=args.derive)
    if args.stix:
        from . import stix
        summary["stix"] = stix.export(args.out_dir)
    json.dump(summary, sys.stdout, default=str)
    sys.stdout.write("\n")
    return 0 if summary["events"] or summary["artefacts"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

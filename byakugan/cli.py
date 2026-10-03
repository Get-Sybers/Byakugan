"""The `byakugan` command — the engine's multi-tool entry point.

One binary, nine operations, selected by the first argument (the GoDFIR-toolz
container framework's multi-tool dispatcher: name the sub-tool, pass the
environment — DX_DFIR drives the engine image with `-e`/`-v` and nothing else):

    byakugan build       materialise CAR from a processed-evidence tree:
                         pipeline --batch BYAKUGAN_BUILD_INPUT_DIR
                         --out BYAKUGAN_BUILD_OUT_DIR [--force] [--derive] [--stix]
    byakugan timeline    the unified, time-ordered CAR timeline of a car tree:
                         timeline BYAKUGAN_TIMELINE_INPUT_DIR
                         --out BYAKUGAN_TIMELINE_OUT_DIR/timeline.jsonl [--host …]
                         — or, from the logs-car.* Elastic data streams instead
                         of the local materialised JSONL tree (epic #99 phase 5),
                         by passing timeline.py's own [--elastic ES_URL --namespace NS
                         --es-api-key … | --es-user … --es-password …] through
                         BYAKUGAN_TIMELINE_ARGS (no dedicated env var: the
                         container's env-block contract is frozen)
    byakugan verify      the CAR run-through (verify.py) over a materialised
                         tree: verify BYAKUGAN_VERIFY_INPUT_DIR — the report on
                         stderr and in <OUT_DIR>/verify.txt when the output dir
                         is writable (an absent or read-only /output is fine:
                         the gate still runs, stderr only)
    byakugan car-vocab   {object: [car_actions]} — the canonical car_action
                         vocabulary the verify gate checks values against; its
                         stdout IS that JSON, one line
    byakugan load        bulk-load a materialised car tree into an Elastic
                         stack's logs-car.* data streams (the CAR->ECS
                         projection contract, byakugan.elastic.projection/
                         byakugan.elastic.load) — the DX_DFIR-integrated
                         stack, Byakugan's own standalone one (elastic/), or
                         any other Elasticsearch that serves the same contract:
                         load BYAKUGAN_LOAD_INPUT_DIR --out BYAKUGAN_LOAD_OUT_DIR
                         --namespace BYAKUGAN_LOAD_NAMESPACE [--force] — offline
                         Elasticsearch _bulk NDJSON bundles by default, or also
                         pushed over HTTP(S) when BYAKUGAN_LOAD_ES_URL is set
                         (the URL's own scheme; push mode: [--es-url …]
                         [--es-api-key … | --es-user … --es-password …|
                         --es-password-file …] [--es-ca-file …]
                         [--setup [--kibana-url …]])

    byakugan stix-export     the exchange (byakugan.exchange, docs/STIX-Exchange.md):
                             detections -> STIX 2.1 sightings + indicators, the
                             projection's stix_bundle.json files merged through.
                             Every file under BYAKUGAN_STIX_EXPORT_INPUT_DIR is a
                             hits input; _BUNDLES_DIR passes projections through;
                             _RULES_DIR (default: /rules when mounted) resolves
                             indicator patterns; _CASE, _TLP, _CONFIG, _PUSH ->
                             <OUT_DIR>/bundle.json
    byakugan stix-behaviour  the detection lanes joined to the CAR entities they
                             touch: sightings of ATT&CK attack-patterns over the
                             matched rows' spindle-keyed observed-data.
                             INPUT_DIR = the materialised car tree;
                             _DETECTIONS_DIR and _CASE required; _TLP, _PRODUCER,
                             _ATTACK_INDEX -> <OUT_DIR>/behaviour-sightings.json
    byakugan cti-pull        OpenCTI's STIX 2.1 indicators -> the cti-* copy
                             Elastic's indicator-match rule reads, as _bulk
                             NDJSON: _SINCE, _PAGE_SIZE, _MAX_PAGES, _INDEX,
                             _FROM_BUNDLE (offline re-normalise), _BUNDLE_OUT ->
                             <OUT_DIR>/cti-bulk.ndjson (needs no input mount)
    byakugan cti-sightings   indicator-match alerts -> sightings of the
                             platform's own indicators: every file under
                             INPUT_DIR is an alerts input; _CASE, _TLP, _PUSH ->
                             <OUT_DIR>/sightings.json

The exchange sub-tools read the OpenCTI wire from the shared
BYAKUGAN_OPENCTI_URL / BYAKUGAN_OPENCTI_TOKEN / BYAKUGAN_OPENCTI_CONNECTOR_ID
variables (push/pull modes only; a token never rides argv).

Each batch sub-tool reads its own env block — BYAKUGAN_<SUBTOOL>_INPUT_DIR
(default /input, read-only), _OUT_DIR (default /output), _FORCE, _LOG_LEVEL
(error|warn|info|debug, stderr only), _ARGS (extra engine argv) and the
sub-tool's own flags — and prints exactly one JSON summary line on stdout:
`tool`, `subtool`, `version`, `engine_ref`, `status`, `inputs`, `processed`,
`skipped`, `failed`, `records`, `outputs`, `exit`, `started`, `duration_s`,
the engine's own summary as `engine`, `failures` when something failed and
`error` on a config error. The engine's own stdout is captured; progress and
errors go to stderr.

Exit codes follow the framework's uniform table:

    0  ok            build: every source processed or already up to date;
                     timeline: written (or kept); verify: the gate PASSED;
                     load: every stream bundled (push mode: pushed+verified);
                     exchange: bundle valid, written (and pushed/pulled, if asked)
    1  nothing       build: no source produced events; timeline: no
                     materialised CAR under the input dir; verify: no
                     materialised CAR under the input dir — or the gate
                     FAILED (status `failed`, `failed` = the failed checks,
                     `failures` names them); load: no materialised CAR under
                     the input dir (status `nothing`) — or, push mode, every
                     stream failed to push (status `failed`); exchange: the
                     bundle failed validation or a push/pull was refused
                     (status `failed`)
    2  config_error  no sub-tool named, a bad variable, a missing or unreadable
                     input, an unwritable output, an engine argument error
    3  partial       build: at least one source processed, at least one failed;
                     load: push mode, at least one stream pushed, at least one failed

A sub-tool followed by arguments is the pass-through to the engine's own CLI,
with its own stdout and exit code: `byakugan timeline <car_dir> [flags]`,
`byakugan verify [car_dir]`, `byakugan load <car_dir> [flags]`, `byakugan
[build] --in FILE --out DIR | --batch DIR [--out DIR] [--force] [--derive]
[--stix]`. `--version` prints the version and the pinned engine ref
(BYAKUGAN_VERSION / BYAKUGAN_REF), `--print-contract` prints the contract file
at BYAKUGAN_CONTRACT (default /opt/byakugan/contract.yml).
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import time

TOOL = "byakugan"
EXCHANGE_SUBTOOLS = ("stix-export", "stix-behaviour", "cti-pull", "cti-sightings")
SUBTOOLS = ("build", "timeline", "verify", "car-vocab", "load", *EXCHANGE_SUBTOOLS)
BATCH_SUBTOOLS = ("build", "timeline", "verify", "load", *EXCHANGE_SUBTOOLS)
DEFAULT_INPUT_DIR = "/input"
DEFAULT_OUT_DIR = "/output"
CONTRACT_ENV = "BYAKUGAN_CONTRACT"
CONTRACT_DEFAULT = "/opt/byakugan/contract.yml"
LEVELS = {"error": 0, "warn": 1, "info": 2, "debug": 3}
BOOL_TRUE = {"1", "true", "yes", "on"}
BOOL_FALSE = {"", "0", "false", "no", "off"}
EXIT_OK, EXIT_NOTHING, EXIT_CONFIG, EXIT_PARTIAL = 0, 1, 2, 3


class ConfigError(Exception):
    """A bad variable or an unusable mount: exit 2, never a traceback."""


def version() -> str:
    """BYAKUGAN_VERSION (what the image was built as), else the installed
    distribution's version, else a dev marker (run from the source tree)."""
    env = os.environ.get("BYAKUGAN_VERSION")
    if env:
        return env
    try:
        from importlib.metadata import version as dist_version
        return dist_version("byakugan")
    except Exception:                       # noqa: BLE001 — not installed
        return "0.0.0-dev"


def engine_ref() -> str:
    return os.environ.get("BYAKUGAN_REF") or ""


def _probe_writable(path: str) -> str | None:
    """None when a file can be created under the directory `path`, else why
    not (a read-only mount, a missing directory, a path that is a file)."""
    try:
        probe = os.path.join(path, f".probe-{os.getpid()}")
        with open(probe, "w"):
            pass
        os.remove(probe)
    except OSError as e:
        return e.strerror or str(e)
    return None


class Config:
    """The resolved env block of one sub-tool (BYAKUGAN_<SUBTOOL>_*).

    The input dir must exist. The output dir is required (created and probed
    writable) unless `out_optional`: then a dir named explicitly must be
    writable, while the default is used only when it already exists and is
    writable (a mounted, read-write /output) and is None otherwise — an
    absent or read-only default is not an error, and the default path is
    never created as a side effect."""

    def __init__(self, subtool: str, env, out_optional: bool = False, in_optional: bool = False):
        self.subtool = subtool
        self.prefix = f"{TOOL.upper()}_{subtool.upper().replace('-', '_')}"
        self._env = env
        self.input_dir = self.get("INPUT_DIR", DEFAULT_INPUT_DIR)
        self.force = self.bool("FORCE", "0")
        level = self.get("LOG_LEVEL", "info").lower()
        if level not in LEVELS:
            raise ConfigError(f"{self.prefix}_LOG_LEVEL: {level!r} is not one of error|warn|info|debug")
        self.level = LEVELS[level]
        if not in_optional and not os.path.isdir(self.input_dir):
            raise ConfigError(f"{self.prefix}_INPUT_DIR {self.input_dir}: not a readable directory")
        explicit = self._env.get(f"{self.prefix}_OUT_DIR") or ""
        self.out_dir: str | None = explicit or DEFAULT_OUT_DIR
        self.out_dir_unused: str | None = None       # why the optional default is not used
        if out_optional and not explicit:
            why = (_probe_writable(self.out_dir) if os.path.isdir(self.out_dir)
                   else "no such directory")
            if why is not None:
                self.out_dir_unused = f"{self.out_dir}: {why}"
                self.out_dir = None
        if self.out_dir is not None:
            self._ensure_writable(self.out_dir)

    def _ensure_writable(self, path: str) -> None:
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            raise ConfigError(f"{self.prefix}_OUT_DIR {path}: not writable: {e}") from e
        why = _probe_writable(path)
        if why is not None:
            raise ConfigError(f"{self.prefix}_OUT_DIR {path}: not writable: {why}")

    def get(self, suffix: str, default: str) -> str:
        return self._env.get(f"{self.prefix}_{suffix}") or default

    def explicit(self, suffix: str) -> str | None:
        """The raw BYAKUGAN_<SUBTOOL>_<suffix> value with no default applied —
        None when unset or empty. `get`'s own default-vs-set distinction (see
        `out_dir`/`out_dir_unused`), exposed for a sub-tool whose default is
        itself conditional (load's ES_CA_FILE: the default path is used only
        when it exists, but an operator-set path is used as given)."""
        return self._env.get(f"{self.prefix}_{suffix}") or None

    def bool(self, suffix: str, default: str) -> bool:
        raw = self.get(suffix, default).strip().lower()
        if raw in BOOL_TRUE:
            return True
        if raw in BOOL_FALSE:
            return False
        raise ConfigError(f"{self.prefix}_{suffix}: {raw!r} is not a boolean "
                          "(1/true/yes/on or 0/false/no/off)")

    def log(self, level: int, msg: str) -> None:
        if level <= self.level:
            sys.stderr.write(f"{TOOL} {self.subtool}: {msg}\n")
            sys.stderr.flush()


def run_engine(main, argv: list[str]):
    """Run an engine main() with its stdout captured (it prints its own JSON
    summary there); return (return code, captured stdout, error message or
    None). A returned code is the engine's verdict (0 ok, 1 nothing). A
    SystemExit is the engine failing fast — argparse refusing the argv (code
    2), a missing parse binary (a message) — and is reported as the error
    message, a config error; only SystemExit(0)/SystemExit(None) is success."""
    saved = sys.stdout
    buf = io.StringIO()
    sys.stdout = buf
    try:
        rc = main(argv)
        message = None
    except SystemExit as e:
        code = e.code
        if code is None or code == 0:
            rc, message = 0, None
        elif isinstance(code, int):
            rc, message = code, f"engine exited {code} (rejected arguments: {' '.join(argv)})"
        else:
            rc, message = None, str(code)
    finally:
        sys.stdout = saved
    return rc, buf.getvalue(), message


def _engine_json(out: str, cfg: Config, summary: dict, default):
    """The engine's own summary out of its captured stdout: the whole capture,
    else its last line (a stray line before the summary), else kept verbatim."""
    text = out.strip()
    if not text:
        return default
    for candidate in (text, text.splitlines()[-1]):
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    cfg.log(1, "engine summary is not JSON; kept verbatim")
    summary["engine_raw"] = text
    return default


class _Run:
    """One batch run: the summary line, finished exactly once."""

    def __init__(self, subtool: str, stdout):
        self.started = time.time()
        self.stdout = stdout
        self.summary = {
            "tool": TOOL, "subtool": subtool, "version": version(), "engine_ref": engine_ref(),
            "status": "", "inputs": 0, "processed": 0, "skipped": 0, "failed": 0, "records": 0,
            "outputs": [], "exit": 0,
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started)),
            "duration_s": 0.0}

    def finish(self, status: str, code: int) -> int:
        s = self.summary
        s["status"], s["exit"] = status, code
        s["duration_s"] = round(time.time() - self.started, 3)
        self.stdout.write(json.dumps(s, separators=(",", ":"), default=str) + "\n")
        self.stdout.flush()
        return code


def _build(cfg: Config, run: _Run) -> int:
    from .pipeline import main as build_main
    s = run.summary
    argv = ["--batch", cfg.input_dir, "--out", cfg.out_dir]
    if cfg.force:
        argv.append("--force")
    if cfg.bool("DERIVE", "0"):
        argv.append("--derive")
    if cfg.bool("STIX", "0"):
        argv.append("--stix")
    argv += cfg.get("ARGS", "").split()
    cfg.log(3, "engine argv: " + " ".join(argv))
    rc, out, message = run_engine(build_main, argv)
    if message is not None:
        s["error"] = message
        cfg.log(0, f"engine: {message}")
        return run.finish("config_error", EXIT_CONFIG)
    results = _engine_json(out, cfg, s, default=[])
    s["engine"] = results
    rows = [r for r in results if isinstance(r, dict)] if isinstance(results, list) else []
    s["inputs"] = len(rows)
    s["failed"] = sum(1 for r in rows if "error" in r)
    s["skipped"] = sum(1 for r in rows if r.get("skipped"))
    s["processed"] = s["inputs"] - s["failed"] - s["skipped"]
    s["records"] = sum(int(r.get("events", 0) or 0) for r in rows)
    s["outputs"] = sorted({os.path.join(cfg.out_dir, str(r["source"]))
                           for r in rows if r.get("source") and "error" not in r}) or [cfg.out_dir]
    if s["failed"]:
        s["failures"] = [{"item": str(r.get("source") or r.get("input") or "?"), "error": str(r["error"])}
                         for r in rows if "error" in r]
    cfg.log(2, "{inputs} sources: {processed} processed, {skipped} skipped, {failed} failed".format(**s))
    if rc == 0 and s["failed"]:
        return run.finish("partial", EXIT_PARTIAL)
    return run.finish("ok", EXIT_OK) if rc == 0 else run.finish("nothing", EXIT_NOTHING)


def _timeline(cfg: Config, run: _Run) -> int:
    from .timeline import main as timeline_main
    s = run.summary
    out_path = os.path.join(cfg.out_dir, "timeline.jsonl")
    s["inputs"] = 1
    s["outputs"] = [cfg.out_dir]
    if os.path.isfile(out_path) and not cfg.force:
        s["skipped"] = 1
        cfg.log(2, f"skip {cfg.input_dir} (output exists: {out_path})")
        return run.finish("ok", EXIT_OK)
    argv = [cfg.input_dir, "--out", out_path]
    for flag in ("HOST", "AFTER", "BEFORE"):
        if value := cfg.get(flag, ""):
            argv += [f"--{flag.lower()}", value]
    argv += cfg.get("ARGS", "").split()
    cfg.log(3, "engine argv: " + " ".join(argv))
    rc, out, message = run_engine(timeline_main, argv)
    if message is not None:
        s["error"] = message
        cfg.log(0, f"engine: {message}")
        if message.startswith("no materialised CAR"):
            return run.finish("nothing", EXIT_NOTHING)
        return run.finish("config_error", EXIT_CONFIG)
    engine = _engine_json(out, cfg, s, default={})
    s["engine"] = engine
    s["records"] = int(engine.get("entries", 0) or 0) if isinstance(engine, dict) else 0
    s["processed"] = 1
    cfg.log(2, f"timeline {out_path}: {s['records']} entries")
    return run.finish("ok", EXIT_OK) if rc == 0 else run.finish("nothing", EXIT_NOTHING)


def _verify(cfg: Config, run: _Run) -> int:
    """The CAR run-through over BYAKUGAN_VERIFY_INPUT_DIR: `inputs` are the
    source directories holding materialised CAR, `records` the rows the gate
    read, `failed` the checks that failed (named in `failures`); the report
    goes to stderr, and to <OUT_DIR>/verify.txt when there is an output dir."""
    from . import verify
    s = run.summary
    files = [p for obj in (*verify._OBJECTS, verify.RELATIONSHIPS)   # noqa: SLF001
             for p in verify.car_files(cfg.input_dir, obj)]
    s["inputs"] = len({os.path.dirname(p) for p in files})
    if not files:
        cfg.log(1, f"no materialised CAR under {cfg.input_dir} — build the CAR first")
        return run.finish("nothing", EXIT_NOTHING)
    c = verify.run(cfg.input_dir)
    text = verify.report(c)
    sys.stderr.write(text)
    sys.stderr.flush()
    s["engine"] = {"passed": c.passed, "failed": c.failed, "not_exercised": c.skipped,
                   "os_families_covered": c.os_families_covered,
                   "os_families_total": c.os_families_total}
    s["records"] = len(c.rows(verify.CAR))
    s["processed"] = s["inputs"]
    s["failed"] = c.failed
    if c.failed:
        s["failures"] = [{"item": desc} for desc in verify.failures(c)]
    if cfg.out_dir is not None:
        with open(os.path.join(cfg.out_dir, "verify.txt"), "w", encoding="utf-8") as fh:
            fh.write(text)
        s["outputs"] = [cfg.out_dir]
    else:
        cfg.log(2, f"no writable output dir ({cfg.out_dir_unused}): report on stderr only")
    cfg.log(2, f"{s['inputs']} source(s), {s['records']} rows: {c.passed} passed, "
               f"{c.failed} failed, {c.skipped} not exercised")
    return run.finish("failed", EXIT_NOTHING) if c.failed else run.finish("ok", EXIT_OK)


_NAMESPACE_JUNK = re.compile(r"[^a-z0-9_-]+")
_DEFAULT_CA_FILE = "/certs/ca/ca.crt"


def _slugify_namespace(raw: str) -> str | None:
    """BYAKUGAN_LOAD_NAMESPACE -> a slug: lower-cased, every run of characters
    outside [a-z0-9_-] collapsed to one '-'; None (config error) when that is
    empty or starts with -/_/+ (an Elastic data-stream namespace may not)."""
    slug = _NAMESPACE_JUNK.sub("-", raw.lower())
    if not slug or slug[0] in "-_+":
        return None
    return slug


def _load(cfg: Config, run: _Run) -> int:
    """`byakugan load`: BYAKUGAN_LOAD_* -> `byakugan.elastic.load`'s own CLI,
    wired like build/timeline (run_engine + its one JSON summary line as
    `engine`). Bundle mode (BYAKUGAN_LOAD_ES_URL unset) never touches the
    network; the ES_* / KIBANA_URL / SETUP variables are only even resolved
    in push mode."""
    from .elastic.load import main as load_main
    s = run.summary
    ns = _slugify_namespace(cfg.get("NAMESPACE", "default"))
    if ns is None:
        s["error"] = f"{cfg.prefix}_NAMESPACE: {cfg.get('NAMESPACE', 'default')!r} has no usable slug"
        return run.finish("config_error", EXIT_CONFIG)

    argv = [cfg.input_dir, "--out", cfg.out_dir, "--namespace", ns]
    if cfg.force:
        argv.append("--force")
    es_url = cfg.get("ES_URL", "")
    if es_url:
        argv += ["--es-url", es_url]
        if api_key := cfg.get("ES_API_KEY", ""):
            argv += ["--es-api-key", api_key]
        if es_user := cfg.get("ES_USER", ""):
            argv += ["--es-user", es_user]
        if es_password := cfg.get("ES_PASSWORD", ""):
            argv += ["--es-password", es_password]
        if pw_file := cfg.get("ES_PASSWORD_FILE", ""):
            argv += ["--es-password-file", pw_file]
        # the default CA is used only when the certs mount is actually
        # present; an operator-set path is passed through as given (load.py's
        # own ssl context construction is what would fail on a bad one)
        ca_file = cfg.explicit("ES_CA_FILE") or (
            _DEFAULT_CA_FILE if os.path.isfile(_DEFAULT_CA_FILE) else None)
        if ca_file:
            argv += ["--es-ca-file", ca_file]
        if kibana_url := cfg.get("KIBANA_URL", ""):
            argv += ["--kibana-url", kibana_url]
        if cfg.bool("SETUP", "0"):
            argv.append("--setup")
    argv += cfg.get("ARGS", "").split()
    cfg.log(3, "engine argv: " + " ".join(argv))

    rc, out, message = run_engine(load_main, argv)
    if message is not None:
        if message.startswith("no materialised CAR"):
            cfg.log(1, f"nothing to load under {cfg.input_dir}")
            return run.finish("nothing", EXIT_NOTHING)
        s["error"] = message
        cfg.log(0, f"engine: {message}")
        return run.finish("config_error", EXIT_CONFIG)

    engine = _engine_json(out, cfg, s, default={})
    s["engine"] = engine
    e = engine if isinstance(engine, dict) else {}
    for key in ("records", "processed", "skipped", "failed"):
        s[key] = int(e.get(key, 0) or 0)
    s["inputs"] = len(e.get("sources") or [])
    s["outputs"] = [os.path.join(cfg.out_dir, "elastic")]
    if s["failed"]:
        items = []
        for name, info in (e.get("streams") or {}).items():
            if info.get("failed"):
                items.append({"item": name, "error": "; ".join(info.get("errors") or []) or "push failed"})
            elif info.get("verified") is False:
                items.append({"item": name, "error": info.get("verify_error") or "verification shortfall"})
        if items:
            s["failures"] = items
    status = e.get("status", "ok")
    cfg.log(2, f"{s['inputs']} source(s), {s['records']} record(s): "
              f"{e.get('mode', 'bundle')} mode, status {status}")
    if status == "partial":
        return run.finish("partial", EXIT_PARTIAL)
    if status == "failed":
        return run.finish("failed", EXIT_NOTHING)
    return run.finish("ok", EXIT_OK)


def _walk_files(root: str) -> list[str]:
    found: list[str] = []
    for cur, _dirs, files in os.walk(root):
        found.extend(os.path.join(cur, name) for name in files)
    return sorted(found)


def _exchange_argv(cfg: Config, verb: str) -> tuple[list[str] | None, str | None]:
    """The exchange CLI argv for one env block — or (None, why) on a config error."""
    argv: list[str] = [verb]
    if verb == "stix-export":
        for p in _walk_files(cfg.input_dir):
            argv += ["--hits", p]
        bundles_dir = cfg.get("BUNDLES_DIR", "")
        if bundles_dir:
            if not os.path.isdir(bundles_dir):
                return None, f"{cfg.prefix}_BUNDLES_DIR {bundles_dir}: not a readable directory"
            for p in _walk_files(bundles_dir):
                if os.path.basename(p) == "stix_bundle.json":
                    argv += ["--bundle", p]
        # like load's CA default: the /rules mount is used only when present;
        # an operator-set path is passed through as given
        rules_dir = cfg.explicit("RULES_DIR") or ("/rules" if os.path.isdir("/rules") else "")
        if rules_dir:
            argv += ["--rules-dir", rules_dir]
        for flag in ("CASE", "TLP", "CONFIG"):
            if value := cfg.get(flag, ""):
                argv += [f"--{flag.lower()}", value]
        if cfg.bool("PUSH", "0"):
            argv.append("--push")
        argv += ["--out", os.path.join(cfg.out_dir, "bundle.json")]
    elif verb == "stix-behaviour":
        detections_dir = cfg.get("DETECTIONS_DIR", "")
        case = cfg.get("CASE", "")
        if not detections_dir or not case:
            return None, f"{cfg.prefix}_DETECTIONS_DIR and {cfg.prefix}_CASE are required"
        argv += ["--car", cfg.input_dir, "--detections", detections_dir, "--case", case]
        for flag in ("TLP", "PRODUCER", "ATTACK_INDEX"):
            if value := cfg.get(flag, ""):
                argv += [f"--{flag.lower().replace('_', '-')}", value]
        argv += ["--out", os.path.join(cfg.out_dir, "behaviour-sightings.json")]
    elif verb == "cti-pull":
        for flag in ("SINCE", "INDEX", "FROM_BUNDLE", "BUNDLE_OUT", "CONFIG", "PAGE_SIZE", "MAX_PAGES"):
            if value := cfg.get(flag, ""):
                argv += [f"--{flag.lower().replace('_', '-')}", value]
        argv += ["--out", os.path.join(cfg.out_dir, "cti-bulk.ndjson")]
    else:                                                   # cti-sightings
        for p in _walk_files(cfg.input_dir):
            argv += ["--alerts", p]
        for flag in ("CASE", "TLP", "CONFIG"):
            if value := cfg.get(flag, ""):
                argv += [f"--{flag.lower()}", value]
        if cfg.bool("PUSH", "0"):
            argv.append("--push")
        argv += ["--out", os.path.join(cfg.out_dir, "sightings.json")]
    argv.append("--compact")
    argv += cfg.get("ARGS", "").split()
    return argv, None


def _exchange(cfg: Config, run: _Run) -> int:
    """One exchange verb from its env block (byakugan.exchange.cli behind the
    same run_engine plumbing as build/load); the OpenCTI wire rides the shared
    BYAKUGAN_OPENCTI_URL / _TOKEN / _CONNECTOR_ID variables, never argv."""
    from .exchange.cli import main as exchange_main
    s = run.summary
    argv, why = _exchange_argv(cfg, cfg.subtool)
    if why is not None:
        s["error"] = why
        cfg.log(0, f"config error: {why}")
        return run.finish("config_error", EXIT_CONFIG)
    cfg.log(3, "engine argv: " + " ".join(argv))
    rc, out, message = run_engine(exchange_main, argv)
    if rc is None and message is None:
        rc = 0                                  # the exchange returns None on success
    engine = _engine_json(out, cfg, s, default={})
    s["engine"] = engine
    e = engine if isinstance(engine, dict) else {}
    # exit 1 is the exchange's own verdict (validation / push / pull refused,
    # summary already on stdout) — everything else unexpected is config-shaped
    if rc not in (0, 1):
        s["error"] = message or f"engine exited {rc}"
        cfg.log(0, f"engine: {s['error']}")
        return run.finish("config_error", EXIT_CONFIG)
    shape = e.get("summary") if isinstance(e.get("summary"), dict) else {}
    s["records"] = int(shape.get("objects", 0) or 0) or int((e.get("pull") or {}).get("indicators", 0) or 0)
    s["inputs"] = len(e.get("inputs") or []) or 1
    s["processed"] = 1 if rc == 0 else 0
    s["failed"] = 0 if rc == 0 else 1
    s["outputs"] = [cfg.out_dir]
    problems = ((e.get("validation") or {}).get("errors") or [])[:8]
    if rc != 0 and problems:
        s["failures"] = [{"item": cfg.subtool, "error": str(p)} for p in problems]
    cfg.log(2, f"{cfg.subtool}: {'ok' if rc == 0 else 'failed'} ({s['records']} objects)")
    return run.finish("ok", EXIT_OK) if rc == 0 else run.finish("failed", EXIT_NOTHING)


_RUNNERS = {"build": _build, "timeline": _timeline, "verify": _verify, "load": _load,
            **{verb: _exchange for verb in EXCHANGE_SUBTOOLS}}


def batch(subtool: str, env, stdout) -> int:
    """Run one sub-tool from its env block; the one summary line goes to
    `stdout`, everything else to stderr."""
    run = _Run(subtool, stdout)
    try:
        cfg = Config(subtool, env, out_optional=subtool == "verify",
                     in_optional=subtool == "cti-pull")
    except ConfigError as e:
        run.summary["error"] = str(e)
        sys.stderr.write(f"{TOOL} {subtool}: config error: {e}\n")
        return run.finish("config_error", EXIT_CONFIG)
    return _RUNNERS[subtool](cfg, run)


def car_vocab() -> int:
    from . import carmodel
    model = carmodel.load()
    json.dump({obj: sorted(model[obj].get("actions", [])) for obj in model}, sys.stdout)
    sys.stdout.write("\n")
    return 0


def print_contract() -> int:
    path = os.environ.get(CONTRACT_ENV) or CONTRACT_DEFAULT
    try:
        with open(path, encoding="utf-8") as fh:
            sys.stdout.write(fh.read())
    except OSError as e:
        sys.stderr.write(f"{TOOL}: no contract at {path} ({e.strerror}); set {CONTRACT_ENV}\n")
        return EXIT_CONFIG
    return 0


def usage() -> None:
    sys.stderr.write(
        "usage: byakugan build|timeline|verify|load   (env-driven batch: BYAKUGAN_<SUBTOOL>_*)\n"
        "       byakugan stix-export|stix-behaviour|cti-pull|cti-sightings   (the exchange, same env contract)\n"
        "       byakugan car-vocab                   (the car_action vocabulary, one JSON line)\n"
        "       byakugan timeline <car_dir> [flags] | byakugan verify [car_dir] | "
        "byakugan load <car_dir> [flags] |\n"
        "       byakugan stix-export|stix-behaviour|cti-pull|cti-sightings <flags...> | "
        "byakugan [build] <pipeline flags...>   (pass-through)\n"
        "       byakugan --version | --print-contract\n")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 1:
        head = argv[0]
        if head.lstrip("-") == "version":
            print(f"{TOOL} {version()} ({engine_ref() or 'unpinned'})")
            return 0
        if head.lstrip("-") == "print-contract":
            return print_contract()
        if head == "car-vocab":
            return car_vocab()
        if head in BATCH_SUBTOOLS:
            return batch(head, os.environ, sys.stdout)
    if not argv:
        usage()
        run = _Run("", sys.stdout)
        run.summary["error"] = f"no sub-tool named ({'|'.join(SUBTOOLS)})"
        return run.finish("config_error", EXIT_CONFIG)
    # pass-through: the engine's own argv
    if argv[0] in EXCHANGE_SUBTOOLS:
        from .exchange.cli import main as exchange_main
        exchange_main(argv)                     # raises SystemExit on any non-zero outcome
        return 0
    if argv[0] == "timeline":
        from .timeline import main as timeline_main
        return timeline_main(argv[1:])
    if argv[0] == "verify":
        from .verify import main as verify_main
        return verify_main(argv[1:])
    if argv[0] == "load":
        from .elastic.load import main as load_main
        return load_main(argv[1:])
    if argv[0] == "car-vocab":
        usage()
        return EXIT_CONFIG
    if argv[0] == "build":
        argv = argv[1:]
    from .pipeline import main as build_main
    return build_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())

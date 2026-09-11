"""Byakugan — Sigma detection over the CAR entries.

PIIAT-MitreCar cascades many sources into normalised CAR objects. This module
lets a **Sigma** rule (the community detection format hayabusa ships thousands
of, each ATT&CK-tagged) detect off those CAR objects DIRECTLY — no evtx, no
per-source event shape. A rule's ``logsource.category`` names the CAR object it
runs over (``process_creation`` -> the ``process`` table); its ``detection``
fields name CAR columns (``CommandLine`` -> ``command_line``, ``Image`` ->
``exe``/``image_path`` ...) resolved through the same field bag every other CAR
consumer reads; its ``tags`` (``attack.t1059.001``) become the analytic's
coverage.

Each rule compiles to a :class:`~piiat_mitrecar.analytics.CarAnalytic` — the
SAME object the pinned MITRE CAR analytics compile to — so hayabusa's corpus and
MITRE's 102 run through one behaviour engine and project to STIX Sightings
identically. A rule whose category is not a CAR object, that names no resolvable
ATT&CK technique, or whose condition/detection cannot compile is skipped and
counted (never a partial that changes the rule's meaning), exactly as the CAR
analytic compiler defers what it cannot honour.

Scope of the compiler (v1): the field-based Sigma most detection rules use —
named selections of ``field|modifier: value`` (``contains`` / ``startswith`` /
``endswith`` / ``re`` / exact; a value list is OR; ``|all`` makes it AND), and a
boolean ``condition`` (``and`` / ``or`` / ``not`` / parens / ``N of sel*`` /
``all|1 of them``). Value-transform modifiers that cannot be honoured over CAR
text (``base64``/``cidr``/``utf16`` ...) make their leaf refuse to match rather
than match loosely. Correlation/aggregation rules are out of scope (deferred).
"""
from __future__ import annotations

import glob
import os
import re

from . import analytics as A
from .analytics import CarAnalytic, Clause, Coverage

# Sigma logsource category -> the CAR (object, action) the rule runs over. Only a
# mapped category is runnable; the action is the object's canonical write action.
LOGSOURCE: dict[str, tuple[str, str]] = {
    "process_creation": ("process", "create"),
    "process_access": ("process", "access"),
    "process_termination": ("process", "terminate"),
    "network_connection": ("flow", "start"),
    "dns_query": ("flow", "message"),
    "image_load": ("module", "load"),
    "driver_load": ("driver", "load"),
    "file_event": ("file", "create"),
    # Sysmon EID 15 (FileCreateStreamHash) writes a new (alternate-data-)stream —
    # a file create; the rules key off TargetFilename/Contents, resolved off the
    # file object like file_event.
    "create_stream_hash": ("file", "create"),
    "file_change": ("file", "modify"),
    "file_delete": ("file", "delete"),
    "registry_set": ("registry", "modify"),
    "registry_add": ("registry", "create"),
    "registry_event": ("registry", "modify"),
    "registry_delete": ("registry", "delete"),
    "create_remote_thread": ("thread", "remote_create"),
}
# The Sigma-field -> CAR-column map is DERIVED from the engine's own artefact
# maps (mappings.MAPPINGS), so it is authoritative and stays in sync: whatever
# Sysmon/Windows field a map reads into a CAR column is exactly how a Sigma rule
# naming that field resolves. Built per CAR object (a field like `ProcessId`
# lands in `pid` on a process event but `owning_pid`/`src_pid` elsewhere — the
# rule's logsource object disambiguates). The raw Sigma name is always tried
# last, so a field a map kept only in `native_extract` still resolves via
# analytics._field's native-bag fallback.


def _marker_fields(marker):
    """The source event field name(s) a normalize marker reads (recursively
    through first/basename/map_value/… wrappers). A bare string is a System
    field name; anything else contributes nothing."""
    if isinstance(marker, str):
        yield marker
        return
    if not isinstance(marker, tuple) or not marker:
        return
    tag = marker[0]
    arg = marker[1] if len(marker) > 1 else None
    if tag in ("payload", "userdata"):
        yield arg[1]                                  # (field, key) -> the key
    elif tag == "const":
        return
    elif tag == "first" or tag == "concat":
        for sub in arg or ():
            yield from _marker_fields(sub)
    elif tag == "map_value" or tag == "regex1":
        yield from _marker_fields(arg[0])
    else:                                             # basename/ext/lower/domain_of/exe_path/host_label/…
        yield from _marker_fields(arg)


def _build_field_map() -> dict[str, dict[str, list[str]]]:
    """{CAR object: {Sigma/source field: [CAR columns]}} from every artefact map."""
    from .mappings import MAPPINGS
    out: dict[str, dict[str, set]] = {}
    for entry in MAPPINGS.values():
        variants = entry["variants"] if isinstance(entry.get("variants"), list) else [(None, entry)]
        for item in variants:
            v = item[1] if isinstance(item, tuple) else item
            if not isinstance(v, dict):
                continue
            obj = v.get("object")
            if not obj:
                continue
            table = out.setdefault(obj, {})
            for car_col, marker in (v.get("props") or {}).items():
                for field in _marker_fields(marker):
                    table.setdefault(field, set()).add(car_col)
    return {obj: {f: sorted(cols) for f, cols in fields.items()} for obj, fields in out.items()}


_FIELDS_BY_OBJECT: dict[str, dict[str, list[str]]] = _build_field_map()
# Transform/alias fields no direct payload mapping captures: Sysmon's combined
# `Hashes` string is split into the CAR hash columns, so a rule matching a digest
# should test all three; the bare algorithm names alias the same columns.
_SUPPLEMENT: dict[str, list[str]] = {
    "Hashes": ["sha256_hash", "sha1_hash", "md5_hash"], "Hash": ["sha256_hash", "sha1_hash", "md5_hash"],
    "md5": ["md5_hash"], "sha1": ["sha1_hash"], "sha256": ["sha256_hash"], "Imphash": ["imphash"],
}


def _car_columns(field: str, obj: str) -> list[str]:
    """The CAR columns a Sigma ``field`` resolves to for a rule over ``obj``,
    plus the raw name last (native-bag fallback via analytics._field)."""
    cols = list(_FIELDS_BY_OBJECT.get(obj, {}).get(field, []))
    for c in _SUPPLEMENT.get(field, []):
        if c not in cols:
            cols.append(c)
    cols.append(field)
    return cols
# fields that only pin the evtx SOURCE (channel/record/provider) — meaningless
# over CAR, so a selection built only of these is treated as satisfied.
_GATE_ONLY = frozenset({"eventid", "channel", "provider", "provider_name", "computer",
                        "eventrecordid", "task", "opcode", "level", "keywords"})
# modifiers whose value transform cannot be honoured over CAR text; their leaf
# refuses to match (conservative — never a loose match).
_UNSUPPORTED_MODS = frozenset({"base64", "base64offset", "cidr", "utf16", "utf16le",
                               "utf16be", "wide", "gzip"})
_TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


# --------------------------------------------------------------- field matching
def _values(row: dict, field: str, obj: str):
    for cand in _car_columns(field, obj):
        v = A._field(row, cand)
        if v not in (None, ""):
            return v
    return None


# Sigma value semantics are LITERAL substring/affix tests where only Sigma's own
# `*`/`?` are wildcards (`\*`/`\?` escape them) — `%` is an ordinary character.
# This is deliberately NOT routed through analytics._cmp, whose CAR-analytic glob
# treats `%envvar%` as a wildcard: a Sigma value such as `%windir:~-1,1%` (a
# cmd.exe obfuscation string, a LITERAL to find, not a pattern) would otherwise
# collapse to a match-everything `.*` and fire the rule on every row.
def _sigma_body(value: str) -> str:
    """A Sigma match value -> a regex body: `*` -> ``.*``, `?` -> ``.`` (Sigma's
    only wildcards; `\\*`/`\\?` are literal), every other char (``%`` included)
    ``re.escape``d literal."""
    out, i, s = [], 0, str(value)
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "*?":
            out.append(re.escape(s[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def _matcher(mode: str, value: str):
    """A one-value matcher ``str -> bool`` for a Sigma leaf modifier."""
    if mode == "re":
        try:
            rx = re.compile(str(value), re.IGNORECASE)
        except re.error:                 # a rule regex we cannot compile can't match
            return lambda sval: False
        return lambda sval: bool(rx.search(sval))
    body = _sigma_body(value)
    if mode == "contains":
        rx = re.compile(body, re.IGNORECASE)
        return lambda sval: bool(rx.search(sval))
    if mode == "startswith":
        rx = re.compile(body, re.IGNORECASE)
        return lambda sval: bool(rx.match(sval))
    if mode == "endswith":
        rx = re.compile(body + r"\Z", re.IGNORECASE)
        return lambda sval: bool(rx.search(sval))
    # exact: the whole value; a bare name (no path separator) also matches the
    # resolved value's BASENAME — CAR fills exe/image_path with a full path, so
    # `Image: cmd.exe` must catch `C:\...\cmd.exe` (analytics._cmp's discipline).
    rx = re.compile(body, re.IGNORECASE)
    bare = not re.search(r"[\\/]", str(value))
    return lambda sval: bool(rx.fullmatch(sval)
                             or (bare and rx.fullmatch(A._basename(sval))))


def _leaf(field: str, mods: list[str], value, obj: str):
    """A ``field|modifiers: value`` predicate over a row of CAR object ``obj``. A
    list value is OR unless ``|all``. Pure closure — captures the matchers."""
    mset = {m.lower() for m in mods}
    if mset & _UNSUPPORTED_MODS:
        return lambda row: False
    is_all = "all" in mset
    if "re" in mset or "regex" in mset:
        mode = "re"
    elif "contains" in mset or "windash" in mset:
        mode = "contains"                # windash approximated as contains (v1)
    elif "startswith" in mset:
        mode = "startswith"
    elif "endswith" in mset:
        mode = "endswith"
    else:
        mode = "exact"

    wants = value if isinstance(value, list) else [value]
    matchers = [_matcher(mode, str(x)) for x in wants if x is not None]
    if not matchers:
        return lambda row: False

    def pred(row):
        val = _values(row, field, obj)
        if val in (None, ""):
            return False
        sval = str(val)
        results = (m(sval) for m in matchers)
        return all(results) if is_all else any(results)
    return pred


def _selection(block, obj: str):
    """A selection block -> predicate over a row of CAR object ``obj``. dict = AND
    over fields; list = OR over sub-blocks; a channel/record-only block =
    always-true (evtx source gate, irrelevant over CAR)."""
    if isinstance(block, list):
        preds = [_selection(b, obj) for b in block]
        return lambda row: any(p(row) for p in preds)
    if not isinstance(block, dict):
        return lambda row: False
    leaves = []
    for key, value in block.items():
        field, *mods = key.split("|")
        if not mods and field.lower() in _GATE_ONLY:
            continue                     # pure evtx gate — irrelevant over CAR
        leaves.append(_leaf(field, mods, value, obj))
    if not leaves:
        return lambda row: True
    return lambda row: all(p(row) for p in leaves)


# ------------------------------------------------------------- condition parser
# A real recursive-descent parser over the Sigma condition grammar (the prototype
# used regex and mangled `N of sel*`). Leaves resolve against the per-row map of
# selection results; quantifiers match selection names by prefix or `them`.
_COND_TOKEN = re.compile(r"\(|\)|\b(?:and|or|not|all|any|of|them)\b|[A-Za-z0-9_*]+", re.IGNORECASE)


def _tokenize(cond: str) -> list[str]:
    return _COND_TOKEN.findall(cond)


class _CondParser:
    def __init__(self, tokens: list[str]):
        self.t = tokens
        self.i = 0

    def _peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def _next(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self._or()
        if self.i != len(self.t):
            raise ValueError("trailing tokens in condition")
        return node

    def _or(self):
        node = self._and()
        while self._peek() == "or":
            self._next()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while self._peek() == "and":
            self._next()
            node = ("and", node, self._not())
        return node

    def _not(self):
        if self._peek() == "not":
            self._next()
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        tok = self._peek()
        if tok == "(":
            self._next()
            node = self._or()
            if self._peek() != ")":
                raise ValueError("unclosed parenthesis in condition")
            self._next()
            return node
        if tok in ("all", "any", "1"):
            quant = self._next().lower()
            if self._peek() == "of":
                self._next()
                target = self._next() if self.i < len(self.t) else "them"
                return ("quant", "all" if quant == "all" else "any", target.lower())
            return ("sel", quant)        # a bare '1'/'all' with no 'of' — degenerate
        # a bare selection name
        return ("sel", self._next())


def _match_names(target: str, names: list[str]) -> list[str]:
    if target == "them":
        return names
    if target.endswith("*"):
        pref = target[:-1]
        return [n for n in names if n.startswith(pref)]
    return [n for n in names if n == target]


def _eval_cond(node, results: dict[str, bool]) -> bool:
    kind = node[0]
    if kind == "sel":
        return bool(results.get(node[1], False))
    if kind == "not":
        return not _eval_cond(node[1], results)
    if kind == "and":
        return _eval_cond(node[1], results) and _eval_cond(node[2], results)
    if kind == "or":
        return _eval_cond(node[1], results) or _eval_cond(node[2], results)
    if kind == "quant":
        _, quant, target = node
        names = _match_names(target, list(results))
        if not names:
            return False
        vals = (results[n] for n in names)
        return all(vals) if quant == "all" else any(vals)
    return False


# ------------------------------------------------------------------ compilation
# ATT&CK Enterprise tactic shortname -> tactic id. Sigma tags tactics by
# shortname (`attack.defense-evasion`); MITRE's CAR coverage uses the id
# (`TA0005`). Byakugan emits the ID so a Sigma hit and a CAR-analytic hit carry
# tactics in ONE format (the 14 enterprise tactics are fixed).
_TACTIC_TA = {
    "reconnaissance": "TA0043", "resource-development": "TA0042", "initial-access": "TA0001",
    "execution": "TA0002", "persistence": "TA0003", "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005", "credential-access": "TA0006", "discovery": "TA0007",
    "lateral-movement": "TA0008", "collection": "TA0009", "command-and-control": "TA0011",
    "exfiltration": "TA0010", "impact": "TA0040",
}


def technique_tags(tags) -> tuple[list[str], list[str]]:
    """(techniques as ``T####[.###]``, tactics as ``TA####`` ids) from a rule's
    ``tags`` — the SAME value formats MITRE's CAR coverage uses, so the two
    detection corpora are interchangeable downstream. An unknown tactic shortname
    is dropped (never a fabricated id)."""
    techs, tactics = [], []
    for t in tags or []:
        s = str(t)
        m = _TECHNIQUE_TAG.fullmatch(s)
        if m:
            tid = m.group(1).upper()
            if tid not in techs:
                techs.append(tid)
        elif s.lower().startswith("attack."):
            ta = _TACTIC_TA.get(s.split(".", 1)[1].lower())
            if ta and ta not in tactics:
                tactics.append(ta)
    return techs, tactics


def compile_rule(doc: dict, skip_ids: set[str] | None = None,
                 skip_deprecated: bool = True) -> CarAnalytic | None:
    """One Sigma rule -> a runnable CarAnalytic, or None (unmappable/untagged/
    uncompilable — the caller counts the reason). A rule whose ``status`` is
    ``deprecated`` (unless ``skip_deprecated`` is off) or whose id is in
    ``skip_ids`` (hayabusa's noisy/exclude lists) is recognised but deferred —
    never runnable, so a broad rule cannot over-fire — with the reason recorded
    like every other deferral."""
    if not isinstance(doc, dict):
        return None
    category = (doc.get("logsource") or {}).get("category")
    mapped = LOGSOURCE.get(category)
    rid = str(doc.get("id") or doc.get("title") or "sigma")
    title = str(doc.get("title") or rid)
    techs, tactics = technique_tags(doc.get("tags"))
    # `grade` is MITRE's detection-COVERAGE confidence — a Sigma rule makes no
    # such self-assessment, so it stays None; the rule's `level` is ALERT
    # SEVERITY, carried on the analytic (a different axis), so a Byakugan and a
    # CAR-analytic coverage are the same shape and their values the same format.
    coverage = [Coverage(technique=t, subtechniques=[], tactics=tactics, grade=None)
                for t in techs]
    an = CarAnalytic(id=rid, title=title, coverage=coverage,
                     severity=str(doc.get("level") or "") or None)
    an.pseudocode = None
    if skip_deprecated and str(doc.get("status") or "").lower() == "deprecated":
        an.skip_reason = "rule status is deprecated"
        return an
    if skip_ids and str(doc.get("id") or "") in skip_ids:
        an.skip_reason = "in hayabusa noisy/exclude rule list"
        return an
    if mapped is None:
        an.skip_reason = f"logsource category {category!r} is not a CAR object"
        return an
    if not coverage:
        an.skip_reason = "no ATT&CK technique tag to flag"
        return an
    detection = doc.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        an.skip_reason = "no detection/condition"
        return an
    condition = detection.get("condition")
    if isinstance(condition, list):      # a list of conditions is their OR
        condition = " or ".join(f"({c})" for c in condition)
    car_object, car_action = mapped
    sels = {k: _selection(v, car_object) for k, v in detection.items() if k != "condition"}
    if not sels:
        an.skip_reason = "no selections"
        return an
    try:
        ast = _CondParser(_tokenize(str(condition))).parse()
    except Exception:                    # noqa: BLE001 — a rule we cannot parse is deferred
        an.skip_reason = "condition did not parse"
        return an

    def predicate(row, _ast=ast, _sels=sels):
        results = {name: pred(row) for name, pred in _sels.items()}
        return _eval_cond(_ast, results)

    an.car_object, an.car_action = car_object, car_action
    an.clauses = [Clause(name="sigma", predicate=predicate, source=str(condition))]
    an.runnable = True
    return an


def hayabusa_skip_ids(sigma_dir: str, config_dir: str | None = None) -> set[str]:
    """The rule ids hayabusa ships as noisy or excluded
    (``config/noisy_rules.txt`` + ``exclude_rules.txt``) — broad, duplicate or
    replaced rules it does not run. Each line is ``<id> # comment``; blank and
    ``#`` lines are skipped. ``config_dir`` defaults to the ``config`` sibling of
    the rules' ``sigma`` directory (hayabusa's layout)."""
    cfg = config_dir or os.path.join(os.path.dirname(os.path.normpath(sigma_dir)), "config")
    ids: set[str] = set()
    for name in ("noisy_rules.txt", "exclude_rules.txt"):
        try:
            with open(os.path.join(cfg, name), encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    head = line.split("#", 1)[0].strip()
                    if head:
                        ids.add(head.split()[0])
        except OSError:
            continue
    return ids


def load_sigma_analytics(sigma_dir: str, honor_lists: bool = True,
                         config_dir: str | None = None) -> list[CarAnalytic]:
    """Every ``*.yml`` under ``sigma_dir`` compiled to a CarAnalytic (runnable
    where it maps + tags + compiles; recognised-but-deferred otherwise). With
    ``honor_lists`` (the default) hayabusa's noisy/exclude lists and any
    ``status: deprecated`` rules are deferred instead of run, exactly as native
    hayabusa skips them; pass ``honor_lists=False`` to compile the whole corpus."""
    import yaml
    skip_ids = hayabusa_skip_ids(sigma_dir, config_dir) if honor_lists else set()
    out: list[CarAnalytic] = []
    for path in sorted(glob.glob(os.path.join(sigma_dir, "**", "*.yml"), recursive=True)):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except (yaml.YAMLError, OSError):
            continue
        an = compile_rule(doc, skip_ids=skip_ids, skip_deprecated=honor_lists)
        if an is not None:
            out.append(an)
    return out


# --------------------------------------------------------------------- running
def run_rule(an: CarAnalytic, rows) -> list:
    """Behaviour hits for one Sigma-compiled analytic over rows. Unlike the CAR
    analytic runner this does NOT gate on ``car_action`` — a Sigma logsource
    scopes by object, not by the CAR write verb."""
    from .analytics import BehaviourHit
    hits = []
    if not an.runnable:
        return hits
    cl = an.clauses[0]
    for row in rows:
        if cl.predicate(row):
            hits.append(BehaviourHit(
                analytic_id=an.id, title=an.title, clause=cl.name,
                car_object=an.car_object, car_action=an.car_action,
                guid=row.get("guid"), timestamp=row.get("timestamp"),
                source_host=row.get("source_host"), coverage=an.coverage))
    return hits


def flag_store(car_db: str, analytics: list[CarAnalytic]) -> list:
    """Sigma-compiled analytics over a finished car.db -> behaviour hits."""
    from . import store
    st = store.CarStore(car_db)
    try:
        objects = {a.car_object for a in analytics if a.runnable}
        rows_by_object = {obj: list(st.iter_object(obj)) for obj in objects}
    finally:
        st.close()
    hits = []
    for an in analytics:
        if an.runnable:
            hits.extend(run_rule(an, rows_by_object.get(an.car_object, [])))
    return hits


def coverage_report(analytics: list[CarAnalytic]) -> dict:
    """What compiled, what deferred (by reason), which CAR objects are covered."""
    runnable = [a for a in analytics if a.runnable]
    reasons: dict[str, int] = {}
    for a in analytics:
        if not a.runnable:
            reasons[a.skip_reason or "?"] = reasons.get(a.skip_reason or "?", 0) + 1
    by_object: dict[str, int] = {}
    for a in runnable:
        by_object[a.car_object] = by_object.get(a.car_object, 0) + 1
    return {"rules": len(analytics), "runnable": len(runnable),
            "by_object": dict(sorted(by_object.items())),
            "deferred": dict(sorted(reasons.items(), key=lambda kv: -kv[1]))}


def main(argv: list[str] | None = None) -> int:
    """`python -m piiat_mitrecar.sigma --rules <dir> [--car <db>]` — compile the
    Sigma corpus to CAR analytics; with a car.db, run them and report the
    behaviour hits (Byakugan detection over the cascaded CAR)."""
    import argparse
    import collections
    import json
    ap = argparse.ArgumentParser(prog="piiat_mitrecar.sigma",
                                 description="Byakugan — Sigma detection over CAR objects")
    ap.add_argument("--rules", required=True, help="a Sigma rules directory (walked for *.yml)")
    ap.add_argument("--car", help="a finished car.db to run the rules over")
    ap.add_argument("--include-noisy", action="store_true",
                    help="compile the whole corpus (do NOT honor hayabusa's "
                         "noisy/exclude lists or skip deprecated rules)")
    args = ap.parse_args(argv)
    ans = load_sigma_analytics(args.rules, honor_lists=not args.include_noisy)
    report = coverage_report(ans)
    if args.car:
        hits = flag_store(args.car, [a for a in ans if a.runnable])
        techs = collections.Counter(c.technique for h in hits for c in h.coverage)
        report["hits"] = len(hits)
        report["rules_fired"] = len({h.analytic_id for h in hits})
        report["entities"] = len({(h.car_object, h.guid) for h in hits})
        report["techniques"] = dict(techs.most_common())
    json.dump(report, __import__("sys").stdout, indent=2)
    __import__("sys").stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

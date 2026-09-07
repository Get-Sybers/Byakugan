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
    "file_change": ("file", "modify"),
    "file_delete": ("file", "delete"),
    "registry_set": ("registry", "modify"),
    "registry_add": ("registry", "create"),
    "registry_event": ("registry", "modify"),
    "registry_delete": ("registry", "delete"),
    "create_remote_thread": ("thread", "remote_create"),
}
# Sigma field -> candidate CAR columns; the raw Sigma name is always tried last,
# and analytics._field then resolves it against the row's `native` evidence bag.
FIELD_MAP: dict[str, list[str]] = {
    "Image": ["exe", "image_path"], "NewProcessName": ["exe", "image_path"],
    "OriginalFileName": ["original_file_name"], "CommandLine": ["command_line"],
    "ParentImage": ["parent_exe", "parent_image_path"],
    "ParentProcessName": ["parent_exe", "parent_image_path"],
    "ParentCommandLine": ["parent_command_line"], "IntegrityLevel": ["integrity_level"],
    "User": ["user"], "CurrentDirectory": ["current_working_directory"],
    "TargetFilename": ["file_path", "file_name"], "TargetObject": ["file_path", "target_name"],
    "ImageLoaded": ["image_path", "exe"], "Signed": ["signature_valid"], "Signature": ["signer"],
    "DestinationIp": ["dest_ip"], "DestinationPort": ["dest_port"],
    "DestinationHostname": ["dest_fqdn", "dest_hostname"], "SourceIp": ["src_ip"],
    "Protocol": ["transport_protocol", "application_protocol"], "QueryName": ["dest_fqdn"],
    "md5": ["md5_hash"], "sha1": ["sha1_hash"], "sha256": ["sha256_hash"],
    "Hashes": ["sha256_hash", "sha1_hash", "md5_hash"],
}
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
def _values(row: dict, field: str):
    for cand in FIELD_MAP.get(field, []) + [field]:
        v = A._field(row, cand)
        if v not in (None, ""):
            return v
    return None


def _leaf(field: str, mods: list[str], value):
    """A ``field|modifiers: value`` predicate over a row. A list value is OR
    unless ``|all``. Pure closure — captures the compiled matcher."""
    mset = {m.lower() for m in mods}
    if mset & _UNSUPPORTED_MODS:
        return lambda row: False
    is_all = "all" in mset
    if "re" in mset or "regex" in mset:
        op, tmpl = "match", "{}"
    elif "contains" in mset or "windash" in mset:
        op, tmpl = "==", "*{}*"          # windash approximated as contains (v1)
    elif "startswith" in mset:
        op, tmpl = "==", "{}*"
    elif "endswith" in mset:
        op, tmpl = "==", "*{}"
    else:
        op, tmpl = "==", "{}"

    wants = value if isinstance(value, list) else [value]
    wants = [tmpl.format(w) if op == "==" else str(w) for w in
             (str(x) for x in wants if x is not None)]

    def pred(row):
        val = _values(row, field)
        results = (A._cmp(val, op, w) for w in wants)
        return all(results) if is_all else any(results)
    return pred


def _selection(block):
    """A selection block -> predicate. dict = AND over fields; list = OR over
    sub-blocks; a channel/record-only block = always-true (evtx source gate)."""
    if isinstance(block, list):
        preds = [_selection(b) for b in block]
        return lambda row: any(p(row) for p in preds)
    if not isinstance(block, dict):
        return lambda row: False
    leaves = []
    for key, value in block.items():
        field, *mods = key.split("|")
        if not mods and field.lower() in _GATE_ONLY:
            continue                     # pure evtx gate — irrelevant over CAR
        leaves.append(_leaf(field, mods, value))
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
            if self._peek() == ")":
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
def technique_tags(tags) -> tuple[list[str], list[str]]:
    """(techniques, tactic-shortnames) from a rule's ``tags``."""
    techs, tactics = [], []
    for t in tags or []:
        s = str(t)
        m = _TECHNIQUE_TAG.fullmatch(s)
        if m:
            tid = m.group(1).upper()
            if tid not in techs:
                techs.append(tid)
        elif s.lower().startswith("attack."):
            tac = s.split(".", 1)[1]
            if not tac.lower().startswith("t") and tac not in tactics:
                tactics.append(tac)
    return techs, tactics


def compile_rule(doc: dict) -> CarAnalytic | None:
    """One Sigma rule -> a runnable CarAnalytic, or None (unmappable/untagged/
    uncompilable — the caller counts the reason)."""
    if not isinstance(doc, dict):
        return None
    category = (doc.get("logsource") or {}).get("category")
    mapped = LOGSOURCE.get(category)
    rid = str(doc.get("id") or doc.get("title") or "sigma")
    title = str(doc.get("title") or rid)
    techs, tactics = technique_tags(doc.get("tags"))
    coverage = [Coverage(technique=t, subtechniques=[], tactics=tactics, grade=doc.get("level"))
                for t in techs]
    an = CarAnalytic(id=rid, title=title, coverage=coverage)
    an.pseudocode = None
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
    sels = {k: _selection(v) for k, v in detection.items() if k != "condition"}
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

    an.car_object, an.car_action = mapped
    an.clauses = [Clause(name="sigma", predicate=predicate, source=str(condition))]
    an.runnable = True
    return an


def load_sigma_analytics(sigma_dir: str) -> list[CarAnalytic]:
    """Every ``*.yml`` under ``sigma_dir`` compiled to a CarAnalytic (runnable
    where it maps + tags + compiles; recognised-but-deferred otherwise)."""
    import yaml
    out: list[CarAnalytic] = []
    for path in sorted(glob.glob(os.path.join(sigma_dir, "**", "*.yml"), recursive=True)):
        try:
            doc = yaml.safe_load(open(path, encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            continue
        an = compile_rule(doc)
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
    args = ap.parse_args(argv)
    ans = load_sigma_analytics(args.rules)
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

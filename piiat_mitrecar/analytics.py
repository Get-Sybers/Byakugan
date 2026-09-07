"""The behaviour layer — MITRE CAR analytics compiled over finished car.db (#12).

The third pillar (README: normalise -> relate -> **flag TTPs**). Where the
cascade winds a deterministic **spindle** identity onto every row and resolves
its relationships, this layer reads those enriched rows back and asks each MITRE
CAR analytic "does this row exhibit your behaviour?" — turning an *artefact*
timeline (what was logged) into a *behaviour* timeline (what the adversary did).

**Data, not code** — the analytics are reconstructed LIVE from the pinned car
submodule (third_party/car/analytics/*.yaml), the same discipline carmodel.py
uses for the object model: nothing is hand-copied, a refresh is a pin bump. The
engine here is only the MECHANIC — a compiler from the analytic's CAR-native
`pseudocode` implementation to a predicate over a car.db object row.

    process = search Process:Create
    wsmprovhost = filter process where (exe == "wsmprovhost.exe"
                                        and parent_exe == "svchost.exe")

compiles to: over the `process` table, `car_action == "create"`, the boolean
`exe`/`parent_exe` predicate. A match is a `BehaviourHit` carrying the matched
row's `guid` (its spindle id — the deterministic evidence link) and the
analytic's ATT&CK `coverage`. The STIX projection (stix.py) turns each hit into
a Sighting of the technique's Attack-Pattern over the row's observed-data — so
identity and behaviour share the one STIX-minted id space (ids.py).

**Honest gating.** Only the single-`search` + `filter` subset compiles today
(the bulk of the corpus — dominated by Process:Create TTPs). An analytic that
needs a join, an aggregation, a search over an object/action the model lacks, or
whose pseudocode does not parse is RECOGNISED but not runnable, with the reason
recorded — never silently dropped, never forced into a wrong match.

    python -m piiat_mitrecar.analytics [--json]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from dataclasses import dataclass, field

from . import carmodel

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
# the analytics are a PINNED submodule — never a vendored copy (build_data_model
# reconstructs the object model from the sibling data_model/ the same way)
_ANALYTICS_DIR = os.path.join(_ROOT, "third_party", "car", "analytics")

# CAR object words that are not one of the 13 objects (so an analytic searching
# them cannot run against a car.db) — aliased or genuinely absent.
_OBJECT_ALIASES = {"usersession": "user_session"}


# -- the model ---------------------------------------------------------------

@dataclass
class Coverage:
    """One ATT&CK mapping of an analytic (from the pinned analytic's `coverage`)."""
    technique: str
    subtechniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    grade: str | None = None


@dataclass
class Clause:
    """One `filter ... where (<expr>)` of an analytic: a named boolean predicate
    over a row, plus the verbatim expression it was compiled from (provenance)."""
    name: str
    predicate: "callable"
    source: str


@dataclass
class CarAnalytic:
    """A CAR analytic reconstructed from the pinned submodule and, where its
    pseudocode compiles, a set of clauses runnable over one car.db object table."""
    id: str
    title: str
    coverage: list[Coverage]
    car_object: str | None = None
    car_action: str | None = None
    clauses: list[Clause] = field(default_factory=list)
    runnable: bool = False
    skip_reason: str | None = None
    pseudocode: str | None = None


@dataclass
class BehaviourHit:
    """One row exhibiting one analytic clause's behaviour — a behaviour-timeline
    entry. `guid` is the matched row's spindle id (the evidence link back to its
    observed-data / car.db row); `coverage` carries the ATT&CK technique(s)."""
    analytic_id: str
    title: str
    clause: str
    car_object: str
    car_action: str
    guid: str | None
    timestamp: str | None
    source_host: str | None
    coverage: list[Coverage]


# -- object / action normalisation -------------------------------------------

def _car_object(word: str) -> str | None:
    """A pseudocode search object word -> the CAR object key it names, or None
    when the model has no such object (an honest 'cannot run')."""
    low = re.sub(r"[^a-z0-9]+", "", word.lower())
    model = set(carmodel.objects())
    if low in model:
        return low
    if _OBJECT_ALIASES.get(low) in model:
        return _OBJECT_ALIASES[low]
    snake = _snake(word)                    # UserSession -> user_session
    return snake if snake in model else None


def _car_action(word: str, obj: str) -> str | None:
    """A search action word -> the object's canonical action, or None."""
    act = _snake(word)
    return act if act in set(carmodel.actions(obj)) else None


def _snake(word: str) -> str:
    """CamelCase / PascalCase / spaced -> snake_case (RemoteCreate ->
    remote_create, BootUp -> boot_up), idempotent on already-snake words."""
    s = re.sub(r"[^A-Za-z0-9]+", "_", word).strip("_")
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", s)
    return s.lower()


# -- field resolution + value matching ---------------------------------------

def _field(row: dict, name: str):
    """The value of a (possibly dotted) field on a car.db row: a canonical
    column first, then the row's `native` bag (a join key the map surfaced) —
    an absent field is None, so its clause simply does not match (honest)."""
    if name in row and not isinstance(row.get(name), dict):
        return row[name]
    cur = row
    for part in name.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    if cur is not None:
        return cur
    # fall back to the native evidence bag under either spelling
    for bag in ("native", "_native"):
        nb = row.get(bag)
        if isinstance(nb, dict):
            cur = nb
            for part in name.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
                if cur is None:
                    break
            if cur is not None:
                return cur
    return None


def _glob_re(pattern: str) -> re.Pattern:
    """A CAR-analytic glob ('*' wildcard, '%envvar%' treated as a wildcard since
    the host env is not expanded here) -> a case-insensitive anchored regex."""
    out = []
    for tok in re.split(r"(\*|%[^%]*%)", pattern):
        if tok == "*" or (tok.startswith("%") and tok.endswith("%") and len(tok) > 1):
            out.append(".*")
        else:
            out.append(re.escape(tok))
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def _is_glob(value: str) -> bool:
    return "*" in value or bool(re.search(r"%[^%]+%", value))


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _basename(p) -> str:
    """The last path component of a Windows/POSIX path (else the value itself)."""
    return re.split(r"[\\/]", str(p))[-1]


def _cmp(field_val, op: str, rhs) -> bool:
    """Compile-time operator semantics over a resolved field value.

    Name fields carry a subtlety: MITRE CAR defines `exe` as the executable's
    NAME (`cmd.exe`), and the analytics compare it that way — but our cascade
    fills `exe`/`image_path` with the full path (`C:\\Windows\\System32\\cmd.exe`).
    So an equality/glob RHS that carries no path separator is matched against the
    value's BASENAME as well as the whole value: `exe == "cmd.exe"` catches a
    path-valued exe, and `exe == "procdump*.exe"` a path-valued procdump — without
    ever loosening a comparison the analytic wrote WITH a path."""
    if field_val is None:
        return op == "!="            # a null is 'not equal' to any literal
    sval = str(field_val)
    if op in ("==", "=", "!="):
        if isinstance(rhs, str) and _is_glob(rhs):
            rx = _glob_re(rhs)
            hit = bool(rx.match(sval))
            if not hit and not re.search(r"[\\/]", rhs):     # bare-name glob -> basename
                hit = bool(rx.match(_basename(sval)))
        else:
            r = str(rhs).lower()
            hit = sval.lower() == r
            if not hit and not re.search(r"[\\/]", str(rhs)):  # bare name -> basename
                hit = _basename(sval).lower() == r
        return hit if op in ("==", "=") else not hit
    if op == "match":
        try:
            return bool(re.search(str(rhs), sval, re.IGNORECASE))
        except re.error:
            return False
    if op in (">", ">=", "<", "<="):
        a, b = _num(field_val), _num(rhs)
        if a is None or b is None:
            a, b = sval, str(rhs)
        return {">" : a > b, ">=": a >= b, "<": a < b, "<=": a <= b}[op]
    if op == "in":
        vals = rhs if isinstance(rhs, list) else [rhs]
        return any(_cmp(field_val, "==", v) for v in vals)
    return False


# -- the pseudocode compiler (recursive descent over the filter expression) ---

_TOKEN = re.compile(r"""
      \s+
    | (?P<lparen>\() | (?P<rparen>\))
    | (?P<lbrack>\[) | (?P<rbrack>\])
    | (?P<comma>,)
    | (?P<op>==|!=|>=|<=|=|>|<)
    | (?P<str>"[^"]*"|'[^']*')
    | (?P<word>[A-Za-z0-9_.%:$*\\/-]+)
""", re.VERBOSE)


class _ExprError(Exception):
    pass


def _lex(expr: str) -> list[tuple[str, str]]:
    toks, i = [], 0
    while i < len(expr):
        m = _TOKEN.match(expr, i)
        if not m:
            raise _ExprError(f"unlexable at {expr[i:i+12]!r}")
        i = m.end()
        kind = m.lastgroup
        if kind is None:                 # whitespace
            continue
        toks.append((kind, m.group()))
    return toks


class _Parser:
    """expr := or ; or := and ('or' and)* ; and := unary ('and' unary)* ;
    unary := 'not' unary | atom ; atom := '(' expr ')' | field OP value |
    field 'match'|'in' value . Produces a predicate closure over a row."""

    def __init__(self, toks: list[tuple[str, str]]):
        self.toks = toks
        self.i = 0

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def _kw(self, word: str) -> bool:
        k, v = self._peek()
        return k == "word" and v.lower() == word

    def parse(self):
        pred = self._or()
        if self.i != len(self.toks):
            raise _ExprError(f"trailing tokens from {self._peek()!r}")
        return pred

    def _or(self):
        left = self._and()
        while self._kw("or"):
            self.i += 1
            right = self._and()
            left = (lambda a, b: (lambda row: a(row) or b(row)))(left, right)
        return left

    def _and(self):
        left = self._unary()
        while self._kw("and"):
            self.i += 1
            right = self._unary()
            left = (lambda a, b: (lambda row: a(row) and b(row)))(left, right)
        return left

    def _unary(self):
        if self._kw("not"):
            self.i += 1
            inner = self._unary()
            return lambda row: not inner(row)
        return self._atom()

    def _atom(self):
        k, v = self._peek()
        if k == "lparen":
            self.i += 1
            inner = self._or()
            if self._peek()[0] != "rparen":
                raise _ExprError("unbalanced '('")
            self.i += 1
            return inner
        return self._comparison()

    def _comparison(self):
        k, v = self._peek()
        if k != "word":
            raise _ExprError(f"expected a field, got {v!r}")
        fieldname = v
        self.i += 1
        k, v = self._peek()
        if k == "op":
            op = v
            self.i += 1
        elif k == "word" and v.lower() in ("match", "in"):
            op = v.lower()
            self.i += 1
        else:
            raise _ExprError(f"expected an operator after {fieldname!r}, got {v!r}")
        rhs = self._value()
        return (lambda fn, o, r: (lambda row: _cmp(_field(row, fn), o, r)))(fieldname, op, rhs)

    def _value(self):
        k, v = self._peek()
        if k == "str":
            self.i += 1
            return v[1:-1]
        if k == "lbrack":                       # [a, b, c]
            self.i += 1
            items = []
            while self._peek()[0] not in ("rbrack", None):
                kk, vv = self._peek()
                if kk == "comma":
                    self.i += 1
                    continue
                items.append(vv[1:-1] if kk == "str" else vv)
                self.i += 1
            if self._peek()[0] != "rbrack":
                raise _ExprError("unbalanced '['")
            self.i += 1
            return items
        if k == "word":
            self.i += 1
            return v
        raise _ExprError(f"expected a value, got {v!r}")


def _compile_expr(expr: str):
    return _Parser(_lex(expr)).parse()


# -- pseudocode -> (object, action, clauses) ---------------------------------

_SEARCH = re.compile(r"(?:(\w+)\s*=\s*)?\bsearch\s+([A-Za-z_]+)\s*:\s*([A-Za-z_]+)")
_FILTER = re.compile(r"(?:(\w+)\s*=\s*)?filter\s+\w+\s+where\s*", re.IGNORECASE)


def _balanced_paren(text: str, start: int) -> tuple[str, int] | None:
    """From the '(' at `start`, the inner expression and the index past ')'."""
    depth, i = 0, start
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i], i + 1
        i += 1
    return None


def compile_pseudocode(code: str) -> tuple[str | None, str | None, list[Clause], str | None]:
    """(object_word, action_word, clauses, reason) for a single-`search` +
    `filter` analytic; `reason` is set (clauses empty) when it cannot compile."""
    searches = _SEARCH.findall(code)
    if not searches:
        return None, None, [], "no `search Object:Action`"
    if len(searches) > 1:
        return None, None, [], "multi-search (join/correlation) — deferred"
    search_var, obj_word, act_word = searches[0]
    if re.search(r"\bjoin\b|\bgroup\b|\bcount\b", code, re.IGNORECASE):
        return obj_word, act_word, [], "join/aggregation — deferred"
    # DEPENDENT logic our single-`filter` subset cannot honour -> defer the WHOLE
    # analytic. Never run a partial that changes the analytic's meaning and
    # manufactures false positives: a service-OUTLIER analytic reduced to its
    # base filter "parent == services.exe" flags every normal service. A `filter`
    # over a NON-search variable is a refinement of an earlier result; `now` /
    # `historic` / a `x = a - b` set difference is a temporal/aggregation step.
    subjects = re.findall(r"\bfilter\s+(\w+)", code, re.IGNORECASE)
    if search_var and any(s != search_var for s in subjects):
        return obj_word, act_word, [], "refinement over a derived set — deferred"
    if re.search(r"\bnow\b|\bhistoric|\bcurrent_|\b\w+\s*=\s*\w+\s*-\s*\w+", code, re.IGNORECASE):
        return obj_word, act_word, [], "temporal/set-difference logic — deferred"

    clauses: list[Clause] = []
    for m in _FILTER.finditer(code):
        name = m.group(1) or f"clause{len(clauses) + 1}"
        lp = code.find("(", m.end())
        if lp == -1:
            continue
        got = _balanced_paren(code, lp)
        if got is None:
            continue
        inner, _ = got
        try:
            pred = _compile_expr(inner.strip())
        except _ExprError:
            continue                    # a malformed clause is skipped, not fatal
        clauses.append(Clause(name=name, predicate=pred, source=inner.strip()))
    if not clauses:
        return obj_word, act_word, [], "no filter clause compiled"
    return obj_word, act_word, clauses, None


# -- loading the pinned analytics --------------------------------------------

def _coverage(doc: dict) -> list[Coverage]:
    out = []
    for c in doc.get("coverage") or []:
        if not isinstance(c, dict) or not c.get("technique"):
            continue
        out.append(Coverage(
            technique=c["technique"],
            subtechniques=list(c.get("subtechniques") or []),
            tactics=list(c.get("tactics") or []),
            grade=c.get("coverage"),
        ))
    return out


def _pseudocode(doc: dict) -> str | None:
    for impl in doc.get("implementations") or []:
        if (impl.get("type") or "").lower() in ("pseudocode", "psuedocode") and impl.get("code"):
            return impl["code"]
    return None


def load_analytics(analytics_dir: str | None = None) -> list[CarAnalytic]:
    """Every CAR analytic in the pinned submodule, each compiled where it can be.
    Recognised-but-not-runnable analytics are returned too, with `skip_reason`."""
    import yaml
    d = analytics_dir or _ANALYTICS_DIR
    files = sorted(glob.glob(os.path.join(d, "*.yaml")))
    if not files:
        raise SystemExit("car analytics submodule not checked out — run: "
                         "git submodule update --init --recursive third_party/car")
    out: list[CarAnalytic] = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict) or not doc.get("id"):
            continue
        an = CarAnalytic(id=doc["id"], title=doc.get("title") or doc["id"],
                         coverage=_coverage(doc))
        code = _pseudocode(doc)
        an.pseudocode = code
        if not code:
            an.skip_reason = "no CAR-native pseudocode implementation"
            out.append(an)
            continue
        obj_word, act_word, clauses, reason = compile_pseudocode(code)
        if reason and not clauses:
            an.skip_reason = reason
            out.append(an)
            continue
        obj = _car_object(obj_word) if obj_word else None
        act = _car_action(act_word, obj) if obj and act_word else None
        if obj is None:
            an.skip_reason = f"search object {obj_word!r} is not a CAR object"
        elif act is None:
            an.skip_reason = f"action {act_word!r} is not a {obj} action"
        elif not an.coverage:
            an.skip_reason = "no ATT&CK coverage to flag"
        else:
            an.car_object, an.car_action, an.clauses = obj, act, clauses
            an.runnable = True
        out.append(an)
    return out


# -- running an analytic over rows -------------------------------------------

def run_analytic(an: CarAnalytic, rows: list[dict]) -> list[BehaviourHit]:
    """Behaviour hits for one runnable analytic over an iterable of car.db rows
    (dicts with `car_action`, `guid`, `timestamp`, `source_host`, canonical
    fields and `native`). One hit per (clause, matching row)."""
    if not an.runnable:
        return []
    hits: list[BehaviourHit] = []
    for row in rows:
        if row.get("car_action") != an.car_action:
            continue
        for cl in an.clauses:
            if cl.predicate(row):
                hits.append(BehaviourHit(
                    analytic_id=an.id, title=an.title, clause=cl.name,
                    car_object=an.car_object, car_action=an.car_action,
                    guid=row.get("guid"), timestamp=row.get("timestamp"),
                    source_host=row.get("source_host"), coverage=an.coverage))
    return hits


def flag_rows(rows_by_object: dict[str, list[dict]],
              analytics: list[CarAnalytic] | None = None) -> list[BehaviourHit]:
    """All runnable analytics over rows grouped by CAR object -> the behaviour
    timeline (unsorted; the timeline stage orders by the true instant)."""
    ans = analytics if analytics is not None else load_analytics()
    hits: list[BehaviourHit] = []
    for an in ans:
        if an.runnable:
            hits.extend(run_analytic(an, rows_by_object.get(an.car_object, [])))
    return hits


def flag_store(car_db: str, analytics: list[CarAnalytic] | None = None) -> list[BehaviourHit]:
    """Behaviour hits over a finished car.db, one object table at a time."""
    from . import store
    st = store.CarStore(car_db)
    try:
        ans = analytics if analytics is not None else load_analytics()
        objects = {an.car_object for an in ans if an.runnable}
        rows_by_object = {obj: list(st.iter_object(obj)) for obj in objects}
    finally:
        st.close()
    return flag_rows(rows_by_object, ans)


# -- CLI / coverage report ---------------------------------------------------

def coverage_report(analytics: list[CarAnalytic] | None = None) -> dict:
    ans = analytics if analytics is not None else load_analytics()
    runnable = [a for a in ans if a.runnable]
    deferred = [a for a in ans if not a.runnable]
    by_object: dict[str, int] = {}
    for a in runnable:
        by_object[a.car_object] = by_object.get(a.car_object, 0) + 1
    reasons: dict[str, int] = {}
    for a in deferred:
        reasons[a.skip_reason or "?"] = reasons.get(a.skip_reason or "?", 0) + 1
    return {
        "total": len(ans), "runnable": len(runnable), "deferred": len(deferred),
        "runnable_by_object": dict(sorted(by_object.items())),
        "deferred_reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
        "runnable_ids": sorted(a.id for a in runnable),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="piiat_mitrecar.analytics",
                                 description="compile the pinned CAR analytics to the behaviour layer")
    ap.add_argument("--json", action="store_true", help="emit the coverage report as JSON")
    a = ap.parse_args(argv)
    rep = coverage_report()
    if a.json:
        json.dump(rep, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"CAR analytics: {rep['total']} total | {rep['runnable']} runnable "
              f"| {rep['deferred']} deferred (live from the pinned submodule)")
        print("runnable by object:", rep["runnable_by_object"])
        print("deferred reasons:  ", rep["deferred_reasons"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

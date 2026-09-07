"""Byakugan — Sigma detection over CAR objects (sigma.py).

Covers the pieces that make a Sigma rule run over a CAR row: the recursive-descent
condition parser (the `N of selection*` / `not` / parens grammar the regex
prototype mangled), the field|modifier leaf matching, logsource->CAR-object
mapping, ATT&CK-tag coverage, and end-to-end flagging into BehaviourHits that
carry the same shape the CAR analytics emit.
"""
from piiat_mitrecar import sigma as S
from piiat_mitrecar.analytics import BehaviourHit


# -- condition parser ---------------------------------------------------------
def _cond(expr, results):
    ast = S._CondParser(S._tokenize(expr)).parse()
    return S._eval_cond(ast, results)


def test_condition_and_or_not_parens():
    r = {"a": True, "b": False, "c": True}
    assert _cond("a and c", r) is True
    assert _cond("a and b", r) is False
    assert _cond("a or b", r) is True
    assert _cond("a and not b", r) is True
    assert _cond("(a or b) and not (b and c)", r) is True
    assert _cond("not a", r) is False


def test_condition_quantifiers():
    r = {"selection1": True, "selection2": False, "selection3": True, "filter_x": False}
    # the exact shape the regex prototype mangled -> now compiles and evaluates
    assert _cond("1 of selection* and not 1 of filter_*", r) is True
    assert _cond("all of selection*", r) is False          # selection2 is False
    assert _cond("any of selection*", r) is True
    assert _cond("all of them", r) is False
    # no matching names -> quantifier is False (an absent filter set can't fire)
    assert _cond("1 of filter_*", r) is False
    assert _cond("not 1 of filter_*", r) is True


def test_condition_process_creation_gate_form():
    # `process_creation and (1 of selection*)` — the common hayabusa form
    r = {"process_creation": True, "selection1": False, "selection2": True}
    assert _cond("process_creation and (1 of selection*)", r) is True
    r["selection2"] = False
    assert _cond("process_creation and (1 of selection*)", r) is False


# -- field / modifier leaf matching ------------------------------------------
def test_leaf_modifiers():
    row = {"command_line": "cmd.exe /c whoami", "exe": r"C:\Windows\System32\cmd.exe"}
    assert S._leaf("CommandLine", ["contains"], "/c who")(row) is True
    assert S._leaf("CommandLine", ["startswith"], "cmd.exe")(row) is True
    assert S._leaf("CommandLine", ["endswith"], "whoami")(row) is True
    assert S._leaf("CommandLine", ["re"], r"/c\s+whoami")(row) is True
    assert S._leaf("CommandLine", ["contains"], "powershell")(row) is False
    # Image maps to exe with CAR basename semantics (a path-valued exe matches a bare name)
    assert S._leaf("Image", [], "cmd.exe")(row) is True


def test_leaf_list_is_or_and_all_is_and():
    row = {"command_line": "cmd /c whoami"}
    assert S._leaf("CommandLine", ["contains"], ["nope", "whoami"])(row) is True   # OR
    assert S._leaf("CommandLine", ["contains", "all"], ["cmd", "whoami"])(row) is True   # AND
    assert S._leaf("CommandLine", ["contains", "all"], ["cmd", "notthere"])(row) is False


def test_unsupported_modifier_refuses_to_match():
    row = {"command_line": "whatever"}
    assert S._leaf("CommandLine", ["base64"], "d2hvYW1p")(row) is False


def test_gate_only_selection_is_true():
    # a selection of only channel/eventid gates is satisfied over CAR (no evtx here)
    pred = S._selection({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational"})
    assert pred({"anything": "x"}) is True


def test_selection_list_is_or():
    block = [{"Image|endswith": r"\bcdedit.exe"}, {"OriginalFileName": "bcdedit.exe"}]
    pred = S._selection(block)
    assert pred({"exe": r"C:\Windows\System32\bcdedit.exe"}) is True
    assert pred({"exe": "other.exe", "original_file_name": "bcdedit.exe"}) is True
    assert pred({"exe": "other.exe"}) is False


# -- compile_rule -------------------------------------------------------------
_CMD_RULE = {
    "id": "test-cmd-no-space", "title": "Cmd no space",
    "tags": ["attack.execution", "attack.t1059.001"],
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {
        "process_creation": {"EventID": 4688, "Channel": "Security"},
        "selection": {"CommandLine|contains": ["cmd.exe /c", "cmd /c"]},
        "condition": "process_creation and selection",
    },
}


def test_compile_rule_runnable_and_matches():
    an = S.compile_rule(_CMD_RULE)
    assert an.runnable is True
    assert an.car_object == "process" and an.car_action == "create"
    assert [c.technique for c in an.coverage] == ["T1059.001"]
    pred = an.clauses[0].predicate
    assert pred({"command_line": 'cmd.exe /c "ver"'}) is True
    assert pred({"command_line": "notepad.exe"}) is False


def test_compile_rule_skips_unmapped_and_untagged():
    unmapped = dict(_CMD_RULE, logsource={"category": "ps_script"})
    assert S.compile_rule(unmapped).runnable is False
    assert "not a CAR object" in S.compile_rule(unmapped).skip_reason
    untagged = dict(_CMD_RULE, tags=["some.other"])
    assert S.compile_rule(untagged).runnable is False
    assert "technique" in S.compile_rule(untagged).skip_reason


def test_technique_tags():
    techs, tactics = S.technique_tags(["attack.execution", "attack.t1059.001", "attack.t1053"])
    assert techs == ["T1059.001", "T1053"]
    assert "execution" in tactics


# -- end-to-end flagging ------------------------------------------------------
def test_run_rule_emits_behaviour_hits():
    an = S.compile_rule(_CMD_RULE)
    rows = [
        {"guid": "g1", "timestamp": "2024-01-19T05:40:35.930Z", "source_host": "H",
         "command_line": "cmd /c whoami"},
        {"guid": "g2", "timestamp": "t", "command_line": "explorer.exe"},
    ]
    hits = S.run_rule(an, rows)
    assert len(hits) == 1
    h = hits[0]
    assert isinstance(h, BehaviourHit)
    assert h.guid == "g1" and h.car_object == "process"
    assert [c.technique for c in h.coverage] == ["T1059.001"]


def test_coverage_report_shape():
    ans = [S.compile_rule(_CMD_RULE), S.compile_rule(dict(_CMD_RULE, logsource={"category": "ps_script"}))]
    rep = S.coverage_report(ans)
    assert rep["runnable"] == 1 and rep["by_object"] == {"process": 1}
    assert any("CAR object" in k for k in rep["deferred"])

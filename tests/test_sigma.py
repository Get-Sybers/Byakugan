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
    assert S._leaf("CommandLine", ["contains"], "/c who", "process")(row) is True
    assert S._leaf("CommandLine", ["startswith"], "cmd.exe", "process")(row) is True
    assert S._leaf("CommandLine", ["endswith"], "whoami", "process")(row) is True
    assert S._leaf("CommandLine", ["re"], r"/c\s+whoami", "process")(row) is True
    assert S._leaf("CommandLine", ["contains"], "powershell", "process")(row) is False
    # Image maps to exe with CAR basename semantics (a path-valued exe matches a bare name)
    assert S._leaf("Image", [], "cmd.exe", "process")(row) is True


def test_leaf_list_is_or_and_all_is_and():
    row = {"command_line": "cmd /c whoami"}
    assert S._leaf("CommandLine", ["contains"], ["nope", "whoami"], "process")(row) is True   # OR
    assert S._leaf("CommandLine", ["contains", "all"], ["cmd", "whoami"], "process")(row) is True   # AND
    assert S._leaf("CommandLine", ["contains", "all"], ["cmd", "notthere"], "process")(row) is False


def test_unsupported_modifier_refuses_to_match():
    row = {"command_line": "whatever"}
    assert S._leaf("CommandLine", ["base64"], "d2hvYW1p", "process")(row) is False


def test_gate_only_selection_is_true():
    # a selection of only channel/eventid gates is satisfied over CAR (no evtx here)
    pred = S._selection({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational"}, "process")
    assert pred({"anything": "x"}) is True


def test_selection_list_is_or():
    # a list of sub-blocks is OR; use fields the engine maps actually retain
    block = [{"Image|endswith": r"\bcdedit.exe"}, {"CommandLine|contains": "bcdedit"}]
    pred = S._selection(block, "process")
    assert pred({"exe": r"C:\Windows\System32\bcdedit.exe"}) is True
    assert pred({"exe": "other.exe", "command_line": "run bcdedit now"}) is True
    assert pred({"exe": "other.exe", "command_line": "notepad"}) is False


def test_field_map_is_derived_from_engine_maps():
    # the Sigma->CAR field map comes from the engine's own artefact maps, not a
    # hand list: the authoritative correspondences resolve...
    assert "exe" in S._car_columns("Image", "process")
    assert "command_line" in S._car_columns("CommandLine", "process")
    assert "key" in S._car_columns("TargetObject", "registry")   # NOT file_path (the hand-map's bug)
    assert "dest_ip" in S._car_columns("DestinationIp", "flow")
    # OriginalFileName has no canonical CAR column, so the derived map resolves
    # it by its own name (the native-bag fallback, tried last) — and the engine
    # now RETAINS it natively off Sysmon EID 1, closing the old gap (proven to
    # resolve in test_retained_native_fields_resolve below).
    assert S._car_columns("OriginalFileName", "process") == ["OriginalFileName"]


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


# -- retained native fields (the engine maps now keep the dropped Sigma fields) --
def test_maps_retain_pe_metadata_under_sysmon_names():
    # ADD-ONLY extension of the Sysmon EID-1 map: the PE version-resource fields
    # a Sigma process_creation rule most references (OriginalFileName leads the
    # whole corpus) are now RETAINED natively under their Sysmon names, without
    # disturbing the canonical props the CAR output already carries.
    from piiat_mitrecar.mappings import MAPPINGS
    eid1 = dict(MAPPINGS["evtx_sysmon"]["variants"])["sysmon_proc_create"]
    native = eid1["native_extract"]
    for f in ("OriginalFileName", "Company", "Product", "Description",
              "FileVersion", "ParentUser", "Imphash"):
        assert f in native, f
    # existing canonical props are untouched (add-only)
    assert "command_line" in eid1["props"] and "exe" in eid1["props"]


def test_retained_native_fields_resolve():
    # a CAR process row's native bag now carries these; a Sigma rule naming them
    # resolves through analytics._field's native-bag fallback (raw name tried
    # last), so the field map now RESOLVES what it used to drop.
    row = {"native": {"OriginalFileName": "Cmd.Exe", "Company": "Microsoft Corporation",
                      "Product": "Microsoft Windows", "Imphash": "00AABB"}}
    assert S._values(row, "OriginalFileName", "process") == "Cmd.Exe"
    assert S._values(row, "Company", "process") == "Microsoft Corporation"
    assert S._values(row, "Imphash", "process") == "00AABB"
    # a whole rule keyed on OriginalFileName (a renamed-binary detection) now fires
    rule = {"id": "ofn", "title": "renamed cmd", "tags": ["attack.t1036.003"],
            "logsource": {"category": "process_creation"},
            "detection": {"sel": {"OriginalFileName": "Cmd.Exe"}, "condition": "sel"}}
    an = S.compile_rule(rule)
    assert an.runnable is True
    assert an.clauses[0].predicate(row) is True
    assert an.clauses[0].predicate({"native": {"OriginalFileName": "other.exe"}}) is False


# -- % is literal, not a match-everything wildcard (the T1587.001 over-fire fix) --
def test_percent_wrapped_value_is_literal_not_match_all():
    # a Sigma `contains` value carrying %...% (e.g. the Mustang Panda rule's
    # cmd.exe obfuscation string — a LITERAL to find) must NOT collapse to `.*`
    # and match every command line, as the CAR-analytic %envvar% glob would.
    pred = S._leaf("CommandLine", ["contains"], "%windir:~-1,1%", "process")
    assert pred({"command_line": "chrome.exe --type=renderer"}) is False
    assert pred({"command_line": r"cmd.exe /c echo %windir:~-1,1% x"}) is True
    # Sigma's own `*` wildcard is still honoured
    star = S._leaf("CommandLine", ["contains"], "cmd*whoami", "process")
    assert star({"command_line": "cmd.exe /c whoami"}) is True
    assert star({"command_line": "powershell -enc whoami"}) is False


# -- hayabusa noisy/exclude + deprecated rule lists ---------------------------
_REG_RULE = {
    "id": "1703ba97-b2c2-4071-a241-a16d017d25d3", "title": "noisy reg rule",
    "tags": ["attack.t1112"],
    "logsource": {"category": "registry_set", "product": "windows"},
    "detection": {"selection": {"TargetObject|contains": "Run"}, "condition": "selection"},
}


def test_noisy_and_deprecated_rules_are_deferred():
    # runnable on its own...
    assert S.compile_rule(_REG_RULE).runnable is True
    # ...but a known noisy id is deferred when the list is honoured
    skipped = S.compile_rule(_REG_RULE, skip_ids={_REG_RULE["id"]})
    assert skipped.runnable is False
    assert "noisy/exclude" in skipped.skip_reason
    # deprecated status defers by default, and can be opted out of
    dep = S.compile_rule(dict(_REG_RULE, status="deprecated"))
    assert dep.runnable is False and "deprecated" in dep.skip_reason
    assert S.compile_rule(dict(_REG_RULE, status="deprecated"), skip_deprecated=False).runnable is True


def test_hayabusa_skip_ids_parses_lists(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "noisy_rules.txt").write_text(
        "#Hayabusa rules\n1703ba97-b2c2-4071-a241-a16d017d25d3 # Sysmon 12 noise\n",
        encoding="utf-8")
    (cfg / "exclude_rules.txt").write_text(
        "# Replaced by Hayabusa rules:\n6695d6a2-9365-ee87-ccdd-966b0e1cdbd4 # something\n",
        encoding="utf-8")
    ids = S.hayabusa_skip_ids(str(tmp_path / "sigma"))   # config is the sibling
    assert "1703ba97-b2c2-4071-a241-a16d017d25d3" in ids
    assert "6695d6a2-9365-ee87-ccdd-966b0e1cdbd4" in ids


# -- new logsource category (create_stream_hash -> file:create) ---------------
def test_create_stream_hash_category_is_runnable():
    rule = {"id": "ads", "title": "ADS write", "tags": ["attack.t1564.004"],
            "logsource": {"category": "create_stream_hash", "product": "windows"},
            "detection": {"sel": {"TargetFilename|endswith": ":Zone.Identifier"},
                          "condition": "sel"}}
    an = S.compile_rule(rule)
    assert an.runnable is True
    assert an.car_object == "file" and an.car_action == "create"
    # the action is a real CAR action for the object
    from piiat_mitrecar import carmodel
    assert an.car_action in carmodel.actions(an.car_object)

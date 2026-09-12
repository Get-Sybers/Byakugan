"""The behaviour layer (analytics.py) — the CAR-analytic pseudocode compiler,
the honest runnable/deferred gate, and end-to-end flagging over car.db rows.

The analytics are reconstructed live from the pinned car submodule, so the
count assertions are thresholds + membership (a pin bump may add analytics),
never a brittle exact equality.
"""
from byakugan import analytics as A


# -- the expression compiler --------------------------------------------------

def _pred(expr):
    return A._compile_expr(expr)


def test_equality_both_spellings():
    # CAR pseudocode uses `==` and single `=` interchangeably for equality
    for expr in ('exe == "cmd.exe"', 'exe = "cmd.exe"'):
        p = _pred(expr)
        assert p({"exe": "cmd.exe"}) is True
        assert p({"exe": "CMD.EXE"}) is True          # case-insensitive
        assert p({"exe": "powershell.exe"}) is False
        assert p({"exe": None}) is False              # a null never == a literal


def test_not_equal_and_null():
    p = _pred('exe != "cmd.exe"')
    assert p({"exe": "powershell.exe"}) is True
    assert p({"exe": "cmd.exe"}) is False
    assert p({"exe": None}) is True                   # null is 'not equal' to a literal


def test_glob_and_envvar():
    p = _pred('image_path == "*:\\RECYCLER\\*"')
    assert p({"image_path": "C:\\RECYCLER\\x.exe"}) is True
    assert p({"image_path": "C:\\Windows\\x.exe"}) is False
    # %envvar% is treated as a wildcard (host env is not expanded here)
    q = _pred('image_path == "%windir%\\Tasks\\*"')
    assert q({"image_path": "C:\\Windows\\Tasks\\evil.exe"}) is True


def test_unquoted_glob():
    p = _pred("command_line = *urlcache*")
    assert p({"command_line": "certutil -urlcache -split http://x"}) is True
    assert p({"command_line": "certutil -something"}) is False


def test_exe_basename_matching_path_valued():
    """MITRE CAR defines `exe` as the executable NAME, but our cascade fills it
    with the full PATH. A bare-name RHS must therefore match a path-valued field,
    or every `exe == "X.exe"` analytic misses real data — the defect Hayabusa
    surfaced on LS24 (8 cmd.exe rows, 0 CAR hits until this)."""
    p = _pred('exe == "cmd.exe"')
    assert p({"exe": r"C:\Windows\System32\cmd.exe"}) is True   # path-valued exe
    assert p({"exe": "cmd.exe"}) is True                        # name-valued exe
    assert p({"exe": r"C:\Windows\System32\powershell.exe"}) is False
    g = _pred('exe == "procdump*.exe"')                          # bare-name glob too
    assert g({"exe": r"C:\tools\procdump64.exe"}) is True
    # a comparison the analytic wrote WITH a path is never loosened to a basename
    q = _pred('image_path == "c:\\windows\\system32\\cmd.exe"')
    assert q({"image_path": r"c:\windows\system32\cmd.exe"}) is True
    assert q({"image_path": "cmd.exe"}) is False


def test_regex_match():
    p = _pred('command_line match "sekurlsa"')
    assert p({"command_line": "mimikatz sekurlsa::logonpasswords"}) is True
    assert p({"command_line": "whoami"}) is False


def test_boolean_and_or_not_precedence():
    p = _pred('exe == "wsmprovhost.exe" and parent_exe == "svchost.exe"')
    assert p({"exe": "wsmprovhost.exe", "parent_exe": "svchost.exe"}) is True
    assert p({"exe": "wsmprovhost.exe", "parent_exe": "explorer.exe"}) is False
    o = _pred('exe == "at.exe" or exe == "schtasks.exe"')
    assert o({"exe": "schtasks.exe"}) is True
    assert o({"exe": "cmd.exe"}) is False
    n = _pred('not exe == "cmd.exe"')
    assert n({"exe": "powershell.exe"}) is True
    assert n({"exe": "cmd.exe"}) is False


def test_native_bag_field_resolution():
    # a field absent as a canonical column is looked up in the native bag
    p = _pred('protocol == "smb"')
    assert p({"native": {"protocol": "smb"}}) is True
    assert p({"native": {"protocol": "dns"}}) is False


# -- object / action normalisation --------------------------------------------

def test_object_action_normalisation():
    assert A._car_object("Process") == "process"
    assert A._car_object("UserSession") == "user_session"
    assert A._car_object("User_Session") == "user_session"
    assert A._car_object("SystemLogs") is None        # not a CAR object
    assert A._car_action("Create", "process") == "create"
    assert A._car_action("RemoteCreate", "thread") == "remote_create"
    assert A._car_action("BootUp", "process") is None  # not a process action


# -- loading the pinned analytics --------------------------------------------

def test_load_and_coverage_report():
    ans = A.load_analytics()
    assert len(ans) > 90                               # the full CAR corpus
    rep = A.coverage_report(ans)
    assert rep["runnable"] >= 40                        # the single-search+filter subset
    assert rep["runnable"] + rep["deferred"] == rep["total"]
    # the subset is dominated by Process:Create TTPs
    assert rep["runnable_by_object"].get("process", 0) >= 25
    # every deferred analytic states WHY (honest gating, nothing silently dropped)
    for an in ans:
        assert an.runnable or an.skip_reason


def test_flagship_analytic_is_runnable():
    ans = {a.id: a for a in A.load_analytics()}
    wsmp = ans["CAR-2014-11-004"]                       # wsmprovhost lateral movement
    assert wsmp.runnable
    assert wsmp.car_object == "process" and wsmp.car_action == "create"
    techniques = {c.technique for c in wsmp.coverage}
    assert {"T1059", "T1021"} <= techniques


def test_aggregation_analytic_deferred():
    ans = {a.id: a for a in A.load_analytics()}
    # CAR-2013-10-001 uses `NOT IN TOP30(...)` — an aggregation, honestly deferred
    assert not ans["CAR-2013-10-001"].runnable
    assert ans["CAR-2013-10-001"].skip_reason


def test_service_outlier_deferred_not_run_partial():
    """CAR-2013-09-005 'Service Outlier Executables' — its real signal is a
    temporal set difference (historic - current). Running ONLY its base filter
    (parent_image_path == services.exe) would flag every normal service as
    T1543. It MUST defer whole, never run a meaning-changing partial."""
    ans = {a.id: a for a in A.load_analytics()}
    a = ans["CAR-2013-09-005"]
    assert not a.runnable
    assert a.skip_reason and ("refinement" in a.skip_reason or "temporal" in a.skip_reason)


# -- end-to-end flagging ------------------------------------------------------

def _proc(guid, **fields):
    row = {"car_object": "process", "car_action": "create", "guid": guid,
           "timestamp": "2024-01-01T00:00:00Z", "source_host": "HOST1"}
    row.update(fields)
    return row


def test_run_flagship_over_rows():
    ans = {a.id: a for a in A.load_analytics()}
    wsmp = ans["CAR-2014-11-004"]
    rows = [
        _proc("g1", exe="wsmprovhost.exe", parent_exe="svchost.exe"),   # the TTP
        _proc("g2", exe="wsmprovhost.exe", parent_exe="explorer.exe"),  # benign parent
        _proc("g3", exe="powershell.exe", parent_exe="svchost.exe"),    # benign exe
    ]
    hits = A.run_analytic(wsmp, rows)
    assert [h.guid for h in hits] == ["g1"]
    h = hits[0]
    assert h.analytic_id == "CAR-2014-11-004"
    assert h.car_object == "process" and h.car_action == "create"
    assert {c.technique for c in h.coverage} >= {"T1059", "T1021"}
    assert h.timestamp == "2024-01-01T00:00:00Z" and h.source_host == "HOST1"


def test_action_gate_excludes_wrong_action():
    ans = {a.id: a for a in A.load_analytics()}
    wsmp = ans["CAR-2014-11-004"]
    # a process row matching the fields but with the wrong action is NOT flagged
    row = _proc("g9", exe="wsmprovhost.exe", parent_exe="svchost.exe")
    row["car_action"] = "terminate"
    assert A.run_analytic(wsmp, [row]) == []


def test_flag_rows_groups_by_object():
    ans = A.load_analytics()
    rows_by_object = {"process": [
        _proc("p1", exe="cmd.exe"),                     # CAR-2013-02-003 (cmd.exe)
    ]}
    hits = A.flag_rows(rows_by_object, ans)
    assert any(h.analytic_id == "CAR-2013-02-003" and h.guid == "p1" for h in hits)

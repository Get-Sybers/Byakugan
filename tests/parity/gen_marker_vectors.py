"""Generate the marker parity vectors — the REAL Python resolver's outputs,
recorded, for go/internal/markers' replay test.

Drives byakugan.normalize._resolve (all 24 marker kinds), _clean_ts,
parse_ts and mappings._common.evtx_payload_field through representative and
edge inputs; specs are serialized with export_ir.encode_source (the same
encoding the IR carries), records and outputs as plain JSON.

    python tests/parity/gen_marker_vectors.py   # writes go/internal/markers/testdata/marker_vectors.json
"""
from __future__ import annotations

import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from byakugan import export_ir, normalize as N  # noqa: E402
from byakugan.mappings import _common  # noqa: E402
from byakugan.normalize import (at, basename, concat, const, domain_of,  # noqa: E402
                                epoch_ts, exe_path, ext, first, hex_int,
                                host_label, lower, map_value, payload, regex1,
                                replace, ts_before, unescape_backslashes,
                                user_canon, userdata, win_program_name,
                                win_program_path)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "..", "go", "internal", "markers", "testdata",
                   "marker_vectors.json")

_SEC_PAYLOAD = json.dumps({"EventData": {"Data": [
    {"@Name": "TargetUserName", "#text": "Steve"},
    {"@Name": "Padded", "#text": "  Advapi  "},
    {"@Name": "Dash", "#text": "-"},
    {"@Name": "Empty", "#text": ""},
    {"@Name": "IntVal", "#text": 7},
    {"@Name": "NoText"},
    {"@Name": "ProcessName", "#text": r"C:\Windows\System32\svchost.exe"},
]}})

_UD_PAYLOAD = json.dumps({"UserData": {"EventXML": {
    "User": "DESKTOP-8\\jcloudy", "SessionID": 2, "Pad": "  x  ", "Blank": "-"}}})

_WRAPPED = {"Record": {"file_path": "/tmp/x", "pad": "  y  ", "n": 5, "dash": "-"}}

# (spec, record) pairs — every marker kind, representative + edge inputs.
RESOLVE_CASES = [
    # plain field names
    ("a", {"a": 1}),
    ("missing", {"a": 1}),
    # first
    (first("a", "b", "c"), {"a": "-", "b": "", "c": "x"}),
    (first("a", "b"), {"a": None, "b": None}),
    (first(basename("p"), const("fallback")), {"p": ""}),
    (first("n", "m"), {"n": 0, "m": 2}),          # 0 is NOT blank
    # const
    (const("administrator"), {}),
    (const(5), {}),
    (const(None), {}),
    (const(True), {}),
    # basename
    (basename("p"), {"p": r"C:\Users\jcloudy\x.exe"}),
    (basename("p"), {"p": "/usr/bin/python3"}),
    (basename("p"), {"p": "a/b\\c"}),
    (basename("p"), {"p": "C:\\dir\\"}),
    (basename("p"), {"p": "C:"}),                  # nt drive, empty tail
    (basename("p"), {"p": r"\\srv\share\f.txt"}),
    (basename("p"), {"p": r"\\srv\share"}),
    (basename("p"), {"p": "trailing/"}),
    (basename("p"), {"p": "plain"}),
    (basename("p"), {"p": 42}),
    (basename("p"), {"p": "-"}),
    (basename("p"), {}),
    # ext
    (ext("p"), {"p": "a.TXT"}),
    (ext("p"), {"p": ".bashrc"}),
    (ext("p"), {"p": r"C:\d\a.tar.GZ"}),
    (ext("p"), {"p": "noext"}),
    (ext("p"), {"p": "a."}),
    (ext("p"), {"p": "a..gz"}),
    (ext("p"), {"p": "/p/.hidden"}),
    (ext("p"), {"p": "-"}),
    # lower
    (lower("s"), {"s": "MiXeD"}),
    (lower("s"), {"s": 17}),
    (lower("s"), {"s": [1, "A"]}),                 # str(list) repr path
    (lower("s"), {"s": ""}),
    # regex1
    (regex1("p", r"(?i)[/\\]Users[/\\]([^/\\]+)[/\\]"), {"p": r"C:\USERS\jcloudy\NTUSER.DAT"}),
    (regex1("c", r"^([^.]+\..+)$"), {"c": "HOST1.example.com"}),
    (regex1("c", r"^([^.]+\..+)$"), {"c": "HOST1"}),
    (regex1("s", r"(a)|b"), {"s": "b"}),           # group 1 did not participate
    (regex1("s", r"x(\d+)"), {"s": "x123y"}),
    (regex1("s", r"x(\d+)"), {"s": "nope"}),
    # domain_of
    (domain_of("h"), {"h": "user@EXAMPLE.com"}),
    (domain_of("h"), {"h": "Host.Example.COM"}),
    (domain_of("h"), {"h": "host.com/path/x"}),
    (domain_of("h"), {"h": "http://host.com/x"}),  # split('/')[0] → 'http:'
    (domain_of("h"), {"h": "@"}),                  # empty after '@' → None
    (domain_of("h"), {"h": "-"}),
    # epoch_ts
    (epoch_ts("t"), {"t": 1341856306}),
    (epoch_ts("t"), {"t": 1341856306.5}),
    (epoch_ts("t"), {"t": "1341856306.5"}),
    (epoch_ts("t"), {"t": 1341856211.834184}),
    (epoch_ts("t"), {"t": 0.0000005}),             # round-half-even to 0µs
    (epoch_ts("t"), {"t": 0.0000015}),             # → 2µs (half-even)
    (epoch_ts("t"), {"t": -1.25}),
    (epoch_ts("t"), {"t": True}),
    (epoch_ts("t"), {"t": "2012-07-09T17:51:46.593202Z"}),   # ISO passthrough
    (epoch_ts("t"), {"t": "2012-07-09 17:51:46+02:00"}),
    (epoch_ts("t"), {"t": "not a date"}),
    # out-of-range years → ValueError → the str-fallback gate. (≥ ~1e18 the
    # C fromtimestamp raises OSError, which the Python engine does NOT catch —
    # a crash; the Go engine falls back instead. Recorded in DESIGN.md.)
    (epoch_ts("t"), {"t": 253402300799.0}),
    (epoch_ts("t"), {"t": 253402300800.0}),
    (epoch_ts("t"), {"t": "1e15"}),
    (epoch_ts("t"), {"t": 1e15}),
    (epoch_ts("t"), {"t": -62135596800.0}),
    (epoch_ts("t"), {"t": -62135596801.0}),
    (epoch_ts("t"), {"t": float("nan")}),
    (epoch_ts("t"), {"t": "12-3"}),                # short isdigit gate
    (epoch_ts("t"), {"t": "-"}),
    # map_value
    (map_value("m", {"GET": "get", "POST": "post"}, upper=True), {"m": "get"}),
    (map_value("m", {"GET": "get"}, upper=True), {"m": "HEAD"}),
    (map_value("m", {"SF": "end", "S0": "start"}), {"m": "SF"}),
    (map_value("m", {"SF": "end"}), {"m": "sf"}),  # no upper → miss
    (map_value("m", {"4624": "x"}), {"m": 4624}),  # str() of int key
    # concat
    (concat(const("http://"), "host", "uri"), {"host": "h.com", "uri": "/p"}),
    (concat(const("http://"), "host", "uri"), {"host": "h.com"}),
    (concat("a", "b"), {"a": 1, "b": 2.5}),
    (concat("a"), {"a": "-"}),
    # payload
    (payload("TargetUserName"), {"Payload": _SEC_PAYLOAD}),
    (payload("Padded"), {"Payload": _SEC_PAYLOAD}),
    (payload("Dash"), {"Payload": _SEC_PAYLOAD}),
    (payload("Empty"), {"Payload": _SEC_PAYLOAD}),
    (payload("IntVal"), {"Payload": _SEC_PAYLOAD}),
    (payload("NoText"), {"Payload": _SEC_PAYLOAD}),
    (payload("Missing"), {"Payload": _SEC_PAYLOAD}),
    (payload("k"), {"Payload": "not json"}),
    (payload("k"), {"Payload": 42}),
    (payload("k"), {}),
    (payload("k"), {"Payload": json.dumps({"k": "  v  ", "z": 1})}),   # flat dict
    (payload("z"), {"Payload": json.dumps({"k": "v", "z": 1})}),
    (payload("k"), {"Payload": json.dumps({"EventData": "odd"})}),     # non-dict EventData
    (payload("file_path", "Record"), _WRAPPED),
    (payload("pad", "Record"), _WRAPPED),
    (payload("n", "Record"), _WRAPPED),
    (payload("dash", "Record"), _WRAPPED),
    (payload("absent", "Record"), _WRAPPED),
    # userdata
    (userdata("User"), {"Payload": _UD_PAYLOAD}),
    (userdata("SessionID"), {"Payload": _UD_PAYLOAD}),
    (userdata("Pad"), {"Payload": _UD_PAYLOAD}),
    (userdata("Blank"), {"Payload": _UD_PAYLOAD}),
    (userdata("Missing"), {"Payload": _UD_PAYLOAD}),
    (userdata("User"), {"Payload": _SEC_PAYLOAD}),         # no UserData
    (userdata("User"), {"Payload": json.dumps({"UserData": "odd"})}),
    # host_label
    (host_label("c"), {"c": "HOST1.example.com"}),
    (host_label("c"), {"c": "HOST1"}),
    (host_label("c"), {"c": ".leading"}),
    (host_label("c"), {"c": ""}),
    # hex_int
    (hex_int("v"), {"v": 508}),
    (hex_int("v"), {"v": "0x1FC"}),
    (hex_int("v"), {"v": "1FC"}),
    (hex_int("v"), {"v": "12"}),
    (hex_int("v"), {"v": " 12 "}),
    (hex_int("v"), {"v": "12.5"}),
    (hex_int("v"), {"v": 3.9}),
    (hex_int("v"), {"v": -3.9}),
    (hex_int("v"), {"v": True}),
    (hex_int("v"), {"v": "0x"}),
    (hex_int("v"), {"v": "abc"}),
    (hex_int("v"), {"v": "xyz"}),
    (hex_int("v"), {"v": "1_0"}),
    (hex_int("v"), {"v": "-"}),
    # unescape_backslashes
    (unescape_backslashes("p"), {"p": "C:\\\\x\\\\y"}),
    (unescape_backslashes("p"), {"p": "C:\\x"}),
    (unescape_backslashes("p"), {"p": "a\\\\\\\\b"}),
    # replace
    (replace("t", " ", "T"), {"t": "2018-04-02 01:15"}),
    (replace("t", "aa", "b"), {"t": "aaaa"}),
    # at
    (at("strings", 0), {"strings": ["a", " b ", "-", "", 42]}),
    (at("strings", 1), {"strings": ["a", " b ", "-", "", 42]}),
    (at("strings", 2), {"strings": ["a", " b ", "-", "", 42]}),
    (at("strings", 3), {"strings": ["a", " b ", "-", "", 42]}),
    (at("strings", 4), {"strings": ["a", " b ", "-", "", 42]}),
    (at("strings", -1), {"strings": ["a", " b ", "-", "", 42]}),
    (at("strings", -5), {"strings": ["a", " b ", "-", "", 42]}),
    (at("strings", -6), {"strings": ["a", " b ", "-", "", 42]}),
    (at("strings", 5), {"strings": ["a", " b ", "-", "", 42]}),
    (at("strings", 0), {"strings": "not a list"}),
    (at("strings", 0), {}),
    # ts_before
    (ts_before("a", "b"), {"a": "2020-02-10 08:20:00.000", "b": "2020-02-10T08:28:12.876Z"}),
    (ts_before("b", "a"), {"a": "2020-02-10 08:20:00.000", "b": "2020-02-10T08:28:12.876Z"}),
    (ts_before("b", "c"), {"b": "2020-02-10T08:28:12.876Z", "c": "2020-02-10T09:28:12.876+01:00"}),
    (ts_before("c", "b"), {"b": "2020-02-10T08:28:12.876Z", "c": "2020-02-10T09:28:12.876+01:00"}),
    (ts_before("a", "junk"), {"a": "2020-02-10 08:20:00", "junk": "not a time"}),
    (ts_before("blank", "a"), {"a": "2020-02-10 08:20:00", "blank": "-"}),
    (ts_before("a", "absent"), {"a": "2020-02-10 08:20:00"}),
    (ts_before("a", "b"), {"a": "2020-02-10 08:20:00.1234567", "b": "2020-02-10T08:20:00.123457"}),
    # win_program_path / win_program_name
    (win_program_path("v"), {"v": r"C:\Program Files\x\y.exe"}),
    (win_program_path("v"), {"v": "0\tabcd\tef01\tx64\tPkg.Name\tpublisher8"}),
    (win_program_name("v"), {"v": r"C:\Program Files\x\y.exe"}),
    (win_program_name("v"), {"v": "0\tabcd\tef01\tx64\tPkg.Name\tpublisher8"}),
    (win_program_name("v"), {"v": "0\tabcd\tef01\tx64\tPkg.Name\tpublisher8\tneutral"}),
    (win_program_name("v"), {"v": "0\tabcd\tef01\tx64\tNoDotName\tpublisher8"}),
    (win_program_name("v"), {"v": "a\tb"}),
    (win_program_path("v"), {"v": "-"}),
    # user_canon
    (user_canon("u"), {"u": "S-1-5-18"}),
    (user_canon("u"), {"u": "s-1-5-32-544"}),
    (user_canon("u"), {"u": "NT AUTHORITY\\SYSTEM"}),
    (user_canon("u"), {"u": "nt authority\\NetworkService"}),
    (user_canon("u"), {"u": "BUILTIN\\Administrators"}),
    (user_canon("u"), {"u": "DESKTOP-1\\jdoe"}),
    (user_canon("u"), {"u": "Local System"}),
    (user_canon("u"), {"u": "systemprofile"}),
    (user_canon("u"), {"u": "S-1-5-21-1-2-3-1001"}),
    (user_canon("u"), {"u": "  jcloudy  "}),
    (user_canon("u"), {"u": "DESKTOP-X$"}),
    (user_canon("u"), {"u": "-"}),
    (user_canon("u"), {"u": "   "}),
    # exe_path
    (exe_path("c"), {"c": '"C:\\p q\\x.exe" -k net'}),
    (exe_path("c"), {"c": r"C:\Windows\system32\svchost.exe -k netsvcs"}),
    (exe_path("c"), {"c": "C:\\X.EXE stuff"}),
    (exe_path("c"), {"c": "foo bar baz"}),
    (exe_path("c"), {"c": '"unterminated'}),
    (exe_path("c"), {"c": '""'}),
    (exe_path("c"), {"c": "  word  "}),
    (exe_path("c"), {"c": " leading tok"}),
]

CLEAN_TS_VALUES = ["2020-01-01T00:00:00Z", "1601-01-01T00:00:00", "1970-01-01",
                   "0001-01-01x", "1600-12-31T23:59:59", "2019-01-28T19:40:32+00:00",
                   5, "-", "", None, 1.5]

PARSE_TS_VALUES = ["2020-02-10 08:20:00.000", "2020-02-10T08:28:12.876Z",
                   "2020-02-10T09:28:12.876+01:00", "2020-02-10T08:20:00+02:00",
                   "2020-02-10 08:20:00.1234567", "2020-02-10T08:20:00-05:30",
                   "2020-02-10T08:20:00.5", "2020-13-01T00:00:00",
                   "2020-02-30T00:00:00", "2020-02-29T00:00:00",
                   "2100-02-29T00:00:00", "2000-02-29T00:00:00",
                   "not a time", "", None, 0, "2020-02-10", "  2020-02-10T08:20:00Z  ",
                   "2020-02-10T08:20:00.876543219Z", "2020-02-10T08:20:00Zx"]

PAYLOAD_FIELD_CASES = [
    ({"Payload": _SEC_PAYLOAD}, "TargetUserName"),
    ({"Payload": _SEC_PAYLOAD}, "Padded"),         # UNSTRIPPED
    ({"Payload": _SEC_PAYLOAD}, "Dash"),
    ({"Payload": _SEC_PAYLOAD}, "Empty"),
    ({"Payload": _SEC_PAYLOAD}, "IntVal"),
    ({"Payload": _SEC_PAYLOAD}, "NoText"),
    ({"Payload": _SEC_PAYLOAD}, "Missing"),
    ({"Payload": "not json"}, "X"),
    ({"Payload": ""}, "X"),
    ({}, "X"),
    ({"Payload": json.dumps({"EventData": "odd"})}, "X"),
    ({"Payload": json.dumps({"EventData": {"Data": "odd"}})}, "X"),
]


def main() -> int:
    resolve = []
    for spec, rec in RESOLVE_CASES:
        out = N._resolve(spec, copy.deepcopy(rec))  # noqa: SLF001
        resolve.append({"spec": export_ir.encode_source(spec)
                        if not isinstance(spec, str) else spec,
                        "rec": rec, "out": out})
    clean_ts = [[v, N._clean_ts(v)] for v in CLEAN_TS_VALUES]  # noqa: SLF001
    parse_ts = []
    for v in PARSE_TS_VALUES:
        dt = N.parse_ts(v)
        parse_ts.append([v, None if dt is None else dt.isoformat()])
    payload_field = []
    for rec, name in PAYLOAD_FIELD_CASES:
        payload_field.append({"rec": rec, "name": name,
                              "out": _common.evtx_payload_field(copy.deepcopy(rec), name)})
    doc = {"resolve": resolve, "clean_ts": clean_ts, "parse_ts": parse_ts,
           "payload_field": payload_field}
    out_path = os.path.abspath(OUT)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    n = len(resolve) + len(clean_ts) + len(parse_ts) + len(payload_field)
    print(f"wrote {out_path} ({n} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

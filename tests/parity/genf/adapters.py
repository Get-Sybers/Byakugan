"""Parity vectors + fixtures for the two record ADAPTERS and the l2t SPLITTER.

Not a mapping family: `adapt` and `split` are the two Go packages that replace
byakugan/adapters/{winevt,jlecmd,l2t_split}.py, so their vectors are recorded
from the FROZEN reference copies under tests/parity/reference/ — the executable
spec the byte-parity harness compares against — rather than from a mappings
module. There are no predicates and no markers to record here.

    python tests/parity/genf/adapters.py

Writes ONLY:
    go/internal/adapt/testdata/winevt_vectors.json
    go/internal/adapt/testdata/jlecmd_vectors.json
    go/internal/split/testdata/split_vectors.json
    tests/parity/fixtures/adapter_winevt/
    tests/parity/fixtures/adapter_jlecmd/

The winevt fixture's wrapped rows are the ones in tests/test_car_winevt_adapter
.py verbatim (real LoneWolf / attack-sample positional `strings` arrays), plus
one authored row per remaining RULES entry so the WHOLE table is exercised, plus
the type edges the adapter has to survive (EventId as float/str, a non-list
`strings`, a short `strings`, no xml_string, no Record).
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

REFERENCE = os.path.join(_lib.PARITY, "reference")
ADAPT_TESTDATA = os.path.join(_lib.REPO, "go", "internal", "adapt", "testdata")
SPLIT_TESTDATA = os.path.join(_lib.REPO, "go", "internal", "split", "testdata")

j = _lib.j


def _reference(module_file: str):
    """Import a frozen reference module by path (reference/ is not a package)."""
    path = os.path.join(REFERENCE, module_file)
    spec = importlib.util.spec_from_file_location(
        f"genf_reference_{module_file[:-3]}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: str, doc) -> None:
    """json.dump(indent=1) + trailing newline — the committed vector style
    (_lib._write_json's, for the two package testdata dirs _lib does not own)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")


# ===========================================================================
# winevt — wrapped Plaso rows
# ===========================================================================
_SEC_XML = ("<Event><System><Channel>Security</Channel>"
            "<Computer>WIN-1M3263ACE5D</Computer></System></Event>")


def wrapped(eid, strings, ts="2018-03-27T12:11:42.0Z", xml=_SEC_XML, **rec_extra):
    """tests/test_car_winevt_adapter.py::_wrapped, verbatim."""
    rec = {"data_type": "windows:evtx:record", "event_identifier": eid,
           "strings": strings, "xml_string": xml,
           "source_name": "Microsoft-Windows-Security-Auditing",
           "record_number": 2623, "hostname": "WIN-1M3263ACE5D"}
    rec.update(rec_extra)
    return {"SourceImage": "LoneWolf.E01", "Timestamp": ts, "Parser": "winevtx",
            "Record": rec}


def wrap_ch(eid, strings, channel, source="prov", **rec_extra):
    """tests/test_car_winevt_adapter.py::_wrap_ch, verbatim."""
    xml = (f"<Event><System><Channel>{channel}</Channel>"
           "<Computer>WIN-1M3263ACE5D</Computer></System></Event>")
    rec = {"data_type": "windows:evtx:record", "event_identifier": eid,
           "strings": strings, "xml_string": xml, "source_name": source,
           "record_number": 5, "hostname": "WIN-1M3263ACE5D"}
    rec.update(rec_extra)
    return {"SourceImage": "LoneWolf.E01", "Timestamp": "2018-03-27T12:00:00Z",
            "Parser": "winevtx", "Record": rec}


_TS_CH = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
_BITS_CH = "Microsoft-Windows-Bits-Client/Operational"
_BITS_SRC = "Microsoft-Windows-Bits-Client"
_SYSMON_CH = "Microsoft-Windows-Sysmon/Operational"
_SYSMON_SRC = "Microsoft-Windows-Sysmon"

# ---- VERBATIM from tests/test_car_winevt_adapter.py ------------------------
_S_4688 = ["S-1-5-18", "-", "-", "0x00000000000003e7", "0x0000000000000174",
           r"C:\Windows\System32\smss.exe", "%%1936", "0x0000000000000004",
           None, "S-1-0-0", "-", "-", "0x0000000000000000", None, "S-1-16-16384"]
_S_4624 = ["S-1-5-18", "WIN$", "WORKGROUP", "0x3e7", "S-1-5-21-1-1-1-1001",
           "jcloudy", "DESKTOP-8", "0x16bebd", "2", "User32", "Negotiate",
           "DESKTOP-8", "{0}", "-", "-", "0", "0x238",
           r"C:\Windows\System32\lsass.exe", "10.0.0.9", "445"]
_S_4672 = ["S-1-5-18", "SYSTEM", "NT AUTHORITY", "0x3e7", "SeDebugPrivilege"]
_S_7045 = ["Airplane Mode Switch", r"\SystemRoot\System32\drivers\DellRbtn.sys",
           "kernel mode driver", "demand start", None]
_S_BITS60 = ["{C411}", "Font Download", "{43D8}",
             "https://fs.microsoft.com/fs/x.json", None, "0",
             "2017-04-20T16:10:39Z", "55", "55", "55"]
_S_TS24 = [r"DESKTOP-PM6C56D\defaultuser0", "1", "LOCAL"]
_S_SYSMON1 = ["technique_id=T1112", "2019-05-16 14:17:15.753",
              "{DFAE8213-70EB-5CDD-0000-0010F66D0A00}", "3788",
              r"C:\Windows\System32\reg.exe", "6.3", "Registry Console Tool",
              "MS Windows", "Microsoft Corporation",
              "reg add hklm\\...\\EnableLUA ...", "C:\\",
              r"insecurebank\Administrator", "{DFAE8213-7002}", "0x585e6", "2",
              "High", "SHA1=0873...", "{DFAE8213-702C}", "3748",
              r"C:\Windows\System32\cmd.exe", '"C:\\Windows\\system32\\cmd.exe" ']
_S_SYSMON8 = ["-", "2019-05-26", "{365ABB72-0FA6}", "3884", r"C:\jjs.exe",
              "{365ABB72-0FA7}", "3908", r"C:\svchost.exe", "3916", "0x60000",
              None, None]

# ---- authored: the RULES entries the unit tests do not reach ---------------
_S_4625 = ["S-1-0-0", "-", "-", "0x0", "S-1-0-0", "admin", "DESKTOP-8",
           "0xC000006D", "%%2313", "0xC0000064", "3", "NtLmSsp", "NTLM", "WS1",
           "-", "-", "0", "0x0", "-", "10.0.0.9", "49213"]
_S_4634 = ["S-1-5-21-1-1-1-1001", "jcloudy", "DESKTOP-8", "0x16bebd", "2"]
_S_4647 = ["S-1-5-21-1-1-1-1001", "jcloudy", "DESKTOP-8", "0x16bebd"]
_S_4697 = ["S-1-5-18", "WIN$", "WORKGROUP", "0x3e7", "MaliciousSvc",
           r"C:\Windows\Temp\evil.exe", "0x10", "2", "LocalSystem"]
_S_4778 = ["jcloudy", "DESKTOP-8", "0x16bebd", "RDP-Tcp#0", "CLIENT-1",
           "10.0.0.9"]
_S_4779 = ["jcloudy", "DESKTOP-8", "0x16bebd", "RDP-Tcp#0", "CLIENT-1",
           "10.0.0.9"]
_S_BITS59 = ["{C412}", "Update Download", "{43D9}",
             "http://dl.example.com/pkg.cab", "10.0.0.9", "0",
             "2017-04-20T16:11:39Z", "128", "128", "64"]
_S_TS21 = [r"DESKTOP-PM6C56D\jcloudy", "2", "10.0.0.9"]
_S_TS25 = [r"DESKTOP-PM6C56D\jcloudy", "2", "10.0.0.9"]
_S_SYSMON3 = ["-", "2019-05-16 14:17:16.000", "{DFAE8213-70EB}", "3788",
              r"C:\Windows\System32\reg.exe", r"insecurebank\Administrator",
              "tcp", "true", "false", "10.0.0.5", "WS1", "49155", "-", "false",
              "1.2.3.4", "evil.example.com", "443", "https"]
_S_SYSMON5 = ["-", "2019-05-16 14:18:00.000", "{DFAE8213-70EB}", "3788",
              r"C:\Windows\System32\reg.exe"]
_S_SYSMON6 = ["-", "2019-05-16 14:10:00.000", r"C:\Windows\System32\drv.sys",
              "SHA1=AAAA", "true", "Microsoft Windows", "Valid"]
_S_SYSMON7 = ["-", "2019-05-16 14:11:00.000", "{DFAE8213-70EB}", "3788",
              r"C:\Windows\System32\reg.exe", r"C:\Windows\System32\ntdll.dll",
              "10.0", "NT Layer DLL", "MS Windows", "Microsoft Corporation",
              "SHA1=BBBB", "true", "Microsoft Windows", "Valid"]
_S_SYSMON11 = ["-", "2019-05-16 14:12:00.000", "{DFAE8213-70EB}", "3788",
               r"C:\Windows\System32\reg.exe", r"C:\Users\jcloudy\drop.exe",
               "2019-05-16 14:11:59.000"]
_S_SYSMON12 = ["-", "CreateKey", "2019-05-16 14:13:00.000", "{DFAE8213-70EB}",
               "3788", r"C:\Windows\System32\reg.exe",
               r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"]
_S_SYSMON13 = ["-", "SetValue", "2019-05-16 14:14:00.000", "{DFAE8213-70EB}",
               "3788", r"C:\Windows\System32\reg.exe",
               r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\evil",
               r"C:\Users\jcloudy\drop.exe"]
_S_SYSMON23 = ["-", "2019-05-16 14:15:00.000", "{DFAE8213-70EB}", "3788",
               r"insecurebank\Administrator", r"C:\Windows\System32\reg.exe",
               r"C:\Users\jcloudy\drop.exe", "SHA1=CCCC", "true", "true"]

WINEVT_ROWS = [
    # --- verbatim unit-test rows -------------------------------------------
    wrapped(4688, _S_4688),
    wrapped(4624, _S_4624),
    wrapped(4672, _S_4672),
    wrapped(4907, ["x"]),                                   # no layout → raw
    wrap_ch(7045, _S_7045, "System", "Service Control Manager"),
    wrap_ch(60, _S_BITS60, _BITS_CH, _BITS_SRC),
    wrap_ch(59, ["x"], _TS_CH),                             # BITS must NOT claim it
    wrap_ch(24, _S_TS24, _TS_CH),                           # UserData shape
    wrap_ch(1, _S_SYSMON1, _SYSMON_CH, _SYSMON_SRC),        # RuleName at [0]
    wrap_ch(8, _S_SYSMON8, _SYSMON_CH, _SYSMON_SRC),
    # --- the rest of the RULES table ---------------------------------------
    wrapped(4625, _S_4625),
    wrapped(4634, _S_4634),
    wrapped(4647, _S_4647),
    wrapped(4697, _S_4697),
    wrapped(4778, _S_4778),
    wrapped(4779, _S_4779),
    wrap_ch(59, _S_BITS59, _BITS_CH, _BITS_SRC),
    wrap_ch(21, _S_TS21, _TS_CH),
    wrap_ch(25, _S_TS25, _TS_CH),
    wrap_ch(3, _S_SYSMON3, _SYSMON_CH, _SYSMON_SRC),
    wrap_ch(5, _S_SYSMON5, _SYSMON_CH, _SYSMON_SRC),
    wrap_ch(6, _S_SYSMON6, _SYSMON_CH, _SYSMON_SRC),
    wrap_ch(7, _S_SYSMON7, _SYSMON_CH, _SYSMON_SRC),
    wrap_ch(11, _S_SYSMON11, _SYSMON_CH, _SYSMON_SRC),
    wrap_ch(12, _S_SYSMON12, _SYSMON_CH, _SYSMON_SRC),
    wrap_ch(13, _S_SYSMON13, _SYSMON_CH, _SYSMON_SRC),
    wrap_ch(23, _S_SYSMON23, _SYSMON_CH, _SYSMON_SRC),
    # --- type + shape edges -------------------------------------------------
    wrapped(4624.0, _S_4624),                    # float EventId == the int rule
    wrapped("4624", _S_4624),                    # str EventId: no rule → raw
    wrapped(None, _S_4624),                      # absent EventId → raw
    wrapped(4624, "not a list"),                 # non-list strings → all None
    wrapped(4624, []),                           # empty strings → all None
    wrapped(4624, _S_4624[:6]),                  # short strings → trailing None
    wrapped(4672, _S_4672, xml=""),              # no Channel: kw hits source_name
    # Computer precedence: computer_name wins over hostname
    wrapped(4672, _S_4672, computer_name="COMPUTER-NAME-WINS"),
    # neither → the <Computer> element
    wrapped(4672, _S_4672, hostname=None),
    # no Computer anywhere (no xml, no names) → None
    wrapped(4672, _S_4672, xml="", hostname=None),
    # Sysmon 25 does not exist; the TerminalServices kw is not in a Sysmon hay
    wrap_ch(25, ["a", "b", "c"], _SYSMON_CH, _SYSMON_SRC),
    # bool IS an int in Python: True == 1 claims the Sysmon EID-1 rule
    wrap_ch(True, _S_SYSMON1, _SYSMON_CH, _SYSMON_SRC),
    wrap_ch(False, _S_SYSMON1, _SYSMON_CH, _SYSMON_SRC),   # 0: no rule → raw
    {"SourceImage": "LoneWolf.E01", "Timestamp": "2018-03-27T12:00:00Z",
     "Parser": "winevtx"},                       # no Record at all → raw
]

# ===========================================================================
# jlecmd — raw JLECmd AutomaticDestinations records
# ===========================================================================
# VERBATIM from tests/test_car_jlecmd.py::_RECORD
_JL_RECORD = {
    "AppId": {"AppId": "fb3b0dbfee58fac8", "Description": "Microsoft Word 2016 64-bit"},
    "SourceFile": "/in/AutomaticDestinations/fb3b0dbfee58fac8.automaticDestinations-ms",
    "DestListEntries": [
        {"Path": r"C:\Users\jcloudy\Desktop\Planning.docx", "EntryNumber": 1,
         "CreatedOn": "/Date(1522187139502)/", "LastModified": "/Date(1522917168677)/",
         "Hostname": "desktop-pm6c56d", "InteractionCount": 13, "MRUPosition": 0,
         "Pinned": False, "MacAddress": "28:e3:47:01:77:77", "VolumeDroid": "bc75"},
    ],
}

_JL_MULTI = {
    "AppId": {"AppId": "9b9cdc69c1c24e2b", "Description": "Notepad"},
    "SourceFile": "/in/AutomaticDestinations/9b9cdc69c1c24e2b.automaticDestinations-ms",
    "DestListEntries": [
        # two entries in ONE record: the explosion is 1 record → N events
        {"Path": r"C:\Users\jcloudy\Documents\notes.txt", "EntryNumber": 2,
         "CreatedOn": "/Date(1522187139000)/", "LastModified": "/Date(1522917168000)/",
         "Hostname": "desktop-pm6c56d", "InteractionCount": 3, "MRUPosition": 1,
         "Pinned": True, "MacAddress": "28:e3:47:01:77:77", "VolumeDroid": "bc75"},
        # already-rendered dates pass through str() unchanged
        {"Path": r"\\srv\share\report.pdf", "EntryNumber": 3,
         "CreatedOn": "2018-03-27T20:25:39.502000+00:00",
         "LastModified": "2018-04-05T09:52:48.677000+00:00",
         "Hostname": "DESKTOP-PM6C56D", "InteractionCount": 1.0, "MRUPosition": 2,
         "Pinned": False, "MacAddress": None, "VolumeDroid": None},
        # a negative /Date(..)/ (pre-1970) and a missing Path (gate drops it)
        {"Path": None, "EntryNumber": 4, "CreatedOn": "/Date(-11644473600000)/",
         "LastModified": "/Date(-2208988800000)/", "Hostname": "desktop-pm6c56d"},
        "not a dict",                                   # skipped by isinstance
        # every optional field absent
        {"Path": "/tmp/plain.log", "EntryNumber": 5},
        # falsy + unparseable date forms
        {"Path": "C:\\a\\b.docx", "EntryNumber": 6, "CreatedOn": "",
         "LastModified": 0, "Hostname": "", "InteractionCount": 0,
         "MRUPosition": None, "Pinned": None},
    ],
}

JLECMD_ROWS = [
    _JL_RECORD,
    {"AppId": {}, "DestListEntries": []},               # yields nothing
    _JL_MULTI,
    {"SourceFile": "/in/AutomaticDestinations/none.automaticDestinations-ms"},
    {"AppId": None, "DestListEntries": None},           # both falsy
    # no AppId key at all: AppId/AppDescription come out None
    {"SourceFile": "/in/x.automaticDestinations-ms",
     "DestListEntries": [{"Path": r"D:\evidence\case.eml", "EntryNumber": 9,
                          "LastModified": "/Date(1522917168677)/",
                          "Hostname": "desktop-pm6c56d"}]},
]

DOTNET_DATE_VALUES = [
    "/Date(1522187139502)/", "/Date(1522917168677)/", "/Date(0)/",
    "/Date(-11644473600000)/", "/Date(-1)/", "/Date(1)/", "/Date(999)/",
    "/Date(1522187139502)/ trailing", "prefix /Date(1522187139502)/",
    "2018-04-05T09:52:48.677000+00:00", "not a date", "-",
    "", None, 0, False, True, 1522187139502, 1.5, [], {},
    "/Date(253402300799999)/",        # 9999-12-31T23:59:59.999
    "/Date(253402300800000)/",        # one ms past MAXYEAR → None
    "/Date(-62135596800000)/",        # 0001-01-01T00:00:00
    "/Date(-62135596800001)/",        # one ms before MINYEAR → None
    "/Date(99999999999999999999999)/",
]

# ===========================================================================
# split — table names + wrapped rows
# ===========================================================================
TABLE_NAME_VALUES = [
    "filestat", "winreg/appcompatcache", "firefox_cache", "usnjrnl", "mft",
    "text/syslog_traditional", "olecf/olecf_automatic_destinations",
    "winevtx", "winevt", "sqlite/chrome_27_history", "utmp", "utmpx",
    "", "/", "///", "unknown", "UPPER", "a_b-c.d", "___", "9lives",
    "esedb/srum", "plist/macosx_bluetooth", "recycle_bin", "prefetch",
    "a b", "Ünïcödé", "x/y/z", "-leading", "trailing-",
]

_PLASO_UTMP = {
    "data_type": "linux:utmp:event", "display_name": "OS:/var/log/wtmp",
    "hostname": "pits-insec", "username": "insec", "terminal": "pts/0",
    "ip_address": "156.59.33.60", "pid": 3756, "type": 7,
    "timestamp_desc": "Start Time",
}
_PLASO_MFT = {
    "data_type": "fs:stat:ntfs", "display_name": "NTFS:\\Windows\\notepad.exe",
    "path_hints": ["\\Windows\\notepad.exe"], "file_reference": 281474976727294,
    "attribute_type": 16, "timestamp_desc": "Creation Time",
}
_PLASO_USN = {
    "data_type": "fs:ntfs:usn_change", "display_name": "NTFS:\\$Extend\\$UsnJrnl:$J",
    "filename": "a15f3474.tmp", "update_reason_flags": 2147484416,
    "update_sequence_number": 1048576, "timestamp_desc": "Metadata Modification Time",
}

SPLIT_ROW_CASES = [
    # (record, source_rel, record_id)
    (dict(_PLASO_UTMP, parser="utmp", timestamp=1600262099805465), "img.jsonl", 1),
    (dict(_PLASO_MFT, parser="mft", timestamp=1600262070462820), "img.jsonl", 4),
    (dict(_PLASO_USN, parser="usnjrnl", timestamp=1600262070462821), "img.jsonl", 5),
    # no record id at all (the bare-row call shape)
    (dict(_PLASO_UTMP, parser="utmp", timestamp=1600262099805465), "img.jsonl", None),
    # timestamp edges: 0 / negative / absent / float / bool / str / huge
    (dict(_PLASO_MFT, parser="mft", timestamp=0), "img.jsonl", 2),
    (dict(_PLASO_MFT, parser="mft", timestamp=-1), "img.jsonl", 3),
    (dict(_PLASO_MFT, parser="mft"), "img.jsonl", 6),
    (dict(_PLASO_MFT, parser="mft", timestamp=1600262070462820.75), "img.jsonl", 7),
    (dict(_PLASO_MFT, parser="mft", timestamp=1), "img.jsonl", 8),
    (dict(_PLASO_MFT, parser="mft", timestamp=True), "img.jsonl", 9),
    (dict(_PLASO_MFT, parser="mft", timestamp="1600262070462820"), "img.jsonl", 10),
    (dict(_PLASO_MFT, parser="mft", timestamp=None), "img.jsonl", 11),
    (dict(_PLASO_MFT, parser="mft", timestamp=253402300799999999), "img.jsonl", 12),
    (dict(_PLASO_MFT, parser="mft", timestamp=253402300800000000), "img.jsonl", 13),
    (dict(_PLASO_MFT, parser="mft", timestamp=10 ** 30), "img.jsonl", 14),
    # parser edges: absent / falsy / non-str / multi-segment
    ({"data_type": "x", "timestamp": 1600262070462820}, "img.jsonl", 15),
    ({"parser": "", "timestamp": 1600262070462820}, "img.jsonl", 16),
    ({"parser": 42, "timestamp": 1600262070462820}, "img.jsonl", 17),
    ({"parser": "olecf/olecf_automatic_destinations"}, "img.jsonl", 18),
    # non-ASCII + escaping in the record (json.dumps ensure_ascii=True)
    ({"parser": "text/syslog", "message": "ünïcödé \u2603 \"q\" \\ \n",
      "timestamp": 1600262070462820}, "img.jsonl", 19),
    # an empty source_rel (l2t_tables' dry-run shape)
    (dict(_PLASO_UTMP, parser="utmp", timestamp=1600262099805465), "", 20),
]


def main() -> int:
    winevt = _reference("winevt.py")
    jlecmd = _reference("jlecmd.py")
    l2t = _reference("l2t_split.py")

    # --- adapt/testdata/winevt_vectors.json --------------------------------
    cases = [{"wrapped": w, "out": winevt.adapt(w)} for w in WINEVT_ROWS]
    matched = sum(1 for c in cases if c["out"] is not None)
    assert matched, "no winevt row matched a rule"
    _write_json(os.path.join(ADAPT_TESTDATA, "winevt_vectors.json"),
                {"cases": cases})
    print(f"wrote go/internal/adapt/testdata/winevt_vectors.json "
          f"({len(cases)} cases, {matched} matched)")

    # --- adapt/testdata/jlecmd_vectors.json --------------------------------
    doc = {
        "dotnet_date": [[v, jlecmd.dotnet_date(v)] for v in DOTNET_DATE_VALUES],
        "flatten": [{"rec": r, "out": list(jlecmd.flatten(r))} for r in JLECMD_ROWS],
    }
    _write_json(os.path.join(ADAPT_TESTDATA, "jlecmd_vectors.json"), doc)
    print(f"wrote go/internal/adapt/testdata/jlecmd_vectors.json "
          f"({len(doc['dotnet_date'])} dates, {len(doc['flatten'])} records)")

    # --- split/testdata/split_vectors.json ---------------------------------
    rows = []
    for rec, source, rid in SPLIT_ROW_CASES:
        table, line = l2t._l2t_row(rec, source, rid)  # noqa: SLF001
        rows.append({"rec": rec, "source_rel": source, "record_id": rid,
                     "table": table, "line": line})
    _write_json(os.path.join(SPLIT_TESTDATA, "split_vectors.json"),
                {"table_name": [[v, l2t.table_name(v)] for v in TABLE_NAME_VALUES],
                 "rows": rows})
    print(f"wrote go/internal/split/testdata/split_vectors.json "
          f"({len(TABLE_NAME_VALUES)} names, {len(rows)} rows)")

    # --- fixtures/adapter_winevt --------------------------------------------
    from byakugan.pipeline import EVTX_MAPS  # the fan-out the adapter feeds
    _lib.write_fixture(
        "adapter_winevt",
        {"artefacts": list(EVTX_MAPS), "host": "lonewolf",
         "adapter": "winevt", "input": "input.jsonl"},
        [j(w) + b"\n" for w in WINEVT_ROWS])

    # --- fixtures/adapter_jlecmd --------------------------------------------
    _lib.write_fixture(
        "adapter_jlecmd",
        {"artefacts": ["jlecmd_dest"], "host": None,
         "adapter": "jlecmd", "input": "input.jsonl"},
        [j(r) + b"\n" for r in JLECMD_ROWS])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

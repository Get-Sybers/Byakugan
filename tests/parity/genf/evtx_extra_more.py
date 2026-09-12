"""Parity vectors + fixtures for the `evtx_extra_more` family — the two
operational-channel event-log modules that share one Go predicate file:

    byakugan/mappings/evtx_extra.py  → evtx_bits, evtx_rdp
                                       (evtxx_is_bits_transfer, evtxx_is_ts_session)
    byakugan/mappings/evtx_more.py   → evtx_more (7 variants, 7 gates)

The two modules gate EventId DIFFERENTLY and the difference is observable, so
both halves are pinned here:

  * evtx_extra: ``rec.get("EventId") in (59, 60)`` — Python ``==``. The STRING
    "59" never matches; 59.0 does; True is 1.
  * evtx_more:  ``int(rec.get("EventId"))`` in a try/except (TypeError,
    ValueError). "4907" DOES match, 7034.9 truncates to 7034, "7_034" parses,
    "0x1D9A"/""/None/absent do not.

`evtx_more` has ZERO behavioural tests in tests/; its fixture rows are authored
from the module docstring's six documented shapes (4907 File, WMI 5857,
UserPnp 20003, SmbClient 30803, Winlogon 7001/7002, SCM 7034) and every one was
checked to actually EMIT through the live Python map before being committed.

    python tests/parity/genf/evtx_extra_more.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/evtx_extra_more.json
    tests/parity/fixtures/evtx_extra_more_bits/
    tests/parity/fixtures/evtx_extra_more_rdp/
    tests/parity/fixtures/evtx_extra_more_variants/
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "evtx_extra_more"

j = _lib.j


# ---------------------------------------------------------------------------
# payload shape builders (the two EvtxECmd blob shapes these channels use)
# ---------------------------------------------------------------------------

def _data(pairs) -> str:
    """EventData.Data — the {@Name,#text} list shape, as the JSON STRING
    EvtxECmd stamps into Payload."""
    return json.dumps({"EventData": {"Data": [
        ({"@Name": k} if v is _ABSENT else {"@Name": k, "#text": v})
        for k, v in pairs]}})


def _ud(child: str, fields: dict) -> str:
    """UserData -> <single child> -> fields — the TerminalServices / WMI /
    UserPnp shape, as the JSON STRING in Payload."""
    return json.dumps({"UserData": {child: fields}})


class _Absent:
    pass


_ABSENT = _Absent()


# ---------------------------------------------------------------------------
# predicate vectors
# ---------------------------------------------------------------------------

_BITS_CH = "Microsoft-Windows-Bits-Client/Operational"
_TS_CH = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"


def _ot(value):
    """A Security 4907-shaped record whose ObjectType payload entry is `value`
    (`_ABSENT` for an entry with no #text at all)."""
    return {"EventId": 4907, "Channel": "Security",
            "Payload": _data([("ObjectType", value),
                              ("ObjectName", r"C:\secrets\payroll.xlsx")])}


PREDICATE_CASES = [
    # --- evtxx_is_bits_transfer: `EventId in (59, 60)` (==, not int()) -------
    ("evtxx_is_bits_transfer", {"EventId": 59, "Channel": _BITS_CH}),
    ("evtxx_is_bits_transfer", {"EventId": 60, "Channel": _BITS_CH}),
    ("evtxx_is_bits_transfer", {"EventId": 58, "Channel": _BITS_CH}),
    ("evtxx_is_bits_transfer", {"EventId": 59.0, "Channel": _BITS_CH}),   # float ==
    ("evtxx_is_bits_transfer", {"EventId": "59", "Channel": _BITS_CH}),   # str ≠ int
    ("evtxx_is_bits_transfer", {"EventId": True, "Channel": _BITS_CH}),   # True == 1
    ("evtxx_is_bits_transfer", {"EventId": None, "Channel": _BITS_CH}),
    ("evtxx_is_bits_transfer", {"Channel": _BITS_CH}),                    # absent
    ("evtxx_is_bits_transfer", {"EventId": 59}),                          # Channel absent → ""
    ("evtxx_is_bits_transfer", {"EventId": 59, "Channel": None}),         # str(None) = "None"
    ("evtxx_is_bits_transfer", {"EventId": 59, "Channel": 59}),           # str(int)
    ("evtxx_is_bits_transfer", {"EventId": 59, "Channel": "BITS-Client"}),  # case-sensitive
    ("evtxx_is_bits_transfer", {"EventId": 59, "Channel": "Bits-Client"}),  # bare needle
    ("evtxx_is_bits_transfer", {}),
    # --- evtxx_is_ts_session: `EventId in (21, 24, 25)` ---------------------
    ("evtxx_is_ts_session", {"EventId": 21, "Channel": _TS_CH}),
    ("evtxx_is_ts_session", {"EventId": 24, "Channel": _TS_CH}),
    ("evtxx_is_ts_session", {"EventId": 25, "Channel": _TS_CH}),
    ("evtxx_is_ts_session", {"EventId": 22, "Channel": _TS_CH}),
    ("evtxx_is_ts_session", {"EventId": 21.0, "Channel": _TS_CH}),  # gate yes, action miss
    ("evtxx_is_ts_session", {"EventId": "21", "Channel": _TS_CH}),  # str ≠ int
    ("evtxx_is_ts_session", {"EventId": 21, "Channel": "TerminalServices-LocalSessionManager"}),
    ("evtxx_is_ts_session", {"EventId": 21, "Channel": "Microsoft-Windows-TerminalServices-RDPClient"}),
    ("evtxx_is_ts_session", {"EventId": 21, "Channel": None}),
    ("evtxx_is_ts_session", {"EventId": 21}),
    ("evtxx_is_ts_session", {}),
    # --- em_is_4907_file: int() EventId + Security + unstripped ObjectType --
    ("em_is_4907_file", _ot("File")),
    ("em_is_4907_file", _ot("Key")),
    ("em_is_4907_file", _ot("File ")),            # UNSTRIPPED gate: no match
    ("em_is_4907_file", _ot(" File")),
    ("em_is_4907_file", _ot("file")),             # case-sensitive
    ("em_is_4907_file", _ot("")),
    ("em_is_4907_file", _ot(None)),               # str(None or '') → ""
    ("em_is_4907_file", _ot(0)),                  # `0 or ''` → ""
    ("em_is_4907_file", _ot(_ABSENT)),            # entry with no #text
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security"}),        # no Payload
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security", "Payload": ""}),
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security", "Payload": "{not json"}),
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security", "Payload": 123}),
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security", "Payload": '"a string"'}),
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security",
                         "Payload": json.dumps({"EventData": "not-a-dict"})}),
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security",
                         "Payload": json.dumps({"EventData": {"Data": []}})}),
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security",
                         "Payload": json.dumps({"EventData": {"Data": {"@Name": "ObjectType"}}})}),
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security",
                         "Payload": json.dumps({"UserData": {"X": {"ObjectType": "File"}}})}),
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security",       # Payload as a DICT
                         "Payload": {"EventData": {"Data": [
                             {"@Name": "ObjectType", "#text": "File"}]}}}),
    ("em_is_4907_file", {"EventId": 4907, "Channel": "Security",       # FIRST @Name wins
                         "Payload": _data([("ObjectType", "Key"), ("ObjectType", "File")])}),
    ("em_is_4907_file", dict(_ot("File"), EventId="4907")),            # int("4907") == 4907
    ("em_is_4907_file", dict(_ot("File"), EventId=4907.9)),            # int() truncates
    ("em_is_4907_file", dict(_ot("File"), EventId=None)),              # TypeError → None
    ("em_is_4907_file", dict(_ot("File"), EventId="")),                # ValueError → None
    ("em_is_4907_file", dict(_ot("File"), EventId="0x132B")),          # ValueError → None
    ("em_is_4907_file", dict(_ot("File"), Channel="System")),
    ("em_is_4907_file", dict(_ot("File"), Channel="Microsoft-Windows-Security-Auditing")),
    ("em_is_4907_file", {k: v for k, v in _ot("File").items() if k != "Channel"}),
    # --- em_is_wmi_5857 -----------------------------------------------------
    ("em_is_wmi_5857", {"EventId": 5857, "Channel": "Microsoft-Windows-WMI-Activity/Operational"}),
    ("em_is_wmi_5857", {"EventId": "5857", "Channel": "WMI-Activity"}),   # str coerces
    ("em_is_wmi_5857", {"EventId": " 5857 ", "Channel": "WMI-Activity"}),  # int() strips
    ("em_is_wmi_5857", {"EventId": "5_857", "Channel": "WMI-Activity"}),   # int() underscores
    ("em_is_wmi_5857", {"EventId": True, "Channel": "WMI-Activity"}),      # int(True) == 1
    ("em_is_wmi_5857", {"EventId": 5857, "Channel": "System"}),
    ("em_is_wmi_5857", {"EventId": 5858, "Channel": "WMI-Activity"}),
    ("em_is_wmi_5857", {}),
    # --- em_is_pnp_20003 ----------------------------------------------------
    ("em_is_pnp_20003", {"EventId": 20003, "Channel": "System"}),
    ("em_is_pnp_20003", {"EventId": "20003", "Channel": "System"}),
    ("em_is_pnp_20003", {"EventId": 20003, "Channel": "Microsoft-Windows-UserPnp/DeviceInstall"}),
    ("em_is_pnp_20003", {"EventId": 20001, "Channel": "System"}),
    ("em_is_pnp_20003", {"EventId": 20003, "Channel": None}),
    # --- em_is_smb_30803 ----------------------------------------------------
    ("em_is_smb_30803", {"EventId": 30803, "Channel": "Microsoft-Windows-SmbClient/Connectivity"}),
    ("em_is_smb_30803", {"EventId": 30803.0, "Channel": "SmbClient"}),
    ("em_is_smb_30803", {"EventId": 30803, "Channel": "Microsoft-Windows-SMBClient/Connectivity"}),
    ("em_is_smb_30803", {"EventId": 30804, "Channel": "SmbClient"}),
    # --- em_is_winlogon_7001 / 7002 / em_is_scm_7034 ------------------------
    ("em_is_winlogon_7001", {"EventId": 7001, "Channel": "System"}),
    ("em_is_winlogon_7001", {"EventId": 7002, "Channel": "System"}),
    ("em_is_winlogon_7001", {"EventId": 7001, "Channel": "Application"}),
    ("em_is_winlogon_7001", {"EventId": "7001", "Channel": "System"}),
    ("em_is_winlogon_7002", {"EventId": 7002, "Channel": "System"}),
    ("em_is_winlogon_7002", {"EventId": 7001, "Channel": "System"}),
    ("em_is_winlogon_7002", {"EventId": 7002.0, "Channel": "System"}),
    ("em_is_scm_7034", {"EventId": 7034, "Channel": "System"}),
    ("em_is_scm_7034", {"EventId": 7034.9, "Channel": "System"}),   # int() truncates
    ("em_is_scm_7034", {"EventId": "7_034", "Channel": "System"}),  # int() underscores
    ("em_is_scm_7034", {"EventId": -7034, "Channel": "System"}),
    ("em_is_scm_7034", {"EventId": 7040, "Channel": "System"}),     # deliberately unmapped
    ("em_is_scm_7034", {"EventId": 7034, "Channel": "SystemD"}),    # substring, not equality
    ("em_is_scm_7034", {"EventId": 7034}),
    ("em_is_scm_7034", {}),
]


# ---------------------------------------------------------------------------
# fixture rows — evtx_bits (records VERBATIM from tests/test_car_evtx_extra.py)
# ---------------------------------------------------------------------------

def _bits(**o):
    """tests/test_car_evtx_extra.py::_bits, verbatim."""
    data = [{"@Name": k, "#text": v} for k, v in {
        "transferId": "c411", "name": "Font Download",
        "url": "https://fs.microsoft.com/fs/windows/config.json",
        "bytesTotal": "55", "bytesTransferred": "55"}.items()]
    rec = {"EventId": 59, "Channel": "Microsoft-Windows-Bits-Client/Operational",
           "Computer": "WIN-1M3263ACE5D", "EventRecordId": 3,
           "TimeCreated": "2018-03-27T12:11:42+00:00",
           "Payload": json.dumps({"EventData": {"Data": data}})}
    rec.update(o); return rec


def _bits_url(url, **o):
    """The same record with a different `url` payload entry."""
    return _bits(Payload=_data([("transferId", "c411"), ("name", "Font Download"),
                                ("url", url), ("bytesTotal", "55"),
                                ("bytesTransferred", "55")]), **o)


BITS_LINES = [
    j(_bits()) + b"\n",                                              # the test record
    j(_bits(EventId=60, EventRecordId=4)) + b"\n",                   # 60 = transfer stopped
    j(_bits(EventId=59.0, EventRecordId=5)) + b"\n",                 # float == 59
    j(_bits(EventId=58, EventRecordId=6)) + b"\n",                   # dropped: gate
    j(_bits(EventId="59", EventRecordId=7)) + b"\n",                 # dropped: str ≠ int
    j(_bits(Channel="Microsoft-Windows-BITS-Client/Operational",
            EventRecordId=8)) + b"\n",                               # dropped: case
    j(_bits_url("fs.microsoft.com/fs/windows/config.json",
                EventRecordId=9)) + b"\n",                           # no scheme → 3 nulls
    j(_bits_url("http://10.0.0.5:8080/stage/a.bin?q=1#frag",
                EventRecordId=10)) + b"\n",                          # port + query + fragment
    j(_bits_url("https://fs.microsoft.com", EventRecordId=11)) + b"\n",  # no path
    j(_bits(Payload=_data([("transferId", "  c411  "), ("name", "-"),
                           ("url", "  https://h.example/x  "),
                           ("bytesTransferred", ""), ("bytesTotal", _ABSENT)]),
            EventRecordId=12)) + b"\n",                              # strip / blank / no #text
    j(_bits(Computer="WIN-1M3263ACE5D.corp.example.com", EventRecordId=13)) + b"\n",
    j({k: v for k, v in _bits(EventRecordId=14).items()
       if k != "Computer"}) + b"\n",                                 # host fallback, guid voided
    j({k: v for k, v in _bits(EventRecordId=15).items()
       if k != "Payload"}) + b"\n",                                  # every payload prop null
    j(_bits(Payload="{not json", EventRecordId=16)) + b"\n",
    j(_bits(Payload=_ud("EventXML", {"url": "https://h/x"}),
            EventRecordId=17)) + b"\n",                              # wrong blob shape
    j(_bits(EventRecordId=None)) + b"\n",                            # guid voided by None
    j(_bits(SourceFile="C:\\evtx\\Bits.evtx",
            MapDescription="BITS transfer", EventRecordId=18)) + b"\n",
]


# ---------------------------------------------------------------------------
# fixture rows — evtx_rdp (records VERBATIM from tests/test_car_evtx_extra.py)
# ---------------------------------------------------------------------------

def _ts(eid=21, address="LOCAL"):
    """tests/test_car_evtx_extra.py::_ts, verbatim."""
    return {"EventId": eid,
            "Channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Computer": "WIN-1M3263ACE5D", "EventRecordId": 7,
            "TimeCreated": "2018-03-27T12:11:42+00:00",
            "Payload": json.dumps({"UserData": {"EventXML": {
                "User": r"DESKTOP-PM6C56D\defaultuser0", "SessionID": "1",
                "Address": address}}})}


def _ts_ud(eid, fields, **o):
    rec = _ts(eid)
    rec["Payload"] = _ud("EventXML", fields)
    rec.update(o)
    return rec


RDP_LINES = [
    j(_ts(21, "LOCAL")) + b"\n",                     # the test record: src_ip null
    j(dict(_ts(24), EventRecordId=8)) + b"\n",       # logout
    j(dict(_ts(21, "10.0.0.9"), EventRecordId=9)) + b"\n",   # a real remote source
    j(dict(_ts(25, "10.0.0.9"), EventRecordId=10)) + b"\n",  # reconnect
    j(dict(_ts(22, "10.0.0.9"), EventRecordId=11)) + b"\n",  # dropped: gate
    j(dict(_ts(21.0, "10.0.0.9"), EventRecordId=12)) + b"\n",  # gate YES, action miss → dropped
    j(dict(_ts("21", "10.0.0.9"), EventRecordId=13)) + b"\n",  # dropped: str ≠ int
    j(_ts_ud(21, {"User": r"DESKTOP-PM6C56D\defaultuser0", "SessionID": "1",
                  "Address": "LOCALHOST"}, EventRecordId=14)) + b"\n",   # ^(?!LOCAL$) passes
    j(_ts_ud(21, {"User": r"  DESKTOP-PM6C56D\jcloudy  ", "SessionID": 2,
                  "Address": ""}, EventRecordId=15)) + b"\n",            # strip + blank
    j(_ts_ud(24, {"SessionID": "3"}, EventRecordId=16)) + b"\n",         # no User/Address
    j(_ts_ud(21, {"User": "NT AUTHORITY\\SYSTEM", "SessionID": "0",
                  "Address": "-"}, EventRecordId=17)) + b"\n",           # canon + '-' blank
    j(_ts_ud(21, {"User": "S-1-5-18", "Address": "::1"},
             EventRecordId=18)) + b"\n",                                 # well-known SID
    j(dict(_ts(21, "10.0.0.9"), Payload=json.dumps({"UserData": "not-a-dict"}),
           EventRecordId=19)) + b"\n",
    j({k: v for k, v in dict(_ts(21, "10.0.0.9"), EventRecordId=20).items()
       if k != "Payload"}) + b"\n",
    j({k: v for k, v in dict(_ts(21, "10.0.0.9"), EventRecordId=21).items()
       if k != "Computer"}) + b"\n",                                     # host fallback
    j(dict(_ts(21, "10.0.0.9"), Computer="WIN-1M3263ACE5D.corp.example.com",
           UserName=r"DESKTOP-PM6C56D\defaultuser0", EventRecordId=22)) + b"\n",
]


# ---------------------------------------------------------------------------
# fixture rows — evtx_more (AUTHORED from the module docstring: zero existing
# behavioural tests). Every shape below was verified to emit through the live
# Python map before being committed.
# ---------------------------------------------------------------------------

def _sys(eid, pairs, **o):
    """A System-channel EvtxECmd record with an EventData.Data payload."""
    rec = {"EventId": eid, "Channel": "System", "Provider": "Service Control Manager",
           "Computer": "WIN-1M3263ACE5D.corp.example.com", "EventRecordId": 100,
           "TimeCreated": "2018-03-27T12:11:42+00:00", "Payload": _data(pairs)}
    rec.update(o)
    return rec


_4907 = {
    "EventId": 4907, "Channel": "Security",
    "Provider": "Microsoft-Windows-Security-Auditing",
    "Computer": "WIN-1M3263ACE5D.corp.example.com", "EventRecordId": 200,
    "TimeCreated": "2018-03-27T12:11:42+00:00",
    "UserName": "CORP\\jcloudy",
    "SourceFile": "C:\\evtx\\Security.evtx",
    "MapDescription": "Auditing settings on object changed",
    "Payload": _data([
        ("SubjectUserSid", "S-1-5-21-1004336348-1177238915-682003330-1004"),
        ("SubjectUserName", "jcloudy"), ("SubjectDomainName", "CORP"),
        ("SubjectLogonId", "0x1f8a3"),
        ("ObjectServer", "Security"), ("ObjectType", "File"),
        ("ObjectName", r"C:\Users\jcloudy\Documents\payroll.xlsx"),
        ("HandleId", "0x8fc"),
        ("ProcessId", "0x1f4"), ("ProcessName", r"C:\Windows\explorer.exe"),
        ("OldSd", "D:AI(A;;FA;;;SY)"), ("NewSd", "D:AI(A;;FA;;;SY)S:AI(AU;SA;FA;;;WD)"),
    ]),
}

_5857 = {
    "EventId": 5857, "Channel": "Microsoft-Windows-WMI-Activity/Operational",
    "Provider": "Microsoft-Windows-WMI-Activity",
    "Computer": "WIN-1M3263ACE5D.corp.example.com", "EventRecordId": 300,
    "TimeCreated": "2018-03-27T12:12:00+00:00",
    "Payload": _ud("Operation_StartedOperational", {
        "ProviderName": "CIMWin32", "Code": "0x0",
        "HostProcess": "wmiprvse.exe", "ProcessID": "2768",
        "ProviderPath": r"%systemroot%\system32\wbem\cimwin32.dll"}),
}

_20003 = {
    "EventId": 20003, "Channel": "System", "Provider": "Microsoft-Windows-UserPnp",
    "Computer": "WIN-1M3263ACE5D.corp.example.com", "EventRecordId": 400,
    "TimeCreated": "2018-03-27T12:13:00+00:00",
    "Payload": _ud("InstallDeviceID", {
        "DeviceInstanceID": r"USB\VID_0951&PID_1666\4C530001260516117401",
        "DriverName": "usbstor.inf_amd64_1a0d", "ServiceName": "USBSTOR",
        "DriverFileName": r"C:\Windows\System32\drivers\USBSTOR.SYS",
        "PrimaryService": "true", "AddServiceStatus": "0"}),
}

_30803 = {
    "EventId": 30803, "Channel": "Microsoft-Windows-SmbClient/Connectivity",
    "Provider": "Microsoft-Windows-SMBClient",
    "Computer": "WIN-1M3263ACE5D.corp.example.com", "EventRecordId": 500,
    "TimeCreated": "2018-03-27T12:14:00+00:00",
    "Payload": _data([
        ("ServerName", "FILESRV01.corp.example.com"),
        ("RemoteAddress", "02000239AC10011400000000000000000000000000000000"),
        ("LocalAddress", "02000000AC1001160000000000000000"),
        ("Status", "0"), ("Reason", "4"),
    ]),
}

_7001 = _sys(7001, [("UserSid", "S-1-5-21-1004336348-1177238915-682003330-1004"),
                    ("TSId", "1")],
             Provider="Microsoft-Windows-Winlogon", EventRecordId=600,
             TimeCreated="2018-03-27T12:15:00+00:00")
_7002 = _sys(7002, [("UserSid", "S-1-5-21-1004336348-1177238915-682003330-1004"),
                    ("TSId", "1")],
             Provider="Microsoft-Windows-Winlogon", EventRecordId=601,
             TimeCreated="2018-03-27T12:45:00+00:00")
_7034 = _sys(7034, [("param1", "Print Spooler"), ("param2", "3")],
             EventRecordId=700, TimeCreated="2018-03-27T12:16:00+00:00",
             SourceFile="C:\\evtx\\System.evtx",
             MapDescription="Service terminated unexpectedly")

MORE_LINES = [
    j(_4907) + b"\n",                                            # file/acl_modify
    j(dict(_4907, EventId="4907", EventRecordId=201)) + b"\n",   # int("4907") matches
    j(dict(_4907, EventRecordId=202,
           Payload=_data([("ObjectType", "Key"),
                          ("ObjectName", r"\REGISTRY\MACHINE\SOFTWARE")]))) + b"\n",  # dropped
    j(dict(_4907, EventRecordId=203,
           Payload=_data([("ObjectType", "File "),
                          ("ObjectName", r"C:\x.txt")]))) + b"\n",   # unstripped gate: dropped
    j(dict(_4907, EventRecordId=204,
           Payload=_data([("ObjectType", "File"),
                          ("ObjectName", r"C:\Windows\System32\drivers\etc\hosts"),
                          ("ProcessId", "1908"),           # decimal, not hex
                          ("SubjectUserName", "SYSTEM")]))) + b"\n",
    j(dict(_4907, EventRecordId=205, Channel="System")) + b"\n",     # dropped: channel
    j(_5857) + b"\n",                                                # module/load
    j(dict(_5857, EventRecordId=301, Channel="System")) + b"\n",     # dropped: channel
    j(dict(_5857, EventRecordId=302,
           Payload=_ud("Operation_StartedOperational",
                       {"ProviderName": "-", "ProcessID": "", "Code": "0x0"}))) + b"\n",
    j(_20003) + b"\n",                                               # service/create
    j(dict(_20003, EventId="20003", EventRecordId=401)) + b"\n",     # str EventId matches
    j(dict(_20003, EventRecordId=402,
           Channel="Microsoft-Windows-UserPnp/DeviceInstall")) + b"\n",  # dropped: channel
    j(_30803) + b"\n",                                               # flow/start
    j(dict(_30803, EventRecordId=501, EventId=30803.0)) + b"\n",     # int(30803.0) matches
    j(_7001) + b"\n",                                                # user_session/login
    j(_7002) + b"\n",                                                # user_session/logout
    j(_7034) + b"\n",                                                # service/stop
    j(dict(_7034, EventId=7034.9, EventRecordId=701)) + b"\n",       # int() truncates → matches
    j(dict(_7034, EventId="7_034", EventRecordId=702)) + b"\n",      # int() underscores
    j(dict(_7034, EventId="0x1B7A", EventRecordId=703)) + b"\n",     # ValueError → dropped
    j(dict(_7034, EventId=None, EventRecordId=704)) + b"\n",         # TypeError → dropped
    j(dict(_7034, EventId=7040, EventRecordId=705)) + b"\n",         # deliberately unmapped
    j(dict(_7034, EventRecordId=706, Computer="WIN-1M3263ACE5D")) + b"\n",   # no dot → fqdn null
    j({k: v for k, v in dict(_7034, EventRecordId=707).items()
       if k != "Computer"}) + b"\n",                                 # host fallback, guid voided
    j(dict(_7034, EventRecordId=708, Payload="{not json")) + b"\n",  # name null
    j({k: v for k, v in dict(_7001, EventRecordId=709).items()
       if k != "Payload"}) + b"\n",                                  # uid null, const stays
]


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)
    _lib.write_fixture("evtx_extra_more_bits",
                       {"artefacts": ["evtx_bits"], "host": "WIN-FALLBACK",
                        "adapter": "none", "input": "input.jsonl"}, BITS_LINES)
    _lib.write_fixture("evtx_extra_more_rdp",
                       {"artefacts": ["evtx_rdp"], "host": "WIN-FALLBACK",
                        "adapter": "none", "input": "input.jsonl"}, RDP_LINES)
    _lib.write_fixture("evtx_extra_more_variants",
                       {"artefacts": ["evtx_more"], "host": "WIN-FALLBACK",
                        "adapter": "none", "input": "input.jsonl"}, MORE_LINES)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

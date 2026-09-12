"""Parity vectors + fixtures for the `evtx_windows` family
(byakugan/mappings/evtx_windows.py — Security logon sessions → user_session,
System 7045 / Security 4697 → service, Security 4688 → process, and the six
``evtxwin_*`` channel/EventId gates).

Every gate in the module has one shape —
``rec.get("EventId") == <id> and "<Channel>" in str(rec.get("Channel", ""))`` —
so the predicate cases pin the numeric-equality edges (str vs int vs float vs
bool, absent) and the channel-substring edges (absent key → "", ``None`` →
Python's ``"None"``, a substring hit inside a longer provider channel name).

The fixture rows are the inline record dicts of tests/test_car_evtx_windows.py,
extracted verbatim (its ``_evtx`` builder is reproduced below field for field),
plus the edge shapes the module docstring calls out: LogonType 7 = unlock, the
4778/4779 AccountName/LogonID/ClientAddress naming, the "LOCAL"/loopback
src_ip deny, the IpPort "0" deny, the 4697 ServiceFileName/ServiceAccount/
ServiceStartType coalescing, and 4688's S-1-0-0 negative-lookahead sid
fallthrough. NOTE: that test module defines ``_sec_4688`` TWICE — the second
(running) definition is the one used here.

    python tests/parity/genf/evtx_windows.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/evtx_windows.json
    tests/parity/fixtures/evtx_windows_sessions/
    tests/parity/fixtures/evtx_windows_services/
    tests/parity/fixtures/evtx_windows_process/
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "evtx_windows"

# ---------------------------------------------------------------------------
# predicate vectors — the six evtxwin_* gates
# ---------------------------------------------------------------------------
PREDICATE_CASES = [
    # --- evtxwin_is_sec_4624 -------------------------------------------------
    ("evtxwin_is_sec_4624", {"EventId": 4624, "Channel": "Security"}),
    ("evtxwin_is_sec_4624", {"EventId": 4624,
                             "Channel": "Microsoft-Windows-Security-Auditing"}),
    ("evtxwin_is_sec_4624", {"EventId": 4624, "Channel": "System"}),
    ("evtxwin_is_sec_4624", {"EventId": "4624", "Channel": "Security"}),  # str ≠ int
    ("evtxwin_is_sec_4624", {"EventId": 4624.0, "Channel": "Security"}),  # float == int
    ("evtxwin_is_sec_4624", {"EventId": True, "Channel": "Security"}),    # bool is 1
    ("evtxwin_is_sec_4624", {"EventId": None, "Channel": "Security"}),
    ("evtxwin_is_sec_4624", {"EventId": 4624}),                 # Channel absent → ""
    ("evtxwin_is_sec_4624", {"EventId": 4624, "Channel": None}),  # str(None) = "None"
    ("evtxwin_is_sec_4624", {"EventId": 4624, "Channel": ""}),
    ("evtxwin_is_sec_4624", {"EventId": 4624, "Channel": 5}),   # str(int) channel
    ("evtxwin_is_sec_4624", {}),                                # both absent
    # --- evtxwin_is_sec_logoff (the 4634/4647/4779 tuple) --------------------
    ("evtxwin_is_sec_logoff", {"EventId": 4634, "Channel": "Security"}),
    ("evtxwin_is_sec_logoff", {"EventId": 4647, "Channel": "Security"}),
    ("evtxwin_is_sec_logoff", {"EventId": 4779, "Channel": "Security"}),
    ("evtxwin_is_sec_logoff", {"EventId": 4624, "Channel": "Security"}),
    ("evtxwin_is_sec_logoff", {"EventId": 4778, "Channel": "Security"}),
    ("evtxwin_is_sec_logoff", {"EventId": 4647.0, "Channel": "Security"}),  # float member
    ("evtxwin_is_sec_logoff", {"EventId": "4634", "Channel": "Security"}),  # str member
    ("evtxwin_is_sec_logoff", {"EventId": 4779, "Channel": "System"}),
    ("evtxwin_is_sec_logoff", {"EventId": 4634}),
    ("evtxwin_is_sec_logoff", {"EventId": None, "Channel": "Security"}),
    ("evtxwin_is_sec_logoff", {}),
    # --- evtxwin_is_sec_4778 -------------------------------------------------
    ("evtxwin_is_sec_4778", {"EventId": 4778, "Channel": "Security"}),
    ("evtxwin_is_sec_4778", {"EventId": 4778, "Channel": "System"}),
    ("evtxwin_is_sec_4778", {"EventId": 4779, "Channel": "Security"}),
    ("evtxwin_is_sec_4778", {"EventId": 4778.0, "Channel": "Security"}),
    ("evtxwin_is_sec_4778", {"EventId": "4778", "Channel": "Security"}),
    ("evtxwin_is_sec_4778", {"EventId": 4778}),
    # --- evtxwin_is_sys_7045 (the ONE System-channel gate) -------------------
    ("evtxwin_is_sys_7045", {"EventId": 7045, "Channel": "System"}),
    ("evtxwin_is_sys_7045", {"EventId": 7045, "Channel": "Security"}),
    ("evtxwin_is_sys_7045", {"EventId": 7045, "Channel": "Windows System Log"}),
    ("evtxwin_is_sys_7045", {"EventId": 7036, "Channel": "System"}),
    ("evtxwin_is_sys_7045", {"EventId": 7045.0, "Channel": "System"}),
    ("evtxwin_is_sys_7045", {"EventId": "7045", "Channel": "System"}),
    ("evtxwin_is_sys_7045", {"EventId": 7045}),
    ("evtxwin_is_sys_7045", {"EventId": 7045, "Channel": None}),
    ("evtxwin_is_sys_7045", {}),
    # --- evtxwin_is_sec_4697 -------------------------------------------------
    ("evtxwin_is_sec_4697", {"EventId": 4697, "Channel": "Security"}),
    ("evtxwin_is_sec_4697", {"EventId": 4697, "Channel": "System"}),
    ("evtxwin_is_sec_4697", {"EventId": 7045, "Channel": "Security"}),
    ("evtxwin_is_sec_4697", {"EventId": 4697.0, "Channel": "Security"}),
    ("evtxwin_is_sec_4697", {"EventId": "4697", "Channel": "Security"}),
    ("evtxwin_is_sec_4697", {"EventId": 4697}),
    # --- evtxwin_is_sec_4688 -------------------------------------------------
    ("evtxwin_is_sec_4688", {"EventId": 4688, "Channel": "Security"}),
    ("evtxwin_is_sec_4688", {"EventId": 4688, "Channel": "System"}),
    ("evtxwin_is_sec_4688", {"EventId": 4688.0, "Channel": "Security"}),
    ("evtxwin_is_sec_4688", {"EventId": "4688", "Channel": "Security"}),
    ("evtxwin_is_sec_4688", {"EventId": 4688, "Channel": None}),
    ("evtxwin_is_sec_4688", {"EventId": 4688}),
    ("evtxwin_is_sec_4688", {"EventId": 4624, "Channel": "Security"}),
    ("evtxwin_is_sec_4688", {}),
]

# ---------------------------------------------------------------------------
# fixtures — the inline records of tests/test_car_evtx_windows.py, verbatim
# ---------------------------------------------------------------------------
j = _lib.j


def _evtx(event_id, channel, data, **cols):
    """tests/test_car_evtx_windows.py::_evtx — a synthetic EvtxECmd JSON row."""
    rec = {"EventId": event_id, "Channel": channel,
           "Computer": "WIN-1M3263ACE5D", "EventRecordId": "1234",
           "TimeCreated": "2018-03-27T12:11:45.4997252+00:00",
           "Payload": json.dumps({"EventData": {"Data": [
               {"@Name": k, "#text": v} for k, v in data.items()]}})}
    rec.update(cols)
    return rec


# --- user_session: the 4624 login family (test module, verbatim) ------------
_4624_DATA = {
    "SubjectUserSid": "S-1-5-18", "SubjectUserName": "WIN-1M3263ACE5D$",
    "SubjectDomainName": "WORKGROUP", "SubjectLogonId": "0x3E7",
    "TargetUserSid": "S-1-5-21-2734969515-1644526556-1039763013-1000",
    "TargetUserName": "defaultuser0", "TargetDomainName": "DESKTOP-PM6C56D",
    "TargetLogonId": "0x18846", "LogonType": "2",
    "LogonProcessName": "User32", "AuthenticationPackageName": "Negotiate",
    "WorkstationName": "WIN-1M3263ACE5D", "ProcessId": "0x1FC",
    "IpAddress": "-", "IpPort": "-",
}

# test_4624_network_logon_src_endpoint's network-logon shape
_4624_NET = dict(_4624_DATA, LogonType="3", IpAddress="10.0.0.9", IpPort="49731")

# test_4634_and_4647_are_logout
_LOGOFF_DATA = {"TargetUserSid": "S-1-5-21-1-2-3-1000",
                "TargetUserName": "defaultuser0",
                "TargetDomainName": "DESKTOP-PM6C56D",
                "TargetLogonId": "0x18846", "LogonType": "2"}
_4647_DATA = {k: v for k, v in _LOGOFF_DATA.items() if k != "LogonType"}

# test_4779_disconnect_is_logout_with_477x_field_names
_4779_DATA = {"AccountName": "jcloudy", "AccountDomain": "DESKTOP-PM6C56D",
              "LogonID": "0x2A5E1", "SessionName": "RDP-Tcp#1",
              "ClientName": "ATTACKER-PC", "ClientAddress": "192.168.1.50"}

# test_4778_reconnect_and_local_console_address
_4778_DATA = {"AccountName": "jcloudy", "LogonID": "0x2A5E1",
              "SessionName": "Console", "ClientName": "WIN-1M3263ACE5D",
              "ClientAddress": "LOCAL"}

# --- service: 7045 (real) / 4697 (synthetic) --------------------------------
_7045_DATA = {"ServiceName": "EvilSvc",
              "ImagePath": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
              "ServiceType": "user mode service", "StartType": "auto start",
              "AccountName": "LocalSystem"}

_4697_DATA = {"SubjectUserSid": "S-1-5-21-1-2-3-1000",
              "SubjectUserName": "jcloudy",
              "SubjectDomainName": "DESKTOP-PM6C56D",
              "SubjectLogonId": "0x2A5E1",
              "ServiceName": "PwnSvc", "ServiceFileName": "C:\\Tools\\pwn.exe",
              "ServiceType": "0x10", "ServiceStartType": "2",
              "ServiceAccount": "LocalSystem"}

# test_service_fqdn_when_computer_is_one / test_service_wrong_channel_and_ids
_SVC_MIN = {"ServiceName": "S", "ImagePath": "C:\\x.exe"}


# --- process: Security 4688 (the SECOND, running _sec_4688) -----------------
def _sec_4688(**over):
    """tests/test_car_evtx_windows.py::_sec_4688 — the SECOND definition (the
    earlier one is shadowed and never runs)."""
    data = [
        {"@Name": "SubjectUserSid", "#text": "S-1-5-18"},
        {"@Name": "SubjectUserName", "#text": "-"},
        {"@Name": "SubjectLogonId", "#text": "0x3E7"},
        {"@Name": "NewProcessId", "#text": "0x150"},
        {"@Name": "NewProcessName", "#text": r"C:\Windows\System32\smss.exe"},
        {"@Name": "TokenElevationType", "#text": "%%1936"},
        {"@Name": "ProcessId", "#text": "0x4"},
        {"@Name": "CommandLine", "#text": None},
        {"@Name": "TargetUserSid", "#text": "S-1-0-0"},
        {"@Name": "TargetUserName", "#text": "-"},
        {"@Name": "MandatoryLabel", "#text": "S-1-16-16384"},
    ]
    rec = {"EventId": 4688, "Channel": "Security", "Computer": "WIN-1M3263ACE5D",
           "EventRecordId": 9, "TimeCreated": "2018-03-27T12:11:42+00:00",
           "Payload": json.dumps({"EventData": {"Data": data}})}
    rec.update(over)
    return rec


# test_sec_4688_is_process_create's runas override (verbatim payload)
_RUNAS_PAYLOAD = json.dumps({"EventData": {"Data": [
    {"@Name": "NewProcessId", "#text": "0x200"},
    {"@Name": "NewProcessName", "#text": r"C:\tmp\x.exe"},
    {"@Name": "ProcessId", "#text": "0x150"},
    {"@Name": "SubjectUserSid", "#text": "S-1-5-18"},
    {"@Name": "TargetUserSid", "#text": "S-1-5-21-1-2-3-1001"},
    {"@Name": "TargetUserName", "#text": "alice"},
]}})


def _payload(pairs):
    """An EvtxECmd Payload blob from an ordered list of (name, text) pairs."""
    return json.dumps({"EventData": {"Data": [
        {"@Name": k, "#text": v} for k, v in pairs]}})


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    # --- evtx_security_sessions ---------------------------------------------
    # 4624 login-type vocabulary + unlock action, the 4634/4647 logoff family,
    # 4778/4779's alternate field names, every src_ip / src_port deny, and the
    # rows that must NOT map (4625/4648/4688/4800/4801, wrong channel).
    _lib.write_fixture(
        "evtx_windows_sessions",
        {"artefacts": ["evtx_security_sessions"], "host": "fallback-host",
         "adapter": "none", "input": "input.jsonl"},
        [j(_evtx(4624, "Security", _4624_DATA)) + b"\n",            # LogonType 2
         # test_4624_login_type_vocabulary: 3 → remote, 10 → rdp, 0/5/11 → null
         j(_evtx(4624, "Security", dict(_4624_DATA, LogonType="3"))) + b"\n",
         j(_evtx(4624, "Security", dict(_4624_DATA, LogonType="10"))) + b"\n",
         j(_evtx(4624, "Security", dict(_4624_DATA, LogonType="0"))) + b"\n",
         j(_evtx(4624, "Security", dict(_4624_DATA, LogonType="5"))) + b"\n",
         j(_evtx(4624, "Security", dict(_4624_DATA, LogonType="11"))) + b"\n",
         # LogonType 7 → the unlock ACTION, login_type still null
         j(_evtx(4624, "Security", dict(_4624_DATA, LogonType="7"))) + b"\n",
         # network logon: real src endpoint, then every nulled origin
         j(_evtx(4624, "Security", _4624_NET)) + b"\n",
         j(_evtx(4624, "Security", dict(_4624_NET, IpAddress="127.0.0.1"))) + b"\n",
         j(_evtx(4624, "Security", dict(_4624_NET, IpAddress="::1"))) + b"\n",
         j(_evtx(4624, "Security", dict(_4624_NET, IpAddress="LOCAL"))) + b"\n",
         j(_evtx(4624, "Security", dict(_4624_NET, IpPort="0"))) + b"\n",
         j(_evtx(4624, "Security", dict(_4624_NET, IpPort="497a1"))) + b"\n",  # non-digit
         # the logoff family (4634 with LogonType, 4647 without) and the 477x pair
         j(_evtx(4634, "Security", _LOGOFF_DATA)) + b"\n",
         j(_evtx(4647, "Security", _4647_DATA)) + b"\n",
         j(_evtx(4779, "Security", _4779_DATA)) + b"\n",
         j(_evtx(4778, "Security", _4778_DATA)) + b"\n",            # ClientAddress LOCAL
         j(_evtx(4778, "Security", dict(_4778_DATA, ClientAddress="10.4.4.4"))) + b"\n",
         # UserName column fallback for `user` (no payload name at all)
         j(_evtx(4634, "Security", {"TargetLogonId": "0x9"}, UserName="fallbackuser")) + b"\n",
         # a Computer-less row: host_label → null, so the fields-guid voids and
         # pipeline's --host fallback fills source_host
         j({"EventId": 4647, "Channel": "Security", "EventRecordId": "77",
            "TimeCreated": "2018-03-27T12:11:45.4997252+00:00",
            "Payload": _payload([("TargetUserName", "ghost"),
                                 ("TargetLogonId", "0x5")])}) + b"\n",
         # test_failures_and_non_session_events_stay_raw — all dropped
         j(_evtx(4625, "Security", _4624_DATA)) + b"\n",
         j(_evtx(4648, "Security", _4624_DATA)) + b"\n",
         j(_evtx(4688, "Security", _4624_DATA)) + b"\n",
         j(_evtx(4800, "Security", _4624_DATA)) + b"\n",
         j(_evtx(4801, "Security", _4624_DATA)) + b"\n",
         j(_evtx(4624, "System", _4624_DATA)) + b"\n"])

    # --- evtx_services -------------------------------------------------------
    _lib.write_fixture(
        "evtx_windows_services",
        {"artefacts": ["evtx_services"], "host": None,
         "adapter": "none", "input": "input.jsonl"},
        [j(_evtx(7045, "System", _7045_DATA, UserId="S-1-5-18")) + b"\n",
         j(_evtx(4697, "Security", _4697_DATA)) + b"\n",
         # fqdn only when Computer actually is one (and hostname is its label)
         j(_evtx(7045, "System", _SVC_MIN, Computer="HOST1.example.com")) + b"\n",
         # a quoted ImagePath with a space: exe_path takes the quoted argument
         j(_evtx(7045, "System", dict(_7045_DATA, ServiceName="Quoted",
                                      ImagePath='"C:\\Program Files\\a b\\svc.exe" -x'))) + b"\n",
         # no .exe and no quote: exe_path cuts at the first space token
         j(_evtx(7045, "System", dict(_7045_DATA, ServiceName="Driver",
                                      ImagePath="\\SystemRoot\\System32\\drivers\\evil.sys"))) + b"\n",
         # AccountName absent → ServiceAccount → UserName column last resort
         j(_evtx(7045, "System", {"ServiceName": "NoAcct", "ImagePath": "C:\\y.exe"},
                 UserName="DESKTOP-PM6C56D\\jcloudy")) + b"\n",
         # blanks everywhere the map coalesces: honest nulls, not fabricated
         j(_evtx(7045, "System", {"ServiceName": "-", "ImagePath": "",
                                  "AccountName": "-", "StartType": "-",
                                  "ServiceType": ""})) + b"\n",
         # test_service_wrong_channel_and_ids_stay_raw — all dropped
         j(_evtx(7045, "Security", _SVC_MIN)) + b"\n",
         j(_evtx(4697, "System", _SVC_MIN)) + b"\n",
         j(_evtx(7036, "System", _SVC_MIN)) + b"\n"])

    # --- evtx_process --------------------------------------------------------
    _lib.write_fixture(
        "evtx_windows_process",
        {"artefacts": ["evtx_process"], "host": "fallback-host",
         "adapter": "none", "input": "input.jsonl"},
        [j(_sec_4688()) + b"\n",                                  # S-1-0-0 → Subject sid
         j(_sec_4688(Payload=_RUNAS_PAYLOAD, EventRecordId=10)) + b"\n",  # a real runas
         # ParentProcessName present → parent_image_path / parent_exe (the
         # module docstring's 4688 field set; the running test's row omits it)
         j(_sec_4688(EventRecordId=11, Payload=_payload([
             ("SubjectUserSid", "S-1-5-18"), ("SubjectUserName", "WIN-ABC$"),
             ("SubjectLogonId", "0x3E7"), ("SubjectDomainName", "WORKGROUP"),
             ("NewProcessId", "0x150"),
             ("NewProcessName", r"C:\Windows\System32\smss.exe"),
             ("TokenElevationType", "%%1936"), ("ProcessId", "0x4"),
             ("CommandLine", None), ("TargetUserSid", "S-1-0-0"),
             ("TargetUserName", "-"),
             ("ParentProcessName", r"C:\Windows\System32\wininit.exe"),
             ("MandatoryLabel", "S-1-16-16384")]))) + b"\n",
         # command-line auditing ON + every other MandatoryLabel value
         j(_sec_4688(EventRecordId=12, Payload=_payload([
             ("SubjectUserSid", "S-1-5-21-1-2-3-1000"),
             ("SubjectUserName", "jcloudy"), ("SubjectLogonId", "0x2A5E1"),
             ("SubjectDomainName", "DESKTOP-PM6C56D"),
             ("NewProcessId", "0x7B0"),
             ("NewProcessName", r"C:\Windows\System32\cmd.exe"),
             ("CommandLine", r'"C:\Windows\System32\cmd.exe" /c whoami'),
             ("ProcessId", "0x150"),
             ("ParentProcessName", r"C:\Windows\explorer.exe"),
             ("TargetUserSid", "S-1-0-0"), ("TargetUserName", "-"),
             ("MandatoryLabel", "S-1-16-12288"),
             ("TokenElevationType", "%%1937")]))) + b"\n",
         j(_sec_4688(EventRecordId=13, Payload=_payload([
             ("SubjectUserName", "jcloudy"), ("NewProcessId", "0x10"),
             ("ProcessId", "0x8"), ("NewProcessName", r"C:\t\low.exe"),
             ("MandatoryLabel", "S-1-16-4096")]))) + b"\n",     # low
         j(_sec_4688(EventRecordId=14, Payload=_payload([
             ("SubjectUserName", "jcloudy"), ("NewProcessId", "0x11"),
             ("ProcessId", "0x8"), ("NewProcessName", r"C:\t\u.exe"),
             ("MandatoryLabel", "S-1-16-0")]))) + b"\n",        # untrusted
         j(_sec_4688(EventRecordId=15, Payload=_payload([
             ("SubjectUserName", "jcloudy"), ("NewProcessId", "0x12"),
             ("ProcessId", "0x8"), ("NewProcessName", r"C:\t\m.exe"),
             ("MandatoryLabel", "S-1-16-8448")]))) + b"\n",     # medium (plus-)
         j(_sec_4688(EventRecordId=16, Payload=_payload([
             ("SubjectUserName", "jcloudy"), ("NewProcessId", "0x13"),
             ("ProcessId", "0x8"), ("NewProcessName", r"C:\t\x.exe"),
             ("MandatoryLabel", "S-1-16-99999")]))) + b"\n",    # unmapped → null
         # hex_int edges: a non-hex pid, a decimal pid, a blank pid
         j(_sec_4688(EventRecordId=17, Payload=_payload([
             ("SubjectUserName", "jcloudy"), ("NewProcessId", "nothex"),
             ("ProcessId", "1234"), ("NewProcessName", "cmd.exe")]))) + b"\n",
         j(_sec_4688(EventRecordId=18, Payload=_payload([
             ("SubjectUserName", "jcloudy"), ("NewProcessId", "-"),
             ("ProcessId", "-"), ("NewProcessName", "-")]))) + b"\n",
         # a TargetUserSid that is neither S-1-0-0 nor S-prefixed: the deny
         # regex accepts only ^S-.+, so this falls through to SubjectUserSid
         j(_sec_4688(EventRecordId=19, Payload=_payload([
             ("SubjectUserSid", "S-1-5-18"), ("SubjectUserName", "WIN-ABC$"),
             ("NewProcessId", "0x20"), ("ProcessId", "0x4"),
             ("NewProcessName", r"C:\t\z.exe"),
             ("TargetUserSid", "NULL SID"), ("TargetUserName", "-")]))) + b"\n",
         # dropped: wrong channel / wrong EventId
         j(_sec_4688(Channel="System", EventRecordId=20)) + b"\n",
         j(_sec_4688(EventId=4689, EventRecordId=21)) + b"\n"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Parity vectors + fixtures for the `sysmon` family (byakugan/mappings/sysmon.py:
the single `evtx_sysmon` artefact key and its thirteen per-EID gates).

Every gate is `_is_sysmon(rec) and _eid(rec) == <EID>`, where `_eid` is
`int(rec.get("EventId"))` with TypeError/ValueError swallowed — an int()
COERCION, not core's `==` comparison, so "1"/1.9/True all resolve to 1. The
three registry EIDs additionally read the Payload's EventType through the
UNSTRIPPED gating view with a case-SENSITIVE substring test.

    python tests/parity/genf/sysmon.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/sysmon.json
    tests/parity/fixtures/sysmon/          (the unit tests' own records, verbatim)
    tests/parity/fixtures/sysmon_edge/     (the docstrings' edge shapes)

No marker vectors: sysmon resolves only kinds core.json already pins
(payload, basename, ext, lower, regex1, map_value, replace, ts_before,
user_canon, host_label).
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "sysmon"


def _payload(data) -> str:
    """An EvtxECmd Payload blob out of an ordered {name: value} mapping."""
    return json.dumps({"EventData": {"Data": [
        {"@Name": k, "#text": v} for k, v in data.items()]}})


def _et(event_type) -> str:
    """A Payload blob carrying just EventType (the registry gates' authority)."""
    return _payload({"EventType": event_type})


_SYS = "Microsoft-Windows-Sysmon"

# ---------------------------------------------------------------------------
# predicate vectors — every gate, every Provider/EventId/EventType branch
# ---------------------------------------------------------------------------
PREDICATE_CASES = [
    # --- the Provider half: a case-insensitive SUBSTRING test ---------------
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": 1}),
    ("sysmon_proc_create", {"Provider": "SYSMON", "EventId": 1}),
    ("sysmon_proc_create", {"Provider": "sysmon", "EventId": 1}),
    ("sysmon_proc_create", {"Provider": "my-sysmon-shim", "EventId": 1}),
    ("sysmon_proc_create", {"Provider": "Microsoft-Windows-Security-Auditing",
                            "EventId": 1}),
    ("sysmon_proc_create", {"EventId": 1}),                    # absent → ""
    ("sysmon_proc_create", {"Provider": None, "EventId": 1}),  # str(None) = "None"
    ("sysmon_proc_create", {"Provider": "", "EventId": 1}),
    ("sysmon_proc_create", {"Provider": 5, "EventId": 1}),     # str(5) = "5"
    ("sysmon_proc_create", {"Provider": True, "EventId": 1}),  # str(True) = "True"
    # --- the EventId half: int() COERCES (never core's numEq) --------------
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": "1"}),      # str → 1
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": " 1 "}),    # int() strips
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": 1.0}),      # float → 1
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": 1.9}),      # TRUNCATES → 1
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": True}),     # bool → 1
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": False}),    # bool → 0
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": "0x1"}),    # ValueError
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": "1.0"}),    # ValueError
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": "abc"}),    # ValueError
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": ""}),       # ValueError
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": None}),     # TypeError
    ("sysmon_proc_create", {"Provider": _SYS}),                      # absent → TypeError
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": [1]}),      # TypeError
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": 0}),
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": -1}),
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": 10000000000000000000000}),
    ("sysmon_proc_create", {"Provider": _SYS, "EventId": 5}),        # another gate's EID
    # --- one match + one miss for every remaining non-registry gate --------
    ("sysmon_proc_terminate", {"Provider": _SYS, "EventId": 5}),
    ("sysmon_proc_terminate", {"Provider": _SYS, "EventId": "5"}),
    ("sysmon_proc_terminate", {"Provider": _SYS, "EventId": 1}),
    ("sysmon_flow_start", {"Provider": _SYS, "EventId": 3}),
    ("sysmon_flow_start", {"Provider": _SYS, "EventId": 30}),
    ("sysmon_driver_load", {"Provider": _SYS, "EventId": 6}),
    ("sysmon_driver_load", {"Provider": _SYS, "EventId": 7}),
    ("sysmon_module_load", {"Provider": _SYS, "EventId": 7}),
    ("sysmon_module_load", {"Provider": _SYS, "EventId": 6}),
    ("sysmon_thread_remote", {"Provider": _SYS, "EventId": 8}),
    ("sysmon_thread_remote", {"Provider": _SYS, "EventId": 80}),
    ("sysmon_proc_access", {"Provider": _SYS, "EventId": 10}),
    ("sysmon_proc_access", {"Provider": _SYS, "EventId": "10"}),
    ("sysmon_proc_access", {"Provider": _SYS, "EventId": 1}),
    ("sysmon_file_create", {"Provider": _SYS, "EventId": 11}),
    ("sysmon_file_create", {"Provider": _SYS, "EventId": 23}),
    ("sysmon_file_delete", {"Provider": _SYS, "EventId": 23}),
    ("sysmon_file_delete", {"Provider": _SYS, "EventId": 11}),
    ("sysmon_file_delete", {"Provider": "Microsoft-Windows-Security-Auditing",
                            "EventId": 23}),
    # --- the registry EIDs: EventType out of the UNSTRIPPED gating view ----
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et("CreateKey")}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et("CreateValue")}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et("  CreateKey  ")}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et("createkey")}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et("DeleteKey")}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et("Mystery")}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et("")}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et("-")}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et(0)}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et(None)}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": _et(12)}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12,
                        "Payload": _payload({"TargetObject": r"HKLM\X"})}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": "not json"}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": ""}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": None}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12, "Payload": 42}),
    # a Payload that is already a dict (not the EvtxECmd string form)
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12,
                        "Payload": {"EventData": {"Data": [
                            {"@Name": "EventType", "#text": "CreateKey"}]}}}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12,
                        "Payload": json.dumps({"EventData": "odd"})}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12,
                        "Payload": json.dumps({"EventData": {"Data": "odd"}})}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12,
                        "Payload": json.dumps({"UserData": {"X": {"EventType": "CreateKey"}}})}),
    # first matching @Name wins
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 12,
                        "Payload": json.dumps({"EventData": {"Data": [
                            {"@Name": "EventType", "#text": "DeleteKey"},
                            {"@Name": "EventType", "#text": "CreateKey"}]}})}),
    ("sysmon_reg_add", {"Provider": _SYS, "EventId": 13, "Payload": _et("CreateKey")}),
    ("sysmon_reg_remove", {"Provider": _SYS, "EventId": 12, "Payload": _et("DeleteKey")}),
    ("sysmon_reg_remove", {"Provider": _SYS, "EventId": 12, "Payload": _et("DeleteValue")}),
    ("sysmon_reg_remove", {"Provider": _SYS, "EventId": 12, "Payload": _et("deletekey")}),
    ("sysmon_reg_remove", {"Provider": _SYS, "EventId": 12, "Payload": _et("CreateKey")}),
    ("sysmon_reg_remove", {"Provider": _SYS, "EventId": 14, "Payload": _et("DeleteKey")}),
    ("sysmon_reg_value_set", {"Provider": _SYS, "EventId": 13, "Payload": _et("SetValue")}),
    ("sysmon_reg_value_set", {"Provider": _SYS, "EventId": 13, "Payload": _et("Set")}),
    ("sysmon_reg_value_set", {"Provider": _SYS, "EventId": 13, "Payload": _et("setvalue")}),
    ("sysmon_reg_value_set", {"Provider": _SYS, "EventId": 13, "Payload": _et("CreateKey")}),
    ("sysmon_reg_value_set", {"Provider": _SYS, "EventId": 12, "Payload": _et("SetValue")}),
    ("sysmon_reg_rename", {"Provider": _SYS, "EventId": 14, "Payload": _et("RenameKey")}),
    ("sysmon_reg_rename", {"Provider": _SYS, "EventId": 14, "Payload": _et("RenameValue")}),
    ("sysmon_reg_rename", {"Provider": _SYS, "EventId": 14, "Payload": _et("renamekey")}),
    ("sysmon_reg_rename", {"Provider": _SYS, "EventId": 14, "Payload": _et("Mystery")}),
    ("sysmon_reg_rename", {"Provider": _SYS, "EventId": 13, "Payload": _et("RenameKey")}),
]

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
j = _lib.j


def _rec(eid, data, computer="IEWIN7", record_id="4857", **extra) -> dict:
    """One EvtxECmd-shaped Sysmon record — tests/test_car_sysmon.py's _rec."""
    rec = {
        "Computer": computer, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider": "Microsoft-Windows-Sysmon", "EventId": eid,
        "EventRecordId": record_id, "TimeCreated": "2019-05-26T04:01:42+00:00",
        "UserName": "IEWIN7\\IEUser", "SourceFile": "x.evtx",
        "Payload": _payload(data),
    }
    rec.update(extra)
    return rec


# --- verbatim from tests/test_car_sysmon.py ---------------------------------
_GUID = "365abb72-0fa6-5cea-0000-001049b50a00"
_PGUID = "365abb72-0f32-5cea-0000-0010b5460100"
_HASHES = ("SHA1=8CC66ED54FBEFF205151898D65F6415400124553,"
           "MD5=64FDBD98584331982A15B1F2DF7F08DA,"
           "SHA256=B5DE10A0091B7AAF491BDB810BCE6DAB3F6B4A1C7A917722B5DE014E4A08B6EB,"
           "IMPHASH=D3310CE6CBCACB3A9F0809BC33E38ABE")

_UNIT_RECORDS = [
    # test_eid1_process_create_full_extraction
    _rec(1, {"UtcTime": "2019-05-26 04:01:42.375", "ProcessGuid": _GUID,
             "ProcessId": "3836", "Image": r"C:\Users\IEUser\Desktop\jjs.exe",
             "CommandLine": '"C:\\Users\\IEUser\\Desktop\\jjs.exe" ',
             "CurrentDirectory": r"C:\Users\IEUser\Desktop" + "\\",
             "User": "IEWIN7\\IEUser",
             "LogonGuid": "365abb72-0f31-5cea-0000-002062290100",
             "LogonId": "0x12962", "IntegrityLevel": "High", "Hashes": _HASHES,
             "ParentProcessGuid": _PGUID, "ParentProcessId": "1372",
             "ParentImage": r"C:\Windows\explorer.exe",
             "ParentCommandLine": r"C:\Windows\Explorer.EXE"}),
    # test_eid5_terminate_shares_the_create_guid
    _rec(5, {"UtcTime": "2019-05-26 04:02:00.000", "ProcessGuid": _GUID,
             "ProcessId": "3836", "Image": r"C:\Users\IEUser\Desktop\jjs.exe"}),
    # test_eid3_flow_with_direction_and_transport_protocol
    _rec(3, {"UtcTime": "2019-05-26 15:47:58.815", "ProcessGuid": _GUID,
             "ProcessId": "3388", "Image": r"C:\Windows\System32\notepad.exe",
             "User": "IIS APPPOOL\\DefaultAppPool", "Protocol": "tcp",
             "Initiated": "True", "SourceIp": "127.0.0.1",
             "SourceHostname": "IEWIN7", "SourcePort": "49166",
             "DestinationIp": "10.0.0.5", "DestinationHostname": "DC1",
             "DestinationPort": "135", "DestinationPortName": "epmap"}),
    # test_eid11_file_create_and_eid23_delete_hashes
    _rec(11, {"UtcTime": "2020-02-10 08:28:12.876", "ProcessGuid": _GUID,
              "ProcessId": "2780", "Image": r"C:\Windows\Explorer.EXE",
              "TargetFilename": r"C:\Users\IEUser\Desktop\dummy.sys",
              "CreationUtcTime": "2020-02-10 08:20:00.000"}),
    _rec(23, {"UtcTime": "2020-02-10 08:30:00.000", "ProcessGuid": _GUID,
              "ProcessId": "2780", "User": "IEWIN7\\IEUser",
              "Image": r"C:\Windows\System32\cmd.exe",
              "TargetFilename": r"C:\Users\IEUser\Desktop\dummy.sys",
              "Hashes": _HASHES, "IsExecutable": "true", "Archived": "true"}),
    # test_eid11_fresh_create_is_not_an_overwrite_and_missing_stamp_is_null
    _rec(11, {"UtcTime": "2020-02-10 08:28:12.876", "ProcessGuid": _GUID,
              "ProcessId": "2780", "Image": r"C:\Windows\Explorer.EXE",
              "TargetFilename": r"C:\Users\IEUser\Desktop\new.txt",
              "CreationUtcTime": "2020-02-10 08:28:12.876"}),
    _rec(11, {"UtcTime": "2020-02-10 08:28:12.876", "ProcessGuid": _GUID,
              "ProcessId": "2780", "Image": r"C:\Windows\Explorer.EXE",
              "TargetFilename": r"C:\Users\IEUser\Desktop\new.txt"}),
    # test_registry_actions_are_authoritative_never_bare_edit
    _rec(12, {"UtcTime": "2019-05-16 14:17:15.763", "ProcessGuid": _GUID,
              "ProcessId": "3132", "Image": r"C:\Windows\regedit.exe",
              "EventType": "CreateKey",
              "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system"}),
    _rec(12, {"UtcTime": "2019-05-16 14:17:15.763", "ProcessGuid": _GUID,
              "ProcessId": "3132", "Image": r"C:\Windows\regedit.exe",
              "EventType": "DeleteKey",
              "TargetObject": r"HKU\S-1-5-21-1\Software\X"}),
    _rec(13, {"UtcTime": "2019-05-16 14:17:15.763", "ProcessGuid": _GUID,
              "ProcessId": "3132", "Image": r"C:\Windows\regedit.exe",
              "EventType": "SetValue",
              "TargetObject": r"HKLM\SOFTWARE\...\system\EnableLUA",
              "Details": "DWORD (0x00000000)"}),
    _rec(14, {"UtcTime": "2019-05-16 14:17:15.763", "ProcessGuid": _GUID,
              "ProcessId": "3132", "Image": r"C:\Windows\regedit.exe",
              "EventType": "RenameKey", "TargetObject": r"HKLM\SOFTWARE\A",
              "NewName": r"HKLM\SOFTWARE\B"}),
    # an EID 12 with an unrecognized EventType: no canonical action → raw
    _rec(12, {"UtcTime": "2019-05-16 14:17:15.763", "ProcessGuid": _GUID,
              "ProcessId": "3132", "Image": r"C:\Windows\regedit.exe",
              "EventType": "Mystery", "TargetObject": r"HKLM\X"}),
    # test_eid7_module_and_eid6_driver_signature_semantics
    _rec(7, {"UtcTime": "2020-02-10 08:28:13.147", "ProcessGuid": _GUID,
             "ProcessId": "2780", "Image": r"C:\tools\loader.exe",
             "ImageLoaded": r"C:\Windows\System32\version.dll",
             "Hashes": _HASHES, "Signed": "true",
             "Signature": "Microsoft Windows", "SignatureStatus": "Valid"}),
    _rec(6, {"UtcTime": "2020-02-10 08:28:12.981",
             "ImageLoaded": r"C:\Windows\System32\drivers\VBoxDrv.sys",
             "Hashes": _HASHES, "Signed": "true",
             "Signature": "ChongKim Chan", "SignatureStatus": "Unavailable"}),
    # test_eid8_remote_thread_owner_is_the_source
    _rec(8, {"UtcTime": "2019-05-26 04:01:43.567", "SourceProcessGuid": _GUID,
             "SourceProcessId": "3836",
             "SourceImage": r"C:\Users\IEUser\Desktop\jjs.exe",
             "TargetProcessGuid": _PGUID, "TargetProcessId": "2996",
             "TargetImage": r"C:\Windows\System32\svchost.exe",
             "NewThreadId": "2072", "StartAddress": "0x0000000000090000",
             "StartModule": r"C:\Windows\System32\kernel32.dll",
             "StartFunction": "LoadLibraryA"}),
    # test_sysmon_eid10_process_access
    _rec(10, {"SourceProcessId": "111", "SourceProcessGUID": _GUID,
              "SourceImage": r"C:\w3wp.exe", "TargetProcessId": "222",
              "TargetProcessGUID": _PGUID, "TargetImage": r"C:\notepad.exe",
              "GrantedAccess": "0x1FFFFF", "CallTrace": "ntdll.dll+..."}),
    # test_enrich_links_sysmon_spokes_definitively
    _rec(1, {"ProcessGuid": _GUID, "ProcessId": "3836", "Image": r"C:\evil.exe",
             "CommandLine": "evil -x", "User": "IEWIN7\\IEUser",
             "Hashes": _HASHES, "ParentProcessGuid": _PGUID,
             "ParentProcessId": "1372",
             "ParentImage": r"C:\Windows\explorer.exe"}),
    _rec(3, {"ProcessGuid": _GUID, "ProcessId": "3836", "Protocol": "tcp",
             "Initiated": "True", "SourceIp": "10.0.0.9", "SourcePort": "1024",
             "DestinationIp": "1.2.3.4", "DestinationPort": "443"},
         record_id="4858"),
    # test_non_sysmon_provider_and_unported_eids_stay_raw — all dropped
    dict(_rec(1, {"ProcessGuid": _GUID, "Image": "x"}),
         Provider="Microsoft-Windows-Security-Auditing"),
    _rec(2, {"ProcessGuid": _GUID}),
    _rec(4, {"ProcessGuid": _GUID}),
    _rec(9, {"ProcessGuid": _GUID}),
    _rec(15, {"ProcessGuid": _GUID}),
    _rec(22, {"ProcessGuid": _GUID}),
]

# --- edge shapes the module docstrings describe -----------------------------
_LOWER_HASHES = _HASHES.lower()
_MIXED_HASHES = ("Sha1=8cc66ed54fbeff205151898d65f6415400124553,"
                 "mD5=64FdBd98584331982a15b1f2DF7f08da,"
                 "SHA256=b5DE10a0091b7aaf491bdb810bce6dab3f6b4a1c7a917722b5de014e4a08b6eb")
_NO_MD5_HASHES = ("SHA1=8CC66ED54FBEFF205151898D65F6415400124553,"
                  "IMPHASH=D3310CE6CBCACB3A9F0809BC33E38ABE")

_EDGE_RECORDS = [
    # hash case: uppercase (above), already-lowercase, mixed, partial, absent
    _rec(1, {"UtcTime": "2019-05-26 04:01:42.375", "ProcessGuid": _GUID,
             "ProcessId": "100", "Image": r"C:\a\low.exe", "Hashes": _LOWER_HASHES},
         record_id="5001"),
    _rec(1, {"UtcTime": "2019-05-26 04:01:42.375", "ProcessGuid": _GUID,
             "ProcessId": "101", "Image": r"C:\a\mixed.exe", "Hashes": _MIXED_HASHES},
         record_id="5002"),
    _rec(1, {"UtcTime": "2019-05-26 04:01:42.375", "ProcessGuid": _GUID,
             "ProcessId": "102", "Image": r"C:\a\nomd5.exe", "Hashes": _NO_MD5_HASHES},
         record_id="5003"),
    _rec(1, {"UtcTime": "2019-05-26 04:01:42.375", "ProcessGuid": _GUID,
             "ProcessId": "103", "Image": r"C:\a\nohash.exe"}, record_id="5004"),
    # EventId as a STRING and as a float — int() coerces both
    _rec("1", {"ProcessGuid": _GUID, "ProcessId": "104", "Image": r"C:\a\str.exe"},
         record_id="5005"),
    _rec(1.0, {"ProcessGuid": _GUID, "ProcessId": "105", "Image": r"C:\a\float.exe"},
         record_id="5006"),
    # Provider that merely CONTAINS 'sysmon'; Computer an fqdn (fqdn claimed)
    dict(_rec(1, {"ProcessGuid": _GUID, "ProcessId": "106", "Image": r"C:\a\fqdn.exe"},
              computer="WKS1.corp.example.com", record_id="5007"),
         Provider="vendor-SYSMON-forwarder"),
    # Computer ABSENT: hostname/fqdn/host null → the manifest host fills in
    {k: v for k, v in _rec(1, {"ProcessGuid": _GUID, "ProcessId": "107",
                               "Image": r"C:\a\nohost.exe"},
                           record_id="5008").items() if k != "Computer"},
    # a Payload that is not JSON at all: the EID-1 gate never reads it, so the
    # row still maps — with every payload-derived column null
    dict(_rec(1, {}, record_id="5009"), Payload="not json"),
    # EID 3 direction vocabulary: TRUE/false/other/absent
    _rec(3, {"ProcessGuid": _GUID, "ProcessId": "200", "Image": r"C:\a\n1.exe",
             "Protocol": "udp", "Initiated": "false", "SourceIp": "10.0.0.1",
             "SourcePort": "53", "DestinationIp": "10.0.0.2",
             "DestinationPort": "53"}, record_id="5010"),
    _rec(3, {"ProcessGuid": _GUID, "ProcessId": "201", "Image": r"C:\a\n2.exe",
             "Protocol": "tcp", "Initiated": "yes", "SourceIp": "10.0.0.1",
             "SourcePort": "80", "DestinationIp": "10.0.0.2",
             "DestinationPort": "80"}, record_id="5011"),
    _rec(3, {"ProcessGuid": _GUID, "ProcessId": "202", "Image": r"C:\a\n3.exe",
             "Protocol": "tcp", "SourceIp": "10.0.0.1", "SourcePort": "81",
             "DestinationIp": "10.0.0.2", "DestinationPort": "81"},
         record_id="5012"),
    # EID 11 overwrite verdict: before / equal / AFTER / junk / blank
    _rec(11, {"UtcTime": "2020-02-10 08:28:12.876", "ProcessGuid": _GUID,
              "ProcessId": "300", "Image": r"C:\a\w.exe",
              "TargetFilename": r"C:\t\before.txt",
              "CreationUtcTime": "2020-02-10 08:00:00.000"}, record_id="5013"),
    _rec(11, {"UtcTime": "2020-02-10 08:28:12.876", "ProcessGuid": _GUID,
              "ProcessId": "301", "Image": r"C:\a\w.exe",
              "TargetFilename": r"C:\t\after.txt",
              "CreationUtcTime": "2020-02-10 09:00:00.000"}, record_id="5014"),
    _rec(11, {"UtcTime": "2020-02-10 08:28:12.876", "ProcessGuid": _GUID,
              "ProcessId": "302", "Image": r"C:\a\w.exe",
              "TargetFilename": r"C:\t\junk.txt",
              "CreationUtcTime": "not a time"}, record_id="5015"),
    _rec(11, {"UtcTime": "2020-02-10 08:28:12.876", "ProcessGuid": _GUID,
              "ProcessId": "303", "Image": r"C:\a\w.exe",
              "TargetFilename": r"C:\t\dash.txt", "CreationUtcTime": "-"},
         record_id="5016"),
    # no UtcTime at all: the other side of the comparison is blank
    _rec(11, {"ProcessGuid": _GUID, "ProcessId": "304", "Image": r"C:\a\w.exe",
              "TargetFilename": r"C:\t\noutc",
              "CreationUtcTime": "2020-02-10 08:00:00.000"}, record_id="5017"),
    # EID 23 is SYNTHETIC-ONLY (no real FileDelete sample exists): a delete
    # with no hashes, and one whose User is the blank marker
    _rec(23, {"UtcTime": "2020-02-10 08:30:00.000", "ProcessGuid": _GUID,
              "ProcessId": "305", "Image": r"C:\a\cmd.exe",
              "TargetFilename": r"C:\t\gone.tar.GZ", "User": "-"},
         record_id="5018"),
    _rec(23, {"UtcTime": "2020-02-10 08:30:00.000", "ProcessGuid": _GUID,
              "ProcessId": "306", "Image": r"C:\a\cmd.exe",
              "TargetFilename": "noextfile", "Hashes": _LOWER_HASHES,
              "User": "NT AUTHORITY\\SYSTEM"}, record_id="5019"),
    # registry action vocabulary beyond the unit tests' four
    _rec(12, {"ProcessGuid": _GUID, "ProcessId": "400", "Image": r"C:\a\r.exe",
              "EventType": "CreateValue", "TargetObject": r"HKLM\A\B\V"},
         record_id="5020"),
    _rec(12, {"ProcessGuid": _GUID, "ProcessId": "401", "Image": r"C:\a\r.exe",
              "EventType": "DeleteValue", "TargetObject": r"HKLM\A\B\V"},
         record_id="5021"),
    _rec(13, {"ProcessGuid": _GUID, "ProcessId": "402", "Image": r"C:\a\r.exe",
              "EventType": "SetValue", "TargetObject": "NoBackslashKey"},
         record_id="5022"),
    _rec(13, {"ProcessGuid": _GUID, "ProcessId": "403", "Image": r"C:\a\r.exe",
              "EventType": "SetValue", "TargetObject": r"HKLM\A\B\V",
              "User": "IEWIN7\\IEUser"}, record_id="5023"),   # Details absent
    _rec(14, {"ProcessGuid": _GUID, "ProcessId": "404", "Image": r"C:\a\r.exe",
              "EventType": "RenameValue", "TargetObject": r"HKLM\A\B\V",
              "NewName": r"HKLM\A\B\W"}, record_id="5024"),
    _rec(13, {"ProcessGuid": _GUID, "ProcessId": "405", "Image": r"C:\a\r.exe",
              "EventType": "CreateKey", "TargetObject": r"HKLM\A"},
         record_id="5025"),                                   # 13 + non-Set: raw
    _rec(12, {"ProcessGuid": _GUID, "ProcessId": "406", "Image": r"C:\a\r.exe",
              "TargetObject": r"HKLM\A"}, record_id="5026"),  # no EventType: raw
    dict(_rec(12, {}, record_id="5027"), Payload="not json"),  # unparseable: raw
    # EID 6/7 signature verdicts: only the exact 'Valid' asserts True
    _rec(7, {"ProcessGuid": _GUID, "ProcessId": "500", "Image": r"C:\a\l.exe",
             "ImageLoaded": r"C:\W\S32\a.dll", "Hashes": _HASHES,
             "Signed": "false", "Signature": "Nobody",
             "SignatureStatus": "valid", "OriginalFileName": "a.dll",
             "Company": "ACME", "Product": "P", "Description": "D",
             "FileVersion": "1.0"}, record_id="5028"),
    _rec(7, {"ProcessGuid": _GUID, "ProcessId": "501", "Image": r"C:\a\l.exe",
             "ImageLoaded": r"C:\W\S32\b.dll"}, record_id="5029"),
    _rec(6, {"ImageLoaded": r"C:\W\S32\drivers\ok.sys", "Hashes": _HASHES,
             "Signed": "true", "Signature": "Microsoft Windows",
             "SignatureStatus": "Valid"}, record_id="5030"),
    _rec(6, {"ImageLoaded": r"C:\W\S32\drivers\bare.sys"}, record_id="5031"),
    # EID 8 without StartModule / StartFunction
    _rec(8, {"SourceProcessGuid": _GUID, "SourceProcessId": "600",
             "TargetProcessGuid": _PGUID, "TargetProcessId": "601",
             "NewThreadId": "602", "StartAddress": "0x00007FFB0000"},
         record_id="5032"),
    # EID 10 with the v13+ SourceUser
    _rec(10, {"SourceProcessId": "700", "SourceProcessGUID": _GUID,
              "SourceImage": r"C:\a\s.exe", "TargetProcessId": "701",
              "TargetProcessGUID": _PGUID, "TargetImage": r"C:\a\t.exe",
              "GrantedAccess": "0x1410", "CallTrace": "ntdll.dll+9d234",
              "SourceUser": "NT AUTHORITY\\SYSTEM"}, record_id="5033"),
    # EvtxECmd's own extra native columns (kept by the map)
    dict(_rec(5, {"ProcessGuid": _GUID, "ProcessId": "800",
                  "Image": r"C:\a\end.exe"}, record_id="5034"),
         MapDescription="Process terminated", ExecutableInfo="-"),
]


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    # --- sysmon: the unit tests' own records, verbatim ----------------------
    _lib.write_fixture("sysmon",
                       {"artefacts": ["evtx_sysmon"], "host": None,
                        "adapter": "none", "input": "input.jsonl"},
                       [j(r) + b"\n" for r in _UNIT_RECORDS])

    # --- sysmon_edge: the docstrings' edge shapes ---------------------------
    # the first line carries a BOM: the one EID-6-only real export in the
    # data_store is a single BOM-prefixed line (test_car_sysmon.py's caveat).
    _lib.write_fixture("sysmon_edge",
                       {"artefacts": ["evtx_sysmon"], "host": "SENSOR9",
                        "adapter": "none", "input": "input.jsonl"},
                       [b"\xef\xbb\xbf" + j(_EDGE_RECORDS[0]) + b"\n"] +
                       [j(r) + b"\n" for r in _EDGE_RECORDS[1:]])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

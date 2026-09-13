"""Parity vectors + fixtures for the `ez_srum_prefetch` family — the two
Get-Sybers EZ-Tools Go substitutes, each its own artefact key:

    byakugan/mappings/esedump_srum.py    esedump_srum   esedump_srum_is_network_usage
                                                        esedump_srum_is_application_usage
    byakugan/mappings/prefetch_dump.py   prefetch_dump  prefetch_dump_is_execution

Both read the tool's OWN UNWRAPPED flat JSON (no plaso `Record` wrapper): ese_dump
tags each SRUM row with `TableAlias` and decodes `AppIdName`/`UserIdName` from the
SruDbIdMapTable; prefetch_dump names the `Executable` + the run-from `Path`. The
gates are plain-string / truthiness tests on those fields.

Record shapes are VERBATIM-shaped from a real 12 MB SRUDB.dat and real .pf
(scratchpad stage3-parity): AppIdName is a device path OR a bare service name,
UserIdName a SID OR an SRUM-internal index (the sid/uid column gates on ^S-1-),
prefetch Hash renders as 0x-hex.

    python tests/parity/genf/ez_srum_prefetch.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/ez_srum_prefetch.json
    tests/parity/fixtures/ez_srum_prefetch_srum/
    tests/parity/fixtures/ez_srum_prefetch_prefetch/

No marker vectors: every marker kind these maps resolve (first, basename, regex1,
win_program_name, win_program_path) is already covered engine-wide by
marker_vectors/core.json.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "ez_srum_prefetch"

_NET = "NetworkDataUsage"
_APP = "ApplicationResourceUsage"
_CONN = "NetworkConnectivityUsage"


# ---------------------------------------------------------------------------
# predicate vectors — every branch and type edge of the three gates
# ---------------------------------------------------------------------------
PREDICATE_CASES = [
    # --- esedump_srum_is_network_usage: rec.get("TableAlias") == "NetworkDataUsage"
    ("esedump_srum_is_network_usage", {"TableAlias": _NET}),
    ("esedump_srum_is_network_usage", {"TableAlias": _APP}),
    ("esedump_srum_is_network_usage", {"TableAlias": _CONN}),
    ("esedump_srum_is_network_usage", {"TableAlias": "NetworkDataUsage "}),   # trailing space
    ("esedump_srum_is_network_usage", {"TableAlias": "networkdatausage"}),    # case-sensitive
    ("esedump_srum_is_network_usage", {"TableAlias": None}),
    ("esedump_srum_is_network_usage", {"TableAlias": ""}),
    ("esedump_srum_is_network_usage", {"TableAlias": 0}),
    ("esedump_srum_is_network_usage", {"TableAlias": 5}),
    ("esedump_srum_is_network_usage", {"TableAlias": False}),
    ("esedump_srum_is_network_usage", {}),                                    # TableAlias absent
    # a full network row: the gate reads TableAlias only
    ("esedump_srum_is_network_usage", {"TableAlias": _NET, "AppId": 102, "UserId": 8,
                                       "AppIdName": "System", "UserIdName": "S-1-5-18",
                                       "InterfaceLuid": 1689399632855040,
                                       "TimeStamp": "2024-02-20T07:50:00Z",
                                       "BytesSent": 2100, "BytesRecvd": 1440}),

    # --- esedump_srum_is_application_usage ---------------------------------
    ("esedump_srum_is_application_usage", {"TableAlias": _APP}),
    ("esedump_srum_is_application_usage", {"TableAlias": _NET}),
    ("esedump_srum_is_application_usage", {"TableAlias": _CONN}),
    ("esedump_srum_is_application_usage", {"TableAlias": "ApplicationResourceUsage "}),
    ("esedump_srum_is_application_usage", {"TableAlias": None}),
    ("esedump_srum_is_application_usage", {"TableAlias": ""}),
    ("esedump_srum_is_application_usage", {"TableAlias": 0}),
    ("esedump_srum_is_application_usage", {"TableAlias": True}),
    ("esedump_srum_is_application_usage", {}),

    # --- prefetch_dump_is_execution: bool(rec.get("Executable")) -----------
    ("prefetch_dump_is_execution", {"Executable": "ADDINUTIL.EXE"}),
    ("prefetch_dump_is_execution", {"Executable": "-"}),                      # truthy → claimed
    ("prefetch_dump_is_execution", {"Executable": ""}),
    ("prefetch_dump_is_execution", {"Executable": None}),
    ("prefetch_dump_is_execution", {}),                                       # absent
    ("prefetch_dump_is_execution", {"Executable": 0}),
    ("prefetch_dump_is_execution", {"Executable": 5}),
    ("prefetch_dump_is_execution", {"Executable": False}),
    ("prefetch_dump_is_execution", {"Executable": True}),
    ("prefetch_dump_is_execution", {"Executable": []}),
    ("prefetch_dump_is_execution", {"Executable": ["x"]}),
    ("prefetch_dump_is_execution", {"Executable": {}}),
    ("prefetch_dump_is_execution", {"executable": "lower-case key"}),         # case-sensitive
]

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
j = _lib.j


def _net(**over) -> dict:
    rec = {"Table": "{973F5D5C-1D90-4944-BE8E-24B94231A174}", "TableAlias": _NET,
           "AppId": 102, "UserId": 8, "AppIdName": "System", "UserIdName": "S-1-5-18",
           "InterfaceLuid": 1689399632855040, "L2ProfileId": 0, "L2ProfileFlags": 0,
           "TimeStamp": "2024-02-20T07:50:00Z", "BytesSent": 2100, "BytesRecvd": 1440}
    rec.update(over)
    return rec


def _app(**over) -> dict:
    rec = {"Table": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", "TableAlias": _APP,
           "AppId": 388, "UserId": 951,
           "AppIdName": "Microsoft.Windows.ShellExperienceHost_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy",
           "UserIdName": "S-1-5-21-2899045035-919344695-3383792992-500",
           "TimeStamp": "2024-02-20T07:50:59Z",
           "ForegroundCycleTime": 3007288179, "BackgroundCycleTime": 160394860,
           "FaceTime": 32793117916, "ForegroundBytesRead": 420864,
           "ForegroundBytesWritten": 20480, "BackgroundBytesRead": 0,
           "BackgroundBytesWritten": 28672}
    rec.update(over)
    return rec


_DEVPATH = "\\device\\harddiskvolume3\\program files (x86)\\microsoft\\edge\\application\\msedge.exe"


def _pf(**over) -> dict:
    rec = {"SourceFilename": "/input/ADDINUTIL.EXE-4E6085D4.pf",
           "SourceModified": "2024-04-12T14:47:23Z", "Executable": "ADDINUTIL.EXE",
           "Path": "\\DEVICE\\HARDDISKVOLUME3\\WINDOWS\\MICROSOFT.NET\\FRAMEWORK64\\V3.5\\ADDINUTIL.EXE",
           "Hash": "0x4E6085D4", "Version": "Win10", "FileSize": 72428, "RunCount": 4,
           "LastRun": "2024-04-12T14:47:22Z",
           "PreviousRuns": ["2024-04-12T14:47:22Z", "2024-04-12T14:47:17Z"],
           "FilesAccessed": ["\\VOLUME{01d9-1c87}\\WINDOWS\\SYSTEM32\\NTDLL.DLL"]}
    rec.update(over)
    return rec


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    # --- esedump_srum: both variants, the device-path split, the SID gate ---
    _lib.write_fixture(
        "ez_srum_prefetch_srum",
        {"artefacts": ["esedump_srum"], "host": "lonewolf",
         "adapter": "none", "input": "input.jsonl"},
        [j(_net()) + b"\n",                                    # bare name (exe only, no image_path)
         # a device-path AppIdName: image_path + basename → exe; a real SID
         j(_net(AppId=200, AppIdName=_DEVPATH,
                UserIdName="S-1-5-21-2899045035-919344695-3383792992-500",
                TimeStamp="2024-02-20T08:10:00Z", BytesSent=2815, BytesRecvd=9681)) + b"\n",
         j(_app()) + b"\n",                                    # package moniker: exe only
         # an SRUM-internal INDEX in the id column: not a SID → uid honest null
         j(_net(AppId=3, AppIdName="Spooler", UserId=2, UserIdName="2",
                TimeStamp="2024-02-20T09:00:00Z")) + b"\n",
         # a lower-case sid: the ^(S-1-[0-9-]+)$ gate is case-sensitive → null
         j(_net(AppId=4, AppIdName="CryptSvc", UserIdName="s-1-5-18",
                TimeStamp="2024-02-20T09:10:00Z")) + b"\n",
         # no AppIdName decoded (IdMap miss): exe/image_path null, guid still
         # mints from AppId+UserId+InterfaceLuid+TimeStamp+bytes
         j(_net(AppId=999, AppIdName=None, TimeStamp="2024-02-20T09:20:00Z")) + b"\n",
         # a 1601 stamp: _clean_ts drops it → timestamp null (fields-guid intact)
         j(_net(AppId=5, TimeStamp="1601-01-01T00:00:00Z")) + b"\n",
         # NetworkConnectivityUsage + other provider tables: no CAR object → raw
         j({"Table": "{DD6636C4-8929-4683-974E-22C046A43763}", "TableAlias": _CONN,
            "AppId": 1, "InterfaceLuid": 1689399632855040,
            "TimeStamp": "2024-02-20T07:50:00Z"}) + b"\n",
         j({"Table": "x", "TableAlias": "AppTimelineProvider", "AppId": 1}) + b"\n",
         b"{not json\n"])                                      # bad line: skipped

    # --- prefetch_dump: the run-from path convention + edges ----------------
    _lib.write_fixture(
        "ez_srum_prefetch_prefetch",
        {"artefacts": ["prefetch_dump"], "host": "lonewolf",
         "adapter": "none", "input": "input.jsonl"},
        [j(_pf()) + b"\n",                                     # full path → image_path + exe
         # no Path (older .pf): image_path null, exe falls back to Executable
         j(_pf(SourceFilename="/input/CMD.EXE-ABCDEF01.pf", Executable="CMD.EXE",
               Path=None, Hash="0xABCDEF01", LastRun="2024-04-12T15:00:00Z",
               PreviousRuns=[])) + b"\n",
         # never-run .pf (RunCount 0): no LastRun → timestamp null (guid intact)
         j(_pf(SourceFilename="/input/NEVER.EXE-00000001.pf", Executable="NEVER.EXE",
               Path=None, Hash="0x00000001", RunCount=0, LastRun=None,
               PreviousRuns=[])) + b"\n",
         # a 1601 LastRun: _clean_ts drops it → timestamp null
         j(_pf(Executable="OLD.EXE", Hash="0x11112222",
               LastRun="1601-01-01T00:00:00Z")) + b"\n",
         # blank Hash voids the (Executable, Hash) guid
         j(_pf(Executable="NOHASH.EXE", Hash="")) + b"\n",
         # no Executable: claimed by neither → dropped
         j({"SourceFilename": "/input/orphan.pf", "Hash": "0xDEADBEEF"}) + b"\n",
         b"{not json\n"])                                      # bad line: skipped
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

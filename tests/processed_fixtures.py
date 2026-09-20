"""A tiny processed tree in the GoDFIR-toolz framework layouts DX_DFIR's lanes
write (one folder per item), for the discovery, batch and CLI tests.

Every record is shaped exactly like the producing tool's output — the shapes
the sibling map tests assert on — and every source carries ONE record that maps
to a known CAR object (or, for a tool with no map, none). The lanes' staging
directories (the image exports the tools parse) sit beside the sources, as they
do on disk.
"""
from __future__ import annotations

import json
import os

# goevtx (the evtx lane): one record per event in the evtx JSON record shape —
# Payload is the EventData rendered as a JSON string.
GOEVTX_4624 = {
    "EventId": 4624, "Level": "Information",
    "Provider": "Microsoft-Windows-Security-Auditing", "Channel": "Security",
    "Computer": "HOST01", "EventRecordId": 1234,
    "TimeCreated": "2020-01-01T00:00:00.0000000Z", "UserId": "S-1-5-18",
    "MapDescription": None, "SourceFile": "/input/HOST01/Security.evtx",
    "Payload": json.dumps({"EventData": {"Data": [
        {"@Name": k, "#text": v} for k, v in {
            "SubjectUserSid": "S-1-5-18", "SubjectUserName": "HOST01$",
            "SubjectDomainName": "WORKGROUP", "SubjectLogonId": "0x3E7",
            "TargetUserSid": "S-1-5-21-1-2-3-1000", "TargetUserName": "alice",
            "TargetDomainName": "HOST01", "TargetLogonId": "0x18846",
            "LogonType": "2", "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate", "WorkstationName": "HOST01",
            "ProcessId": "0x1FC", "IpAddress": "-", "IpPort": "-",
        }.items()]}}),
}

# psort json_line (the plaso lane): one raw plaso event per line — timestamp in
# microseconds, parser, data_type — the container split-l2t wraps per parser.
PSORT_PREFETCH = {
    "timestamp": 1258709489671875, "parser": "prefetch",
    "data_type": "windows:prefetch:execution",
    "display_name": "NTFS:\\WINDOWS\\Prefetch\\SVCHOST.EXE-3530F672.pf",
    "executable": "SVCHOST.EXE", "image_hostname": "M57-JO", "path_hints": [],
    "prefetch_hash": 892401266, "run_count": 3, "sha256_hash": "12f31dcc" + "0" * 56,
    "timestamp_desc": "Last Time Executed", "username": "-", "version": 17,
}

# gore: one record per extracted registry value (the recmd_batch shape).
GORE_VALUE = {
    "HivePath": "/input/img/export/Windows/System32/config/SOFTWARE",
    "HiveType": "SOFTWARE", "Category": "Autoruns", "Description": "Run keys",
    "Comment": "Programs run at logon", "KeyPath": "Microsoft\\Windows\\CurrentVersion\\Run",
    "ValueName": "Updater", "ValueType": "RegSz", "ValueData": "C:\\Users\\Public\\evil.exe",
    "LastWriteTimestamp": "2020-01-01 00:00:03.0000000", "Recursive": False, "Deleted": False,
}

# goprefetch: one record per .pf.
GOPREFETCH_RUN = {
    "SourceFilename": "/input/img/export/Windows/Prefetch/EVIL.EXE-4E6085D4.pf",
    "SourceModified": "2020-01-01T00:00:02Z", "Executable": "EVIL.EXE",
    "Path": "\\VOLUME{guid}\\TEMP\\EVIL.EXE", "Hash": "0x4E6085D4", "Version": 30,
    "FileSize": 4096, "RunCount": 3, "LastRun": "2020-01-01T00:00:02Z",
    "PreviousRuns": [], "FilesAccessed": [],
}

# goese: one <table>.jsonl per SRUM provider table (rows carry TableAlias and
# the SruDbIdMapTable-decoded names) plus goese.jsonl, the per-table index.
GOESE_NETWORK_USAGE = {
    "Table": "{973F5D5C-1D90-4944-BE8E-24B94231A174}", "TableAlias": "NetworkDataUsage",
    "AppId": 12, "UserId": 3,
    "AppIdName": "\\Device\\HarddiskVolume4\\Windows\\System32\\svchost.exe",
    "UserIdName": "S-1-5-18", "TimeStamp": "2020-01-01T00:00:00Z",
    "InterfaceLuid": 1689399632855040, "L2ProfileId": 0, "L2ProfileFlags": 0,
    "BytesSent": 10, "BytesRecvd": 20,
}
GOESE_INDEX = {"table": GOESE_NETWORK_USAGE["Table"], "alias": "NetworkDataUsage",
               "file": "NetworkDataUsage.jsonl", "rows": 1}

# gojle: one record per jump list (the jlecmd_dest shape the adapter flattens).
GOJLE_LIST = {
    "AppId": {"AppId": "fb3b0dbfee58fac8", "Description": "Microsoft Word 2016 64-bit"},
    "SourceFile": "/input/img/export/AutomaticDestinations/fb3b0dbfee58fac8.automaticDestinations-ms",
    "DestListEntries": [
        {"Path": "C:\\Users\\jcloudy\\Desktop\\Planning.docx", "EntryNumber": 1,
         "CreatedOn": "/Date(1522187139502)/", "LastModified": "/Date(1522917168677)/",
         "Hostname": "desktop-pm6c56d", "InteractionCount": 13, "MRUPosition": 0,
         "Pinned": False, "MacAddress": "28:e3:47:01:77:77", "VolumeDroid": "bc75"},
    ],
}

# gomft: one record per MFT entry — a tool with no CAR map (routed to nothing).
GOMFT_ENTRY = {"EntryNumber": 5, "InUse": True, "FileName": "evil.exe",
               "FullPath": "Users/Public/evil.exe", "FileSize": 4096}

_GOESE_ITEM = "img_Windows_System32_sru_SRUDB.dat"
_GOJLE_ITEM = "img_export_AutomaticDestinations_fb3b0dbfee58fac8.automaticDestinations-ms"


def jsonl(path: str, *records: dict) -> None:
    """Write `records` as JSON Lines at `path`, creating its directory."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


def write_framework_tree(root) -> dict[str, str]:
    """Write one source per framework layout under `root` (a processed tree),
    with the lanes' staging directories beside them. Returns {source_name: the
    CAR object its one record maps to} — the empty string for a source whose
    records are routed to nothing."""
    root = str(root)
    gt = os.path.join(root, "godfir-toolz")
    jsonl(os.path.join(root, "windows_logs", "HOST01_Security.evtx", "goevtx.jsonl"), GOEVTX_4624)
    jsonl(os.path.join(root, "log2timeline", "jsonl", "M57-JO.E01", "timeline.jsonl"), PSORT_PREFETCH)
    jsonl(os.path.join(gt, "gore", "img_Windows_System32_config_SOFTWARE", "gore.jsonl"), GORE_VALUE)
    jsonl(os.path.join(gt, "goprefetch", "img_Windows_Prefetch_EVIL.EXE-4E6085D4.pf",
                       "goprefetch.jsonl"), GOPREFETCH_RUN)
    jsonl(os.path.join(gt, "goese", _GOESE_ITEM, "NetworkDataUsage.jsonl"), GOESE_NETWORK_USAGE)
    jsonl(os.path.join(gt, "goese", _GOESE_ITEM, "goese.jsonl"), GOESE_INDEX)
    jsonl(os.path.join(gt, "gojle", _GOJLE_ITEM, "gojle.jsonl"), GOJLE_LIST)
    jsonl(os.path.join(gt, "gomft", "img_MFT", "gomft.jsonl"), GOMFT_ENTRY)
    # the staging directories: raw image exports the tools parse, never sources
    for stage in (os.path.join(root, "windows_logs", "_extracted_evtx"),
                  os.path.join(gt, "_extracted")):
        export = os.path.join(stage, "img", "export", "Windows")
        os.makedirs(export)
        with open(os.path.join(export, "Security.evtx"), "wb") as fh:
            fh.write(b"ElfFile\x00")
        jsonl(os.path.join(stage, "img", "image_export.jsonl"), {"item": "img", "files": 1})
    return {
        "windows_logs_HOST01_Security.evtx": "user_session",
        "l2t_M57-JO.E01": "process",
        "godfir_toolz_gore_img_Windows_System32_config_SOFTWARE": "registry",
        "godfir_toolz_goprefetch_img_Windows_Prefetch_EVIL.EXE-4E6085D4.pf": "process",
        f"godfir_toolz_goese_{_GOESE_ITEM}": "flow",
        f"godfir_toolz_gojle_{_GOJLE_ITEM}": "file",
        "godfir_toolz_gomft_img_MFT": "",
    }

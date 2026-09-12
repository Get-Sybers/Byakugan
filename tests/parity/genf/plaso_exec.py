"""Parity vectors + fixtures for the `plaso_exec` family
(byakugan/mappings/plaso_exec.py — the wrapped-l2t execution-evidence maps
plaso_exec_prefetch / plaso_exec_winreg / plaso_exec_cron and their seven gates).

The raw shape is the wrapped l2t JSONL the plaso lane emits
(ingest/prepare.split_l2t): {"SourceImage","Timestamp","Parser","Record"} — the
flat plaso event lives under "Record" and is reached with the payload marker
scoped to "Record".

The fixture records are the inline rows of tests/test_car_plaso_exec.py VERBATIM
(real evidence for prefetch/appcompatcache/userassist/cron, synthetic-but-
plaso-shaped for amcache/bam), plus the edge shapes the module docstring and
those tests describe: the appcompatcache inferred-execution labelling over every
plaso timestamp_desc, the userassist UEME_ negative-lookahead family, the
amcache file_identifier "0000"+40hex SHA-1 parse and its timestamp-less Link
Time entity row, bam, and the honest-null cases (no full_path, no command, no
image_hostname, malformed file_identifier, empty company_name).

    python tests/parity/genf/plaso_exec.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/plaso_exec.json
    tests/parity/fixtures/plaso_exec_prefetch/
    tests/parity/fixtures/plaso_exec_winreg/
    tests/parity/fixtures/plaso_exec_cron/
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "plaso_exec"

j = _lib.j


def _copy(rec: dict, **record_fields) -> dict:
    """A deep copy of a wrapped row with Record fields overridden.

    A field whose value is the sentinel `DROP` is deleted from Record instead.
    """
    out = json.loads(json.dumps(rec))
    for k, v in record_fields.items():
        if v is DROP:
            out["Record"].pop(k, None)
        else:
            out["Record"][k] = v
    return out


class _Drop:
    pass


DROP = _Drop()


# ---------------------------------------------------------------------------
# predicate vectors — plaso_exec.py's seven gates
#
# Both shared readers use `or ""`, NOT `.get(key, "")`: a present-but-FALSY
# Parser / timestamp_desc / value_name (None, "", 0, False) renders "" rather
# than str() of it — so the type edges below carry 0/False/None separately from
# an absent key.
# ---------------------------------------------------------------------------
PREDICATE_CASES = [
    # --- plaso_is_prefetch_execution -----------------------------------------
    ("plaso_is_prefetch_execution", {"Record": {"data_type": "windows:prefetch:execution"}}),
    ("plaso_is_prefetch_execution", {"Record": {"data_type": "windows:volume:creation"}}),
    ("plaso_is_prefetch_execution", {"Record": {"data_type": "WINDOWS:PREFETCH:EXECUTION"}}),
    ("plaso_is_prefetch_execution", {"Record": {}}),               # data_type absent
    ("plaso_is_prefetch_execution", {"Record": {"data_type": None}}),
    ("plaso_is_prefetch_execution", {"Record": {"data_type": 7}}),  # int never == str
    ("plaso_is_prefetch_execution", {}),                            # Record absent → {}
    ("plaso_is_prefetch_execution", {"Record": None}),              # None → {}
    ("plaso_is_prefetch_execution", {"Record": {}, "Parser": "prefetch"}),
    # --- plaso_is_cron_task_run ----------------------------------------------
    ("plaso_is_cron_task_run", {"Record": {"data_type": "syslog:cron:task_run"}}),
    ("plaso_is_cron_task_run", {"Record": {"data_type": "syslog:line"}}),
    ("plaso_is_cron_task_run", {"Record": {"data_type": ""}}),
    ("plaso_is_cron_task_run", {"Record": None}),
    ("plaso_is_cron_task_run", {}),
    # --- plaso_is_amcache_link_time ------------------------------------------
    ("plaso_is_amcache_link_time", {"Parser": "amcache",
                                    "Record": {"timestamp_desc": "Link Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": "winreg/amcache",
                                    "Record": {"timestamp_desc": "Link Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": "AMCACHE",          # .lower()
                                    "Record": {"timestamp_desc": "LINK TIME"}}),
    ("plaso_is_amcache_link_time", {"Parser": "amcache",          # tolerant "compil"
                                    "Record": {"timestamp_desc": "Compilation Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": "amcache",
                                    "Record": {"timestamp_desc": "Content Modification Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": "amcache",
                                    "Record": {"timestamp_desc": "Creation Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": "amcache",
                                    "Record": {"timestamp_desc": "Installation Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": "amcache", "Record": {}}),
    ("plaso_is_amcache_link_time", {"Parser": "amcache",
                                    "Record": {"timestamp_desc": None}}),
    ("plaso_is_amcache_link_time", {"Parser": "amcache",
                                    "Record": {"timestamp_desc": ""}}),
    ("plaso_is_amcache_link_time", {"Parser": "amcache",
                                    "Record": {"timestamp_desc": 0}}),      # falsy → ""
    ("plaso_is_amcache_link_time", {"Parser": "amcache",
                                    "Record": {"timestamp_desc": 42}}),     # str(42)
    ("plaso_is_amcache_link_time", {"Parser": "amcache",
                                    "Record": {"timestamp_desc": True}}),   # str(True)
    ("plaso_is_amcache_link_time", {"Parser": "winreg/userassist",
                                    "Record": {"timestamp_desc": "Link Time"}}),
    ("plaso_is_amcache_link_time", {"Record": {"timestamp_desc": "Link Time"}}),  # no Parser
    ("plaso_is_amcache_link_time", {"Parser": None,
                                    "Record": {"timestamp_desc": "Link Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": "", "Record": {"timestamp_desc": "Link Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": 0, "Record": {"timestamp_desc": "Link Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": False, "Record": {"timestamp_desc": "Link Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": 17, "Record": {"timestamp_desc": "Link Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": True, "Record": {"timestamp_desc": "Link Time"}}),
    ("plaso_is_amcache_link_time", {"Parser": "amcache", "Record": None}),
    ("plaso_is_amcache_link_time", {"Parser": "amcache"}),
    # --- plaso_is_amcache (every dated row EXCEPT the Link Time one) ----------
    ("plaso_is_amcache", {"Parser": "amcache",
                          "Record": {"timestamp_desc": "Content Modification Time"}}),
    ("plaso_is_amcache", {"Parser": "amcache", "Record": {"timestamp_desc": "Link Time"}}),
    ("plaso_is_amcache", {"Parser": "amcache", "Record": {"timestamp_desc": "Compilation Time"}}),
    ("plaso_is_amcache", {"Parser": "amcache", "Record": {}}),
    ("plaso_is_amcache", {"Parser": "winreg/amcache",
                          "Record": {"timestamp_desc": "Creation Time"}}),
    ("plaso_is_amcache", {"Parser": "winreg/bam", "Record": {"timestamp_desc": "x"}}),
    ("plaso_is_amcache", {}),
    # --- plaso_is_userassist_run ---------------------------------------------
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "UEME_RUNPATH:E:\\R54402.EXE"}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "UEME_RUNPATH:"}}),  # prefix only
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "UEME_RUNPATH"}}),   # no colon
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "UEME_RUNPIDL:%csidl2%\\x.lnk"}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "UEME_RUNCPL:timedate.cpl"}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "UEME_CTLSESSION"}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "UEME_CTLCUACount:ctor"}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "UEME_UISCUT"}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "notepad.exe"}}),    # Win7+ decoded
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "C:\\Program Files\\x\\y.exe"}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": "ueme_ctlsession"}}),  # case-sensitive
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": ""}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": None}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": 0}}),      # falsy → ""
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": 42}}),     # str(42) → maps
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist",
                                 "Record": {"value_name": True}}),   # str(True) → maps
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist", "Record": {}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/userassist", "Record": None}),
    ("plaso_is_userassist_run", {"Parser": "USERASSIST",
                                 "Record": {"value_name": "notepad.exe"}}),
    ("plaso_is_userassist_run", {"Parser": "winreg/appcompatcache",
                                 "Record": {"value_name": "notepad.exe"}}),
    ("plaso_is_userassist_run", {"Record": {"value_name": "notepad.exe"}}),
    # --- plaso_is_bam (token match, never a substring) -----------------------
    ("plaso_is_bam", {"Parser": "winreg/bam"}),
    ("plaso_is_bam", {"Parser": "bam"}),
    ("plaso_is_bam", {"Parser": "bam/x"}),
    ("plaso_is_bam", {"Parser": "a/bam/b"}),
    ("plaso_is_bam", {"Parser": "WINREG/BAM"}),          # .lower() first
    ("plaso_is_bam", {"Parser": "winreg/bamboo"}),       # substring → no
    ("plaso_is_bam", {"Parser": "bambam"}),
    ("plaso_is_bam", {"Parser": "winreg/xbam"}),
    ("plaso_is_bam", {"Parser": "winreg\\bam"}),         # backslash is not the separator
    ("plaso_is_bam", {"Parser": ""}),
    ("plaso_is_bam", {"Parser": None}),
    ("plaso_is_bam", {"Parser": 0}),
    ("plaso_is_bam", {"Parser": False}),
    ("plaso_is_bam", {"Parser": 17}),
    ("plaso_is_bam", {"Parser": True}),
    ("plaso_is_bam", {"Parser": ["winreg/BAM"]}),        # str(list) repr path
    ("plaso_is_bam", {}),
    # --- plaso_is_appcompatcache ---------------------------------------------
    ("plaso_is_appcompatcache", {"Parser": "winreg/appcompatcache"}),
    ("plaso_is_appcompatcache", {"Parser": "appcompatcache"}),
    ("plaso_is_appcompatcache", {"Parser": "WINREG/AppCompatCache"}),
    ("plaso_is_appcompatcache", {"Parser": "winreg/appcompatcache_extra"}),  # substring: yes
    ("plaso_is_appcompatcache", {"Parser": "winreg/userassist"}),
    ("plaso_is_appcompatcache", {"Parser": None}),
    ("plaso_is_appcompatcache", {}),
]


# ---------------------------------------------------------------------------
# fixture rows — VERBATIM from tests/test_car_plaso_exec.py, plus edge shapes
# ---------------------------------------------------------------------------

_PREFETCH_EXEC = {
    "SourceImage": "log2timeline/jsonl/M57-JO.jsonl",
    "Timestamp": "2009-11-20T09:31:29.671875Z",
    "Parser": "prefetch",
    "Record": {
        "data_type": "windows:prefetch:execution",
        "display_name": "NTFS:\\WINDOWS\\Prefetch\\SVCHOST.EXE-3530F672.pf",
        "executable": "SVCHOST.EXE",
        "image_hostname": "M57-JO",
        "parser": "prefetch",
        "path_hints": [],
        "prefetch_hash": 892401266,
        "run_count": 3,
        "sha256_hash": "12f31dcc" + "0" * 56,
        "timestamp_desc": "Last Time Executed",
        "username": "-",
        "version": 17,
    },
}

_PREFETCH_VOLUME = {
    "SourceImage": "log2timeline/jsonl/M57-JO.jsonl",
    "Timestamp": "2009-11-20T09:38:03.625000Z",
    "Parser": "prefetch",
    "Record": {
        "data_type": "windows:volume:creation",
        "display_name": "NTFS:\\WINDOWS\\Prefetch\\SVCHOST.EXE-3530F672.pf",
        "image_hostname": "M57-JO",
        "origin": "SVCHOST.EXE-3530F672.pf",
        "parser": "prefetch",
    },
}

_APPCOMPAT = {
    "SourceImage": "log2timeline/jsonl/M57-JO.jsonl",
    "Timestamp": "2004-02-10T18:31:30.000000Z",
    "Parser": "winreg/appcompatcache",
    "Record": {
        "control_set": 2,
        "data_type": "windows:registry:appcompatcache",
        "display_name": "NTFS:\\WINDOWS\\system32\\config\\system",
        "entry_index": 49,
        "image_hostname": "M57-JO",
        "key_path": "HKEY_LOCAL_MACHINE\\System\\ControlSet002\\Control\\"
                    "Session Manager\\AppCompatibility",
        "parser": "winreg/appcompatcache",
        "path": "\\??\\C:\\WINDOWS\\system32\\hkcmd.exe",
        "timestamp_desc": "File Last Modification Time",
        "username": "-",
    },
}

_USERASSIST_RUNPATH = {
    "SourceImage": "log2timeline/jsonl/DESKTOP-PM6C56D.jsonl",
    "Timestamp": "2009-11-20T01:23:45.000000Z",
    "Parser": "winreg/userassist",
    "Record": {
        "data_type": "windows:registry:userassist",
        "display_name": "VSS2:NTFS:\\Users\\jcloudy\\NTUSER.DAT",
        "image_hostname": "DESKTOP-PM6C56D",
        "key_path": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\"
                    "CurrentVersion\\Explorer\\UserAssist\\"
                    "{75048700-EF1F-11D0-9888-006097DEACF9}\\Count",
        "number_of_executions": 1,
        "parser": "winreg/userassist",
        "username": "-",
        "value_name": "UEME_RUNPATH:E:\\R54402.EXE",
    },
}

_AMCACHE = {
    "SourceImage": "log2timeline/jsonl/synth.jsonl",
    "Timestamp": "2023-05-01T10:00:00.000000Z",
    "Parser": "amcache",
    "Record": {
        "data_type": "windows:registry:amcache",
        "display_name": "NTFS:\\Windows\\appcompat\\Programs\\Amcache.hve",
        "filename": "Amcache.hve",
        "full_path": "c:\\users\\bob\\downloads\\evil.exe",
        "image_hostname": "HOST1",
        "parser": "amcache",
        "program_identifier": "0006a1c48f048a1c",
        "file_identifier": "0000a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "sha256_hash": "f" * 64,
        "company_name": "Contoso Ltd",
        "timestamp_desc": "Content Modification Time",
        "username": "-",
    },
}

_AMCACHE_LINK = json.loads(json.dumps(_AMCACHE))
_AMCACHE_LINK["Timestamp"] = "2021-11-11T11:11:11.000000Z"
_AMCACHE_LINK["Record"]["timestamp_desc"] = "Link Time"

_BAM = {
    "SourceImage": "log2timeline/jsonl/synth.jsonl",
    "Timestamp": "2023-05-01T11:00:00.000000Z",
    "Parser": "winreg/bam",
    "Record": {
        "data_type": "windows:registry:bam",
        "display_name": "NTFS:\\Windows\\System32\\config\\SYSTEM",
        "image_hostname": "HOST1",
        "key_path": "HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\bam\\"
                    "State\\UserSettings\\S-1-5-21-1-2-3-1001",
        "parser": "winreg/bam",
        "path": "\\Device\\HarddiskVolume2\\Windows\\System32\\notepad.exe",
        "timestamp_desc": "Last Time Executed",
        "user_identifier": "S-1-5-21-1-2-3-1001",
        "username": "-",
    },
}

_CRON = {
    "SourceImage": "log2timeline/jsonl/dualserver_logs.jsonl",
    "Timestamp": "2020-08-26T11:46:13.000000Z",
    "Parser": "text/syslog_traditional",
    "Record": {
        "command": "test -x /etc/cron.daily/popularity-contest && "
                   "/etc/cron.daily/popularity-contest --crond",
        "data_type": "syslog:cron:task_run",
        "display_name": "OS:/data/dualserver_logs/logserver-logs-day2/log/message",
        "hostname": "pits-gatsby",
        "image_hostname": "",
        "parser": "text/syslog_traditional",
        "pid": 2534,
        "reporter": "CRON",
        "username": "root",
    },
}

# a modern Win10 .pf: the fields an XP-era (version 17) row has none of —
# a non-empty path_hints LIST (the marker set cannot index it: it stays native
# and image_path stays an honest null), the touched-file list, the volume block
_PREFETCH_WIN10 = {
    "SourceImage": "log2timeline/jsonl/DESKTOP-PM6C56D.jsonl",
    "Timestamp": "2018-04-02T01:15:23.456789Z",
    "Parser": "prefetch",
    "Record": {
        "data_type": "windows:prefetch:execution",
        "display_name": "NTFS:\\Windows\\Prefetch\\POWERSHELL.EXE-022A5A7E.pf",
        "executable": "POWERSHELL.EXE",
        "image_hostname": "DESKTOP-PM6C56D",
        "mapped_files": ["\\VOLUME{01d1}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                         "\\VOLUME{01d1}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL"],
        "number_of_volumes": 1,
        "parser": "prefetch",
        "path_hints": ["\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE"],
        "prefetch_hash": 36331646,
        "run_count": 12,
        "sha256_hash": "ab" * 32,
        "timestamp_desc": "Previous Last Time Executed",
        "username": "NT AUTHORITY\\SYSTEM",
        "version": 30,
        "volume_device_paths": ["\\DEVICE\\HARDDISKVOLUME2"],
        "volume_serial_numbers": ["0x1E2C4B7A"],
    },
}


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    # --- plaso_exec_prefetch: L2tPrefetch ----------------------------------
    # only windows:prefetch:execution rows are runs; exe is the bare NAME and
    # image_path stays an honest null (path_hints is a LIST, native only).
    _lib.write_fixture(
        "plaso_exec_prefetch",
        {"artefacts": ["plaso_exec_prefetch"], "host": "plaso-fallback",
         "adapter": "none", "input": "input.jsonl"},
        [j(_PREFETCH_EXEC) + b"\n",
         j(_PREFETCH_VOLUME) + b"\n",                        # volume metadata: dropped
         j(_PREFETCH_WIN10) + b"\n",                         # modern .pf, canon'd username
         # no image_hostname → hostname null, source_host from the manifest host
         j(_copy(_PREFETCH_EXEC, image_hostname=DROP)) + b"\n",
         j(_copy(_PREFETCH_EXEC, image_hostname="")) + b"\n",
         # no executable → exe an honest null (the .pf name must never fill it)
         j(_copy(_PREFETCH_EXEC, executable=DROP)) + b"\n",
         j(_copy(_PREFETCH_EXEC, executable="-")) + b"\n",   # blank rule
         # a real username survives user_canon unchanged
         j(_copy(_PREFETCH_EXEC, username="DESKTOP-8\\jcloudy")) + b"\n",
         j(_copy(_PREFETCH_EXEC, username="S-1-5-18")) + b"\n",
         # no data_type at all, and no Record at all: not executions
         j(_copy(_PREFETCH_EXEC, data_type=DROP)) + b"\n",
         j({"SourceImage": "x.jsonl", "Timestamp": "2009-11-20T09:31:29.671875Z",
            "Parser": "prefetch"}) + b"\n",
         # no Timestamp: ts resolves to null
         j({k: v for k, v in _PREFETCH_EXEC.items() if k != "Timestamp"}) + b"\n",
         # a 1601 epoch stamp is scrubbed by _clean_ts
         j(_copy(dict(_PREFETCH_EXEC, Timestamp="1601-01-01T00:00:00.000000Z"))) + b"\n"])

    # --- plaso_exec_winreg: amcache / userassist / bam / appcompatcache -----
    # variant order is declaration order: amcache_link_time, amcache,
    # userassist, bam, appcompatcache.
    _lib.write_fixture(
        "plaso_exec_winreg",
        {"artefacts": ["plaso_exec_winreg"], "host": "plaso-fallback",
         "adapter": "none", "input": "input.jsonl"},
        [
            # appcompatcache: the path verbatim (NT form), execution INFERRED,
            # and time_meaning over every plaso timestamp_desc + the fallback
            j(_APPCOMPAT) + b"\n",
            j(_copy(_APPCOMPAT, timestamp_desc="Registry Last Written Time")) + b"\n",
            j(_copy(_APPCOMPAT, timestamp_desc="Last Time Executed")) + b"\n",
            j(_copy(_APPCOMPAT, timestamp_desc="")) + b"\n",
            j(_copy(_APPCOMPAT, timestamp_desc=DROP)) + b"\n",
            j(_copy(_APPCOMPAT, timestamp_desc="Some Unknown Stamp")) + b"\n",
            # a modern Store/UWP cache entry: a TAB-delimited package descriptor,
            # not a path — win_program_name yields the Package Family Name and
            # win_program_path stays null (never the raw tab blob)
            j(_copy(_APPCOMPAT,
                    path="0\tabcd\tef01\tx64\tMicrosoft.WindowsStore\tpublisher8")) + b"\n",
            j(_copy(_APPCOMPAT, path=DROP)) + b"\n",         # no path → exe/image_path null
            j(_copy(_APPCOMPAT, username="M57-JO\\Jo")) + b"\n",
            # userassist
            j(_USERASSIST_RUNPATH) + b"\n",
            j(_copy(_USERASSIST_RUNPATH, value_name="notepad.exe")) + b"\n",
            j(_copy(_USERASSIST_RUNPATH,
                    value_name="C:\\Program Files\\7-Zip\\7zFM.exe")) + b"\n",
            j(_copy(_USERASSIST_RUNPATH, value_name="%ProgramFiles%/x/y.exe")) + b"\n",
            # the recorded username wins over the hive-path derivation
            j(_copy(_USERASSIST_RUNPATH, username="DESKTOP-PM6C56D\\jcloudy")) + b"\n",
            # a system hive path: no \Users\ segment → user is an honest null
            j(_copy(_USERASSIST_RUNPATH,
                    display_name="NTFS:\\Windows\\System32\\config\\SOFTWARE")) + b"\n",
            # the UEME_ negative-lookahead family: every one stays raw
            j(_copy(_USERASSIST_RUNPATH, value_name="UEME_CTLCUACount:ctor")) + b"\n",
            j(_copy(_USERASSIST_RUNPATH, value_name="UEME_CTLSESSION")) + b"\n",
            j(_copy(_USERASSIST_RUNPATH, value_name="UEME_UISCUT")) + b"\n",
            j(_copy(_USERASSIST_RUNPATH, value_name="UEME_RUNPIDL:%csidl2%\\x.lnk")) + b"\n",
            j(_copy(_USERASSIST_RUNPATH, value_name="UEME_RUNCPL:timedate.cpl")) + b"\n",
            j(_copy(_USERASSIST_RUNPATH, value_name="UEME_RUNPATH")) + b"\n",
            j(_copy(_USERASSIST_RUNPATH, value_name="")) + b"\n",
            # amcache: the key write (execution), and the SHA-1 out of
            # file_identifier ("0000"+40hex) — never the hive's own sha256
            j(_AMCACHE) + b"\n",
            j(_copy(_AMCACHE, timestamp_desc="Creation Time")) + b"\n",
            j(_copy(_AMCACHE, timestamp_desc="Installation Time")) + b"\n",
            j(_copy(_AMCACHE, file_identifier="deadbeef")) + b"\n",      # malformed → null
            j(_copy(_AMCACHE,
                    file_identifier="0000A94A8FE5CCB19BA61C4C0873D391E987982FBBD3")) + b"\n",
            j(_copy(_AMCACHE, file_identifier=DROP)) + b"\n",
            j(_copy(_AMCACHE, full_path=DROP)) + b"\n",     # filename must NOT fill exe
            # a UWP package descriptor in full_path
            j(_copy(_AMCACHE,
                    full_path="0\tabcd\tef01\tx64\tContoso.App\tpublisher8")) + b"\n",
            # the Link Time row: a timestamp-LESS file entity carrying the
            # compile stamp natively — never a process create, never an event
            j(_AMCACHE_LINK) + b"\n",
            j(_copy(_AMCACHE_LINK, timestamp_desc="Compilation Time")) + b"\n",
            j(_copy(_AMCACHE_LINK, company_name="")) + b"\n",        # → honest null
            j(_copy(_AMCACHE_LINK, company_name=DROP)) + b"\n",
            j(_copy(_AMCACHE_LINK, full_path=DROP)) + b"\n",         # path props all null
            j(_copy(_AMCACHE_LINK, full_path="c:\\users\\bob\\downloads\\noext")) + b"\n",
            j(_copy(_AMCACHE_LINK, file_identifier="deadbeef")) + b"\n",
            # bam
            j(_BAM) + b"\n",
            j(_copy(_BAM, path=DROP)) + b"\n",
            j(_copy(_BAM, user_identifier=DROP)) + b"\n",
            j(_copy(_BAM, path="\\Device\\HarddiskVolume2\\Windows\\notepad")) + b"\n",
            # nothing provable: programscache / plain winreg rows stay raw
            j({"SourceImage": "x.jsonl", "Parser": "winreg/explorer_programscache",
               "Record": {"parser": "winreg/explorer_programscache",
                          "key_path": "HKLM\\X", "image_hostname": "M57-JO"}}) + b"\n",
            j({"SourceImage": "x.jsonl", "Parser": "winreg/winreg_default",
               "Record": {"parser": "winreg/winreg_default",
                          "key_path": "HKLM\\X", "image_hostname": "M57-JO"}}) + b"\n",
            j({"SourceImage": "x.jsonl", "Parser": "winreg/windows_usbstor_devices",
               "Record": {"parser": "winreg/windows_usbstor_devices",
                          "key_path": "HKLM\\X", "image_hostname": "M57-JO"}}) + b"\n",
            # "bam" as a substring is NOT the bam parser
            j({"SourceImage": "x.jsonl", "Parser": "winreg/bamboo",
               "Record": {"parser": "winreg/bamboo", "image_hostname": "M57-JO",
                          "path": "\\Device\\HarddiskVolume2\\x.exe"}}) + b"\n",
        ])

    # --- plaso_exec_cron: L2tText syslog:cron:task_run ----------------------
    _lib.write_fixture(
        "plaso_exec_cron",
        {"artefacts": ["plaso_exec_cron"], "host": "plaso-fallback",
         "adapter": "none", "input": "input.jsonl"},
        [j(_CRON) + b"\n",
         # a ROOTED first token fills image_path; a shell builtin never does
         j(_copy(_CRON, command="/usr/lib/php/sessionclean 2>/dev/null")) + b"\n",
         j(_copy(_CRON, command="cd /tmp && ./run.sh")) + b"\n",
         j(_copy(_CRON, command="  /usr/bin/php -f x.php")) + b"\n",   # leading space
         j(_copy(_CRON, command="/usr/bin/php")) + b"\n",              # single token
         j(_copy(_CRON, command=DROP)) + b"\n",                        # honest nulls
         j(_copy(_CRON, command="")) + b"\n",
         j(_copy(_CRON, command="-")) + b"\n",                         # blank rule
         # the image identity wins over the syslog-recorded hostname
         j(_copy(_CRON, image_hostname="webserver01")) + b"\n",
         # neither → host null, source_host from the manifest fallback
         j(_copy(_CRON, image_hostname="", hostname=DROP)) + b"\n",
         j(_copy(_CRON, hostname="pits-adams")) + b"\n",
         j(_copy(_CRON, pid=DROP, username=DROP)) + b"\n",
         j(_copy(_CRON, message_body="(root) CMD (test -x /etc/cron.daily/"
                                     "popularity-contest)")) + b"\n",
         j(_copy(_CRON, reporter=DROP)) + b"\n",
         # other syslog lines are not cron executions
         j(_copy(_CRON, data_type="syslog:line")) + b"\n",
         j(_copy(_CRON, data_type=DROP)) + b"\n"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

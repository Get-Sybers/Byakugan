"""Parity vectors + fixtures for the `srum_recmd_jlecmd` family — the three
per-tool mapping modules that each own exactly one artefact key:

    byakugan/mappings/plaso_srum.py   l2t_srum      srum_is_network_usage
                                                    srum_is_application_usage
    byakugan/mappings/recmd.py        recmd_batch   recmd_is_value_record
    byakugan/mappings/jlecmd.py       jlecmd_dest   jl_is_dest_entry

Three different record SHAPES ride in one family:

* SRUM is a WRAPPED plaso row — the gates read the nested `Record` dict through
  plaso_srum._dt's `str((rec.get("Record") or {}).get("data_type") or "")`, so
  both `or` folds are Python truthiness (a FALSY non-dict Record is the empty
  dict; a falsy data_type is ""). SRUM's `user_identifier` is a SID *or* an
  SRUM-internal index, so the sid/uid column is gated on the `^(S-1-[0-9-]+)$`
  form — an index is not an identity — and `application` is either a
  \\Device\\... kernel path (image_path + basename → exe) or a bare service
  name (exe only).
* RECmd rows are UNWRAPPED raw JSON straight out of `RECmd --json`
  (HivePath/KeyPath/ValueName/LastWriteTimestamp), timestamped by the key's
  LastWriteTimestamp with its ' ' → 'T' separator swap.
* JLECmd rows here are PRE-FLATTENED (adapter "none"): they mirror exactly what
  byakugan/adapters/jlecmd.py `flatten()` emits for the real LoneWolf record in
  tests/test_car_jlecmd.py, /Date(ms)/ stamps already rendered to ISO. The
  raw-jump-list end-to-end fixture (adapter "jlecmd") belongs to the adapters
  agent, not to this family.

    python tests/parity/genf/srum_recmd_jlecmd.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/srum_recmd_jlecmd.json
    tests/parity/fixtures/srum_recmd_jlecmd_srum/
    tests/parity/fixtures/srum_recmd_jlecmd_recmd/
    tests/parity/fixtures/srum_recmd_jlecmd_jlecmd/

No marker vectors: every marker kind these three maps resolve (payload over the
"Record" field, first, basename, ext, regex1, replace, user_canon) is already
covered engine-wide by marker_vectors/core.json.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "srum_recmd_jlecmd"

_NET = "windows:srum:network_usage"
_APP = "windows:srum:application_usage"
_CONN = "windows:srum:network_connectivity"


def _w(rec) -> dict:
    """A wrapped plaso row carrying only what the SRUM gates read."""
    return {"Record": rec}


# ---------------------------------------------------------------------------
# predicate vectors — every branch and every type edge of the four gates
# ---------------------------------------------------------------------------
PREDICATE_CASES = [
    # --- srum_is_network_usage: _dt(rec) == "windows:srum:network_usage" ----
    ("srum_is_network_usage", _w({"data_type": _NET})),
    ("srum_is_network_usage", _w({"data_type": _APP})),
    ("srum_is_network_usage", _w({"data_type": _CONN})),
    ("srum_is_network_usage", _w({"data_type": "windows:srum:network_usage:x"})),
    ("srum_is_network_usage", _w({"data_type": "windows:srum:network_"})),
    ("srum_is_network_usage", _w({"data_type": "WINDOWS:SRUM:NETWORK_USAGE"})),
    ("srum_is_network_usage", _w({"data_type": " windows:srum:network_usage"})),
    ("srum_is_network_usage", _w({"data_type": None})),            # `or ""`
    ("srum_is_network_usage", _w({"data_type": ""})),
    ("srum_is_network_usage", _w({"data_type": "-"})),             # not blank here
    ("srum_is_network_usage", _w({"data_type": 0})),               # falsy int → ""
    ("srum_is_network_usage", _w({"data_type": 5})),               # str(5)
    ("srum_is_network_usage", _w({"data_type": 5.0})),             # str(float)
    ("srum_is_network_usage", _w({"data_type": False})),
    ("srum_is_network_usage", _w({"data_type": True})),            # str(True)
    ("srum_is_network_usage", _w({"data_type": [_NET]})),          # str(list) repr
    ("srum_is_network_usage", _w({})),                             # no data_type
    ("srum_is_network_usage", {"Record": None}),                   # `or {}`
    ("srum_is_network_usage", {"Record": {}}),                     # falsy dict → {}
    ("srum_is_network_usage", {"Record": []}),                     # falsy list → {}
    ("srum_is_network_usage", {"Record": 0}),                      # falsy int → {}
    ("srum_is_network_usage", {"Record": ""}),                     # falsy str → {}
    ("srum_is_network_usage", {}),                                 # no Record at all
    # (a TRUTHY non-dict Record — "Record": "x" — makes Python raise
    #  AttributeError; unreachable on the L2tSrum route, so no vector.)
    # a full network_usage row: the gate reads data_type only
    ("srum_is_network_usage", _w({"data_type": _NET, "application": "DiagTrack",
                                  "bytes_received": 251792, "bytes_sent": 372082,
                                  "user_identifier": "S-1-5-21-1-2-3-1001",
                                  "interface_luid": 19985273102270464})),

    # --- srum_is_application_usage -----------------------------------------
    ("srum_is_application_usage", _w({"data_type": _APP})),
    ("srum_is_application_usage", _w({"data_type": _NET})),
    ("srum_is_application_usage", _w({"data_type": _CONN})),
    ("srum_is_application_usage", _w({"data_type": "windows:srum:application_usage "})),
    ("srum_is_application_usage", _w({"data_type": None})),
    ("srum_is_application_usage", _w({"data_type": ""})),
    ("srum_is_application_usage", _w({"data_type": 0})),
    ("srum_is_application_usage", _w({"data_type": True})),
    ("srum_is_application_usage", _w({})),
    ("srum_is_application_usage", {"Record": None}),
    ("srum_is_application_usage", {}),
    ("srum_is_application_usage", _w({"data_type": _APP,
                                      "application": r"\Device\HarddiskVolume4\Windows"
                                                     r"\System32\LogonUI.exe",
                                      "user_identifier": "S-1-5-18",
                                      "foreground_cycle_time": 3680219664})),

    # --- recmd_is_value_record: bool(rec["KeyPath"]) and rec["Deleted"] is not True
    ("recmd_is_value_record", {"KeyPath": r"S-1-5-21-1_Classes\...\MuiCache",
                               "Deleted": False}),
    ("recmd_is_value_record", {"KeyPath": r"Software\Foo", "Deleted": True}),
    ("recmd_is_value_record", {"KeyPath": r"Software\Foo"}),         # Deleted absent
    ("recmd_is_value_record", {"KeyPath": r"Software\Foo", "Deleted": None}),
    # `is not True` is an IDENTITY test, not truthiness — a truthy non-bool is
    # NOT the True singleton, so the record is still claimed.
    ("recmd_is_value_record", {"KeyPath": "K", "Deleted": 1}),
    ("recmd_is_value_record", {"KeyPath": "K", "Deleted": 1.0}),
    ("recmd_is_value_record", {"KeyPath": "K", "Deleted": "true"}),
    ("recmd_is_value_record", {"KeyPath": "K", "Deleted": "True"}),
    ("recmd_is_value_record", {"KeyPath": "K", "Deleted": ["x"]}),
    ("recmd_is_value_record", {"KeyPath": "K", "Deleted": 0}),
    ("recmd_is_value_record", {"KeyPath": "K", "Deleted": ""}),
    # bool(KeyPath) is truthiness, NOT the engine blank rule
    ("recmd_is_value_record", {"KeyPath": "-", "Deleted": False}),   # truthy → claimed
    ("recmd_is_value_record", {"KeyPath": "", "Deleted": False}),
    ("recmd_is_value_record", {"KeyPath": None, "Deleted": False}),
    ("recmd_is_value_record", {"Deleted": False}),                   # KeyPath absent
    ("recmd_is_value_record", {"KeyPath": 0}),
    ("recmd_is_value_record", {"KeyPath": 5}),
    ("recmd_is_value_record", {"KeyPath": False}),
    ("recmd_is_value_record", {"KeyPath": True}),
    ("recmd_is_value_record", {"KeyPath": []}),
    ("recmd_is_value_record", {"KeyPath": ["a"]}),
    ("recmd_is_value_record", {"KeyPath": {}}),
    ("recmd_is_value_record", {"KeyPath": {"a": 1}}),
    ("recmd_is_value_record", {}),

    # --- jl_is_dest_entry: bool(rec.get("Path")) ---------------------------
    ("jl_is_dest_entry", {"Path": r"C:\Users\jcloudy\Desktop\Planning.docx"}),
    ("jl_is_dest_entry", {"Path": "-"}),                             # truthy → claimed
    ("jl_is_dest_entry", {"Path": ""}),
    ("jl_is_dest_entry", {"Path": None}),
    ("jl_is_dest_entry", {}),
    ("jl_is_dest_entry", {"Path": 0}),
    ("jl_is_dest_entry", {"Path": 5}),
    ("jl_is_dest_entry", {"Path": 0.0}),
    ("jl_is_dest_entry", {"Path": False}),
    ("jl_is_dest_entry", {"Path": True}),
    ("jl_is_dest_entry", {"Path": []}),
    ("jl_is_dest_entry", {"Path": ["x"]}),
    ("jl_is_dest_entry", {"Path": {}}),
    ("jl_is_dest_entry", {"Path": {"a": 1}}),
    ("jl_is_dest_entry", {"path": "lower-case key"}),                # case-sensitive
]

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
j = _lib.j

# --- SRUM: wrapped plaso rows ----------------------------------------------
# The wrapper + the four Record dicts below are VERBATIM from
# tests/test_car_srum_recmd.py (`_srum` and the rows its two tests feed through
# normalize); the rest are edge shapes the module docstring names.
_SRUM_TS = "2018-03-27T12:19:00Z"


def _srum(dt, **extra) -> dict:
    rec = {"data_type": dt, "parser": "esedb/srum", "timestamp_desc": "Recorded Time"}
    rec.update(extra)
    return {"SourceImage": "lw", "Timestamp": _SRUM_TS,
            "Parser": "esedb/srum", "Record": rec}


def _rid(row: dict, n: int, ts: str | None = None) -> dict:
    """The same wrapped row with a RecordId (and optionally another Timestamp)
    so the spindle's positional (SourceImage, RecordId) fallback is distinct."""
    out = dict(row, RecordId=n)
    if ts is not None:
        out["Timestamp"] = ts
    return out


# tests/test_car_srum_recmd.py::test_srum_network_usage_is_flow_message_with_attribution
_SRUM_NET_BARE = _srum(_NET, application="DiagTrack",
                       bytes_received=251792, bytes_sent=372082,
                       user_identifier="S-1-5-21-1-2-3-1001",
                       interface_luid=19985273102270464)
_SRUM_NET_DEVICE = _srum(
    _NET,
    application=r"\Device\HarddiskVolume4\Program Files\S3 Browser\s3browser-win32.exe",
    bytes_received=1, bytes_sent=2, user_identifier=2)
# tests/test_car_srum_recmd.py::test_srum_application_usage_is_execution_evidence
_SRUM_APP_DEVICE = _srum(
    _APP, application=r"\Device\HarddiskVolume4\Windows\System32\LogonUI.exe",
    user_identifier="S-1-5-18", foreground_cycle_time=3680219664)
_SRUM_CONNECTIVITY = _srum(_CONN, application=1)

# --- authored edge shapes (the docstring's field spread) --------------------
# the FULL application_usage native list — every foreground_* counter + face_time
_SRUM_APP_FULL = _srum(
    _APP, application=r"\Device\HarddiskVolume4\Program Files\Google\Chrome"
                      r"\Application\chrome.exe",
    identifier=1234, interface_luid=0,
    user_identifier="S-1-5-21-2734969515-1644526556-1039763013-1001",
    foreground_cycle_time=1234567890, foreground_bytes_read=987654,
    foreground_bytes_written=54321, face_time=3600000)
# a bare SERVICE name under application_usage: exe only, image_path honest null
_SRUM_APP_BARE = _srum(_APP, application="DiagTrack", user_identifier="S-1-5-18",
                       foreground_cycle_time=17)
# an SRUM-INTERNAL INDEX in the sid column: not an identity → sid honest null
_SRUM_APP_INDEX_SID = _srum(_APP, application="DiagTrack", user_identifier=3,
                            identifier=7)
# the SID gate is case-SENSITIVE (^(S-1-[0-9-]+)$): a lower-case sid misses
_SRUM_NET_LOWER_SID = _srum(_NET, application="DiagTrack", bytes_received=10,
                            bytes_sent=20, user_identifier="s-1-5-18",
                            interface_luid=19985273102270464)
# a device path ENDING in a separator: basename → "" → first() falls back to the
# whole application string
_SRUM_NET_TRAILING_SEP = _srum(_NET, application="\\Device\\HarddiskVolume4\\",
                               bytes_received=3, bytes_sent=4,
                               user_identifier="S-1-5-18", interface_luid=1)
# no application at all: exe/image_path null → the spindle identity is
# incomplete → the positional (SourceImage, RecordId) fallback mints the guid
_SRUM_NET_NO_APP = _srum(_NET, bytes_received=5, bytes_sent=6,
                         user_identifier="S-1-5-18", interface_luid=2)
# counters as strings / floats / null — SRUM columns ride through as-is
_SRUM_NET_ODD_COUNTERS = _srum(_NET, application="Spooler", bytes_received="0",
                               bytes_sent=1.5, user_identifier=None,
                               interface_luid=None)
# network_connectivity with a real interface: still no honest CAR object → raw
_SRUM_CONN_REAL = _srum(_CONN, interface_luid=19985273102270464,
                        connected_time=3600, connection_start_time=1)
_SRUM_NO_DATA_TYPE = _srum(None, application="DiagTrack")

# --- RECmd: UNWRAPPED raw batch rows ---------------------------------------
# `_recmd()` is VERBATIM from tests/test_car_srum_recmd.py.


def _recmd(**over) -> dict:
    rec = {"HivePath": r"/in/Users/jcloudy/AppData/Local/Microsoft/Windows/UsrClass.dat",
           "HiveType": "UsrClass", "Description": "MuiCache (Vista+)",
           "Category": "Program Execution",
           "KeyPath": r"S-1-5-21-1_Classes\Local Settings\...\MuiCache",
           "ValueName": "LangID", "ValueType": "RegBinary",
           "ValueData": "(Binary data)", "ValueData2": None, "ValueData3": None,
           "Comment": "Displays new applications", "Recursive": False,
           "Deleted": False, "LastWriteTimestamp": "2018-04-02 01:15:16.9540407"}
    rec.update(over)
    return rec


# --- JLECmd: PRE-FLATTENED per-entry records -------------------------------
# Exactly what byakugan/adapters/jlecmd.flatten() emits for the real LoneWolf
# record inlined in tests/test_car_jlecmd.py (key order and all), with the
# /Date(1522917168677)/ and /Date(1522187139502)/ stamps already rendered by
# dotnet_date(). The raw-file (adapter "jlecmd") end-to-end fixture is the
# adapters agent's, not this family's.
_JL_SOURCE = "/in/AutomaticDestinations/fb3b0dbfee58fac8.automaticDestinations-ms"
_JL_ENTRY1 = {
    "Path": r"C:\Users\jcloudy\Desktop\Planning.docx",
    "LastModified": "2018-04-05T08:32:48.677000+00:00",
    "CreatedOn": "2018-03-27T21:45:39.502000+00:00",
    "Hostname": "desktop-pm6c56d",
    "InteractionCount": 13,
    "EntryNumber": 1,
    "MRUPosition": 0,
    "Pinned": False,
    "MacAddress": "28:e3:47:01:77:77",
    "VolumeDroid": "bc75",
    "AppId": "fb3b0dbfee58fac8",
    "AppDescription": "Microsoft Word 2016 64-bit",
    "SourceFile": _JL_SOURCE,
}


def _jl(**over) -> dict:
    return dict(_JL_ENTRY1, **over)


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    # --- l2t_srum: both variants, the SID gate, the device-path split -------
    _lib.write_fixture(
        "srum_recmd_jlecmd_srum",
        {"artefacts": ["l2t_srum"], "host": "lonewolf",
         "adapter": "none", "input": "input.jsonl"},
        [j(_SRUM_NET_BARE) + b"\n",
         j(_SRUM_NET_DEVICE) + b"\n",
         j(_SRUM_APP_DEVICE) + b"\n",
         j(_SRUM_APP_FULL) + b"\n",
         j(_SRUM_APP_BARE) + b"\n",
         j(_SRUM_APP_INDEX_SID) + b"\n",
         j(_SRUM_NET_LOWER_SID) + b"\n",
         j(_SRUM_NET_TRAILING_SEP) + b"\n",
         # identity incomplete (no application) → positional fallback needs a
         # RecordId; the same row without one shows the fallback's own null
         j(_rid(_SRUM_NET_NO_APP, 11)) + b"\n",
         j(_SRUM_NET_NO_APP) + b"\n",
         # a 1601 stamp: _clean_ts drops it → timestamp null → positional too
         j(_rid(_SRUM_NET_BARE, 12, ts="1601-01-01T00:00:00.000000Z")) + b"\n",
         j(_SRUM_NET_ODD_COUNTERS) + b"\n",
         j(_SRUM_CONNECTIVITY) + b"\n",        # no honest CAR object: dropped
         j(_SRUM_CONN_REAL) + b"\n",           # dropped
         j(_SRUM_NO_DATA_TYPE) + b"\n",        # claimed by neither gate: dropped
         j({"SourceImage": "lw", "RecordId": 99, "Timestamp": _SRUM_TS,
            "Parser": "esedb/srum"}) + b"\n",  # no Record at all: dropped
         b"{not json\n"])                      # bad line: skipped silently

    # --- recmd_batch: the live/deleted split + hive-path user attribution ---
    _lib.write_fixture(
        "srum_recmd_jlecmd_recmd",
        {"artefacts": ["recmd_batch"], "host": "DESKTOP-PM6C56D",
         "adapter": "none", "input": "input.jsonl"},
        [j(_recmd()) + b"\n",
         # a recovered-deleted record's deletion TIME is unknowable → raw
         j(_recmd(Deleted=True)) + b"\n",
         # `is not True` is identity, not truthiness: a 1 is still claimed
         j(_recmd(Deleted=1, ValueName="TruthyNotTrue")) + b"\n",
         # a SYSTEM hive: no \Users\ segment → user honest null
         j(_recmd(HivePath=r"C:\Windows\System32\config\SOFTWARE",
                  HiveType="Software", ValueName="ProductName",
                  ValueType="RegSz", ValueData="Windows 10 Pro",
                  KeyPath=r"Microsoft\Windows NT\CurrentVersion",
                  Category="System Info", Description="Windows version")) + b"\n",
         # the lower-case /users/ form (the regex is (?i))
         j(_recmd(HivePath=r"/in/users/jcloudy/ntuser.dat", HiveType="NtUser",
                  KeyPath=r"Software\Microsoft\Windows\CurrentVersion\Run",
                  ValueName="OneDrive", ValueType="RegSz",
                  ValueData=r"C:\Users\jcloudy\AppData\Local\Microsoft\OneDrive"
                            r"\OneDrive.exe /background")) + b"\n",
         # the Windows-separator hive path form
         j(_recmd(HivePath=r"C:\Users\Administrator\NTUSER.DAT",
                  HiveType="NtUser", ValueName="Shell", ValueType="RegSz",
                  ValueData="explorer.exe")) + b"\n",
         # first(ValueData, ValueData2, ValueData3): the fall-through chain
         j(_recmd(ValueName="Fallback2", ValueData=None,
                  ValueData2="second slot", ValueData3="third")) + b"\n",
         j(_recmd(ValueName="Fallback3", ValueData="-", ValueData2="",
                  ValueData3="third")) + b"\n",
         j(_recmd(ValueName="NoData", ValueData=None, ValueData2=None,
                  ValueData3=None)) + b"\n",
         # a DWORD value: ValueData is an int, not a string
         j(_recmd(ValueName="Start", ValueType="RegDword", ValueData=2,
                  Recursive=True, Comment="", Category="Services",
                  KeyPath=r"ControlSet001\Services\WinDefend")) + b"\n",
         # a 1601 key write: replace() still swaps ' '→'T', _clean_ts then
         # drops it → timestamp null (the fields-guid is unaffected)
         j(_recmd(ValueName="NeverWritten",
                  LastWriteTimestamp="1601-01-01 00:00:00.0000000")) + b"\n",
         # no LastWriteTimestamp at all → timestamp null
         j(_recmd(ValueName="NoStamp", LastWriteTimestamp=None)) + b"\n",
         # a blank ValueName voids the (HivePath, KeyPath, ValueName) guid
         j(_recmd(ValueName="")) + b"\n",
         j(_recmd(KeyPath="")) + b"\n",        # no key path: dropped
         j({"HivePath": "/in/x.dat", "ValueName": "Orphan"}) + b"\n",  # dropped
         b"{not json\n"])                      # bad line: skipped silently

    # --- jlecmd_dest: the flattened DestList entries ------------------------
    _lib.write_fixture(
        "srum_recmd_jlecmd_jlecmd",
        {"artefacts": ["jlecmd_dest"], "host": "fallback-host",
         "adapter": "none", "input": "input.jsonl"},
        [j(_JL_ENTRY1) + b"\n",
         # a second entry of the same jump list: same SourceFile, new EntryNumber
         j(_jl(Path=r"\\FILESRV01\shared\Quarterly Results.xlsx", EntryNumber=2,
               MRUPosition=1, Pinned=True, InteractionCount=1,
               LastModified="2018-04-06T10:00:00.000000+00:00",
               CreatedOn="2018-04-06T09:00:00.000000+00:00")) + b"\n",
         # a path with no extension: ext() honest null
         j(_jl(Path=r"C:\Users\jcloudy\Documents\README", EntryNumber=3)) + b"\n",
         # a POSIX-looking path (basename picks posixpath without a backslash)
         j(_jl(Path="/mnt/share/report.final.pdf", EntryNumber=4)) + b"\n",
         # no Hostname on the entry → the map's host is null → the pipeline's
         # --host fallback fills source_host instead
         j(_jl(EntryNumber=5, Hostname=None)) + b"\n",
         # CreatedOn absent (dotnet_date(None) → None) and no MRU/Mac/Droid
         j(_jl(EntryNumber=6, CreatedOn=None, MacAddress=None,
               VolumeDroid=None, MRUPosition=None)) + b"\n",
         # "-" is truthy for the gate but BLANK for the resolver: the row is
         # claimed and every Path-derived prop is an honest null
         j(_jl(Path="-", EntryNumber=7)) + b"\n",
         # a blank EntryNumber voids the (SourceFile, EntryNumber) guid
         j(_jl(EntryNumber=None)) + b"\n",
         j(_jl(Path=None, EntryNumber=8)) + b"\n",      # no path: dropped
         j(_jl(Path="", EntryNumber=9)) + b"\n",        # dropped
         j({"EntryNumber": 10, "SourceFile": _JL_SOURCE}) + b"\n",  # dropped
         b"{not json\n"])                               # bad line: skipped
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Parity vectors + fixtures for the `plaso_registry_shell` family — the three
wrapped-plaso disk-artefact mapping modules and their eight gates:

    byakugan/mappings/plaso_registry.py    plaso_registry     plaso_is_registry
    byakugan/mappings/plaso_shellitem.py   plaso_shellitem    plasoshell_create/modify/read
    byakugan/mappings/plaso_artifacts.py   l2t_lnk            plasoart_lnk_create/modify/read
                                           l2t_recyclebin     plasoart_recycle_delete

Every gate reads the NESTED plaso `Record` dict of the wrapped row. Seven of
the eight are `data_type == <literal>` AND a case-insensitive re.search over
`timestamp_desc`; plaso_is_registry is a `str(...).startswith("windows:registry:")`
prefix test with Python's `or {}` / `or ""` falsy folds around it.

The fixture rows are the inline record dicts of tests/test_car_fs_user_from_path.py
and tests/test_car_plaso_web.py extracted VERBATIM (user attribution:
\\Users\\<name>\\ incl. the lower-case form, fill-only-null, $Recycle.Bin
SID→uid incl. the lower-case bucket dir) plus authored full-field rows — one
realistic wrapped-plaso row per props/keep/native_extract list of each map, and
the registry data_type spread the plaso_registry docstring names (service, run,
winlogon, sam_users, usbstor, mount_points2, bagmru, windows_version,
key_value).

    python tests/parity/genf/plaso_registry_shell.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/plaso_registry_shell.json
    tests/parity/fixtures/plaso_registry_shell_registry/
    tests/parity/fixtures/plaso_registry_shell_shellitem/
    tests/parity/fixtures/plaso_registry_shell_lnk/
    tests/parity/fixtures/plaso_registry_shell_recyclebin/
    tests/parity/fixtures/plaso_registry_shell_routes/

No marker vectors: every marker kind this family resolves (payload over the
"Record" field, first, regex1, user_canon, host_label, basename, ext,
unescape_backslashes) is already covered engine-wide by marker_vectors/core.json.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "plaso_registry_shell"

_SHELL_DT = "windows:shell_item:file_entry"
_LNK_DT = "windows:lnk:link"
_RECYCLE_DT = "windows:metadata:deleted_item"


def _w(rec: dict) -> dict:
    """A wrapped row carrying only what the gates read (the nested Record)."""
    return {"Record": rec}


# ---------------------------------------------------------------------------
# predicate vectors — every branch and every type edge of the eight gates
# ---------------------------------------------------------------------------
PREDICATE_CASES = [
    # --- plaso_is_registry: str((rec["Record"] or {}).get("data_type") or "")
    #     .startswith("windows:registry:") ----------------------------------
    ("plaso_is_registry", _w({"data_type": "windows:registry:key_value"})),
    ("plaso_is_registry", _w({"data_type": "windows:registry:service"})),
    ("plaso_is_registry", _w({"data_type": "windows:registry:bagmru"})),
    ("plaso_is_registry", _w({"data_type": "windows:registry:"})),      # bare prefix
    ("plaso_is_registry", _w({"data_type": "windows:registry"})),       # no colon: False
    ("plaso_is_registry", _w({"data_type": "WINDOWS:REGISTRY:RUN"})),   # case-SENSITIVE
    ("plaso_is_registry", _w({"data_type": " windows:registry:run"})),  # leading space
    ("plaso_is_registry", _w({"data_type": _SHELL_DT})),                # the shell rows
    ("plaso_is_registry", _w({"data_type": _LNK_DT})),
    ("plaso_is_registry", _w({"data_type": None})),                     # `or ""`
    ("plaso_is_registry", _w({"data_type": ""})),
    ("plaso_is_registry", _w({"data_type": "-"})),                      # not blank here
    ("plaso_is_registry", _w({"data_type": 0})),                        # falsy int → ""
    ("plaso_is_registry", _w({"data_type": 5})),                        # str(5)
    ("plaso_is_registry", _w({"data_type": False})),
    ("plaso_is_registry", _w({"data_type": True})),                     # str(True)
    ("plaso_is_registry", _w({"data_type": ["windows:registry:x"]})),   # str(list) repr
    ("plaso_is_registry", _w({})),                                      # no data_type
    ("plaso_is_registry", {"Record": None}),                            # `or {}`
    ("plaso_is_registry", {"Record": {}}),                              # falsy dict → {}
    ("plaso_is_registry", {"Record": []}),                              # falsy list → {}
    ("plaso_is_registry", {}),                                          # no Record at all
    # (a TRUTHY non-dict Record — "Record": "x" — makes Python raise
    #  AttributeError; unreachable on the L2tWinreg route, so no vector.)

    # --- plasoshell_create / modify / read --------------------------------
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": "Creation Time"})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": "crtime"})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": "CRTIME"})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": "Birth Time"})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": "BIRTH"})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT,
                              "timestamp_desc": "Content Modification Time"})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": "Not a time"})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": None})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": ""})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": "-"})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": 5})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT, "timestamp_desc": True})),
    ("plasoshell_create", _w({"data_type": _SHELL_DT})),                 # desc absent
    ("plasoshell_create", _w({"timestamp_desc": "Creation Time"})),      # data_type absent
    ("plasoshell_create", _w({"data_type": _LNK_DT, "timestamp_desc": "Creation Time"})),
    ("plasoshell_create", _w({"data_type": None, "timestamp_desc": "Creation Time"})),
    # plaso_rec's isinstance gate (NOT plaso_is_registry's `or {}`): a truthy
    # non-dict Record is the empty dict here — no crash.
    ("plasoshell_create", {"Record": "not a dict"}),
    ("plasoshell_create", {"Record": ["x"]}),
    ("plasoshell_create", {"Record": None}),
    ("plasoshell_create", {}),

    ("plasoshell_modify", _w({"data_type": _SHELL_DT,
                              "timestamp_desc": "Content Modification Time"})),
    ("plasoshell_modify", _w({"data_type": _SHELL_DT,
                              "timestamp_desc": "Metadata Modification Time"})),
    ("plasoshell_modify", _w({"data_type": _SHELL_DT, "timestamp_desc": "mtime"})),
    ("plasoshell_modify", _w({"data_type": _SHELL_DT, "timestamp_desc": "MTIME"})),
    ("plasoshell_modify", _w({"data_type": _SHELL_DT, "timestamp_desc": "Creation Time"})),
    ("plasoshell_modify", _w({"data_type": _SHELL_DT, "timestamp_desc": "Last Access Time"})),
    ("plasoshell_modify", _w({"data_type": _RECYCLE_DT,
                              "timestamp_desc": "Content Modification Time"})),

    ("plasoshell_read", _w({"data_type": _SHELL_DT, "timestamp_desc": "Last Access Time"})),
    ("plasoshell_read", _w({"data_type": _SHELL_DT, "timestamp_desc": "last access"})),
    ("plasoshell_read", _w({"data_type": _SHELL_DT, "timestamp_desc": "Access Time"})),
    ("plasoshell_read", _w({"data_type": _SHELL_DT, "timestamp_desc": "atime"})),
    ("plasoshell_read", _w({"data_type": _SHELL_DT, "timestamp_desc": "ATIME"})),
    ("plasoshell_read", _w({"data_type": _SHELL_DT, "timestamp_desc": "Accessed"})),  # no
    ("plasoshell_read", _w({"data_type": _SHELL_DT, "timestamp_desc": "Creation Time"})),

    # --- plasoart_lnk_create / modify / read ------------------------------
    ("plasoart_lnk_create", _w({"data_type": _LNK_DT, "timestamp_desc": "Creation Time"})),
    ("plasoart_lnk_create", _w({"data_type": _LNK_DT, "timestamp_desc": "crtime"})),
    ("plasoart_lnk_create", _w({"data_type": _LNK_DT, "timestamp_desc": "Birth Time"})),
    ("plasoart_lnk_create", _w({"data_type": _LNK_DT, "timestamp_desc": "Not a time"})),
    ("plasoart_lnk_create", _w({"data_type": _LNK_DT, "timestamp_desc": None})),
    ("plasoart_lnk_create", _w({"data_type": _LNK_DT})),
    ("plasoart_lnk_create", _w({"data_type": _SHELL_DT, "timestamp_desc": "Creation Time"})),
    ("plasoart_lnk_create", _w({"data_type": "windows:lnk:link:x",
                                "timestamp_desc": "Creation Time"})),   # equality, not prefix
    ("plasoart_lnk_create", {"Record": "not a dict"}),
    ("plasoart_lnk_create", {}),

    ("plasoart_lnk_modify", _w({"data_type": _LNK_DT,
                                "timestamp_desc": "Content Modification Time"})),
    ("plasoart_lnk_modify", _w({"data_type": _LNK_DT, "timestamp_desc": "mtime"})),
    ("plasoart_lnk_modify", _w({"data_type": _LNK_DT, "timestamp_desc": "Creation Time"})),
    ("plasoart_lnk_modify", _w({"data_type": _LNK_DT, "timestamp_desc": "Not a time"})),

    ("plasoart_lnk_read", _w({"data_type": _LNK_DT, "timestamp_desc": "Last Access Time"})),
    ("plasoart_lnk_read", _w({"data_type": _LNK_DT, "timestamp_desc": "atime"})),
    ("plasoart_lnk_read", _w({"data_type": _LNK_DT, "timestamp_desc": "access time"})),
    ("plasoart_lnk_read", _w({"data_type": _LNK_DT, "timestamp_desc": "Creation Time"})),
    ("plasoart_lnk_read", _w({"data_type": _LNK_DT, "timestamp_desc": "Not a time"})),

    # --- plasoart_recycle_delete ------------------------------------------
    ("plasoart_recycle_delete", _w({"data_type": _RECYCLE_DT,
                                    "timestamp_desc": "Content Deletion Time"})),
    ("plasoart_recycle_delete", _w({"data_type": _RECYCLE_DT,
                                    "timestamp_desc": "deletion"})),
    ("plasoart_recycle_delete", _w({"data_type": _RECYCLE_DT,
                                    "timestamp_desc": "DELETION TIME"})),
    ("plasoart_recycle_delete", _w({"data_type": _RECYCLE_DT,
                                    "timestamp_desc": "Deleted"})),      # no 'deletion'
    ("plasoart_recycle_delete", _w({"data_type": _RECYCLE_DT,
                                    "timestamp_desc": "Not a time"})),
    ("plasoart_recycle_delete", _w({"data_type": _RECYCLE_DT, "timestamp_desc": None})),
    ("plasoart_recycle_delete", _w({"data_type": _RECYCLE_DT, "timestamp_desc": 0})),
    ("plasoart_recycle_delete", _w({"data_type": _RECYCLE_DT})),
    ("plasoart_recycle_delete", _w({"data_type": _LNK_DT,
                                    "timestamp_desc": "Content Deletion Time"})),
    ("plasoart_recycle_delete", _w({"timestamp_desc": "Content Deletion Time"})),
    ("plasoart_recycle_delete", {"Record": None}),
    ("plasoart_recycle_delete", {}),
]

# ---------------------------------------------------------------------------
# fixtures — wrapped plaso rows (SourceImage/RecordId/Timestamp/Parser/Record)
# ---------------------------------------------------------------------------
j = _lib.j

_IMAGE = "log2timeline/jsonl/DESKTOP-PM6C56D.jsonl"   # the LoneWolf container
_M57 = "jo.E01"
_TS = "2018-04-05T12:00:00.000000Z"
_HOSTNAME = "DESKTOP-PM6C56D"

_n = [0]


def _wrap(rec: dict, ts: str = _TS, image: str = _IMAGE, parser: str = "x") -> dict:
    """The wrapped l2t row shape the maps consume (tests/test_car_*'s _wrap):
    a per-row RecordId so the spindle's positional fallback is distinct."""
    _n[0] += 1
    return {"SourceImage": image, "RecordId": _n[0], "Timestamp": ts,
            "Parser": rec.get("parser", parser), "Record": rec}


# --- registry rows ----------------------------------------------------------
# VERBATIM from tests/test_car_fs_user_from_path.py (user attribution).
_REG_PER_USER_HIVE = {
    "data_type": "windows:registry:key_value",
    "key_path": r"HKEY_CURRENT_USER\Software\Foo",
    "display_name": r"VSS2:NTFS:\Users\jcloudy\NTUSER.DAT",
    "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
_REG_SYSTEM_HIVE = {
    "data_type": "windows:registry:key_value",
    "key_path": r"HKEY_LOCAL_MACHINE\System\ControlSet001\Services\foo",
    "display_name": r"NTFS:\Windows\System32\config\SYSTEM",
    "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
_REG_REAL_USERNAME = {
    "data_type": "windows:registry:key_value",
    "key_path": r"HKEY_CURRENT_USER\Software\Foo",
    "display_name": r"NTFS:\Users\jcloudy\NTUSER.DAT",
    "image_hostname": "DESKTOP-PM6C56D", "username": "REALDOM\\real"}
_REG_LOWER_USERS = {
    "data_type": "windows:registry:key_value",
    "key_path": r"HKEY_CURRENT_USER\Software\Foo",
    "display_name": r"NTFS:\users\jcloudy\ntuser.dat",
    "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
# VERBATIM from tests/test_spindle_ids.py (_REGISTRY — the M57 Run key snapshot).
_REG_RUN_SNAPSHOT = {
    "data_type": "windows:registry:key_value",
    "display_name": "NTFS:\\WINDOWS\\system32\\config\\software",
    "key_path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "image_hostname": "M57-JO", "values": [{"name": "x", "data": "y"}]}

# Authored full-field rows: one per native_extract cluster of the map.
_REG_SERVICE = {
    "data_type": "windows:registry:service",
    "key_path": r"HKEY_LOCAL_MACHINE\System\ControlSet001\Services\WinDefend",
    "display_name": r"NTFS:\Windows\System32\config\SYSTEM",
    "image_path": r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe",
    "image_hostname": _HOSTNAME, "name": "WinDefend", "object_name": "LocalSystem",
    "start_type": 2, "service_type": 16, "error_control": 1,
    "service_dll": r"C:\Windows\System32\mpsvc.dll",
    "values": [{"name": "Start", "data": 2, "type": "REG_DWORD"},
               {"name": "ImagePath", "data": r"C:\Windows\system32\svchost.exe -k netsvcs",
                "type": "REG_EXPAND_SZ"}],
    "username": "-"}
_REG_RUN = {
    "data_type": "windows:registry:run",
    "key_path": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
    "display_name": r"VSS1:NTFS:\Users\jcloudy\NTUSER.DAT",
    "image_hostname": _HOSTNAME,
    "entries": "OneDrive: C:\\Users\\jcloudy\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background",
    "command": r"C:\Users\jcloudy\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background",
    "application": "OneDrive.exe",
    "values": [{"name": "OneDrive", "data": "OneDrive.exe", "type": "REG_SZ"}]}
_REG_WINLOGON = {
    "data_type": "windows:registry:winlogon",
    "key_path": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "display_name": r"NTFS:\Windows\System32\config\SOFTWARE",
    "image_hostname": _HOSTNAME, "application": "Userinit",
    "command": r"C:\Windows\system32\userinit.exe,", "handler": "Explorer.exe",
    "trigger": "Logon", "values": []}
_REG_SAM_USER = {
    "data_type": "windows:registry:sam_users",
    "key_path": r"HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\000003E9",
    "display_name": r"NTFS:\Windows\System32\config\SAM",
    "image_hostname": _HOSTNAME, "username": "jcloudy", "fullname": "J. Cloudy",
    "comments": "", "account_rid": 1001, "login_count": 22,
    "values": []}
_REG_USBSTOR = {
    "data_type": "windows:registry:usbstor",
    "key_path": r"HKEY_LOCAL_MACHINE\System\ControlSet001\Enum\USBSTOR",
    "display_name": r"NTFS:\Windows\System32\config\SYSTEM",
    "image_hostname": _HOSTNAME,
    "subkey_name": "Disk&Ven_SanDisk&Prod_Cruzer_Glide&Rev_1.26",
    "serial": "4C530001120716117282&0", "vendor": "SanDisk", "product": "Cruzer_Glide",
    "revision": "1.26", "device_type": "Disk", "device_display_name": "SanDisk Cruzer Glide USB Device",
    "values": []}
_REG_MOUNTPOINTS = {
    "data_type": "windows:registry:mount_points2",
    "key_path": (r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion"
                 r"\Explorer\MountPoints2"),
    "display_name": r"NTFS:\Users\jcloudy\NTUSER.DAT",
    "image_hostname": _HOSTNAME, "server_name": "FILESRV01", "share_name": "shared",
    "source_type": "Remote Drive", "drive_letter": "Z", "values": []}
_REG_WINVER = {
    "data_type": "windows:registry:windows_version",
    "key_path": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion",
    "display_name": r"NTFS:\Windows\System32\config\SOFTWARE",
    "image_hostname": _HOSTNAME, "product_name": "Windows 10 Pro",
    "build_number": "17134", "service_pack": "", "version": "10.0",
    "owner": "jcloudy", "configuration": "Multiprocessor Free",
    "settings": ["InstallDate", "RegisteredOwner"], "values": []}
_REG_BAGMRU = {
    "data_type": "windows:registry:bagmru",
    "key_path": (r"HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\BagMRU\1\0"),
    "display_name": r"NTFS:\Users\jcloudy\AppData\Local\Microsoft\Windows\UsrClass.dat",
    "image_hostname": _HOSTNAME,
    "values": [{"name": "0", "data": "My Computer", "type": "REG_BINARY"}]}
# a hive path with NO \Users\ segment and NO recorded username: honest null user
_REG_NO_DISPLAY_NAME = {
    "data_type": "windows:registry:key_value",
    "key_path": r"HKEY_LOCAL_MACHINE\Software\Foo",
    "image_hostname": _HOSTNAME}                 # display_name absent → hive null
# not a registry row (shell items ride the SAME L2tWinreg route): dropped
_REG_SHELL_INTRUDER = {
    "data_type": _SHELL_DT, "timestamp_desc": "Creation Time",
    "shell_item_path": r"<My Computer> C:\Windows", "image_hostname": _HOSTNAME}

# --- shell-item rows --------------------------------------------------------
# VERBATIM from tests/test_car_fs_user_from_path.py.
_SHELL_PER_USER = {
    "data_type": "windows:shell_item:file_entry",
    "timestamp_desc": "Creation Time",
    "display_name": (r"VSS2:NTFS:\Users\jcloudy\AppData\Roaming\Microsoft"
                     r"\Windows\Start Menu\Programs\Windows PowerShell"
                     r"\Windows PowerShell.lnk"),
    "origin": "Windows PowerShell.lnk",
    "shell_item_path": r"<My Computer> C:\Windows\System32\cmd.exe",
    "long_name": "cmd.exe", "name": "cmd.exe",
    "image_hostname": "DESKTOP-PM6C56D"}
_SHELL_SYSTEM_ORIGIN = {
    "data_type": "windows:shell_item:file_entry",
    "timestamp_desc": "Creation Time",
    "display_name": (r"NTFS:\Windows\WinSxS\amd64_x\Windows PowerShell "
                     r"(x86).lnk"),
    "origin": "Windows PowerShell (x86).lnk",
    "shell_item_path": r"<My Computer> C:\Windows\SysWOW64\cmd.exe",
    "long_name": "cmd.exe", "name": "cmd.exe",
    "image_hostname": "DESKTOP-PM6C56D"}
# VERBATIM from tests/test_spindle_ids.py (the shell row minted next to _REGISTRY).
_SHELL_SPINDLE = {
    "data_type": "windows:shell_item:file_entry", "timestamp_desc": "Creation Time",
    "origin": "NTFS:\\WINDOWS\\system32\\config\\software",
    "shell_item_path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "image_hostname": "M57-JO"}

_SHELL_MODIFY = {
    "data_type": "windows:shell_item:file_entry",
    "timestamp_desc": "Content Modification Time",
    "display_name": r"NTFS:\Users\jcloudy\AppData\Local\Microsoft\Windows\UsrClass.dat",
    "origin": "UsrClass.dat", "shell_item_path": r"<My Computer> D:\Tools\nmap\nmap.exe",
    "long_name": "nmap.exe", "name": "NMAP~1.EXE",
    "localized_name": "@shell32.dll,-21786",
    "disk_id": 1, "volume_id": "6c8b4df0", "volume_offset": 105906176,
    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "image_hostname": _HOSTNAME}
_SHELL_READ = {
    "data_type": "windows:shell_item:file_entry",
    "timestamp_desc": "Last Access Time",
    "display_name": r"NTFS:\Users\jcloudy\AppData\Roaming\Microsoft\Windows\Recent\report.lnk",
    "origin": "report.lnk", "shell_item_path": r"<Shared Documents Folder (Users Files)> ",
    "long_name": r"C:\\Users\\jcloudy\\Documents\\report.docx", "name": "REPORT~1.DOC",
    "image_hostname": _HOSTNAME}
# no shell_item_path at all → first() falls to long_name
_SHELL_LONGNAME_ONLY = {
    "data_type": "windows:shell_item:file_entry",
    "timestamp_desc": "crtime",
    "display_name": r"NTFS:\Users\bob\AppData\Local\Microsoft\Windows\UsrClass.dat",
    "origin": "UsrClass.dat", "long_name": "Quarterly Results.xlsx",
    "name": "QUARTE~1.XLS", "image_hostname": _HOSTNAME}
# neither shell_item_path nor long_name → the 8.3 `name`
_SHELL_NAME_ONLY = {
    "data_type": "windows:shell_item:file_entry", "timestamp_desc": "atime",
    "display_name": r"NTFS:\Windows\System32\config\SOFTWARE",
    "origin": "SOFTWARE", "long_name": "-", "name": "SETUP~1.EXE",
    "image_hostname": _HOSTNAME}
# shell_item_path with NO "<...>" prefix; the user comes from the TARGET path
_SHELL_NO_PREFIX = {
    "data_type": "windows:shell_item:file_entry",
    "timestamp_desc": "Content Modification Time",
    "display_name": r"NTFS:\Windows\System32\config\SOFTWARE",
    "origin": "SOFTWARE",
    "shell_item_path": r"C:\Users\Administrator\Downloads\setup.exe",
    "image_hostname": _HOSTNAME}
_SHELL_NOT_A_TIME = {
    "data_type": "windows:shell_item:file_entry", "timestamp_desc": "Not a time",
    "display_name": r"NTFS:\Users\jcloudy\NTUSER.DAT", "origin": "NTUSER.DAT",
    "shell_item_path": r"<My Computer> C:\x", "image_hostname": _HOSTNAME}
_SHELL_LNK_INTRUDER = {
    "data_type": _LNK_DT, "timestamp_desc": "Creation Time",
    "link_target": r"<My Computer> C:\Windows\System32\notepad.exe",
    "image_hostname": _HOSTNAME}

# --- lnk rows ---------------------------------------------------------------
# VERBATIM from tests/test_car_plaso_web.py.
_LNK_M57 = {
    "data_type": "windows:lnk:link", "timestamp_desc": "Creation Time",
    "link_target": r"<My Computer> C:\Program Files\OO3\soffice.exe",
    "working_directory": r"C:\Program Files\OO3\\", "file_size": 0,
    "image_hostname": "M57-JO", "username": "-",
    "display_name": r"NTFS:\...\OpenOffice.org.lnk"}
# VERBATIM from tests/test_car_fs_user_from_path.py.
_LNK_RECENT = {
    "data_type": "windows:lnk:link", "timestamp_desc": "Creation Time",
    "link_target": r"<My Computer> C:\Windows\System32\notepad.exe",
    "display_name": (r"NTFS:\Users\jcloudy\AppData\Roaming\Microsoft"
                     r"\Windows\Recent\notepad.lnk"),
    "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
# the full LNK native_extract list, local_path winning over network_path
_LNK_FULL = {
    "data_type": "windows:lnk:link", "timestamp_desc": "Content Modification Time",
    "local_path": r"C:\Users\jcloudy\Documents\quarterly.xlsx",
    "network_path": r"\\FILESRV01\shared\quarterly.xlsx",
    "link_target": r"<My Computer> C:\Users\jcloudy\Documents\quarterly.xlsx",
    "display_name": (r"NTFS:\Users\jcloudy\AppData\Roaming\Microsoft\Office"
                     r"\Recent\quarterly.LNK"),
    "description": "Quarterly numbers", "working_directory": r"C:\Users\jcloudy\Documents",
    "relative_path": r"..\..\Documents\quarterly.xlsx", "file_size": 48219,
    "command_line_arguments": "/e", "env_var_location": "%USERPROFILE%\\Documents",
    "icon_location": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    "file_attribute_flags": 32, "drive_type": 3, "drive_serial_number": 1820735344,
    "volume_label": "OS",
    "droid_file_identifier": "0e4d8b5c-8a6d-11e8-9c2d-5254001f1f2a",
    "droid_volume_identifier": "9e1a5f36-8a6d-11e8-9c2d-5254001f1f2a",
    "birth_droid_file_identifier": "0e4d8b5c-8a6d-11e8-9c2d-5254001f1f2a",
    "birth_droid_volume_identifier": "9e1a5f36-8a6d-11e8-9c2d-5254001f1f2a",
    "image_hostname": _HOSTNAME, "username": "-"}
# network_path only, and a recorded username that WINS over the path inference
_LNK_NETWORK = {
    "data_type": "windows:lnk:link", "timestamp_desc": "Last Access Time",
    "network_path": r"\\FILESRV01\shared\tools\psexec.exe",
    "link_target": r"<My Computer> \\FILESRV01\shared\tools\psexec.exe",
    "display_name": r"NTFS:\Users\jcloudy\AppData\Roaming\Microsoft\Windows\Recent\psexec.lnk",
    "image_hostname": _HOSTNAME, "username": "DESKTOP-PM6C56D\\admin"}
# escaped backslashes in the recorded target (unescape_backslashes)
_LNK_ESCAPED = {
    "data_type": "windows:lnk:link", "timestamp_desc": "mtime",
    "local_path": "C:\\\\Users\\\\jcloudy\\\\Desktop\\\\evil.exe",
    "display_name": r"NTFS:\Users\jcloudy\Desktop\evil.lnk",
    "image_hostname": _HOSTNAME}
_LNK_NOT_A_TIME = dict(_LNK_M57, timestamp_desc="Not a time")
# no target at all: file_path/file_name/extension honest nulls, guid positional
_LNK_NO_TARGET = {
    "data_type": "windows:lnk:link", "timestamp_desc": "Creation Time",
    "display_name": r"NTFS:\Windows\System32\config\x.lnk", "image_hostname": _HOSTNAME}

# --- recycle-bin rows -------------------------------------------------------
# VERBATIM from tests/test_car_fs_user_from_path.py.
_RB_SID = {
    "data_type": "windows:metadata:deleted_item",
    "timestamp_desc": "Content Deletion Time",
    "original_filename": (r"C:\Users\jcloudy\Desktop\Larry King_ Time to "
                          r"Repeal the Second Amendment_files"),
    "display_name": (r"NTFS:\$Recycle.Bin"
                     r"\S-1-5-21-2734969515-1644526556-1039763013-1001"
                     r"\$IQAU6NQ"),
    "file_size": 5092043, "record_index": 1,
    "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
_RB_SID_LOWER = {
    "data_type": "windows:metadata:deleted_item",
    "timestamp_desc": "Content Deletion Time",
    "original_filename": r"C:\users\jcloudy\Desktop\x",
    "display_name": (r"NTFS:\$recycle.bin"
                     r"\S-1-5-21-2734969515-1644526556-1039763013-1001"
                     r"\$IQAU6NQ"),
    "file_size": 1, "record_index": 1,
    "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
# VERBATIM from tests/test_car_plaso_web.py (the INFO2-era M57 row).
_RB_M57 = {
    "data_type": "windows:metadata:deleted_item",
    "timestamp_desc": "Content Deletion Time",
    "original_filename": r"C:\Documents and Settings\Jo\secret.xls",
    "file_size": 12288, "record_index": 1, "image_hostname": "M57-JO"}
# the full native_extract list + drive_number (INFO2) + artefact hash
_RB_FULL = {
    "data_type": "windows:metadata:deleted_item",
    "timestamp_desc": "Content Deletion Time",
    "original_filename": r"D:\Projects\2018\budget.xlsx",
    "display_name": r"NTFS:\$Recycle.Bin\S-1-5-21-2734969515-1644526556-1039763013-1001\$IZZZ001",
    "file_size": 208384, "record_index": 42, "drive_number": 3,
    "sha256_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "disk_id": 1, "volume_id": "6c8b4df0", "volume_offset": 105906176,
    "image_hostname": _HOSTNAME, "username": "DESKTOP-PM6C56D\\jcloudy"}
# no $Recycle.Bin path → uid honest null; no \Users\ → user honest null
_RB_NO_SID = {
    "data_type": "windows:metadata:deleted_item",
    "timestamp_desc": "Content Deletion Time",
    "original_filename": r"C:\Temp\scratch.tmp",
    "display_name": r"NTFS:\RECYCLER\INFO2", "file_size": 0, "record_index": 7,
    "image_hostname": _HOSTNAME}
_RB_NOT_DELETION = dict(_RB_M57, timestamp_desc="Content Modification Time")


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    # --- plaso_registry: the data_type spread + user attribution ------------
    _lib.write_fixture(
        "plaso_registry_shell_registry",
        {"artefacts": ["plaso_registry"], "host": "fallback-host",
         "adapter": "none", "input": "input.jsonl"},
        [j(_wrap(_REG_PER_USER_HIVE)) + b"\n",
         j(_wrap(_REG_SYSTEM_HIVE)) + b"\n",
         j(_wrap(_REG_REAL_USERNAME)) + b"\n",
         j(_wrap(_REG_LOWER_USERS)) + b"\n",
         j(_wrap(_REG_RUN_SNAPSHOT, image=_M57)) + b"\n",
         j(_wrap(_REG_SERVICE)) + b"\n",
         j(_wrap(_REG_RUN)) + b"\n",
         j(_wrap(_REG_WINLOGON)) + b"\n",
         j(_wrap(_REG_SAM_USER)) + b"\n",
         j(_wrap(_REG_USBSTOR)) + b"\n",
         j(_wrap(_REG_MOUNTPOINTS)) + b"\n",
         j(_wrap(_REG_WINVER)) + b"\n",
         j(_wrap(_REG_BAGMRU)) + b"\n",
         # hive null → the spindle identity is incomplete → positional fallback
         j(_wrap(_REG_NO_DISPLAY_NAME)) + b"\n",
         # a 1601 epoch stamp: _clean_ts drops it → timestamp null → positional
         j(_wrap(_REG_BAGMRU, ts="1601-01-01T00:00:00.000000Z")) + b"\n",
         # no image_hostname anywhere → pipeline's --host fallback fills it
         j(_wrap({k: v for k, v in _REG_SERVICE.items() if k != "image_hostname"})) + b"\n",
         j(_wrap(_REG_SHELL_INTRUDER)) + b"\n",          # not registry: dropped
         j({"SourceImage": _IMAGE, "RecordId": 99, "Timestamp": _TS,
            "Parser": "winreg"}) + b"\n",                # no Record: dropped
         b"{not json\n"])                                # bad line: skipped

    # --- plaso_shellitem: the three timestamp_desc variants -----------------
    _lib.write_fixture(
        "plaso_registry_shell_shellitem",
        {"artefacts": ["plaso_shellitem"], "host": "fallback-host",
         "adapter": "none", "input": "input.jsonl"},
        [j(_wrap(_SHELL_PER_USER)) + b"\n",
         j(_wrap(_SHELL_SYSTEM_ORIGIN)) + b"\n",
         j(_wrap(_SHELL_SPINDLE, image=_M57)) + b"\n",
         j(_wrap(_SHELL_MODIFY)) + b"\n",
         j(_wrap(_SHELL_READ)) + b"\n",
         j(_wrap(_SHELL_LONGNAME_ONLY)) + b"\n",
         j(_wrap(_SHELL_NAME_ONLY)) + b"\n",
         j(_wrap(_SHELL_NO_PREFIX)) + b"\n",
         # create wins when a desc matches BOTH create and modify (variant order)
         j(_wrap(dict(_SHELL_MODIFY, timestamp_desc="Creation Modification"))) + b"\n",
         j(_wrap(_SHELL_NOT_A_TIME)) + b"\n",            # no variant: dropped
         j(_wrap(_SHELL_LNK_INTRUDER)) + b"\n",          # a lnk row: dropped
         j(_wrap({"data_type": _SHELL_DT, "timestamp_desc": "Creation Time"})) + b"\n"])

    # --- l2t_lnk: target resolution + the rich native list ------------------
    _lib.write_fixture(
        "plaso_registry_shell_lnk",
        {"artefacts": ["l2t_lnk"], "host": "fallback-host",
         "adapter": "none", "input": "input.jsonl"},
        [j(_wrap(_LNK_M57, image=_M57)) + b"\n",
         j(_wrap(_LNK_RECENT)) + b"\n",
         j(_wrap(_LNK_FULL)) + b"\n",
         j(_wrap(_LNK_NETWORK)) + b"\n",
         j(_wrap(_LNK_ESCAPED)) + b"\n",
         j(_wrap(_LNK_NO_TARGET)) + b"\n",
         j(_wrap(_LNK_NOT_A_TIME, image=_M57)) + b"\n",  # "Not a time": dropped
         j(_wrap(dict(_LNK_M57, timestamp_desc="Last Access Time"), image=_M57)) + b"\n",
         j(_wrap(_SHELL_PER_USER)) + b"\n"])             # a shell row: dropped

    # --- l2t_recyclebin: the deletion event + the SID uid -------------------
    _lib.write_fixture(
        "plaso_registry_shell_recyclebin",
        {"artefacts": ["l2t_recyclebin"], "host": "fallback-host",
         "adapter": "none", "input": "input.jsonl"},
        [j(_wrap(_RB_SID)) + b"\n",
         j(_wrap(_RB_SID_LOWER)) + b"\n",
         j(_wrap(_RB_M57, image=_M57)) + b"\n",
         j(_wrap(_RB_FULL)) + b"\n",
         j(_wrap(_RB_NO_SID)) + b"\n",
         j(_wrap(_RB_NOT_DELETION, image=_M57)) + b"\n",  # dropped
         j(_wrap(_LNK_M57, image=_M57)) + b"\n"])         # a lnk row: dropped

    # --- routes: the fan-out the pipeline actually runs ---------------------
    # .L2tWinreg → [plaso_exec_winreg, plaso_registry, plaso_shellitem] and
    # .L2tLnk → [l2t_lnk, plaso_shellitem]: one record may legitimately emit
    # through more than one map, in artefact order.
    _lib.write_fixture(
        "plaso_registry_shell_routes",
        {"artefacts": ["plaso_registry", "plaso_shellitem", "l2t_lnk",
                       "l2t_recyclebin"],
         "host": "fallback-host", "adapter": "none", "input": "input.jsonl"},
        [j(_wrap(_REG_PER_USER_HIVE)) + b"\n",
         j(_wrap(_SHELL_PER_USER)) + b"\n",
         j(_wrap(_LNK_RECENT)) + b"\n",
         j(_wrap(_RB_SID)) + b"\n",
         # a row whose data_type is registry AND whose desc is a create time:
         # only plaso_registry claims it (the shell gate is data_type-strict)
         j(_wrap(dict(_REG_BAGMRU, timestamp_desc="Creation Time"))) + b"\n",
         j(_wrap(_REG_SHELL_INTRUDER)) + b"\n",          # shell only
         j(_wrap(_LNK_NOT_A_TIME, image=_M57)) + b"\n"])  # claimed by nobody
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

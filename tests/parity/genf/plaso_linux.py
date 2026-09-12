"""Parity vectors + fixtures for the `plaso_linux` family
(byakugan/mappings/plaso_linux.py — the Plaso filesystem MACB maps
l2t_filestat / l2t_mft / l2t_usnjrnl and the Linux session maps
l2t_utmp / l2t_utmpx / l2t_text, with their nine variant gates).

Every gate reads the WRAPPED l2t row (``{SourceImage, RecordId, Parser,
Record, Timestamp}`` — what ``adapters/l2t_split._l2t_row`` emits) through
``_record(rec)``, an ISINSTANCE gate (a truthy non-dict ``Record`` yields the
empty dict, it does not raise), so the cases below drive absent / non-dict /
empty Record shapes as well as every value edge of the three readers:

    _td         str(... or "")        — `or ""`, so 0/False/None/"" all give ""
    _usn_flags  int(... or 0)         — TypeError/ValueError caught → 0
    _login_type int(...)              — NO `or`, so absent/None → None, not 0

    python tests/parity/genf/plaso_linux.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/plaso_linux.json
    go/internal/markers/testdata/marker_vectors/plaso_linux.json
    tests/parity/fixtures/plaso_linux_filestat/
    tests/parity/fixtures/plaso_linux_mft/
    tests/parity/fixtures/plaso_linux_usnjrnl/
    tests/parity/fixtures/plaso_linux_utmp/
    tests/parity/fixtures/plaso_linux_utmpx/
    tests/parity/fixtures/plaso_linux_text/
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

from byakugan.normalize import (basename, ext, first, host_label,  # noqa: E402
                                lower, payload, regex1)

FAMILY = "plaso_linux"


def _w(rec, **row):
    """One wrapped l2t row carrying `rec` as its plaso Record."""
    return dict(row, Record=rec)


# ---------------------------------------------------------------------------
# predicate vectors — plaso_linux.py's nine gates
# ---------------------------------------------------------------------------
PREDICATE_CASES = [
    # --- l2t_td_create: (?i)creation|crtime|birth ---------------------------
    ("l2t_td_create", _w({"timestamp_desc": "Creation Time"})),
    ("l2t_td_create", _w({"timestamp_desc": "creation time"})),
    ("l2t_td_create", _w({"timestamp_desc": "CRTIME"})),
    ("l2t_td_create", _w({"timestamp_desc": "crtime"})),
    ("l2t_td_create", _w({"timestamp_desc": "Birth Time"})),
    ("l2t_td_create", _w({"timestamp_desc": "Content Modification Time"})),
    ("l2t_td_create", _w({"timestamp_desc": "Metadata Modification Time"})),
    ("l2t_td_create", _w({"timestamp_desc": "Backup Time"})),
    ("l2t_td_create", _w({"timestamp_desc": ""})),
    ("l2t_td_create", _w({"timestamp_desc": None})),
    ("l2t_td_create", _w({"timestamp_desc": "-"})),        # not blank for a gate
    ("l2t_td_create", _w({"timestamp_desc": 0})),          # `or ""` → ""
    ("l2t_td_create", _w({"timestamp_desc": False})),
    ("l2t_td_create", _w({"timestamp_desc": True})),       # str(True) = "True"
    ("l2t_td_create", _w({"timestamp_desc": 17})),         # str(17) = "17"
    ("l2t_td_create", _w({"timestamp_desc": ["Creation Time"]})),  # str(list)
    # CPython's re (?i) folds U+0131 'ı' and U+0130 'İ' onto ASCII 'i';
    # Go's SimpleFold orbits do not, so the port pre-folds them (the ONLY
    # (?i) difference these all-ASCII patterns can reach — 'ſ'/'s' agree).
    ("l2t_td_create", _w({"timestamp_desc": "Creatıon Time"})),
    ("l2t_td_create", _w({"timestamp_desc": "CREATİON TIME"})),
    ("l2t_td_create", _w({"timestamp_desc": "BİRTH"})),
    ("l2t_td_create", _w({"timestamp_desc": "bırth"})),
    ("l2t_td_create", _w({})),                             # key absent
    ("l2t_td_create", {}),                                 # Record absent
    ("l2t_td_create", {"Record": None}),
    ("l2t_td_create", {"Record": "Creation Time"}),        # truthy non-dict → {}
    ("l2t_td_create", {"Record": ["Creation Time"]}),
    ("l2t_td_create", {"Record": 5}),
    # --- l2t_td_modify: (?i)modification|mtime ------------------------------
    ("l2t_td_modify", _w({"timestamp_desc": "Content Modification Time"})),
    ("l2t_td_modify", _w({"timestamp_desc": "Metadata Modification Time"})),
    ("l2t_td_modify", _w({"timestamp_desc": "mtime"})),
    ("l2t_td_modify", _w({"timestamp_desc": "MTIME"})),
    ("l2t_td_modify", _w({"timestamp_desc": "mtıme"})),            # dotless ı
    ("l2t_td_modify", _w({"timestamp_desc": "MODİFİCATİON TİME"})),
    ("l2t_td_modify", _w({"timestamp_desc": "mtiıme"})),           # no run of 5
    ("l2t_td_modify", _w({"timestamp_desc": "Creation Time"})),
    ("l2t_td_modify", _w({"timestamp_desc": "Last Access Time"})),
    ("l2t_td_modify", _w({})),
    ("l2t_td_modify", {}),
    # --- l2t_td_read: (?i)last access|atime ---------------------------------
    ("l2t_td_read", _w({"timestamp_desc": "Last Access Time"})),
    ("l2t_td_read", _w({"timestamp_desc": "LAST ACCESS TIME"})),
    ("l2t_td_read", _w({"timestamp_desc": "atime"})),
    ("l2t_td_read", _w({"timestamp_desc": "atıme"})),
    ("l2t_td_read", _w({"timestamp_desc": "ATİME"})),
    ("l2t_td_read", _w({"timestamp_desc": "laſt access"})),  # ſ folds to s in BOTH
    ("l2t_td_read", _w({"timestamp_desc": "Last  Access Time"})),  # two spaces: no
    ("l2t_td_read", _w({"timestamp_desc": "Creation Time"})),
    ("l2t_td_read", _w({})),
    # --- l2t_td_delete: (?i)deletion|deleted --------------------------------
    ("l2t_td_delete", _w({"timestamp_desc": "Deletion Time"})),
    ("l2t_td_delete", _w({"timestamp_desc": "File Deleted"})),
    ("l2t_td_delete", _w({"timestamp_desc": "DELETED"})),
    ("l2t_td_delete", _w({"timestamp_desc": "deletıon"})),
    ("l2t_td_delete", _w({"timestamp_desc": "DELETİON"})),
    ("l2t_td_delete", _w({"timestamp_desc": "Delete Time"})),      # neither alt
    ("l2t_td_delete", _w({"timestamp_desc": "Creation Time"})),
    ("l2t_td_delete", _w({})),
    # --- l2t_usn_create: flags & 0x100 --------------------------------------
    ("l2t_usn_create", _w({"update_reason_flags": 2147484416})),   # real row
    ("l2t_usn_create", _w({"update_reason_flags": 0x100})),
    ("l2t_usn_create", _w({"update_reason_flags": 0x200})),
    ("l2t_usn_create", _w({"update_reason_flags": 0x300})),        # create wins
    ("l2t_usn_create", _w({"update_reason_flags": 0x80008000})),
    ("l2t_usn_create", _w({"update_reason_flags": 0})),
    ("l2t_usn_create", _w({"update_reason_flags": None})),
    ("l2t_usn_create", _w({"update_reason_flags": ""})),
    ("l2t_usn_create", _w({"update_reason_flags": "-"})),          # ValueError → 0
    ("l2t_usn_create", _w({"update_reason_flags": "256"})),        # decimal str
    ("l2t_usn_create", _w({"update_reason_flags": "  256  "})),    # int() strips
    ("l2t_usn_create", _w({"update_reason_flags": "0x100"})),      # base 10 → 0
    ("l2t_usn_create", _w({"update_reason_flags": 256.9})),        # int() truncates
    ("l2t_usn_create", _w({"update_reason_flags": 255.9})),
    ("l2t_usn_create", _w({"update_reason_flags": True})),         # bool is int
    ("l2t_usn_create", _w({"update_reason_flags": False})),
    ("l2t_usn_create", _w({"update_reason_flags": -1})),           # two's complement
    ("l2t_usn_create", _w({"update_reason_flags": -256})),
    ("l2t_usn_create", _w({"update_reason_flags": [256]})),        # TypeError → 0
    ("l2t_usn_create", _w({"update_reason_flags": {"a": 1}})),
    ("l2t_usn_create", _w({"update_reason_flags": 1e30})),
    ("l2t_usn_create", _w({})),
    ("l2t_usn_create", {}),
    ("l2t_usn_create", {"Record": "0x100"}),
    # --- l2t_usn_delete: flags & 0x200 --------------------------------------
    ("l2t_usn_delete", _w({"update_reason_flags": 0x200})),
    ("l2t_usn_delete", _w({"update_reason_flags": 2147484416})),   # CREATE|DELETE
    ("l2t_usn_delete", _w({"update_reason_flags": 0x100})),
    ("l2t_usn_delete", _w({"update_reason_flags": 0x80008000})),
    ("l2t_usn_delete", _w({"update_reason_flags": "512"})),
    ("l2t_usn_delete", _w({"update_reason_flags": -1})),
    ("l2t_usn_delete", _w({})),
    ("l2t_usn_delete", {}),
    # --- l2t_utmp_login: login_type in (6, 7) -------------------------------
    ("l2t_utmp_login", _w({"login_type": 7})),             # USER_PROCESS
    ("l2t_utmp_login", _w({"login_type": 6})),             # LOGIN_PROCESS
    ("l2t_utmp_login", _w({"login_type": 8})),             # DEAD_PROCESS
    ("l2t_utmp_login", _w({"login_type": 0})),             # EMPTY
    ("l2t_utmp_login", _w({"login_type": 1})),             # RUN_LVL
    ("l2t_utmp_login", _w({"login_type": 2})),             # BOOT_TIME
    ("l2t_utmp_login", _w({"login_type": 5})),             # INIT_PROCESS
    ("l2t_utmp_login", _w({"login_type": "7"})),           # decimal str
    ("l2t_utmp_login", _w({"login_type": " 7 "})),
    ("l2t_utmp_login", _w({"login_type": "7.5"})),         # ValueError → None
    ("l2t_utmp_login", _w({"login_type": "seven"})),
    ("l2t_utmp_login", _w({"login_type": 7.9})),           # float truncates
    ("l2t_utmp_login", _w({"login_type": 6.0})),
    ("l2t_utmp_login", _w({"login_type": True})),          # int(True) = 1
    ("l2t_utmp_login", _w({"login_type": None})),          # TypeError → None
    ("l2t_utmp_login", _w({"login_type": ""})),            # ValueError → None
    ("l2t_utmp_login", _w({"login_type": 0.0})),           # NOT `or 0`: int(0.0)=0
    ("l2t_utmp_login", _w({"login_type": [7]})),           # TypeError → None
    ("l2t_utmp_login", _w({})),
    ("l2t_utmp_login", {}),
    ("l2t_utmp_login", {"Record": 7}),                     # non-dict Record
    # --- l2t_utmp_logout: login_type == 8 -----------------------------------
    ("l2t_utmp_logout", _w({"login_type": 8})),
    ("l2t_utmp_logout", _w({"login_type": "8"})),
    ("l2t_utmp_logout", _w({"login_type": 8.7})),
    ("l2t_utmp_logout", _w({"login_type": 7})),
    ("l2t_utmp_logout", _w({"login_type": None})),
    ("l2t_utmp_logout", _w({})),
    ("l2t_utmp_logout", {}),
    # --- l2t_text_ssh_login: data_type == "syslog:ssh:login" ----------------
    ("l2t_text_ssh_login", _w({"data_type": "syslog:ssh:login"})),
    ("l2t_text_ssh_login", _w({"data_type": "syslog:line"})),
    ("l2t_text_ssh_login", _w({"data_type": "SYSLOG:SSH:LOGIN"})),  # case matters
    ("l2t_text_ssh_login", _w({"data_type": " syslog:ssh:login"})),  # no strip
    ("l2t_text_ssh_login", _w({"data_type": None})),
    ("l2t_text_ssh_login", _w({"data_type": ""})),
    ("l2t_text_ssh_login", _w({"data_type": 0})),
    ("l2t_text_ssh_login", _w({"data_type": ["syslog:ssh:login"]})),
    ("l2t_text_ssh_login", _w({})),
    ("l2t_text_ssh_login", {}),
    ("l2t_text_ssh_login", {"Record": "syslog:ssh:login"}),
]

# ---------------------------------------------------------------------------
# marker vectors — the family's own composed specs. core.json covers the 24
# kinds engine-wide; what it does NOT cover is this family's regex1 shapes:
# the "TYPE:"-prefix strip and, above all, the _SRC_IP DENY pattern
# (\A(?!(?:...)\Z)(.+)\Z — the pyre negative-lookahead translation).
# ---------------------------------------------------------------------------
_r = lambda key: payload(key, "Record")  # noqa: E731 — mappings._common.R

_FN_DN_PATH = first(_r("filename"),
                    regex1(_r("display_name"), r"\A[A-Z0-9]+:(.*)\Z"),
                    _r("display_name"))
_MFT_PATH = first(_r("name"), _r("filename"))
_SRC_IP = regex1(_r("ip_address"),
                 r"\A(?!(?:0\.0\.0\.0|127\.0\.0\.1|::1)\Z)(.+)\Z")

RESOLVE_CASES = [
    # --- _FN_DN_PATH: filename, else the display_name with its TYPE: prefix --
    (_FN_DN_PATH, _w({"filename": "\\Program Files\\app\\FPEXT.MSG",
                      "display_name": "NTFS:\\Program Files\\app\\FPEXT.MSG"})),
    (_FN_DN_PATH, _w({"filename": "",
                      "display_name": "GZIP:\\.fseventsd\\fc007712b62e1122"})),
    (_FN_DN_PATH, _w({"filename": "-", "display_name": "OS:/var/log/syslog"})),
    (_FN_DN_PATH, _w({"display_name": "TSK:/$MFT"})),
    (_FN_DN_PATH, _w({"display_name": "/plain/path"})),       # no prefix → as-is
    (_FN_DN_PATH, _w({"display_name": "ntfs:\\x"})),          # [A-Z0-9]+ is upper
    (_FN_DN_PATH, _w({"display_name": "NTFS:"})),             # group 1 "" → blank
    (_FN_DN_PATH, _w({"display_name": "OS:/y"})),
    (_FN_DN_PATH, _w({"display_name": "A1:tail"})),           # digits in the prefix
    (_FN_DN_PATH, _w({"display_name": "NTFS:a\nb"})),         # '.' does not span \n
    (_FN_DN_PATH, _w({})),
    (_FN_DN_PATH, {}),
    # --- ext / basename over the same path ----------------------------------
    (ext(_FN_DN_PATH), _w({"filename": "\\Program Files\\app\\FPEXT.MSG"})),
    (ext(_FN_DN_PATH), _w({"filename": "a15f3474-ab93-46b9-8834-124287ab1646.tmp"})),
    (ext(_FN_DN_PATH), _w({"filename": "/etc/hostname"})),
    (ext(_FN_DN_PATH), _w({})),
    (basename(_FN_DN_PATH), _w({"filename": "\\Program Files\\app\\FPEXT.MSG"})),
    (basename(_FN_DN_PATH), _w({"filename": "", "display_name":
                                "GZIP:\\.fseventsd\\fc007712b62e1122"})),
    (basename(_FN_DN_PATH), _w({"filename": "/var/log/syslog"})),
    (basename(_FN_DN_PATH), _w({})),
    # --- _MFT_PATH: the described file, name before filename ----------------
    (_MFT_PATH, _w({"name": "notes.txt", "filename": "\\$MFT"})),
    (_MFT_PATH, _w({"name": "", "filename": "\\$MFT"})),
    (_MFT_PATH, _w({"name": "-", "filename": "\\$MFT"})),
    (_MFT_PATH, _w({"filename": "\\$MFT"})),
    (_MFT_PATH, _w({})),
    # --- _SRC_IP: the loopback/unset DENY list (negative lookahead) ---------
    (_SRC_IP, _w({"ip_address": "10.0.0.9"})),
    (_SRC_IP, _w({"ip_address": "156.59.33.60"})),
    (_SRC_IP, _w({"ip_address": "0.0.0.0"})),                 # denied
    (_SRC_IP, _w({"ip_address": "127.0.0.1"})),               # denied
    (_SRC_IP, _w({"ip_address": "::1"})),                     # denied
    (_SRC_IP, _w({"ip_address": "0.0.0.0.1"})),               # not the full string
    (_SRC_IP, _w({"ip_address": "127.0.0.10"})),
    (_SRC_IP, _w({"ip_address": "::11"})),
    (_SRC_IP, _w({"ip_address": "x0.0.0.0"})),                # \A anchors the deny
    (_SRC_IP, _w({"ip_address": "0.0.0.0 "})),                # trailing space
    (_SRC_IP, _w({"ip_address": "1.2.3.4\n"})),               # \Z is a hard end
    (_SRC_IP, _w({"ip_address": "0.0.0.0\n"})),
    (_SRC_IP, _w({"ip_address": "::ffff:10.0.0.9"})),
    (_SRC_IP, _w({"ip_address": ""})),
    (_SRC_IP, _w({"ip_address": "-"})),
    (_SRC_IP, _w({"ip_address": None})),
    (_SRC_IP, _w({"ip_address": 5})),                         # int → str() first
    (_SRC_IP, _w({})),
    (_SRC_IP, {}),
    # --- lower(): the filestat hashes canonicalized to one format -----------
    (lower(_r("sha256_hash")), _w({"sha256_hash": "B64170B5"})),
    (lower(_r("md5_hash")), _w({"md5_hash": "-"})),
    (lower(_r("md5_hash")), _w({})),
    # --- host_label(): the imaged host, and the utmp/ssh blank that makes
    #     pipeline's --host fallback fill source_host -------------------------
    (host_label(_r("image_hostname")), _w({"image_hostname": "M57-JO"})),
    (host_label(_r("image_hostname")), _w({"image_hostname": "m57-jo.local.dom"})),
    (host_label(_r("image_hostname")), _w({"image_hostname": ""})),
    (host_label(_r("image_hostname")), _w({"image_hostname": "-"})),
    (host_label(_r("image_hostname")), _w({})),
    # --- the bare payload reads the props use (0 is a real uid, not a blank) -
    (_r("mode"), _w({"mode": 420})),
    (_r("owner_identifier"), _w({"owner_identifier": 0})),
    (_r("group_identifier"), _w({"group_identifier": "0"})),
    (_r("username"), _w({"username": "-"})),
    (_r("username"), _w({"username": "  logserv  "})),        # payload strips
    (_r("is_allocated"), _w({"is_allocated": False})),        # False is not blank
    (_r("path_hints"), _w({"path_hints": ["\\Users\\jo\\notes.txt"]})),
    (_r("file_reference"), _w({"file_reference": 281474976727294})),
    (_r("port"), _w({"port": "54544"})),
    (_r("pid"), _w({"pid": 3401})),
    (_r("anything"), {"Record": "not a dict"}),               # flat-dict gate
    (_r("anything"), {"Record": ["not a dict"]}),
]

# ---------------------------------------------------------------------------
# fixtures — the inline record dicts of tests/test_car_plaso_linux.py verbatim,
# wrapped exactly as adapters/l2t_split._l2t_row emits them
# ({SourceImage, RecordId, Parser, Record, Timestamp}), plus the edge shapes
# the module docstring calls out.
# ---------------------------------------------------------------------------
j = _lib.j


def _wrap(parser, rec, ts="2020-09-16T13:14:30.462820Z",
          source="dualserver_logs.jsonl", record_id=None):
    """The wrapped l2t row: _l2t_row's key order, the unit test's `parser`
    stamp inside Record. `ts=None` is the zero/unset-timestamp row split_l2t
    leaves Timestamp off entirely."""
    row = {"SourceImage": source}
    if record_id is not None:
        row["RecordId"] = record_id
    row["Parser"] = parser
    row["Record"] = dict(rec, parser=parser)
    if ts:
        row["Timestamp"] = ts
    return row


# ---- CarFile_Plaso: filestat (tests/test_car_plaso_linux.py::_FILESTAT) -----
_FILESTAT = {
    "data_type": "fs:stat",
    "display_name": "NTFS:\\Program Files\\app\\FPEXT.MSG",
    "filename": "\\Program Files\\app\\FPEXT.MSG",
    "file_entry_type": "file", "file_size": 78706,
    "file_system_type": "NTFS", "image_hostname": "M57-JO",
    "is_allocated": True, "inode": "281474976721211",
    "sha256_hash": "b64170b533469d8fe289f295d7a644bfd6f24949800b3be05e928b0da1"
                   "3289b6",
    "timestamp_desc": "Content Modification Time", "username": "-",
}

# ---- CarFile_Plaso: usnjrnl (::_USN) ----------------------------------------
_USN = {
    "data_type": "fs:ntfs:usn_change",
    "display_name": "NTFS:\\$Extend\\$UsnJrnl:$J",
    "filename": "a15f3474-ab93-46b9-8834-124287ab1646.tmp",
    "image_hostname": "M57-JO", "file_reference": 281474976727294,
    "parent_file_reference": 281474976725861,
    "timestamp_desc": "Metadata Modification Time",
    "update_reason_flags": 2147484416,     # CREATE|DELETE|CLOSE (real row)
    "update_source_flags": 0, "update_sequence_number": 1048576,
    "username": "-",
    "sha256_hash": "not-the-described-files-hash",
}

# ---- CarFile_Plaso: mft (::_MFT — synthetic, per the plaso mft parser) ------
_MFT = {
    "data_type": "fs:stat:ntfs",
    "display_name": "NTFS:\\$MFT", "filename": "\\$MFT",
    "name": "notes.txt", "path_hints": ["\\Users\\jo\\notes.txt"],
    "file_reference": 843, "parent_file_reference": 29,
    "image_hostname": "M57-JO", "is_allocated": True,
    "timestamp_desc": "Creation Time", "username": "-",
}

# ---- CarUserSession_Utmp (::_UTMP — real dualserver wtmp row) ---------------
_UTMP = {
    "data_type": "linux:utmp:event", "exit_status": 0,
    "hostname": "localhost", "image_hostname": "", "ip_address": "0.0.0.0",
    "login_type": 7, "pid": 3401, "terminal": "tty7",
    "terminal_identifier": 12346, "timestamp_desc": "Content Modification Time",
    "username": "logserv",
}

# ---- CarUserSession_Ssh (::_SSH — real dualserver syslog row) ---------------
_SSH = {
    "data_type": "syslog:ssh:login", "authentication_method": "password",
    "hostname": "pits-insec", "image_hostname": "",
    "ip_address": "156.59.33.60", "pid": 3756, "port": "54544",
    "protocol": "ssh2", "reporter": "sshd",
    "timestamp_desc": "Content Modification Time", "username": "insec",
}

# ---- the plain syslog row that must stay raw (::test_other_text_rows_stay_raw)
_SYSLOG_PLAIN = {"data_type": "syslog:line", "hostname": "pits-gatsby",
                 "image_hostname": "", "reporter": "kernel", "username": "-"}


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)
    _lib.write_marker_vectors(FAMILY, resolve=RESOLVE_CASES)

    # --- l2t_filestat: the MACB variant order + the hash/POSIX blocks --------
    _lib.write_fixture(
        "plaso_linux_filestat",
        {"artefacts": ["l2t_filestat"], "host": "vantage1",
         "adapter": "none", "input": "input.jsonl"},
        [j(_wrap("filestat", _FILESTAT, source="M57-JO.jsonl", record_id=1)) + b"\n",
         # create is tested BEFORE modify, so creation_time is asserted only here
         j(_wrap("filestat", dict(_FILESTAT, timestamp_desc="Creation Time"),
                 record_id=2)) + b"\n",
         j(_wrap("filestat", dict(_FILESTAT, timestamp_desc="Last Access Time"),
                 record_id=3)) + b"\n",
         j(_wrap("filestat", dict(_FILESTAT, timestamp_desc="Deletion Time"),
                 record_id=4)) + b"\n",
         # 'Backup Time' matches no variant → the row stays raw (dropped)
         j(_wrap("filestat", dict(_FILESTAT, timestamp_desc="Backup Time"),
                 record_id=5)) + b"\n",
         # a description matching BOTH create and modify resolves to create
         j(_wrap("filestat", dict(_FILESTAT, timestamp_desc="crtime/mtime"),
                 record_id=6)) + b"\n",
         j(_wrap("filestat", dict(_FILESTAT, timestamp_desc="Metadata Modification Time"),
                 record_id=7)) + b"\n",
         # filename empty → display_name with its "GZIP:" prefix stripped
         j(_wrap("filestat", dict(_FILESTAT, filename="",
                                  display_name="GZIP:\\.fseventsd\\fc007712b62e1122"),
                 record_id=8)) + b"\n",
         # a display_name with no TYPE: prefix passes through unchanged
         j(_wrap("filestat", dict(_FILESTAT, filename="-",
                                  display_name="/var/log/syslog"), record_id=9)) + b"\n",
         # hashing was ON: the file's OWN hashes, canonicalized to lowercase
         j(_wrap("filestat", dict(_FILESTAT, timestamp_desc="Creation Time",
                                  md5_hash="9E107D9D372BB6826BD81D3542A419D6",
                                  sha1_hash="2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"),
                 record_id=10)) + b"\n",
         # the POSIX stat block: 0 (root) is a real id, never a blank
         j(_wrap("filestat", dict(_FILESTAT, mode=420, owner_identifier=0,
                                  group_identifier=0, number_of_links=2,
                                  disk_id="d1", volume_id="p1", volume_offset=1048576),
                 record_id=11)) + b"\n",
         # Plaso stamps timestamp 0 on unset MACB values → no wrapped Timestamp
         j(_wrap("filestat", _FILESTAT, ts=None, record_id=12)) + b"\n",
         # 1601-01-01 is _clean_ts's epoch-zero sentinel → timestamp null
         j(_wrap("filestat", _FILESTAT, ts="1601-01-01T00:00:00.000000Z",
                 record_id=13)) + b"\n",
         # a blank file_path (no filename, no display_name) still normalizes
         j(_wrap("filestat", {k: v for k, v in _FILESTAT.items()
                              if k not in ("filename", "display_name")},
                 record_id=14)) + b"\n",
         # a blank image_hostname → source_host falls back to the manifest host
         j(_wrap("filestat", dict(_FILESTAT, image_hostname="", username="root"),
                 record_id=15)) + b"\n"])

    # --- l2t_mft: the described file, not the $MFT artefact ------------------
    _lib.write_fixture(
        "plaso_linux_mft",
        {"artefacts": ["l2t_mft"], "host": "vantage1",
         "adapter": "none", "input": "input.jsonl"},
        [j(_wrap("mft", _MFT, record_id=1)) + b"\n",
         j(_wrap("mft", dict(_MFT, timestamp_desc="Content Modification Time"),
                 record_id=2)) + b"\n",
         j(_wrap("mft", dict(_MFT, timestamp_desc="Last Access Time"),
                 record_id=3)) + b"\n",
         j(_wrap("mft", dict(_MFT, timestamp_desc="Deletion Time"), record_id=4)) + b"\n",
         # $FN vs $SI rows of the same entry: same file_reference, same action,
         # different event time — the identity's event_time component separates them
         j(_wrap("mft", _MFT, ts="2020-09-16T13:14:31.000000Z", record_id=5)) + b"\n",
         # no `name` → the KQL's next-preferred source, Record.filename
         j(_wrap("mft", {k: v for k, v in _MFT.items() if k != "name"},
                 record_id=6)) + b"\n",
         j(_wrap("mft", dict(_MFT, name="-"), record_id=7)) + b"\n",
         # no file_reference → the identity component is blank → positional
         j(_wrap("mft", {k: v for k, v in _MFT.items() if k != "file_reference"},
                 record_id=8)) + b"\n",
         # 'Backup Time' has no canonical file action → dropped
         j(_wrap("mft", dict(_MFT, timestamp_desc="Backup Time"), record_id=9)) + b"\n"])

    # --- l2t_usnjrnl: the reason-flag precedence order ----------------------
    _lib.write_fixture(
        "plaso_linux_usnjrnl",
        {"artefacts": ["l2t_usnjrnl"], "host": "vantage1",
         "adapter": "none", "input": "input.jsonl"},
        [j(_wrap("usnjrnl", _USN, record_id=1)) + b"\n",              # 0x100 beats 0x200
         j(_wrap("usnjrnl", dict(_USN, update_reason_flags=0x200,
                                 update_sequence_number=1048584), record_id=2)) + b"\n",
         j(_wrap("usnjrnl", dict(_USN, update_reason_flags=0x80008000,
                                 update_sequence_number=1048592), record_id=3)) + b"\n",
         j(_wrap("usnjrnl", dict(_USN, update_reason_flags=0x100,
                                 update_sequence_number=1048600), record_id=4)) + b"\n",
         j(_wrap("usnjrnl", dict(_USN, update_reason_flags=0x300,
                                 update_sequence_number=1048608), record_id=5)) + b"\n",
         # 0 / absent / unparseable flags all fall through to the default modify
         j(_wrap("usnjrnl", dict(_USN, update_reason_flags=0,
                                 update_sequence_number=1048616), record_id=6)) + b"\n",
         j(_wrap("usnjrnl", {k: v for k, v in _USN.items()
                             if k != "update_reason_flags"}, record_id=7)) + b"\n",
         j(_wrap("usnjrnl", dict(_USN, update_reason_flags="0x100",
                                 update_sequence_number=1048624), record_id=8)) + b"\n",
         # a DECIMAL string does parse (int(s) is base 10)
         j(_wrap("usnjrnl", dict(_USN, update_reason_flags="256",
                                 update_sequence_number=1048632), record_id=9)) + b"\n",
         # no usn/file_reference → both identity components blank → positional
         j(_wrap("usnjrnl", {k: v for k, v in _USN.items()
                             if k not in ("update_sequence_number", "file_reference")},
                 record_id=10)) + b"\n",
         # the $UsnJrnl:$J display_name is the artefact's, the filename the file's
         j(_wrap("usnjrnl", dict(_USN, filename="",
                                 update_sequence_number=1048640), record_id=11)) + b"\n",
         j(_wrap("usnjrnl", dict(_USN, offset=8192, disk_id="d1", volume_id="p1",
                                 volume_offset=1048576,
                                 file_attribute_flags=32,
                                 update_sequence_number=1048648), record_id=12)) + b"\n"])

    # --- l2t_utmp: the login_type vocabulary + the _SRC_IP deny pattern ------
    utmp_lines = [
        j(_wrap("utmp", _UTMP, record_id=1)) + b"\n",                   # 7 → login
        j(_wrap("utmp", dict(_UTMP, login_type=6, pid=3402,
                             terminal="tty1"), record_id=2)) + b"\n",   # 6 → login
        j(_wrap("utmp", dict(_UTMP, login_type=8, ip_address="10.0.0.9",
                             pid=3403), record_id=3)) + b"\n",          # 8 → logout
        # BOOT_TIME/INIT_PROCESS/EMPTY/RUN_LVL are not user sessions → dropped
        j(_wrap("utmp", dict(_UTMP, login_type=0), record_id=4)) + b"\n",
        j(_wrap("utmp", dict(_UTMP, login_type=1), record_id=5)) + b"\n",
        j(_wrap("utmp", dict(_UTMP, login_type=2), record_id=6)) + b"\n",
        j(_wrap("utmp", dict(_UTMP, login_type=5), record_id=7)) + b"\n",
        # the _SRC_IP deny list: loopback/unset never becomes src_ip
        j(_wrap("utmp", dict(_UTMP, ip_address="127.0.0.1", pid=3404),
                record_id=8)) + b"\n",
        j(_wrap("utmp", dict(_UTMP, ip_address="::1", pid=3405), record_id=9)) + b"\n",
        j(_wrap("utmp", dict(_UTMP, ip_address="127.0.0.10", pid=3406),
                record_id=10)) + b"\n",   # NOT the denied string
        j(_wrap("utmp", dict(_UTMP, ip_address="0.0.0.0.1", pid=3407),
                record_id=11)) + b"\n",
        j(_wrap("utmp", dict(_UTMP, ip_address="", pid=3408), record_id=12)) + b"\n",
        j(_wrap("utmp", dict(_UTMP, ip_address="-", pid=3409), record_id=13)) + b"\n",
        # a string login_type still parses through int()
        j(_wrap("utmp", dict(_UTMP, login_type="7", pid=3410), record_id=14)) + b"\n",
        # no pid → the identity's first component is blank → positional fallback
        j(_wrap("utmp", {k: v for k, v in _UTMP.items() if k != "pid"},
                record_id=15)) + b"\n",
        # a real imaged host: source_host comes from the map, not --host
        j(_wrap("utmp", dict(_UTMP, image_hostname="dualserver.corp.lan",
                             pid=3411), record_id=16)) + b"\n",
        # the wrapped shape-lock row (::test_wrapped_shape_matches_prepare_l2t_row)
        j(_wrap("utmp", dict(_UTMP, timestamp=1600262099805465),
                ts="2020-09-16T13:14:59.805465Z", record_id=17)) + b"\n",
    ]
    _lib.write_fixture(
        "plaso_linux_utmp",
        {"artefacts": ["l2t_utmp"], "host": "dualserver",
         "adapter": "none", "input": "input.jsonl"}, utmp_lines)

    # --- l2t_utmpx: the same typed rows through the utmpx registry entry -----
    _lib.write_fixture(
        "plaso_linux_utmpx",
        {"artefacts": ["l2t_utmpx"], "host": "dualserver",
         "adapter": "none", "input": "input.jsonl"},
        [j(_wrap("utmpx", _UTMP, record_id=1)) + b"\n",
         j(_wrap("utmpx", dict(_UTMP, login_type=8, ip_address="10.0.0.9"),
                 record_id=2)) + b"\n",
         j(_wrap("utmpx", dict(_UTMP, login_type=2), record_id=3)) + b"\n"])

    # --- l2t_text: only a typed sshd login has user_session semantics --------
    _lib.write_fixture(
        "plaso_linux_text",
        {"artefacts": ["l2t_text"], "host": "dualserver",
         "adapter": "none", "input": "input.jsonl"},
        [j(_wrap("text/syslog_traditional", _SSH, record_id=1)) + b"\n",
         j(_wrap("text/syslog_traditional", dict(_SSH, ip_address="127.0.0.1",
                                                 pid=3757), record_id=2)) + b"\n",
         j(_wrap("text/syslog_traditional", dict(_SSH, ip_address="::1",
                                                 pid=3758), record_id=3)) + b"\n",
         j(_wrap("text/syslog_traditional", dict(_SSH, ip_address="0.0.0.0",
                                                 pid=3759), record_id=4)) + b"\n",
         # publickey auth, a different reporter host, a numeric port
         j(_wrap("text/syslog_traditional",
                 dict(_SSH, authentication_method="publickey", port=22,
                      hostname="pits-gatsby", pid=3760, username="root"),
                 record_id=5)) + b"\n",
         # every other text/syslog row stays raw (dropped)
         j(_wrap("text/syslog_traditional", _SYSLOG_PLAIN, record_id=6)) + b"\n",
         j(_wrap("text/syslog_traditional", {"data_type": "syslog:cron:task_run",
                                             "image_hostname": "", "username": "root"},
                 record_id=7)) + b"\n",
         # no pid and no user → both intrinsic components blank → positional
         j(_wrap("text/syslog_traditional",
                 {k: v for k, v in _SSH.items() if k not in ("pid", "username")},
                 record_id=8)) + b"\n"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Parity vectors + fixtures for the `plaso_web_fs` family — the two Plaso
mapping modules that turn browser/download evidence and the leftover
filesystem/file parsers into CAR events:

    byakugan/mappings/plaso_web.py       l2t_msiecf, l2t_firefox_cache,
                                         l2t_firefox_places, l2t_javaidx
                                         (4 gates: plasoweb_is_*)
    byakugan/mappings/plaso_fs_extra.py  plaso_fseventsd, plaso_pecoff,
                                         plaso_olecf
                                         (6 gates: fse_*, pe_*, ole_*)

    python tests/parity/genf/plaso_web_fs.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/plaso_web_fs.json
    tests/parity/fixtures/plaso_web_fs_msiecf/
    tests/parity/fixtures/plaso_web_fs_firefox_cache/
    tests/parity/fixtures/plaso_web_fs_history/
    tests/parity/fixtures/plaso_web_fs_javaidx/
    tests/parity/fixtures/plaso_web_fs_fseventsd/
    tests/parity/fixtures/plaso_web_fs_pecoff/
    tests/parity/fixtures/plaso_web_fs_olecf/

No marker-vector file: every marker kind these two modules use (first, regex1,
host_label, payload/R, map_value, hex_int, basename, ext, lower) is already
covered engine-wide by marker_vectors/core.json.

NOT covered here on purpose: l2t_lnk / l2t_recyclebin. tests/test_car_plaso_web.py
carries fixtures for them, but both maps live in mappings/plaso_registry_shell.py
— another family's files.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "plaso_web_fs"

j = _lib.j


# ---------------------------------------------------------------------------
# predicate vectors
#
# Both modules gate on the WRAPPED row, but through DIFFERENT readers:
#   plaso_web:      _dt = str((rec.get("Record") or {}).get("data_type") or "")
#                   -> a non-str data_type is str()-coerced, a FALSY one is ""
#   plaso_fs_extra: _dt = _rec(rec).get("data_type") == "<literal>"
#                   -> raw equality, so a non-str data_type never matches
# Both edges are pinned below.
#
# A TRUTHY non-dict Record is deliberately absent: plaso_web's `(r or {})`
# raises AttributeError there (the live Python CRASHES), so there is no Python
# truth to record. A FALSY non-dict (0, "", []) is recorded — `or {}` and
# isinstance() agree on it.
# ---------------------------------------------------------------------------
def _w(record, **extra):
    """A wrapped l2t row as l2t_split emits it."""
    row = {"SourceImage": "log2timeline/jsonl/M57-JO.jsonl", "RecordId": 1,
           "Timestamp": "2009-11-20T19:13:29.625000Z",
           "Parser": record.get("parser", "x") if isinstance(record, dict) else "x",
           "Record": record}
    row.update(extra)
    return row


PREDICATE_CASES = [
    # --- plasoweb_is_ie_visit: data_type AND "Last Visited" in timestamp_desc
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:url",
                                 "timestamp_desc": "Last Visited Time"})),
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:url",
                                 "timestamp_desc": "Expiration Time"})),
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:url",
                                 "timestamp_desc": "Last Visited"})),   # exact
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:url",
                                 "timestamp_desc": "last visited time"})),  # case
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:leak",
                                 "timestamp_desc": "Last Visited Time"})),
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:url"})),           # td absent
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:url",
                                 "timestamp_desc": None})),              # or "" -> ""
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:url",
                                 "timestamp_desc": ""})),
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:url",
                                 "timestamp_desc": 0})),                 # falsy int
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:url",
                                 "timestamp_desc": False})),
    ("plasoweb_is_ie_visit", _w({"data_type": "msiecf:url",
                                 "timestamp_desc": ["Last Visited Time"]})),  # str(list)
    ("plasoweb_is_ie_visit", _w({})),                                    # no data_type
    ("plasoweb_is_ie_visit", {"SourceImage": "x"}),                      # no Record
    ("plasoweb_is_ie_visit", {"Record": None}),                          # None -> {}
    ("plasoweb_is_ie_visit", {"Record": {}}),
    ("plasoweb_is_ie_visit", {"Record": 0}),                             # falsy non-dict
    ("plasoweb_is_ie_visit", {"Record": ""}),
    ("plasoweb_is_ie_visit", {"Record": []}),
    # --- plasoweb_is_ff_cache
    ("plasoweb_is_ff_cache", _w({"data_type": "firefox:cache:record"})),
    ("plasoweb_is_ff_cache", _w({"data_type": "firefox:cache2:record"})),
    ("plasoweb_is_ff_cache", _w({"data_type": None})),
    ("plasoweb_is_ff_cache", _w({"data_type": 0})),                      # or "" -> ""
    ("plasoweb_is_ff_cache", _w({"data_type": 42})),                     # str() -> "42"
    ("plasoweb_is_ff_cache", _w({"data_type": 4.5})),
    ("plasoweb_is_ff_cache", _w({"data_type": True})),                   # str() -> "True"
    ("plasoweb_is_ff_cache", _w({"data_type": "-"})),
    # --- plasoweb_is_ff_visit: the three-element data_type set
    ("plasoweb_is_ff_visit", _w({"data_type": "firefox:places:page_visited"})),
    ("plasoweb_is_ff_visit", _w({"data_type": "chrome:history:page_visited"})),
    ("plasoweb_is_ff_visit", _w({"data_type": "chrome:history:file_downloaded"})),
    ("plasoweb_is_ff_visit", _w({"data_type": "firefox:places:bookmark_annotation"})),
    ("plasoweb_is_ff_visit", _w({"data_type": "chrome:history:page_visited "})),  # pad
    ("plasoweb_is_ff_visit", _w({"data_type": ""})),
    ("plasoweb_is_ff_visit", _w({})),
    # --- plasoweb_is_javaidx
    ("plasoweb_is_javaidx", _w({"data_type": "java:download:idx"})),
    ("plasoweb_is_javaidx", _w({"data_type": "java:download"})),
    ("plasoweb_is_javaidx", _w({})),

    # --- fse_is_record (plaso_fs_extra: RAW equality, no str() coercion) -----
    ("fse_is_record", _w({"data_type": "macos:fseventsd:record"})),
    ("fse_is_record", _w({"data_type": "macos:fseventsd:record "})),
    ("fse_is_record", _w({"data_type": "fs:stat"})),
    ("fse_is_record", _w({"data_type": None})),
    ("fse_is_record", _w({"data_type": 0})),
    ("fse_is_record", _w({})),
    ("fse_is_record", {"Record": None}),
    ("fse_is_record", {"Record": "macos:fseventsd:record"}),   # non-dict -> {}
    ("fse_is_record", {"Record": ["macos:fseventsd:record"]}),
    ("fse_is_record", {}),
    # --- pe_is_compile_stamp / pe_is_table_stamp / pe_is_file ---------------
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:file",
                                "timestamp_desc": "Creation Time"})),
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:file",
                                "timestamp_desc": "creation time"})),     # (?i)
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:file",
                                "timestamp_desc": "crtime"})),
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:file",
                                "timestamp_desc": "Birth Time"})),
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:file",
                                "timestamp_desc": "Content Modification Time"})),
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:file",
                                "timestamp_desc": "Not a time"})),
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:file"})),
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:file",
                                "timestamp_desc": None})),
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:file",
                                "timestamp_desc": 0})),
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:file",
                                "timestamp_desc": 17})),                  # str(int)
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:dll_import",
                                "timestamp_desc": "Creation Time"})),
    ("pe_is_compile_stamp", _w({"data_type": "pe_coff:resource",
                                "timestamp_desc": "Creation Time"})),
    ("pe_is_table_stamp", _w({"data_type": "pe_coff:file",
                              "timestamp_desc": "Content Modification Time"})),
    ("pe_is_table_stamp", _w({"data_type": "pe_coff:file",
                              "timestamp_desc": "mtime"})),
    ("pe_is_table_stamp", _w({"data_type": "pe_coff:file",
                              "timestamp_desc": "Last Written Time"})),
    ("pe_is_table_stamp", _w({"data_type": "pe_coff:file",
                              "timestamp_desc": "LAST WRITTEN"})),
    ("pe_is_table_stamp", _w({"data_type": "pe_coff:file",
                              "timestamp_desc": "Creation Time"})),
    ("pe_is_table_stamp", _w({"data_type": "pe_coff:file",
                              "timestamp_desc": "Content Creation Time"})),  # both
    ("pe_is_table_stamp", _w({"data_type": "pe_coff:file",
                              "timestamp_desc": "Not a time"})),
    ("pe_is_table_stamp", _w({"data_type": "pe_coff:dll_import",
                              "timestamp_desc": "Content Modification Time"})),
    ("pe_is_file", _w({"data_type": "pe_coff:file", "timestamp_desc": "Not a time"})),
    ("pe_is_file", _w({"data_type": "pe_coff:file"})),
    ("pe_is_file", _w({"data_type": "pe_coff:dll_import"})),
    ("pe_is_file", _w({"data_type": "pe_coff:resource"})),
    ("pe_is_file", _w({"data_type": None})),
    ("pe_is_file", {"Record": 0}),
    # --- ole_is_create / ole_is_modify (modify = NOT create) ----------------
    ("ole_is_create", _w({"data_type": "olecf:summary_info",
                          "timestamp_desc": "Creation Time"})),
    ("ole_is_create", _w({"data_type": "olecf:summary_info",
                          "timestamp_desc": "Last Saved Time"})),
    ("ole_is_create", _w({"data_type": "olecf:summary_info",
                          "timestamp_desc": "Document Creation Time"})),
    ("ole_is_create", _w({"data_type": "olecf:summary_info"})),
    ("ole_is_create", _w({"data_type": "olecf:summary_info",
                          "timestamp_desc": None})),
    ("ole_is_create", _w({"data_type": "olecf:item",
                          "timestamp_desc": "Creation Time"})),
    ("ole_is_modify", _w({"data_type": "olecf:summary_info",
                          "timestamp_desc": "Last Saved Time"})),
    ("ole_is_modify", _w({"data_type": "olecf:summary_info",
                          "timestamp_desc": "Document Last Printed Time"})),
    ("ole_is_modify", _w({"data_type": "olecf:summary_info",
                          "timestamp_desc": "Creation Time"})),
    ("ole_is_modify", _w({"data_type": "olecf:summary_info",
                          "timestamp_desc": "crtime"})),
    ("ole_is_modify", _w({"data_type": "olecf:summary_info"})),      # absent -> modify
    ("ole_is_modify", _w({"data_type": "olecf:summary_info",
                          "timestamp_desc": 0})),                    # falsy -> modify
    ("ole_is_modify", _w({"data_type": "olecf:item",
                          "timestamp_desc": "Last Saved Time"})),
    ("ole_is_modify", _w({})),
]


# ---------------------------------------------------------------------------
# fixtures — one dir per artefact key (each key is its own l2t route table)
#
# The records marked VERBATIM are lifted unchanged out of
# tests/test_car_plaso_web.py / tests/test_car_plaso_fs_extra.py; the rest are
# the type/branch edges the module docstrings describe.
# ---------------------------------------------------------------------------
def _row(record, ts="2009-11-20T19:13:29.625000Z", rid=1,
         image="log2timeline/jsonl/M57-JO.jsonl"):
    return {"SourceImage": image, "RecordId": rid, "Timestamp": ts,
            "Parser": record.get("parser", "x"), "Record": record}


# ---- l2t_msiecf ------------------------------------------------------------
_IE_VISIT = {  # VERBATIM (test_ie_visit_maps_only_last_visited_and_strips_prefix)
    "data_type": "msiecf:url", "timestamp_desc": "Last Visited Time",
    "url": "Visited: Administrator@http://windowsupdate.microsoft.com/x",
    "number_of_hits": 2, "image_hostname": "M57-JO",
    "display_name": "NTFS:\\...\\index.dat", "parser": "msiecf"}

_IE_ABOUT = {  # VERBATIM (test_ie_visit_non_http_target_yields_null_url_parts)
    "data_type": "msiecf:url", "timestamp_desc": "Last Visited Time",
    "url": "Visited: Administrator@about:Home", "image_hostname": "M57-JO",
    "parser": "msiecf"}

MSIECF_LINES = [
    j(_row(_IE_VISIT)) + b"\n",
    j(_row(dict(_IE_VISIT, timestamp_desc="Expiration Time"), rid=2)) + b"\n",   # raw
    j(_row({"data_type": "msiecf:leak", "timestamp_desc": "Not a time",
            "parser": "msiecf"}, rid=3)) + b"\n",                                # raw
    j(_row(_IE_ABOUT, rid=4)) + b"\n",
    # a "Visited:" rendering with no '@' — regex1 misses, first() falls back
    j(_row(dict(_IE_VISIT, url="Visited: http://no-at.example/x"), rid=5)) + b"\n",
    # the bare-url cache rendering (no "Visited:" prefix at all)
    j(_row(dict(_IE_VISIT, url="http://bare.example/index.html",
                number_of_hits="7"), rid=6)) + b"\n",
    # url absent -> url_full null -> the spindle identity loses a component
    j(_row({"data_type": "msiecf:url", "timestamp_desc": "Last Visited Time",
            "image_hostname": "M57-JO", "display_name": "NTFS:\\x\\index.dat",
            "parser": "msiecf"}, rid=7)) + b"\n",
    # no image_hostname -> source_host falls back to the manifest host
    j(_row({"data_type": "msiecf:url", "timestamp_desc": "Last Visited Time (UTC)",
            "url": "http://nohost.example/", "parser": "msiecf"}, rid=8)) + b"\n",
    # url with port + query: url_domain stops at ':' , remainder keeps the query
    j(_row(dict(_IE_VISIT, url="Visited: Jo@https://proxy.example:8443/a/b?c=1#f",
                display_name="NTFS:\\...\\index.dat"), rid=9)) + b"\n",
    # url '-' (blank) and a url that is not a string at all
    j(_row(dict(_IE_VISIT, url="-"), rid=10)) + b"\n",
    j(_row(dict(_IE_VISIT, url=1234), rid=11)) + b"\n",
]

# ---- l2t_firefox_cache -----------------------------------------------------
_FFC = {  # VERBATIM (test_firefox_cache_method_status_and_http_prefix)
    "data_type": "firefox:cache:record", "request_method": "GET",
    "response_code": "HTTP/1.1 200 OK", "fetch_count": 3,
    "url": "HTTP:http://windowsupdate.microsoft.com/",
    "image_hostname": "M57-JO", "parser": "firefox_cache"}

FFCACHE_LINES = [
    j(_row(_FFC)) + b"\n",
    j(_row(dict(_FFC, request_method="POST", response_code="HTTP/1.1 302 Found",
                url="HTTP:http://post.example/submit"), rid=2)) + b"\n",
    j(_row(dict(_FFC, request_method="PUT", response_code="HTTP/1.1 204 No Content",
                data_size=0), rid=3)) + b"\n",
    j(_row(dict(_FFC, request_method="get"), rid=4)) + b"\n",       # upper=True
    j(_row(dict(_FFC, request_method="HEAD"), rid=5)) + b"\n",      # raw (no action)
    j(_row(dict(_FFC, request_method=None), rid=6)) + b"\n",        # raw
    j(_row({"data_type": "firefox:cache:record", "request_method": "GET",
            "url": "http://noprefix.example/", "parser": "firefox_cache",
            "image_hostname": "M57-JO"}, rid=7)) + b"\n",           # no "HTTP:" prefix
    j(_row(dict(_FFC, response_code="Unknown"), rid=8)) + b"\n",    # status null
    j(_row(dict(_FFC, response_code="HTTP/1.1 4004 Odd"), rid=9)) + b"\n",  # \s\d{3}\s
    j(_row(dict(_FFC, response_code=404), rid=10)) + b"\n",         # non-str
    j(_row(dict(_FFC, request_method="GET", url=None,
                fetch_count=None), rid=11)) + b"\n",                # url voided
    j(_row({"data_type": "firefox:cache2:record", "request_method": "GET",
            "url": "http://other.example/", "parser": "firefox_cache"},
           rid=12)) + b"\n",                                        # raw
    # WITH the cache file path: native.artefact_file is the spindle identity's
    # db_path, so this row mints the INTRINSIC guid (the rows above, which
    # carry no display_name, fall back to the positional identity)
    j(_row(dict(_FFC, display_name="NTFS:\\Documents and Settings\\Jo\\Local "
                                   "Settings\\Application Data\\Mozilla\\Firefox"
                                   "\\Profiles\\x.default\\Cache\\_CACHE_001_"),
           rid=13)) + b"\n",
]

# ---- l2t_firefox_places (firefox places + chrome/edge history) -------------
_FF_PLACES = {  # VERBATIM (test_firefox_page_visit_with_referrer)
    "data_type": "firefox:places:page_visited",
    "url": "http://windowsupdate.microsoft.com/",
    "from_visit": "http://www.microsoft.com/isapi/redir.dll?prd=Win2000 (www.microsoft.com)",
    "title": "Microsoft Windows Update", "visit_count": 2,
    "image_hostname": "M57-JO", "parser": "sqlite/firefox_history"}

_CHROME_VISIT = {  # VERBATIM (test_chrome_page_visit_maps_to_http_get)
    "data_type": "chrome:history:page_visited",
    "url": "https://portal.office.com/", "from_visit": "",
    "title": "Sign in to your account", "visit_count": 1,
    "image_hostname": "DESKTOP-PM6C56D",
    "display_name": "NTFS:\\Users\\jcloudy\\AppData\\Local\\Google\\Chrome"
                    "\\User Data\\Default\\History",
    "parser": "sqlite/chrome_history"}

_CHROME_DL = {  # VERBATIM (test_chrome_file_download_maps_with_response_bytes)
    "data_type": "chrome:history:file_downloaded",
    "url": "https://s3browser.com/download/s3browser-7-6-9.exe",
    "received_bytes": 2483848, "total_bytes": 2483848,
    "full_path": "C:\\Users\\jcloudy\\Downloads\\s3browser-7-6-9.exe",
    "image_hostname": "DESKTOP-PM6C56D",
    "display_name": "NTFS:\\Users\\jcloudy\\AppData\\Local\\Google\\Chrome"
                    "\\User Data\\Default\\History",
    "parser": "sqlite/chrome_history"}

HISTORY_LINES = [
    j(_row(_FF_PLACES)) + b"\n",
    j(_row(_CHROME_VISIT, rid=2)) + b"\n",
    j(_row(_CHROME_DL, rid=3)) + b"\n",
    # other sqlite plugins on the same route stay raw (VERBATIM shape)
    j(_row({"data_type": "firefox:places:bookmark_annotation", "url": "place:x",
            "parser": "sqlite/firefox_history"}, rid=4)) + b"\n",
    # from_visit edges: "" -> null referrer; a leading-space rendering misses
    # ^(\S+) so first() falls back to the whole value; absent -> null
    j(_row(dict(_FF_PLACES, from_visit="  http://pad.example/x (pad.example)"),
           rid=5)) + b"\n",
    j(_row(dict(_FF_PLACES, from_visit=None, typed=1, visit_type=2), rid=6)) + b"\n",
    j(_row(dict(_FF_PLACES, from_visit="-"), rid=7)) + b"\n",
    # download edges: float + string received_bytes, no full_path
    j(_row(dict(_CHROME_DL, received_bytes=1024.0, total_bytes=None,
                full_path=None), rid=8)) + b"\n",
    j(_row(dict(_CHROME_DL, received_bytes="2483848"), rid=9)) + b"\n",
    # non-http url on a history row: honest null scheme/domain/remainder
    j(_row(dict(_CHROME_VISIT, url="about:blank", from_visit=None), rid=10)) + b"\n",
    j(_row(dict(_CHROME_VISIT, url="ftp://files.example/pub/x.zip"), rid=11)) + b"\n",
    # no url at all, and no image_hostname (manifest host fallback)
    j(_row({"data_type": "chrome:history:page_visited", "title": None,
            "parser": "sqlite/chrome_history"}, rid=12)) + b"\n",
]

# ---- l2t_javaidx -----------------------------------------------------------
_JAVAIDX = {  # VERBATIM (test_javaidx_download_with_server_ip_native)
    "data_type": "java:download:idx", "url": "http://dl.javafx.com/jogl.jar",
    "ip_address": "72.5.123.29", "idx_version": 603, "image_hostname": "M57-JO",
    "parser": "java_idx"}

JAVAIDX_LINES = [
    j(_row(_JAVAIDX)) + b"\n",
    j(_row(dict(_JAVAIDX, url="https://cdn.example:8443/lib/app.jar?v=2",
                ip_address=None), rid=2)) + b"\n",
    j(_row(dict(_JAVAIDX, url="file:///tmp/local.jar", idx_version="6.03"),
           rid=3)) + b"\n",                                  # honest nulls
    j(_row({"data_type": "java:download:idx", "parser": "java_idx"},
           rid=4)) + b"\n",                                   # no url, no host
    j(_row({"data_type": "java:download", "url": "http://x.example/",
            "parser": "java_idx"}, rid=5)) + b"\n",           # raw
    # the .idx cache file path — native.artefact_file completes the spindle
    # identity, so this row mints the INTRINSIC guid
    j(_row(dict(_JAVAIDX, display_name="NTFS:\\Documents and Settings\\Jo\\"
                                       "Application Data\\Sun\\Java\\Deployment"
                                       "\\cache\\6.0\\12\\1e0d05cc-6a7b1b6d.idx"),
           rid=6)) + b"\n",
]

# ---- plaso_fseventsd (NO unit-test coverage — authored here) ---------------
# Shape per plaso's FSEventsdEventData (path / event_identifier / flags /
# node_identifier, int flags) and to-be-validated/plaso_fseventsd_flags.yml:
# the only CONFIRMED bits are IsDirectory 0x20000000 and EndOfTransaction
# 0x01000000 (a real record: flags 0x21000000 = 553648128), which is exactly
# why the map's action is the generic `modify` and the raw flags ride native.
_FSE = {"data_type": "macos:fseventsd:record",
        "path": "/Users/jo/Documents/notes.txt",
        "event_identifier": 226530, "flags": 16777216,       # EndOfTransaction
        "node_identifier": 1234567, "timestamp_desc": "Creation Time",
        "sha256_hash": "9f2c1a70" + "0" * 56,
        "display_name": "GZIP:/.fseventsd/0000000000226530",
        "image_hostname": "JO-MACBOOK", "disk_id": "disk2", "volume_id": "s1",
        "parser": "fseventsd"}

FSEVENTSD_LINES = [
    j(_row(_FSE)) + b"\n",
    # the confirmed real record: a directory marker, EMPTY path (the only
    # shape our corpus actually contains) -> file_path/name/ext all null
    j(_row(dict(_FSE, path="", flags=553648128, event_identifier=2,
                node_identifier=None, sha256_hash=None), rid=2)) + b"\n",
    # a directory path with a trailing separator: basename("") -> null
    j(_row(dict(_FSE, path="/Users/jo/Music/", event_identifier=226531),
           rid=3)) + b"\n",
    # extension-less path, and a dotfile
    j(_row(dict(_FSE, path="/usr/local/bin/tool", event_identifier=226532),
           rid=4)) + b"\n",
    j(_row(dict(_FSE, path="/Users/jo/.zshrc", event_identifier=226533),
           rid=5)) + b"\n",
    # flags rendered as the string plaso prints, and a missing path
    j(_row(dict(_FSE, flags="IsDirectory, EndOfTransaction",
                event_identifier=226534), rid=6)) + b"\n",
    j(_row({"data_type": "macos:fseventsd:record", "event_identifier": 226535,
            "flags": 0, "parser": "fseventsd"}, rid=7)) + b"\n",
    # a Windows-shaped path on the macOS parser (basename picks ntpath)
    j(_row(dict(_FSE, path="C:\\weird\\mixed.name.txt",
                event_identifier=226536), rid=8)) + b"\n",
    # a non-fseventsd row on the same route stays raw
    j(_row({"data_type": "fs:stat", "path": "/x", "parser": "fseventsd"},
           rid=9)) + b"\n",
]

# ---- plaso_pecoff ----------------------------------------------------------
_PE_RECORD = {  # VERBATIM (tests/test_car_plaso_fs_extra.py::_PE_HEADER["Record"])
    "data_type": "pe_coff:file",
    "display_name": "NTFS:\\Windows\\System32\\evil.dll",
    "export_dll_name": "evil.dll",
    "image_hostname": "HOST1.corp.example",
    "imphash": "d3310ce6cbcacb3a9f0809bc33e38abe",
    "parser": "pe",
    "pe_type": "Dynamic Link Library (DLL)",
    "section_names": [".text", ".rdata", ".data", ".reloc"],
    "sha256_hash": "b5de10a0" + "0" * 56,
    "timestamp_desc": "Creation Time"}

_PE_ROW_IMAGE = "log2timeline/jsonl/synth.jsonl"

PECOFF_LINES = [
    # the three rows of ONE PE: header stamp, table stamp, undated placeholder
    j(_row(_PE_RECORD, ts="2019-06-01T12:34:56.000000Z", image=_PE_ROW_IMAGE)) + b"\n",
    j(_row(dict(_PE_RECORD, timestamp_desc="Content Modification Time"),
           ts="2019-06-01T12:35:00.000000Z", rid=2, image=_PE_ROW_IMAGE)) + b"\n",
    j(_row(dict(_PE_RECORD, timestamp_desc="Not a time"),
           ts="1970-01-01T00:00:00.000000Z", rid=3, image=_PE_ROW_IMAGE)) + b"\n",
    # import-table / resource rows stay raw (VERBATIM: the two raw assertions)
    j(_row(dict(_PE_RECORD, data_type="pe_coff:dll_import"), rid=4,
           image=_PE_ROW_IMAGE)) + b"\n",
    j(_row(dict(_PE_RECORD, data_type="pe_coff:resource"), rid=5,
           image=_PE_ROW_IMAGE)) + b"\n",
    # a desc matching BOTH classifiers: variant order puts compile_time first
    j(_row(dict(_PE_RECORD, timestamp_desc="Content Creation Time"), rid=6,
           image=_PE_ROW_IMAGE)) + b"\n",
    # an UPPERCASE imphash/sha256 (both lower()ed), display_name with no
    # volume prefix (the regex misses -> the raw display_name is the path)
    j(_row(dict(_PE_RECORD, imphash="D3310CE6CBCACB3A9F0809BC33E38ABE",
                sha256_hash="B5DE10A0" + "0" * 56,
                display_name="\\Windows\\System32\\plain.exe",
                timestamp_desc="mtime"), rid=7, image=_PE_ROW_IMAGE)) + b"\n",
    # missing hash / imphash / sections, and no image_hostname (host fallback)
    j(_row({"data_type": "pe_coff:file", "timestamp_desc": "Not a time",
            "display_name": "GZIP:/tmp/x", "parser": "pe"}, rid=8,
           image=_PE_ROW_IMAGE)) + b"\n",
    # a POSIX path (basename picks posixpath) and a numeric imphash
    j(_row(dict(_PE_RECORD, display_name="TSK:/usr/lib/libfoo.so.1",
                imphash=0, section_names=[], timestamp_desc="Creation Time"),
           rid=9, image=_PE_ROW_IMAGE)) + b"\n",
]

# ---- plaso_olecf (NO unit-test coverage — authored here) -------------------
# Shape per plaso's OLECFSummaryInformation (olecf:summary_info): the document
# authoring metadata + the row's timestamp_desc naming which summary-info stamp
# the row carries.
_OLE = {"data_type": "olecf:summary_info", "timestamp_desc": "Creation Time",
        "display_name": "NTFS:\\Documents and Settings\\Jo\\My Documents\\budget.xls",
        "title": "Q4 budget", "author": "Jo Smith", "last_saved_by": "jo",
        "application": "Microsoft Excel", "revision_number": "3",
        "subject": "budget", "keywords": "finance", "comments": "",
        "template": "Normal.xlt", "number_of_pages": 4,
        "number_of_words": 1200, "number_of_characters": 7400,
        "security": 0, "codepage": 1252,
        "sha256_hash": "c0ffee11" + "0" * 56, "image_hostname": "M57-JO",
        "disk_id": "disk0", "volume_id": "vol1", "volume_offset": 32256,
        "parser": "olecf/olecf_summary"}

OLECF_LINES = [
    j(_row(_OLE)) + b"\n",                                              # create
    j(_row(dict(_OLE, timestamp_desc="Last Saved Time", revision_number="4"),
           ts="2009-11-21T08:02:11.000000Z", rid=2)) + b"\n",           # modify
    j(_row(dict(_OLE, timestamp_desc="Document Last Printed Time"),
           rid=3)) + b"\n",                                             # modify
    j(_row(dict(_OLE, timestamp_desc="crtime"), rid=4)) + b"\n",        # create (?i)
    # timestamp_desc absent / falsy -> NOT create -> the modify variant
    j(_row({"data_type": "olecf:summary_info",
            "display_name": "NTFS:\\Docs\\notes.doc", "author": None,
            "sha256_hash": None, "parser": "olecf/olecf_summary"},
           rid=5)) + b"\n",
    # an UPPERCASE hash (lower()ed), a path with no volume prefix, and an
    # author that is a list (str() through the native slot)
    j(_row(dict(_OLE, sha256_hash="C0FFEE11" + "0" * 56,
                display_name="\\Docs\\plain.doc", author=["Jo", "Sam"],
                security=4, codepage=None), rid=6)) + b"\n",
    # olecf:item (the internal OLE streams) stays raw
    j(_row({"data_type": "olecf:item", "timestamp_desc": "Creation Time",
            "display_name": "NTFS:\\Docs\\budget.xls",
            "parser": "olecf/olecf_default"}, rid=7)) + b"\n",
    # no display_name at all -> file_path null -> positional spindle identity
    j(_row({"data_type": "olecf:summary_info", "timestamp_desc": "Last Saved Time",
            "author": "Jo", "parser": "olecf/olecf_summary"}, rid=8)) + b"\n",
]


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    _lib.write_fixture("plaso_web_fs_msiecf",
                       {"artefacts": ["l2t_msiecf"], "host": "M57-JO-FALLBACK",
                        "adapter": "none", "input": "input.jsonl"},
                       MSIECF_LINES)
    _lib.write_fixture("plaso_web_fs_firefox_cache",
                       {"artefacts": ["l2t_firefox_cache"], "host": None,
                        "adapter": "none", "input": "input.jsonl"},
                       FFCACHE_LINES)
    _lib.write_fixture("plaso_web_fs_history",
                       {"artefacts": ["l2t_firefox_places"],
                        "host": "DESKTOP-FALLBACK",
                        "adapter": "none", "input": "input.jsonl"},
                       HISTORY_LINES)
    _lib.write_fixture("plaso_web_fs_javaidx",
                       {"artefacts": ["l2t_javaidx"], "host": "M57-JO-FALLBACK",
                        "adapter": "none", "input": "input.jsonl"},
                       JAVAIDX_LINES)
    _lib.write_fixture("plaso_web_fs_fseventsd",
                       {"artefacts": ["plaso_fseventsd"], "host": "JO-MACBOOK-FALLBACK",
                        "adapter": "none", "input": "input.jsonl"},
                       FSEVENTSD_LINES)
    _lib.write_fixture("plaso_web_fs_pecoff",
                       {"artefacts": ["plaso_pecoff"], "host": "PE-FALLBACK",
                        "adapter": "none", "input": "input.jsonl"},
                       PECOFF_LINES)
    _lib.write_fixture("plaso_web_fs_olecf",
                       {"artefacts": ["plaso_olecf"], "host": None,
                        "adapter": "none", "input": "input.jsonl"},
                       OLECF_LINES)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

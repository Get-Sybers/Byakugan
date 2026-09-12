"""Byte parity for the raw-l2t CONTAINER SPLITTER.

`byakugan-parse split-l2t --in RAW.jsonl --out-dir DIR` must write exactly the
files `byakugan/adapters/l2t_split.py` writes, byte for byte — same names, same
set, same contents, same order of rows within each file. The frozen reference
copy at tests/parity/reference/l2t_split.py is the authority.

The synthetic container below is built to stress everything the splitter's
contract turns on, because RecordId (the positional identity a row's spindle
guid falls back on) is the PHYSICAL line number:

  * many parsers in one container, incl. multi-segment names
    (winreg/appcompatcache, olecf/..., sqlite/...) that collapse to one table;
  * blank and whitespace-only lines — skipped, still counted;
  * an unparseable line — skipped, still counted;
  * a UTF-8 BOM on a line: l2t_split opens with encoding="utf-8" (NOT
    utf-8-sig), so the BOM stays in the text, json.loads fails, and the line is
    skipped-but-counted;
  * an invalid UTF-8 byte inside a string — errors='replace' → one U+FFFD;
  * CRLF and a lone CR (universal newlines), and no trailing newline at EOF;
  * timestamp edges: 0, negative, absent, None, float, bool, a string, and one
    past datetime.MAXYEAR — only ts > 0 (and in range) gets a Timestamp;
  * a record whose `parser` is absent / falsy / not a string.
"""
from __future__ import annotations

import json
import os
import subprocess

import harness  # conftest puts tests/parity on sys.path; used for _load_reference

HERE = os.path.dirname(os.path.abspath(__file__))

_UTMP = {"data_type": "linux:utmp:event", "display_name": "OS:/var/log/wtmp",
         "hostname": "pits-insec", "username": "insec", "terminal": "pts/0",
         "ip_address": "156.59.33.60", "pid": 3756, "type": 7,
         "timestamp_desc": "Start Time"}
_MFT = {"data_type": "fs:stat:ntfs", "display_name": "NTFS:\\Windows\\notepad.exe",
        "path_hints": ["\\Windows\\notepad.exe"], "file_reference": 281474976727294,
        "attribute_type": 16, "timestamp_desc": "Creation Time"}
_USN = {"data_type": "fs:ntfs:usn_change", "display_name": "NTFS:\\$Extend\\$UsnJrnl:$J",
        "filename": "a15f3474.tmp", "update_reason_flags": 2147484416,
        "update_sequence_number": 1048576,
        "timestamp_desc": "Metadata Modification Time"}
_FILESTAT = {"data_type": "fs:stat", "display_name": "NTFS:\\Program Files\\app\\x.MSG",
             "filename": "\\Program Files\\app\\x.MSG", "file_size": 78706,
             "image_hostname": "M57-JO", "is_allocated": True,
             "timestamp_desc": "Content Modification Time"}
_SYSLOG = {"data_type": "syslog:line", "hostname": "pits-insec",
           "reporter": "sshd", "body": "Accepted password for insec"}


def _j(rec) -> bytes:
    return json.dumps(dict(rec)).encode("utf-8")


def _container() -> bytes:
    """The raw bytes of the synthetic multi-parser container."""
    return b"".join([
        _j(dict(_UTMP, parser="utmp", timestamp=1600262099805465)) + b"\n",
        b"\n",                                                  # blank
        b"{not json\n",                                         # unparseable
        _j(dict(_MFT, parser="mft", timestamp=1600262070462820)) + b"\n",
        _j(dict(_USN, parser="usnjrnl", timestamp=1600262070462821)) + b"\n",
        b"   \t  \n",                                           # whitespace only
        # CRLF line ending
        _j(dict(_FILESTAT, parser="filestat", timestamp=1600262070000000)) + b"\r\n",
        # a second row for an already-open table (append path)
        _j(dict(_MFT, parser="mft", timestamp=0)) + b"\n",           # ts 0 → unset
        _j(dict(_MFT, parser="mft", timestamp=-1)) + b"\n",          # negative → unset
        _j(dict(_MFT, parser="mft", timestamp=None)) + b"\n",        # None → unset
        _j(dict(_MFT, parser="mft")) + b"\n",                        # absent → unset
        _j(dict(_MFT, parser="mft", timestamp=1600262070462820.75)) + b"\n",
        _j(dict(_MFT, parser="mft", timestamp=True)) + b"\n",        # bool IS an int
        _j(dict(_MFT, parser="mft", timestamp="1600262070462820")) + b"\n",  # str → unset
        _j(dict(_MFT, parser="mft", timestamp=253402300799999999)) + b"\n",  # MAXYEAR
        _j(dict(_MFT, parser="mft", timestamp=253402300800000000)) + b"\n",  # past it
        # multi-segment parser names collapse to the top segment
        _j(dict(_SYSLOG, parser="text/syslog_traditional",
                timestamp=1600262070462822)) + b"\n",
        _j({"parser": "winreg/appcompatcache", "data_type": "windows:registry:key_value",
            "timestamp": 1600262070462823}) + b"\n",
        _j({"parser": "olecf/olecf_automatic_destinations", "data_type": "olecf:dest_list",
            "timestamp": 1600262070462824}) + b"\n",
        _j({"parser": "sqlite/chrome_27_history", "data_type": "chrome:history:page_visited",
            "timestamp": 1600262070462825}) + b"\n",
        # parser edges: absent / falsy / not a string
        _j({"data_type": "x", "timestamp": 1600262070462826}) + b"\n",
        _j({"parser": "", "timestamp": 1600262070462827}) + b"\n",
        _j({"parser": 42, "timestamp": 1600262070462828}) + b"\n",
        # a BOM'd line: utf-8 (not utf-8-sig) → json.loads fails → skipped, counted
        b"\xef\xbb\xbf" + _j({"parser": "utmp", "timestamp": 1600262070462829}) + b"\n",
        # an invalid UTF-8 byte inside a string → one U+FFFD (errors='replace')
        b'{"parser": "text/syslog", "message": "bad\xffbyte", '
        b'"timestamp": 1600262070462830}\n',
        # non-ASCII + characters json.dumps must escape
        _j({"parser": "text/syslog", "message": "ünïcödé ☃ "
            "\"q\" \\ \n\t", "timestamp": 1600262070462831}) + b"\n",
        # a lone CR ends a line too
        _j(dict(_USN, parser="usnjrnl", timestamp=1600262070462832)) + b"\r",
        # a JSON line that is not an object would crash Python's splitter
        # (rec.get → AttributeError), so it is deliberately NOT in the
        # container — see the module docstring of go/internal/split.
        # last line, no trailing newline
        _j(dict(_UTMP, parser="utmp", timestamp=1600262099805466)),
    ])


def _reference_split(raw_path: str, out_dir: str) -> dict[str, str]:
    """The FROZEN Python splitter, called exactly as pipeline._process calls
    it: source_rel == prefix == os.path.basename(container)."""
    ref = harness._load_reference("l2t_split.py")  # noqa: SLF001
    base = os.path.basename(raw_path)
    return ref.split_l2t(raw_path, base, out_dir, base)


def test_split_l2t_is_byte_identical(tmp_path, go_binary):
    raw = tmp_path / "dualserver_logs.jsonl"
    raw.write_bytes(_container())

    py_dir = tmp_path / "py"
    py_dir.mkdir()
    py_tables = _reference_split(str(raw), str(py_dir))
    assert py_tables, "the reference splitter wrote nothing — the fixture is vacuous"

    go_dir = tmp_path / "go"
    proc = subprocess.run(
        [go_binary, "split-l2t", "--in", str(raw), "--out-dir", str(go_dir)],
        capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")

    py_files = sorted(os.listdir(py_dir))
    go_files = sorted(os.listdir(go_dir))
    assert go_files == py_files, (
        f"different output files\n py: {py_files}\n go: {go_files}")
    # every table the container's parsers imply is really there
    assert set(py_files) >= {
        "dualserver_logs.jsonl.L2tUtmp", "dualserver_logs.jsonl.L2tMft",
        "dualserver_logs.jsonl.L2tUsnjrnl", "dualserver_logs.jsonl.L2tFilestat",
        "dualserver_logs.jsonl.L2tText", "dualserver_logs.jsonl.L2tWinreg",
        "dualserver_logs.jsonl.L2tOlecf", "dualserver_logs.jsonl.L2tSqlite",
        "dualserver_logs.jsonl.L2tUnknown",
    }, py_files

    for name in py_files:
        want = (py_dir / name).read_bytes()
        got = (go_dir / name).read_bytes()
        assert want, f"{name}: reference wrote an empty file"
        if got != want:                      # a readable first-difference report
            wl, gl = want.decode().splitlines(), got.decode().splitlines()
            assert len(gl) == len(wl), f"{name}: {len(gl)} Go rows vs {len(wl)} Python"
            for i, (w, g) in enumerate(zip(wl, gl)):
                assert g == w, f"{name}: row {i} differs\n py: {w}\n go: {g}"
        assert got == want, name


def test_split_l2t_summary_reports_tables_and_physical_lines(tmp_path, go_binary):
    raw = tmp_path / "dualserver_logs.jsonl"
    raw.write_bytes(_container())
    go_dir = tmp_path / "go"
    proc = subprocess.run(
        [go_binary, "split-l2t", "--in", str(raw), "--out-dir", str(go_dir)],
        capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    summary = json.loads(proc.stdout.decode("utf-8"))

    # every announced table file exists and is the one on disk
    assert set(summary["tables"]) == {
        os.path.basename(p).split(".jsonl.", 1)[1] for p in summary["tables"].values()}
    for table, path in summary["tables"].items():
        assert os.path.isfile(path), (table, path)
        assert os.path.basename(path) == f"dualserver_logs.jsonl.{table}"
    assert sorted(summary["tables"]) == sorted(
        n.split(".jsonl.", 1)[1] for n in os.listdir(go_dir))

    # "lines" is the PHYSICAL line count — blank and bad lines included, read
    # with the splitter's own text semantics (universal newlines, replace).
    with open(raw, encoding="utf-8", errors="replace") as fh:
        physical = sum(1 for _ in fh)
    assert summary["lines"] == physical


def test_split_l2t_record_ids_are_physical_lines(tmp_path, go_binary):
    """RecordId must be the row's line in the container (blank/bad lines
    counted), identically on both sides — the positional-identity contract."""
    raw = tmp_path / "img.jsonl"
    raw.write_bytes(_container())
    py_dir, go_dir = tmp_path / "py", tmp_path / "go"
    py_dir.mkdir()
    py_tables = _reference_split(str(raw), str(py_dir))
    proc = subprocess.run(
        [go_binary, "split-l2t", "--in", str(raw), "--out-dir", str(go_dir)],
        capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")

    def ids(d):
        out = {}
        for name in sorted(os.listdir(d)):
            rows = [json.loads(x) for x in open(os.path.join(d, name), encoding="utf-8")]
            out[name] = [r["RecordId"] for r in rows]
        return out

    py_ids, go_ids = ids(py_dir), ids(go_dir)
    assert go_ids == py_ids
    flat = sorted(i for v in py_ids.values() for i in v)
    assert flat == sorted(set(flat)), "a RecordId was reused"
    assert flat[0] == 1, flat        # first physical line is a record
    assert py_tables and len(flat) >= 20

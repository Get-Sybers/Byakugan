"""Generate the readers parity vectors — REAL CPython text-decoding behavior
(utf-8-sig, errors='replace', universal newlines, the line-cleaning rules),
recorded byte-for-byte for go/internal/readers' replay test.

Each case is a crafted byte file (hex-encoded) plus the record list
byakugan.readers.iter_jsonl actually yields for it.

    python tests/parity/gen_reader_vectors.py   # writes go/internal/readers/testdata/reader_vectors.json
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from byakugan import readers  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "..", "go", "internal", "readers", "testdata",
                   "reader_vectors.json")

CASES = [
    # BOM stripped once; trailing comma stripped; plain lines
    b'\xef\xbb\xbf{"a": 1},\n{"b": 2}\n',
    # a JSON-array export: '[' / ']' wrapper lines skipped, commas stripped
    b'[\n{"a": 1},\n{"b": 2},\n]\n',
    # bad JSON lines skipped silently; blank lines skipped
    b'{"a": 1}\n{not json\n\n   \n{"c": 3}\n',
    # multiple trailing commas all stripped (rstrip(","))
    b'{"a": 1},,\n',
    # \r and \r\n line endings (universal newlines)
    b'{"a": 1}\r{"b": 2}\r\n{"c": 3}',
    # invalid UTF-8 maximal subparts -> one U+FFFD each
    b'{"s": "a\xffb"}\n',                          # lone invalid byte
    b'{"s": "\xe2\x82"}\n',                        # truncated 3-byte seq
    b'{"s": "\xe2\x82Ac"}\n',                      # prefix + ASCII resume
    b'{"s": "\xed\xa0\x80"}\n',                    # UTF-8-encoded surrogate
    b'{"s": "\xc0\xaf"}\n',                        # overlong
    b'{"s": "\xf4\x90\x80\x80"}\n',                # > U+10FFFF
    b'{"s": "\xf0\x9f\x92\xa9 ok"}\n',             # valid astral
    # Unicode whitespace stripped by str.strip() (NBSP around the token)
    b' \xc2\xa0{"a": 1}\xc2\xa0 \n',
    # a second BOM is NOT stripped -> undecodable line skipped
    b'\xef\xbb\xbf\xef\xbb\xbf{"a": 1}\n{"b": 2}\n',
    # BOM mid-file decodes as U+FEFF (line skipped as bad JSON)
    b'{"a": 1}\n\xef\xbb\xbf{"b": 2}\n',
    # non-object JSON lines are yielded too (the engine only ever feeds
    # object-shaped lanes, but iter_jsonl itself passes them through)
    b'[1, 2]\n5\ntrue\nnull\n"str"\n',
    # numbers keep int-vs-float identity; NaN/Infinity accepted like Python
    b'{"i": 12345678901234567890123, "f": 1.5, "n": NaN, "inf": -Infinity}\n',
    # empty file / whitespace-only file
    b'',
    b'   \n\t\n',
    # a trailing comma INSIDE whitespace: strip() runs before rstrip(",")
    b'{"a": 1} , \n',
]


def main() -> int:
    cases = []
    for raw in CASES:
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(raw)
            path = fh.name
        try:
            recs = list(readers.iter_jsonl(path))
        finally:
            os.unlink(path)
        cases.append({"hex": raw.hex(), "records": recs})
    out_path = os.path.abspath(OUT)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"cases": cases}, fh, indent=1)
        fh.write("\n")
    print(f"wrote {out_path} ({len(cases)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

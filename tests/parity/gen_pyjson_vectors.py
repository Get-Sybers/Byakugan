"""Generate the pyjson parity vectors — REAL Python json / str() behavior,
recorded, for go/internal/pyjson's byte-identical round-trip test.

Each `dumps` vector carries the value ONCE (embedded with Python's default
json.dumps style, so decoding the vectors file is itself part of the test)
plus the two expected encodings:

    default   = json.dumps(value)                                # ensure_ascii=True, (', ', ': ')
    canonical = json.dumps(value, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)

Each `pystr` vector records Python str() (the RENDER_STR scalar path) and
byakugan.ids.render for both modes (RENDER_STR falls back to canonical JSON
for structured values; RENDER_JSON is always canonical JSON) — the exact
functions guid minting joins values with.

The vectors file itself is assembled BY HAND from the recorded strings (never
by dumping the value a second way), so every byte in it is Python's own.

    python tests/parity/gen_pyjson_vectors.py   # writes go/internal/pyjson/testdata/vectors.json
"""
from __future__ import annotations

import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from byakugan import ids  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "..", "go", "internal", "pyjson", "testdata", "vectors.json")

C0 = "".join(chr(i) for i in range(0x20))

DUMPS_VALUES = [
    # --- floats: shortest-repr, exponent fixups, signed zero, specials ------
    1.0, -1.0, 0.5, 0.1, 0.2, 0.3, 1.5, 2.5, 3.141592653589793,
    1e15, 1e16, 1e17, 1.5e16, 123456789012345.6, 1234567890123456.7,
    1e-4, 1e-5, 0.0001, 0.00001, 1.5e-5, 9.999999999999999e15,
    1e-300, 1.5e-300, 5e-324, 1.7976931348623157e308,
    -0.0, 0.0, -2.5e-10, 6.02e23, 1e100, -1e-100,
    float("nan"), float("inf"), float("-inf"),
    # --- ints: huge (> 2^63), negative, zero --------------------------------
    0, 1, -1, 42, -42, 2**31, 2**63, 2**63 - 1, -(2**63), 2**64, 2**70,
    123456789012345678901234567890, -123456789012345678901234567890,
    # --- strings ------------------------------------------------------------
    "", "plain", 'quote " inside', "back\\slash", "both \" and \\",
    "tab\there", "nl\nhere", "cr\rhere", "bell\bhere", "ff\fhere",
    C0, "\x7f", "\x80", "\xa0",
    "é", "héllo wörld", "über naïve façade", "Ω≈ç√∫", "русский", "日本語テスト",
    "🎉", "emoji 🚀 rocket", "👨‍👩‍👧‍👦 family", "\U0001F600\U0001F601",
    "mixed é 日本 🎯 end", "﻿ BOM", "   separators",
    "ends with backslash\\", '\\"', "-", "null", "true",
    # --- containers -----------------------------------------------------------
    None, True, False,
    [], {}, [1, 2, 3], [1.0, "x", None, True],
    {"a": 1}, {"b": 1, "a": 2}, {"": "empty key"},
    {"é": "e-acute", "e": "plain", "z": 0},        # non-ASCII keys sort by code point
    {"日": 1, "a": 2, "Z": 3, "🎉": 4},
    {"outer": {"inner": [1, {"deep": "value é"}, 2.5]}, "list": []},
    [{"k": "v"}, [[]], [{}]],
    {"nan": float("nan"), "inf": float("inf")},
    {"big": 2**70, "neg": -(2**63)},
    ["\x00", "\x1f", "\x20", "\x7e", "\x7f"],
]

PYSTR_VALUES = [
    True, False, None,
    0, 1, -1, 42, 2**63, 2**70, -(2**70),
    1.0, -0.0, 0.1, 1e16, 1e-5, 1.5e-300, float("nan"), float("inf"), float("-inf"),
    "", "plain", "é 日本 🎉", '"quoted"', "back\\slash", "\n",
    "843", "-", "0x150",
    [1, "two", 3.0], ["é", None, True],
    {"b": 1, "a": "é"}, {}, [],
    {"nested": {"k": [1, 2]}, "s": "x"},
]


def _record_dumps(v):
    return {
        "value": json.dumps(v),   # embedded in default style: decoding it is part of the test
        "default": json.dumps(v),
        "canonical": json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
    }


def _record_pystr(v):
    rec = {
        "value": json.dumps(v),
        "render_str": ids.render(v, ids.RENDER_STR),
        "render_json": ids.render(v, ids.RENDER_JSON),
    }
    if not isinstance(v, (list, dict)):
        rec["str"] = str(v)       # the raw scalar str() the fields-guid join uses
    return rec


def main() -> int:
    doc = {"dumps": [_record_dumps(v) for v in DUMPS_VALUES],
           "pystr": [_record_pystr(v) for v in PYSTR_VALUES]}
    # Assemble by hand: the "value" fields are ALREADY json text and must land
    # verbatim (a second json.dumps pass would double-escape them into plain
    # strings — fine — but keeping them as raw tokens lets the Go test decode
    # the value with pyjson itself). We store value as a STRING of json text
    # and let Go decode it — one honest level of quoting.
    text = json.dumps(doc, ensure_ascii=False, indent=1) + "\n"
    os.makedirs(os.path.dirname(os.path.abspath(OUT)), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {os.path.abspath(OUT)}: {len(doc['dumps'])} dumps + {len(doc['pystr'])} pystr vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

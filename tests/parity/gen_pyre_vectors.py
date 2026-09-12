"""Generate the pyre parity vectors — REAL Python `re` behavior, recorded, for
go/internal/pyre's unit test.

The battery is EVERY regex pattern the live mapping tables actually use
(collected by walking byakugan.mappings for regex1 markers — so a new mapping
pattern shows up here on regeneration) plus targeted inputs per
negative-lookahead idiom and a handful of general-semantics probes. For every
(pattern, input) pair we record Python's re.search verdict and group(1)
(None when the group did not participate or the pattern has no group) —
exactly the semantics normalize's regex1 marker consumes.

    python tests/parity/gen_pyre_vectors.py   # writes go/internal/pyre/testdata/vectors.json
"""
from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from byakugan import export_ir  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "..", "go", "internal", "pyre", "testdata", "vectors.json")


def _live_patterns() -> list[str]:
    """Every regex1 pattern in the live maps, in first-seen order — collected
    off the ENCODED IR (export_ir.build_ir), so this walk and the Go engine
    see the exact same structure by construction."""
    seen: dict[str, None] = {}

    def walk(v):
        if isinstance(v, dict):
            m = v.get(export_ir.MARKER_KEY)
            if isinstance(m, list) and m and m[0] == "regex1":
                seen.setdefault(m[2])
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(export_ir.build_ir()["mappings"])
    return list(seen)


# generic probes thrown at EVERY pattern
COMMON_INPUTS = [
    "", "-", "x", "LOCAL", "local", "0", "1", "42", "0.0.0.0", "127.0.0.1", "::1",
    "10.11.12.13", "S-1-0-0", "S-1-5-18", "S-1-5-21-1-2-3-1001",
    "UEME_RUNPATH:E:\\R54402.EXE", "UEME_CTLSESSION", "RUNPATH", "value",
    "HOST1.dom.example.com", "HOST1", "C:\\Users\\jdoe\\file.txt",
    "/Users/jo/Documents/notes.txt", "\\Users\\jcloudy\\NTUSER.DAT",
    "C:\\Windows\\system32\\svchost.exe -k netsvcs",
    "0000abcdef0123456789abcdef0123456789abcdef", "prefix LOCAL suffix",
    "  spaced  ", "multi\nline\nLOCAL\nend", "é-日本-🎉",
]

# extra, per-idiom inputs (keyed by the exact live pattern text)
SPECIFIC = {
    r"^(?!LOCAL$)(.+)$": ["LOCAL", "LOCALX", "XLOCAL", "LOCA", "LOCAL ", " LOCAL", "L"],
    r"^(?!(?:::1|127\.0\.0\.1|LOCAL)$)(.+)$":
        ["::1", "127.0.0.1", "LOCAL", "::11", "127.0.0.10", "127a0b0c1", "fe80::1"],
    r"^(?!0$)(\d+)$": ["0", "00", "01", "10", "0x10", "7", ""],
    r"^(?!S-1-0-0$)(S-.+)$": ["S-1-0-0", "S-1-0-0-0", "S-", "S-1", "X-1-0-0", "S-1-0-0 "],
    r"^(?!UEME_)(.+)$": ["UEME_", "UEME_RUNPATH:X", "UEME", "ueme_x", "XUEME_Y"],
    r"\A(?!(?:0\.0\.0\.0|127\.0\.0\.1|::1)\Z)(.+)\Z":
        ["0.0.0.0", "127.0.0.1", "::1", "0.0.0.00", "1.2.3.4", "0.0.0.0\n", "x\n"],
}

# general re.search semantics probes (leftmost match, inline flags, classes)
EXTRA_PATTERNS = [
    (r"(?i)[/\\]Users[/\\]([^/\\]+)[/\\]",
     ["C:\\USERS\\Bob\\x", "/users/alice/f", "\\Users\\jo\\", "Users\\jo\\x", "C:\\Users\\jo"]),
    (r"(\d+)", ["abc 12 def 34", "no digits", "0", "x9"]),
    (r"^([^.]+\..+)$", ["HOST1.dom.com", "HOST1", ".x", "a.b", "a."]),
    (r"(?i)^0000([0-9a-f]{40})$",
     ["0000" + "ab" * 20, "0000" + "AB" * 20, "0001" + "ab" * 20, "0000" + "ab" * 19]),
    (r"a(b)?c", ["ac", "abc", "axc"]),                    # optional group -> None vs value
    (r"(?:x)(?:y)", ["xy", "x"]),                          # no capture group at all
    (r"a.c", ["abc", "a\nc", "axc"]),                      # '.' does not match \n
    (r"^x", ["x", "yx", "y\nx"]),                          # '^' start only (no MULTILINE)
    (r"x$", ["x", "xy", "x\n", "x\ny"]),                   # '$' end or before final \n
]


def main() -> int:
    vectors = []
    patterns = _live_patterns()
    for pat in patterns:
        inputs = list(dict.fromkeys(COMMON_INPUTS + SPECIFIC.get(pat, [])))
        cases = []
        for s in inputs:
            m = re.search(pat, s)
            g1 = None
            if m is not None and m.re.groups >= 1:
                g1 = m.group(1)
            cases.append({"in": s, "matched": m is not None, "group1": g1})
        vectors.append({"pattern": pat, "live": True, "cases": cases})
    for pat, extra in EXTRA_PATTERNS:
        inputs = list(dict.fromkeys(extra + COMMON_INPUTS))
        cases = []
        for s in inputs:
            m = re.search(pat, s)
            g1 = None
            if m is not None and m.re.groups >= 1:
                g1 = m.group(1)
            cases.append({"in": s, "matched": m is not None, "group1": g1})
        vectors.append({"pattern": pat, "live": False, "cases": cases})
    text = json.dumps({"vectors": vectors}, ensure_ascii=False, indent=1) + "\n"
    os.makedirs(os.path.dirname(os.path.abspath(OUT)), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    n = sum(len(v["cases"]) for v in vectors)
    print(f"wrote {os.path.abspath(OUT)}: {len(vectors)} patterns, {n} cases "
          f"({len(patterns)} live)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

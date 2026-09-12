"""Generate the spindle-resolution parity vectors — normalize._spindle driven
over synthetic (record, normalized-event) pairs for a representative set of
registry entries: intrinsic minting, the positional fallback on a blank
component, native.<key> sources, and the genuinely-absent (no guid) case.
The exhaustive golden re-mint already lives in go/internal/ids (stage A);
these vectors pin the RESOLUTION seam (field lookup, fallback, natives).

    python tests/parity/gen_spindle_vectors.py   # writes go/internal/spindle/testdata/spindle_vectors.json
"""
from __future__ import annotations

import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from byakugan import normalize as N, spindle  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "..", "go", "internal", "spindle", "testdata",
                   "spindle_vectors.json")

_REC = {"SourceImage": "image.jsonl", "RecordId": 57, "Parser": "filestat"}

# (entry name, record, normalized event) — events carry only what the entry's
# identity paths read (plus _native where a native.<key> source is used).
CASES = [
    # intrinsic: plain event-path identity
    ("l2t_filestat", dict(_REC),
     {"car_object": "file", "timestamp": "2020-01-01T00:00:00Z",
      "file_path": "/tmp/x", "_native": {}}),
    # blank identity component → positional fallback
    ("l2t_filestat", dict(_REC),
     {"car_object": "file", "timestamp": None, "file_path": "/tmp/x", "_native": {}}),
    # "-" is blank too
    ("l2t_filestat", dict(_REC),
     {"car_object": "file", "timestamp": "-", "file_path": "/tmp/x", "_native": {}}),
    # blank component AND no positional index → genuinely absent (None, {})
    ("l2t_filestat", {"SourceImage": "image.jsonl"},
     {"car_object": "file", "timestamp": None, "file_path": "/tmp/x", "_native": {}}),
    ("l2t_filestat", {"SourceImage": "image.jsonl", "RecordId": ""},
     {"car_object": "file", "timestamp": None, "file_path": "/tmp/x", "_native": {}}),
    # int identity value renders through str()
    ("l2t_usnjrnl", dict(_REC, Parser="usnjrnl"), None),  # event filled below
    # positional values keep their types in spindle_ref but render str in the key
    ("l2t_filestat", {"SourceImage": "img", "RecordId": "57"},
     {"car_object": "file", "timestamp": None, "file_path": "/x", "_native": {}}),
]


def _event_for(name):
    """A synthetic normalized event supplying every identity path of `name`."""
    e = spindle.entry(name)
    ev = {"car_object": e["object"], "_native": {}}
    sample = {"file_reference": 843, "usn": 1234567, "update_time": "2020-01-01T00:00:00Z",
              "event_time": "2020-01-01T00:00:00Z"}
    for i, (iname, source, _mode) in enumerate(spindle.identity_fields(e)):
        val = sample.get(iname, f"v{i}")
        if source.startswith("native."):
            ev["_native"][source[len("native."):]] = val
        else:
            ev[source] = val
    return ev


def main() -> int:
    cases = []
    for name, rec, event in CASES:
        if event is None:
            event = _event_for(name)
        e = spindle.entry(name)
        rec2, ev2 = copy.deepcopy(rec), copy.deepcopy(event)
        guid, natives = N._spindle(name, e["object"], rec2, ev2)  # noqa: SLF001
        cases.append({"name": name, "object": e["object"], "rec": rec,
                      "event": event, "guid": guid, "natives": natives})
    # one native.<key>-sourced entry, auto-picked so the vector set always
    # covers the native lookup path if the registry declares one
    native_entries = [n for n, e in spindle.identities().items()
                      if any(str(s).startswith("native.")
                             for _n, s, _m in spindle.identity_fields(e))]
    for name in sorted(native_entries)[:2]:
        e = spindle.entry(name)
        event = _event_for(name)
        rec2, ev2 = copy.deepcopy(_REC), copy.deepcopy(event)
        guid, natives = N._spindle(name, e["object"], rec2, ev2)  # noqa: SLF001
        cases.append({"name": name, "object": e["object"], "rec": _REC,
                      "event": event, "guid": guid, "natives": natives})
    out_path = os.path.abspath(OUT)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"cases": cases}, fh, indent=1)
        fh.write("\n")
    print(f"wrote {out_path} ({len(cases)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

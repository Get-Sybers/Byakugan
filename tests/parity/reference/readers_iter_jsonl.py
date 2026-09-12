# FROZEN REFERENCE COPY — do not edit.
# The iter_jsonl portion of byakugan/readers.py, copied verbatim and frozen
# for the Go parity harness (tests/parity): once the Go engine replaces the
# Python line streaming, readers.iter_jsonl is deleted and THIS copy remains
# the executable reference the byte-parity tests compare against.
from __future__ import annotations

import json


def iter_jsonl(path: str):
    # utf-8-sig: EvtxECmd stamps a UTF-8 BOM on every export — plain utf-8 makes
    # json.loads reject each file's FIRST line, silently dropping a record per
    # file (the same BOM gotcha downstream ingestion once hit).
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

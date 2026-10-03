"""RECmd batch output → CAR registry (un-parked).

RECmd (the hardened dfir/recmd container) runs a curated batch (e.g. Kroll)
over extracted hives and emits JSONL (``--json``): one record per registry
VALUE it matched, with the Kroll categorisation. Field shapes verified against
the real LoneWolf hives (7,493 records).

- Each non-deleted record → **registry/value_edit**: the value as it exists,
  timestamped by its KEY's LastWriteTimestamp — the key's last write is the
  nearest recorded time for the value's content (the same convention the
  memory registry map uses; which value changed last is not per-value
  attributable, and that caveat rides with the action).
- ``Deleted: true`` records (recovered from unallocated) stay RAW: the
  deletion happened but its TIME is unknowable from the record —
  ``remove`` at the key's last-write would assert a time the evidence does
  not contain.
- `user` is recovered from a per-user hive path (Users/<name>/...) — the
  hive-path convention; system hives yield null.
- The Kroll batch's Category/Description/Comment are evidence-grade
  context and ride in native.
"""
from __future__ import annotations


def recmd_is_value_record(rec) -> bool:
    """A live (non-deleted) batch record with a real key path."""
    return bool(rec.get("KeyPath")) and rec.get("Deleted") is not True


PREDICATES = {"recmd_is_value_record": recmd_is_value_record}

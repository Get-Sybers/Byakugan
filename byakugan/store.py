"""The DX_DFIR CAR-event store + the per-object JSONL downstream ingest consumes (epic #86).

The same database model proven in PIIAT-Mem's car.db: one SQLite table per CAR
object (all 13), each row a finished CAR event — a common header plus the
object's canonical properties as nullable columns:

    event_id · timestamp · car_action · guid · owning_pid · owning_guid ·
    parent_pid · parent_guid · link_confidence · source_artefact · source_host ·
    native (JSON: kept fields with no CAR home — never faked into CAR columns)

The store is the pipeline artifact (car.db under the processed tree); the
**JSON output** is the downstream ingest contract: `export_jsonl()` writes one
`car_<object>.jsonl` per populated object, each line a flat event object —
consumed by downstream ingestion (DX_DFIR ships it to Elastic/SOF-ELK).
"""
from __future__ import annotations

import json
import os
import sqlite3

from . import carmodel

# The stored header is deliberately minimal and MITRE-faithful: event metadata
# (timestamp, car_action), the row identity (guid — also the MITRE process guid),
# the ONE non-MITRE addition the model lacks (owning_guid — the definitive link
# from a spoke to its owning process), enrichment confidence, and provenance.
# Everything else is a MITRE field of the object.
#
# Deliberately NOT in the header (were phantom/duplicate columns before):
#   - parent_guid: a MITRE field of `process` ONLY, so it flows as a process
#     column via _cols and never appears as a null column on other objects;
#   - parent_pid / owning_pid: not MITRE fields — transient enrichment inputs
#     (enrich reads them off the in-memory event); the canonical parent/owner
#     pid already lives in the object's own `ppid`/`pid` MITRE fields.
#
# volume_guid is the second non-MITRE addition (B1): the globally-unique volume
# identity (`\\?\Volume{GUID}`) is the strongest cross-source key on a disk image
# (it ties USN ↔ evtx ↔ registry ↔ mount table ↔ cloud-sync), but MITRE CAR has
# no field for it, so like owning_guid it lives in the header as a queryable
# column on every object (nullable — enrich fills it from the in-memory
# `_native` blob before it is serialised into the `native` column).
# mac_address is the third non-MITRE addition (B3): a hardware MAC — literal, or
# recovered from the node of a version-1 (time+MAC) GUID (a DLT birth-droid) —
# is a device-linkage join key MITRE CAR has no field for, so like volume_guid
# it lives in the header (nullable, enrich fills it from `_native`).
# device_serial is the fourth non-MITRE addition (B3): the USB iSerialNumber from
# a USBSTOR device-instance path — the physical-device join key tying USBSTOR ↔
# setupapi ↔ DeviceClasses ↔ MountedDevices ↔ EMDMgmt to one stick — which MITRE
# CAR has no field for, so like mac_address it lives in the header (nullable,
# enrich fills it from `_native`).
HEADER = ["timestamp", "car_action", "guid", "owning_guid", "volume_guid",
          "mac_address", "device_serial", "link_confidence", "source_artefact",
          "source_host", "native"]


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class CarStore:
    """Create/open a car.db and read/write finished CAR events."""

    def __init__(self, path: str):
        self.path = path
        self.model = carmodel.load()
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._create()

    def _cols(self, obj: str) -> list[str]:
        return HEADER + [f for f in self.model[obj]["fields"] if f not in HEADER]

    def _create(self):
        cur = self.conn.cursor()
        for obj in self.model:
            cols = ", ".join(_q(c) for c in self._cols(obj))
            cur.execute(f"CREATE TABLE IF NOT EXISTS {_q(obj)} "
                        f"(event_id INTEGER PRIMARY KEY, {cols})")
            cur.execute(f"CREATE INDEX IF NOT EXISTS {_q('ix_' + obj + '_guid')} "
                        f"ON {_q(obj)} (guid)")
            cur.execute(f"CREATE INDEX IF NOT EXISTS {_q('ix_' + obj + '_ts')} "
                        f"ON {_q(obj)} (timestamp)")
        self.conn.commit()

    def insert_events(self, events: list[dict]) -> int:
        n = 0
        cur = self.conn.cursor()
        for ev in events:
            obj = ev["car_object"]
            cols = self._cols(obj)
            row = []
            for c in cols:
                if c == "native":
                    row.append(json.dumps(ev.get("_native") or {}, default=str))
                else:
                    v = ev.get(c)
                    row.append(json.dumps(v, default=str) if isinstance(v, (list, dict)) else v)
            cur.execute(f"INSERT INTO {_q(obj)} "
                        f"({', '.join(_q(c) for c in cols)}) "
                        f"VALUES ({', '.join('?' for _ in cols)})", row)
            n += 1
        self.conn.commit()
        return n

    def iter_object(self, obj: str):
        for row in self.conn.execute(f"SELECT * FROM {_q(obj)} ORDER BY event_id"):
            d = dict(row)
            d["car_object"] = obj
            try:
                d["native"] = json.loads(d.get("native") or "{}")
            except (TypeError, ValueError):
                pass
            yield d

    def counts(self) -> dict[str, int]:
        out = {}
        for obj in self.model:
            (n,) = self.conn.execute(f"SELECT COUNT(*) FROM {_q(obj)}").fetchone()
            if n:
                out[obj] = n
        return out

    # -- the JSONL ingest contract --------------------------------------------

    def export_jsonl(self, out_dir: str) -> dict[str, int]:
        """One `car_<object>.jsonl` per populated object — the JSONL downstream
        ingestion consumes. Each line: the event header + the object's
        canonical properties (null or not) + `native` as a JSON object."""
        os.makedirs(out_dir, exist_ok=True)
        written = {}
        for obj, count in self.counts().items():
            path = os.path.join(out_dir, f"car_{obj}.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                for ev in self.iter_object(obj):
                    ev.pop("event_id", None)
                    fh.write(json.dumps(ev, sort_keys=False, default=str))
                    fh.write("\n")
            written[obj] = count
        return written

    def close(self):
        self.conn.close()

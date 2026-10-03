"""The DX_DFIR CAR-event store — an in-memory event collection + the per-object
JSONL downstream ingest consumes (epic #86, the PURGE increment).

Byakugan is an elastic engine: it holds a source's finished CAR events in
memory for the duration of a build and writes only the materialised tree —
`export_jsonl()` writes one `car_<object>.jsonl` per populated object, each
line a flat event object — consumed by downstream ingestion (DX_DFIR ships it
to Elastic) and by every in-repo reader (verify.py, timeline.py, crosssource.py,
stix.py, analytics.py, sigma.py, `byakugan.elastic.load`). No SQLite is
written anywhere in this module; `read_object_jsonl`/`read_events` are the
read-back counterparts, shared by every consumer of an already-materialised
tree instead of each re-implementing its own JSONL walk.

    event_id · timestamp · car_action · guid · owning_pid · owning_guid ·
    parent_pid · parent_guid · link_confidence · source_artefact · source_host ·
    native (JSON: kept fields with no CAR home — never faked into CAR columns)

(`event_id` above is Anamnesis's own row id, never carried through; see
byakugan/readers.py, the one place this repo still reads a `car.db` — that
file is Anamnesis's OUTPUT FORMAT, not Byakugan's own store.)
"""
from __future__ import annotations

import json
import os

from . import carmodel

# The stored header: minimal and MITRE-faithful — event metadata, the row
# identity, enrichment confidence, provenance, and the four non-MITRE
# cross-source join keys (owning_guid, volume_guid, mac_address,
# device_serial). Rationale, the phantom-column rule and each key's story:
# docs/DataModel.md "The stored header".
HEADER = ["timestamp", "car_action", "guid", "owning_guid", "volume_guid",
          "mac_address", "device_serial", "link_confidence", "source_artefact",
          "source_host", "native"]


class CarStore:
    """One source's finished CAR events, held in memory, one list per object —
    the engine's working store for the duration of a build. `export_jsonl` is
    the only on-disk product; the materialised tree it writes is the contract
    (verify/timeline/load/DX_DFIR already read it, never this object)."""

    def __init__(self):
        self.model = carmodel.load()
        self._rows: dict[str, list[dict]] = {obj: [] for obj in self.model}

    def _cols(self, obj: str) -> list[str]:
        return HEADER + [f for f in self.model[obj]["fields"] if f not in HEADER]

    def insert_events(self, events: list[dict]) -> int:
        n = 0
        for ev in events:
            obj = ev["car_object"]
            row: dict = {}
            for c in self._cols(obj):
                row[c] = (ev.get("_native") or {}) if c == "native" else ev.get(c)
            row["car_object"] = obj
            self._rows[obj].append(row)
            n += 1
        return n

    def iter_object(self, obj: str):
        yield from self._rows.get(obj, [])

    def counts(self) -> dict[str, int]:
        return {obj: len(rows) for obj, rows in self._rows.items() if rows}

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
                for row in self.iter_object(obj):
                    fh.write(json.dumps(row, sort_keys=False, default=str))
                    fh.write("\n")
            written[obj] = count
        return written

    def close(self) -> None:
        """No-op — an in-memory store holds no file handle. Kept so a caller
        that still treats the store as a closable resource works unchanged."""


# --------------------------------------------------------------------------- #
# Read-back: the shared counterpart to export_jsonl/insert_events, over an
# already-materialised tree. One implementation — timeline.py, analytics.py,
# sigma.py, derive.py, stix.py and crosssource.py all consume it, rather than
# each re-walking car_<object>.jsonl its own way.
# --------------------------------------------------------------------------- #
def read_jsonl(path: str):
    """Every JSON object on its own line of `path`, in file order. A missing
    file yields nothing; a blank or unparseable line is skipped (a vanished
    or partially-written file never crashes a reader)."""
    try:
        fh = open(path, encoding="utf-8")
    except OSError:
        return
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                yield row


def read_object_jsonl(car_dir: str, obj: str):
    """One source's `car_<obj>.jsonl` under `car_dir`, row by row — the
    read-back counterpart to `export_jsonl`/`iter_object`: same row shape
    (`native` a nested dict, `car_object` present)."""
    for row in read_jsonl(os.path.join(car_dir, f"car_{obj}.jsonl")):
        row.setdefault("car_object", obj)
        yield row


def read_events(car_dir: str, objects=None) -> list[dict]:
    """Every object's rows under one source's materialised tree, as the
    in-memory event shape enrich/derive/stix consume (`native` -> `_native`,
    no `event_id`) — the read-back counterpart to `insert_events` +
    `export_jsonl`. `objects` limits which `car_<object>.jsonl` are read
    (default: every CAR object in the model)."""
    model = carmodel.load()
    out: list[dict] = []
    for obj in (objects if objects is not None else model):
        for row in read_object_jsonl(car_dir, obj):
            nat = row.pop("native", None)
            row["_native"] = nat if isinstance(nat, dict) else {}
            out.append(row)
    return out

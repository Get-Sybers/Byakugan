"""Plaso registry artefacts → CAR registry (epic #86, Phase C coverage).

A disk image's registry hives parse into a large family of `windows:registry:*`
data_types (service, run, winlogon, usb, bagmru, typedurls, sam_users,
key_value, …). `plaso_exec_winreg` already claims the ones that evidence
EXECUTION (amcache/userassist/bam/appcompatcache) as process events; this map
claims EVERY registry data_type as a **registry** event so the on-disk registry
state is ingested as CAR — the goal is to populate as many CAR entries as
possible (null/duplicate properties are fine) for the end-stage cascade to
relate. A registry snapshot is the KEY as it exists at its LastWrite time, so
the canonical action is **key_edit** (the same discipline as the RECmd map).

Relationship joins are NOT done here — this only NORMALISES and surfaces the
join keys (service `name`, run/winlogon `command`/`image_path`, hive-owner SID)
into `_native` for the enrichment end-stage.

Values live in a `values` LIST that the marker set cannot index, so `value`/
`data`/`type` stay in `_native.values`; `key`/`hive` are the canonical columns.
Runs alongside `plaso_exec_winreg` on the same L2tWinreg route — a record that
is both an execution artefact and a registry key legitimately yields both a
process row and a registry row (duplicate views are intended).

Row identity (the spindle guid, docs/CAR-Pipeline.md §7): the key snapshot —
hive + key_path at its last-write time. A value-level component is not
expressible on this KEY-level record shape (to-be-validated/spindle_identity.yml).
"""
from __future__ import annotations


def plaso_is_registry(rec) -> bool:
    dt = str((rec.get("Record") or {}).get("data_type") or "")
    # the shell-item rows that also arrive on L2tWinreg are NOT registry
    return dt.startswith("windows:registry:")


PREDICATES = {"plaso_is_registry": plaso_is_registry}

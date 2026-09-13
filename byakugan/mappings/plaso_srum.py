"""Plaso SRUM (System Resource Usage Monitor) → CAR (un-parked).

SRUM is parsed with **Plaso's `esedb/srum` parser** — SrumECmd itself cannot
run on Linux (it P/Invokes the Windows-only ESE native libraries; verified on
the real tool), and the artefact≠processor rule means the SRUM *artefact* maps
the same regardless of parser. Field shapes verified against the real LoneWolf
SRUDB.dat (17,928 rows).

- **windows:srum:network_usage → flow/message**: an HOURLY AGGREGATE of bytes
  an application moved on an interface — application + user attribution with
  in_bytes/out_bytes. `message` is the honest action ("content sent over the
  connection"); there are no endpoints (no ips/ports — SRUM records the
  interface, kept native) and the timestamp is the aggregate's Recorded Time.
- **windows:srum:application_usage → process/create**: execution evidence
  (the prefetch precedent) — the application demonstrably ran in the recorded
  hour; resource counters stay native.
- windows:srum:network_connectivity: interface connect telemetry whose fields
  are SRUM-internal indexes — no honest CAR object; stays raw.

`application` is either a kernel device path
(\\Device\\HarddiskVolume4\\...\\LogonUI.exe) or a bare service name
(DiagTrack); `user_identifier` is a SID *or* an SRUM-internal index — the sid
column is gated on the S-1- form (an index is not an identity).

Row identity (the spindle guid, docs/CAR-Pipeline.md §7): the aggregate's own
key — application + user (+ interface for network usage) at its recorded time.
"""
from __future__ import annotations


def _dt(rec) -> str:
    r = rec.get("Record")
    return str((r or {}).get("data_type") or "")


def srum_is_network_usage(rec) -> bool:
    return _dt(rec) == "windows:srum:network_usage"


def srum_is_application_usage(rec) -> bool:
    return _dt(rec) == "windows:srum:application_usage"


PREDICATES = {
    "srum_is_network_usage": srum_is_network_usage,
    "srum_is_application_usage": srum_is_application_usage,
}

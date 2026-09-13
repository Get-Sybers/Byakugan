"""esedump (ese_dump) SRUM → CAR — the Get-Sybers EZ-Tools SRUM data source.

`ese_dump` (the Get-Sybers/EZTools-Docker `get-sybers/esedump` container, Go on
Velociraptor's go-ese) parses `SRUDB.dat` natively on Linux — the Linux
substitute for SrumECmd, which is .NET/Windows-only (it P/Invokes the Windows
ESE engine). It emits one JSONL file PER SRUM provider table; each row carries
the raw ESE columns plus `TableAlias` (the friendly provider name) and the
SruDbIdMapTable-decoded `AppIdName` / `UserIdName` (a device path or service
name; a SID or an SRUM-internal index).

**The SRUM artefact maps the same regardless of parser** (docs: artefact ≠
processor), so this links to the SAME CAR objects the Plaso SRUM map does —
NetworkDataUsage → flow/message, ApplicationResourceUsage → process/create — but
as its OWN MITRE data source with its OWN positional row identity (EZ-tool maps
carry a `{"fields": …}` guid; the Plaso spindle registry is Plaso-only). Verified
against a real 12 MB SRUDB.dat (2,485 network + 17,173 application rows): the
decoded application/user/interface/bytes match Plaso's exactly; esedump keeps
SECOND-precision timestamps (Plaso rounds to the minute), so it is kept whole.

- **NetworkDataUsage → flow/message**: an hourly aggregate of bytes an
  application moved on an interface — application + user attribution with
  in_bytes/out_bytes. `message` is the honest action (content over the
  connection); no endpoints (SRUM records the interface, kept native).
- **ApplicationResourceUsage → process/create**: execution evidence (the
  prefetch precedent) — the application demonstrably ran in the recorded hour;
  the resource counters stay native.
- NetworkConnectivityUsage and the other provider tables are SRUM-internal
  telemetry with no honest CAR object → stay raw (default None).

`AppIdName` is either a kernel device path
(\\Device\\HarddiskVolume4\\...\\LogonUI.exe) or a bare service name (DiagTrack);
`UserIdName` is a SID *or* an SRUM-internal index — the sid/uid column is gated
on the S-1- form (an index is not an identity).

Row identity (positional, this-source-only): the aggregate's own key — the raw
AppId + UserId (+ interface for network usage) at its recorded TimeStamp.
"""
from __future__ import annotations

from ..normalize import basename, first, regex1  # noqa: F401

_TABLE_NETWORK = "NetworkDataUsage"
_TABLE_APPLICATION = "ApplicationResourceUsage"


def esedump_srum_is_network_usage(rec) -> bool:
    return rec.get("TableAlias") == _TABLE_NETWORK


def esedump_srum_is_application_usage(rec) -> bool:
    return rec.get("TableAlias") == _TABLE_APPLICATION


PREDICATES = {
    "esedump_srum_is_network_usage": esedump_srum_is_network_usage,
    "esedump_srum_is_application_usage": esedump_srum_is_application_usage,
}

# a device path carries the executable; a bare service name is only the exe
_IMAGE = regex1("AppIdName", r"(?i)^(\\Device\\.+)$")
_EXE = first(basename(_IMAGE), "AppIdName")
# a real SID, never an SRUM-internal numeric index
_SID = regex1("UserIdName", r"^(S-1-[0-9-]+)$")

# the raw ESE columns kept verbatim on every SRUM row (the decoded id names ride
# too — exe/uid/sid split them; the positional identity keys on the raw indices)
_KEEP_COMMON = ["Table", "TableAlias", "AppId", "UserId", "AppIdName",
                "UserIdName", "TimeStamp"]

MAPPINGS = {
    "esedump_srum": {
        "variants": [
            ("esedump_srum_is_network_usage", {
                "object": "flow", "action": "message", "ts": "TimeStamp",
                "guid": {"fields": ["AppId", "UserId", "InterfaceLuid",
                                    "TimeStamp", "BytesSent", "BytesRecvd"]},
                "props": {
                    "exe": _EXE,
                    "image_path": _IMAGE,
                    "in_bytes": "BytesRecvd",
                    "out_bytes": "BytesSent",
                    "uid": _SID,
                },
                "keep": _KEEP_COMMON + ["InterfaceLuid", "L2ProfileId",
                                        "L2ProfileFlags", "BytesSent", "BytesRecvd"],
            }),
            ("esedump_srum_is_application_usage", {
                "object": "process", "action": "create", "ts": "TimeStamp",
                "guid": {"fields": ["AppId", "UserId", "TimeStamp"]},
                "props": {
                    "exe": _EXE,
                    "image_path": _IMAGE,
                    "sid": _SID,
                },
                "keep": _KEEP_COMMON + ["ForegroundCycleTime", "BackgroundCycleTime",
                                        "FaceTime", "ForegroundBytesRead",
                                        "ForegroundBytesWritten", "BackgroundBytesRead",
                                        "BackgroundBytesWritten"],
            }),
            # NetworkConnectivityUsage and the other provider tables: SRUM-internal
            # indexes only -> no honest CAR object, stay raw.
        ],
        "default": None,
    },
}

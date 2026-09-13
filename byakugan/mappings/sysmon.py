"""Sysmon (EvtxECmd, Channel Microsoft-Windows-Sysmon/Operational) → CAR maps.

Port of the vetted KQL views (kusto/schema/40-mitre.kql): CarProcess_Sysmon
(EID 1/5), CarFlow_Sysmon (3), CarFile_Sysmon (11/23), CarRegistry_Sysmon
(12/13/14), CarModule_Sysmon (7), CarDriver_Sysmon (6), CarThread_Sysmon (8).
One artefact key (``evtx_sysmon``) with per-EID variants.

Sysmon is the one host artefact that natively carries REAL CAR process guids:

- **ProcessGuid** is the process event's own ``guid`` (EID 1 create and EID 5
  terminate share it — the same process identity across its lifetime) AND every
  spoke event's ``owning_guid`` (flow/file/registry/module/thread rows link to
  their owner DEFINITIVELY, no pid-window heuristic needed — car-store §3
  tier 1). EID 8's acting process is the SOURCE (it performs the injection),
  so SourceProcessGuid is that spoke's owning guid.
- **ParentProcessGuid** (EID 1) is the parent-link candidate — surfaced via
  ``native_extract`` under the exact name ``enrich._resolve_owner``'s parent
  logic consumes; never a canonical column (process has parent_guid, but that
  is the RESOLVED link — enrich fills it, the map never asserts it).

Model-name fixes vs the stale KQL (authoritative car_data_model.json):
``transport_protocol`` (not ``protocol``) on flow; registry actions
``add``/``remove``/``key_edit``/``value_edit`` (never the model-less ``edit``).
The KQL's catch-all ``"edit"`` for an unrecognized registry EventType cannot be
ported — no such canonical action exists — so those rows stay raw (default
None), per docs/CAR-Relations.md: an action is canonical or the row is not CAR.

Additions beyond the KQL where the model has an exact-native home (the CAR
extraction rule is EXHAUSTIVE, additive extraction — never a near-miss):
parent_command_line / current_working_directory / integrity_level (EID 1),
network_direction (EID 3 Initiated), extension (file), signature_valid
(EID 6/7 SignatureStatus). Each is flagged at its line.
"""
from __future__ import annotations

from ..normalize import (basename, const, ext, first, host_label,  # noqa: F401
                         lower, map_value, payload, regex1, replace, ts_before,
                         user_canon)
from ._common import (EVTX_FQDN as _FQDN, EVTX_HOST as _HOSTNAME,  # noqa: F401
                      EVTX_KEEP, EVTX_RECORD_GUID as _RECORD_GUID,
                      evtx_payload_field)


# --- variant predicates -----------------------------------------------------
# Gate = the KQL's `Provider matches regex @"(?i)sysmon"` + EventId; registry
# variants additionally read the Payload's EventType (the action authority).

def _is_sysmon(rec) -> bool:
    return "sysmon" in str(rec.get("Provider", "")).lower()


def _eid(rec):
    try:
        return int(rec.get("EventId"))
    except (TypeError, ValueError):
        return None


def _payload_event_type(rec) -> str:
    """EventType out of the EvtxECmd Payload blob ('CreateKey', 'SetValue', …)."""
    return evtx_payload_field(rec, "EventType")


def sysmon_proc_create(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 1


def sysmon_proc_terminate(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 5


def sysmon_flow_start(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 3


def sysmon_driver_load(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 6


def sysmon_module_load(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 7


def sysmon_thread_remote(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 8


def sysmon_proc_access(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 10


def sysmon_file_create(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 11


def sysmon_file_delete(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 23


# EID 12 covers key AND value create/delete (Sysmon 'RegistryEvent (Object
# create and delete)') — EventType carries which; Create*→add, Delete*→remove
# (the KQL's contains-"Create"/"Delete" logic, actions per the authoritative
# model). An EID 12 with any other EventType falls to default None: raw.
def sysmon_reg_add(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 12 and "Create" in _payload_event_type(rec)


def sysmon_reg_remove(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 12 and "Delete" in _payload_event_type(rec)


# EID 13 is 'RegistryEvent (Value Set)' — EventType SetValue, and ONLY that:
# the authoritative action is value_edit (the KQL's stale bare "edit" fixed).
def sysmon_reg_value_set(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 13 and "Set" in _payload_event_type(rec)


# EID 14 is 'RegistryEvent (Key and Value Rename)' — a rename edits the KEY
# namespace (the object keeps its data, its name changes): key_edit. The KQL
# view maps 14 alongside 12/13; ported with the authoritative action.
def sysmon_reg_rename(rec) -> bool:
    return _is_sysmon(rec) and _eid(rec) == 14 and "Rename" in _payload_event_type(rec)


PREDICATES = {
    "sysmon_proc_create": sysmon_proc_create,
    "sysmon_proc_terminate": sysmon_proc_terminate,
    "sysmon_flow_start": sysmon_flow_start,
    "sysmon_driver_load": sysmon_driver_load,
    "sysmon_module_load": sysmon_module_load,
    "sysmon_thread_remote": sysmon_thread_remote,
    "sysmon_proc_access": sysmon_proc_access,
    "sysmon_file_create": sysmon_file_create,
    "sysmon_file_delete": sysmon_file_delete,
    "sysmon_reg_add": sysmon_reg_add,
    "sysmon_reg_remove": sysmon_reg_remove,
    "sysmon_reg_value_set": sysmon_reg_value_set,
    "sysmon_reg_rename": sysmon_reg_rename,
}


# --- shared blocks ----------------------------------------------------------

# hostname/fqdn split from Computer, the KQL discipline everywhere: the first
# DNS label is hostname; fqdn is claimed ONLY when Computer actually is one
# (contains a dot) — a bare NetBIOS name is not faked into an fqdn.
# _HOSTNAME / _FQDN imported from ._common (EVTX_HOST / EVTX_FQDN)

# The Hashes string ("SHA1=..,MD5=..,SHA256=..,IMPHASH=..") splits into the
# three canonical hash fields; IMPHASH has no CAR home and stays native in
# Payload (kept), never faked into a hash column.
# hashes are canonicalised to LOWERCASE (EvtxECmd/Sysmon stamp them UPPERCASE):
# a hash column means the same across every source, so cross-source equality and
# a Sigma/hayabusa rule's (lowercase) hash literal both match.
def _hashes(src):
    return {
        "md5_hash": lower(regex1(src, r"(?i)\bMD5=([0-9A-Fa-f]+)")),
        "sha1_hash": lower(regex1(src, r"(?i)\bSHA1=([0-9A-Fa-f]+)")),
        "sha256_hash": lower(regex1(src, r"(?i)\bSHA256=([0-9A-Fa-f]+)")),
    }


# MITRE module/driver.signature_valid: asserted True only on the one status
# WinVerifyTrust actually vouches for ('Valid'); every other status string
# (Unavailable/Errors/…) is evidence of a PROBLEM, not proof of forgery — it
# stays native in Payload (Signed/SignatureStatus) rather than a faked False.
_SIGNATURE_VALID = map_value(payload("SignatureStatus"), {"Valid": True})

# Native columns every variant keeps (EvtxECmd's own stamp; the full Payload
# blob preserves everything not canonically mapped — IMPHASH, RuleName,
# Signed/SignatureStatus, Source/TargetImage, …).
_KEEP = EVTX_KEEP + ["ExecutableInfo"]

# Sysmon stamps its OWN event time (UtcTime) inside the payload; TimeCreated
# (the ts) is the log-write time. Surfaced as evidence, never swapped in.
_UTC = {"UtcTime": payload("UtcTime")}

# a stable per-record identity for spoke events (unique per channel within one
# .evtx export; log-clear resets are the documented caveat) — process events
# instead use the REAL identity Sysmon gives them (ProcessGuid).
# _RECORD_GUID imported from ._common (EVTX_RECORD_GUID)


def _proc_ctx():
    """The initiating-process block every Sysmon spoke event carries: canonical
    pid/image_path plus the DEFINITIVE tier-1 owner link (ProcessGuid)."""
    return {
        "owning_pid": payload("ProcessId"),
        "owning_guid": payload("ProcessGuid"),
    }


def _file_props(hashed: bool):
    """CarFile_Sysmon's field block. EID 23 (delete) carries the deleted
    file's own Hashes — canonical there; EID 11 (create) has none."""
    props = {
        "file_path": payload("TargetFilename"),
        "file_name": basename(payload("TargetFilename")),
        # model file.extension — exact native derivation the KQL omitted
        "extension": ext(payload("TargetFilename")),
        "image_path": payload("Image"),
        "pid": payload("ProcessId"),
        "user": user_canon(payload("User")),
        "hostname": _HOSTNAME, "fqdn": _FQDN,
    }
    if hashed:
        props.update(_hashes(payload("Hashes")))
    return props


def _registry_props(with_value: bool, with_data: bool):
    """CarRegistry_Sysmon's field block. `key` is the full TargetObject (for a
    value event that path INCLUDES the value name — the KQL's shape, kept);
    `value` is split out only where the event is about a value (EID 13).
    type/hive: Sysmon gives neither (the KQL's "" placeholders) — honest nulls.
    User is absent from registry events on pre-v11 Sysmon — an honest null."""
    props = {
        "key": payload("TargetObject"),
        "image_path": payload("Image"),
        "pid": payload("ProcessId"),
        "user": user_canon(payload("User")),
        "hostname": _HOSTNAME, "fqdn": _FQDN,
    }
    if with_value:
        props["value"] = basename(payload("TargetObject"))
    if with_data:
        props["data"] = payload("Details")
        # the row IS the value_edit and Details the written data — exactly CAR
        # new_content (same convention as the memory registry map)
        props["new_content"] = payload("Details")
    return props


def _registry_variant(action: str, with_value=False, with_data=False, native=None):
    return {
        "object": "registry", "action": action, "ts": "TimeCreated",
        "guid": _RECORD_GUID, "host": _HOSTNAME,
        **_proc_ctx(),
        "props": _registry_props(with_value, with_data),
        "keep": _KEEP,
        # EventType (CreateKey/SetValue/DeleteValue/…) is the action authority
        # our variants already dispatch on; retained native so a Sigma registry
        # rule that gates on it (`EventType: SetValue`) resolves. No CAR column —
        # the canonical action already encodes it.
        "native_extract": dict(_UTC, EventType=payload("EventType"), **(native or {})),
    }


def _image_load_props():
    """Shared EID 6/7 block: hashes + signer (Signature = WHO signed; the
    validity verdict is signature_valid; Signed/SignatureStatus stay native)."""
    return {
        **_hashes(payload("Hashes")),
        "signer": payload("Signature"),
        "signature_valid": _SIGNATURE_VALID,
        "hostname": _HOSTNAME, "fqdn": _FQDN,
    }


def _image_load_native(pe_metadata: bool):
    """EID 6/7 native retention: the signed flag (a bool string WinVerifyTrust
    reports; signature_valid canonicalises only the 'Valid' verdict) and IMPHASH
    (no CAR hash column) — both prime Sigma image_load fields with no CAR home,
    retained under their Sysmon names for the native-bag fallback. EID 7
    additionally carries the module's PE version-resource identity
    (OriginalFileName/Company/... — heavily referenced by image_load rules); a
    kernel driver (EID 6) carries none of those, so they are module-only."""
    native = dict(
        _UTC,
        Signed=payload("Signed"),
        Imphash=lower(regex1(payload("Hashes"), r"(?i)\bIMPHASH=([0-9A-Fa-f]+)")),
    )
    if pe_metadata:
        native.update(
            OriginalFileName=payload("OriginalFileName"),
            Company=payload("Company"),
            Product=payload("Product"),
            Description=payload("Description"),
            FileVersion=payload("FileVersion"),
        )
    return native

"""Additional Windows event-log → CAR maps (epic #86, Phase C coverage pass).

A coverage triage over the real lonewolf image (55k records, 842 distinct
Channel/EventId) surfaced forensically-meaningful events with a CLEAN canonical
CAR home that were not yet ingested. Only records that fit a real object +
canonical action are mapped here; the high-volume remainder (account/group
lifecycle, local-group ENUMERATION 4798/4799, privilege grants, audit-policy,
system-time) have NO CAR object in the 13-object model and stay raw — mapping
them would be the same near-miss the codebase already refuses (7040/4648).

Each variant is grounded in a verified payload field on a real record:

- **Security 4907** (ObjectType=File) → file/acl_modify: "auditing settings on
  object changed" — a security-descriptor (SACL) change on a file. Gated to
  ObjectType=File; a 4907 on a registry Key has no canonical action (registry
  has add/key_edit/remove/value_edit, not acl_modify) so it stays raw.
- **WMI-Activity 5857** → module/load: a WMI provider DLL (ProviderPath) loaded
  into its host process (HostProcess/ProcessID) — the classic wmiprvse
  execution indicator. UserData shape.
- **System 20003** (UserPnp) → service/create: a driver-service registration
  (ServiceName + DriverFileName). PnP-side, not SCM — no pid/user (honest null).
- **SmbClient/Connectivity 30803** → flow/start: an SMB connection to a named
  server. ServerName is the one clean field; RemoteAddress/LocalAddress are raw
  SOCKADDR hex blobs (not IP strings), kept native rather than faked into ip.
- **System 7001 / 7002** (Winlogon) → user_session/login / logout: corroborates
  4624/4634 by UserSid + session (TSId); no username/src (honest null).
- **System 7034** (SCM) → service/stop: "service crashed unexpectedly" — an
  involuntary stop (param1 = the service display name).
"""
from __future__ import annotations

from ._common import (EVTX_FQDN as _FQDN, EVTX_HOST as _HOST,  # noqa: F401
                      EVTX_KEEP as _KEEP, EVTX_RECORD_GUID as _GUID,
                      evtx_payload_field as _payload_field)


def _eid(rec):
    try:
        return int(rec.get("EventId"))
    except (TypeError, ValueError):
        return None


def _ch(rec, needle):
    return needle in str(rec.get("Channel", ""))


# --- variant predicates -----------------------------------------------------

def em_is_4907_file(rec) -> bool:
    return (_eid(rec) == 4907 and _ch(rec, "Security")
            and _payload_field(rec, "ObjectType") == "File")


def em_is_wmi_5857(rec) -> bool:
    return _eid(rec) == 5857 and _ch(rec, "WMI-Activity")


def em_is_pnp_20003(rec) -> bool:
    return _eid(rec) == 20003 and _ch(rec, "System")


def em_is_smb_30803(rec) -> bool:
    return _eid(rec) == 30803 and _ch(rec, "SmbClient")


def em_is_winlogon_7001(rec) -> bool:
    return _eid(rec) == 7001 and _ch(rec, "System")


def em_is_winlogon_7002(rec) -> bool:
    return _eid(rec) == 7002 and _ch(rec, "System")


def em_is_scm_7034(rec) -> bool:
    return _eid(rec) == 7034 and _ch(rec, "System")


PREDICATES = {
    "em_is_4907_file": em_is_4907_file,
    "em_is_wmi_5857": em_is_wmi_5857,
    "em_is_pnp_20003": em_is_pnp_20003,
    "em_is_smb_30803": em_is_smb_30803,
    "em_is_winlogon_7001": em_is_winlogon_7001,
    "em_is_winlogon_7002": em_is_winlogon_7002,
    "em_is_scm_7034": em_is_scm_7034,
}

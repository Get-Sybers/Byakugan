"""Per-artefact → MITRE CAR maps for the DX_DFIR pipeline (epic #86).

Same declarative shape as Anamnesis's mappings: one entry per artefact, variants
where one artefact's rows split across objects/actions, markers for the small
transforms, `keep`/`native_extract` for native evidence and join keys with no
CAR home (never faked into a canonical column).

Field semantics follow MITRE's own docs verbatim (car.mitre.org), including the
LIMITING principles determined per object (docs/design/car-relations.md):

- **authentication** ← Security 4624 (success) / 4625 (failure). 4648 is
  deliberately NOT mapped: it records an explicit-credential logon at ISSUANCE —
  no service response exists in the record, and CAR offers only
  success/failure/error, so asserting any of them would fake an outcome.
  hostname = the ORIGIN (WorkstationName — client-reported, recorded not
  trusted); auth_target = the machine authenticated TO (Computer). The LUID join
  keys (TargetLogonId/SubjectLogonId) are surfaced into _native for the
  user_session join.
- **http** ← Zeek http.log. hostname is NOT mapped: MITRE defines it as the host
  on which the request was SEEN (the vantage — carried by source_host), not the
  client-forgeable Host header (that is url_domain). url_full/url_scheme are
  reconstructed only for origin-form requests (never for CONNECT tunnels, whose
  request-target has no scheme).
- **email**: principles documented; no artefact feeds it yet (the one real
  smtp.json is STARTTLS-encrypted), so no map — an empty table is honest.

The memory artefact does NOT map here: Anamnesis already emits finished CAR —
`readers.load_anamnesis_car()` passes it straight through.
"""
from __future__ import annotations

from ..normalize import (basename, concat, const, domain_of, epoch_ts, ext,  # noqa: F401
                        first, host_label, lower, map_value, payload, regex1,
                        user_canon)


# --- variant predicates -----------------------------------------------------

def is_sec_4624(rec) -> bool:
    return rec.get("EventId") == 4624 and "Security" in str(rec.get("Channel", ""))


def is_sec_4625(rec) -> bool:
    return rec.get("EventId") == 4625 and "Security" in str(rec.get("Channel", ""))


def is_sec_4672(rec) -> bool:
    """Security 4672 — special (admin-equivalent) privileges assigned to a new
    logon. A COMPANION to the 4624 for the same session: mapped in as its own
    authentication entry (it only fires on success, and its whole meaning is the
    administrative role); the end-cascade links it to the 4624 by the shared LUID
    (SubjectLogonId)."""
    return rec.get("EventId") == 4672 and "Security" in str(rec.get("Channel", ""))


def is_http_origin(rec) -> bool:
    """Origin-form requests — a URL is reconstructable (scheme+Host+uri)."""
    return str(rec.get("method", "")).upper() in ("GET", "POST", "PUT")


def is_http_tunnel(rec) -> bool:
    """CONNECT — authority-form request-target: no scheme, no URL to rebuild."""
    return str(rec.get("method", "")).upper() == "CONNECT"


PREDICATES = {
    "is_sec_4624": is_sec_4624, "is_sec_4625": is_sec_4625,
    "is_sec_4672": is_sec_4672,
    "is_http_origin": is_http_origin, "is_http_tunnel": is_http_tunnel,
}


# --- shared blocks ----------------------------------------------------------

def _auth_props():
    return {
        # who was authenticated (the target of the request). MITRE's "only
        # pertains to privilege escalation" clause is its own copy-paste error —
        # Windows fills TargetUserName on every logon.
        "target_user": payload("TargetUserName"),
        "target_uid": payload("TargetUserSid"),
        "target_ad_domain": payload("TargetDomainName"),
        # the reporting/calling context (often a machine account — evidence,
        # never asserted as "the person who typed the password")
        "user": user_canon(payload("SubjectUserName")),
        "uid": payload("SubjectUserSid"),
        "ad_domain": payload("SubjectDomainName"),
        # ORIGIN vs DESTINATION (4624/4625): WorkstationName is the requesting
        # host (client-reported — recorded, not trusted; no Computer fallback,
        # which is the DESTINATION); Computer is the machine authenticated TO.
        "hostname": payload("WorkstationName"),
        "auth_target": "Computer",
        # Negotiate means negotiated — a concrete protocol is NOT asserted
        "method": payload("AuthenticationPackageName"),
        "auth_service": payload("LogonProcessName"),
        "app_name": basename(payload("ProcessName")),
    }

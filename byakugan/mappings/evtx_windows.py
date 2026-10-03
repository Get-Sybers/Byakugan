"""Windows event logs beyond Sysmon → CAR user_session / service (epic #86).

Ports the vetted KQL views (kusto/schema/40-mitre.kql) to the Python engine:

- **CarUserSession_Security** → ``evtx_security_sessions``: Security
  4624/4634/4647/4778/4779 → **user_session**. The stale KQL names are fixed to
  the authoritative model (car_data_model.json): ``login_id`` (the LUID, was
  logon_id) and ``login_type`` (new — the model moved the session-type
  vocabulary interactive/rdp/remote/local OUT of the action set INTO its own
  field; the canonical ACTIONS are now login/logout/reconnect/lock/unlock).
  Deliberately NOT mapped, unlike the older view:
    * 4625 — a FAILED logon opens **no** session (CAR-Relations "Limits"): it
      is an authentication event (core.py), never a user_session one.
    * 4648 — explicit-credential logon recorded at ISSUANCE; no service
      response exists in the record, and no session provably opens
      (CAR-Relations: "mapping it … would assert an outcome the evidence
      doesn't contain"). Rows stay raw.
    * 4800/4801 (lock/unlock of the workstation) are separate events NOT fed
      by this artefact key; the ``lock`` action therefore never fires here.
      LogonType 7 on a 4624 *is* the unlock relogon — see _LT_ACTION.

- **CarService_Evtx** → ``evtx_services``: System 7045 / Security 4697 →
  **service**, action ``create``. The two events name the same facts
  differently (7045: ImagePath/AccountName; 4697: ServiceFileName/
  ServiceAccount) — coalesced per field, exactly like the view.

NOTE: ``evtx_security_sessions`` reads the SAME Security_EvtxECmd_Output.json
rows as core.py's ``evtx_security`` (authentication) — one file feeds two
artefact keys; the pipeline runs both. Artefact keys and predicates are
prefixed to stay globally unique across mapping submodules.
"""
from __future__ import annotations

from ..normalize import (basename, concat, const, domain_of, epoch_ts, ext, exe_path,  # noqa: F401
                        first, hex_int, host_label, lower, map_value, payload, regex1,
                        user_canon)


# S-1-16-<RID> mandatory-label SID -> CAR integrity_level (the memory processes
# plugin's own vocabulary), so the field means the same across every source.


# --- variant predicates (evtxwin_ prefix: globally unique) -------------------
# Channel guards mirror the KQL (`Channel has "Security"/"System"`): these
# EventIds are reused by other providers, so the channel is pinned.

def evtxwin_is_sec_4624(rec) -> bool:
    """Security 4624 — an account was successfully logged on: a session OPENS."""
    return rec.get("EventId") == 4624 and "Security" in str(rec.get("Channel", ""))


def evtxwin_is_sec_logoff(rec) -> bool:
    """Security 4634 (logged off) / 4647 (user-initiated logoff) / 4779 (RDP
    session disconnected). 4779 is a session DISCONNECT — the session ended
    from the user's side; CAR has no "disconnect" action, so "logout" is the
    nearest honest label (the view's earlier "remote" was wrong and was fixed
    there too)."""
    return (rec.get("EventId") in (4634, 4647, 4779)
            and "Security" in str(rec.get("Channel", "")))


def evtxwin_is_sec_4778(rec) -> bool:
    """Security 4778 — a session was RECONNECTED to a Window Station (RDP/fast
    user switching): the canonical `reconnect` action."""
    return rec.get("EventId") == 4778 and "Security" in str(rec.get("Channel", ""))


def evtxwin_is_sys_7045(rec) -> bool:
    """System 7045 — the Service Control Manager installed a new service."""
    return rec.get("EventId") == 7045 and "System" in str(rec.get("Channel", ""))


def evtxwin_is_sec_4697(rec) -> bool:
    """Security 4697 — a service was installed in the system (audit lane)."""
    return rec.get("EventId") == 4697 and "Security" in str(rec.get("Channel", ""))


def evtxwin_is_sec_4688(rec) -> bool:
    """Security 4688 — a new process has been created."""
    return rec.get("EventId") == 4688 and "Security" in str(rec.get("Channel", ""))


PREDICATES = {
    "evtxwin_is_sec_4624": evtxwin_is_sec_4624,
    "evtxwin_is_sec_logoff": evtxwin_is_sec_logoff,
    "evtxwin_is_sec_4778": evtxwin_is_sec_4778,
    "evtxwin_is_sys_7045": evtxwin_is_sys_7045,
    "evtxwin_is_sec_4697": evtxwin_is_sec_4697,
    "evtxwin_is_sec_4688": evtxwin_is_sec_4688,
}


# --- user_session blocks -----------------------------------------------------

# login_type ← LogonType, per the vetted view's case logic (the model's
# vocabulary is interactive/rdp/remote/local). Only the ints the view asserted
# are mapped; every other LogonType (0 system, 4 batch, 5 service, 8/9
# cleartext/new-credentials, 11 cached) has NO proven canonical value and is
# left null — the raw int stays queryable in _native.LogonType. "local" has no
# LogonType source in this artefact (console feeders like utmp assert it).
# LogonType 7 is "the workstation was unlocked" — it drives the ACTION
# (unlock), not login_type: an unlock relogon happens on console AND on RDP
# sessions alike, so asserting a session type from it would be a near-miss.
_LOGIN_TYPE = {
    "2": "interactive",   # at-keyboard / console logon
    "3": "remote",        # network logon (SMB, RPC, WinRM, ...)
    "10": "rdp",          # RemoteInteractive (Terminal Services / RDP)
}

# 4624 action: LogonType 7 = unlock (canonical action in the model), every
# other successful logon = login. `first` falls through when map_value misses.


def _session_props():
    """Canonical user_session fields shared by every Security session event.

    The 4778/4779 pair names its fields differently from the 4624 family
    (AccountName / LogonID / ClientAddress instead of TargetUserName /
    TargetLogonId / IpAddress) — coalesced per field, exactly like the view
    (payload() returns None for a missing key, so `first` is the analogue of
    the KQL's iff(isempty(...))).
    """
    return {
        # the user whose session this is. UserName (EvtxECmd's own column) is
        # the view's last-resort fallback; in practice every in-scope EventId
        # carries one of the payload names.
        "user": user_canon(first(payload("TargetUserName"), payload("AccountName"),
                                 "UserName")),
        # the session user's SID — the model's uid (4778/4779 carry no SID:
        # honest null there).
        "uid": payload("TargetUserSid"),
        # the LUID — THE designed join key (CAR-Relations: unique per boot per
        # host; the authentication↔user_session join runs on it).
        "login_id": first(payload("TargetLogonId"), payload("LogonID")),
        "login_type": map_value(payload("LogonType"), _LOGIN_TYPE),
        # the host the session exists ON (Computer, first DNS label — the view's
        # split(Computer, ".")[0]).
        "hostname": host_label("Computer"),
        # origin address of the logon. The view nulls the non-addresses:
        # "-"/"" are engine blanks already; "LOCAL" is 4778/4779's
        # ClientAddress for a console session (not an IP), and loopback
        # carries no origin information. `^`-anchored, so regex1 cannot
        # slide past the guard.
        "src_ip": regex1(first(payload("IpAddress"), payload("ClientAddress")),
                         r"^(?!(?:::1|127\.0\.0\.1|LOCAL)$)(.+)$"),
        # 4624's IpPort; "0" and "-" mean no port (the view's toint guard).
        # Kept as the digit string — the engine has no int-cast marker.
        "src_port": regex1(payload("IpPort"), r"^(?!0$)(\d+)$"),
        # dest_ip/dest_port: the record names no destination ADDRESS (Computer
        # is the destination host, already in hostname) — honest nulls, per
        # the view's empty dest_ip / int(null) dest_port.
    }

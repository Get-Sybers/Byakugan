"""Additional Windows operational-channel event-log grabs (epic #86).

More CAR-mappable info the event logs give us, beyond the Security/System/Sysmon
core — each mapped because it CARRIES a CAR object/action/properties:

- **BITS-Client 59/60 → http/get**: a Background Intelligent Transfer is an
  HTTP(S) download; the event carries the URL (staging/C2 evidence) and byte
  counts. hostname = the endpoint that made the request (the http vantage, per
  CAR-Relations — not the server).
- **TerminalServices-LocalSessionManager 21/24/25 → user_session**: RDP/console
  session logon / disconnect / reconnect, carrying the user and the source
  Address (the remote IP for RDP; "LOCAL" for console — recorded as a null
  src_ip, honest).

These channels use the `UserData` payload shape (one nested child dict), read
with the `userdata()` marker; BITS uses the ordinary EventData.Data shape.

Note deliberately NOT mapped: System 7040 (service start-type changed) — the CAR
service object has no `modify`/config-change action (create/delete/pause/start/
stop only), so forcing it would fake an action. It stays raw.
"""
from __future__ import annotations


def evtxx_is_bits_transfer(rec) -> bool:
    return (rec.get("EventId") in (59, 60)
            and "Bits-Client" in str(rec.get("Channel", "")))


def evtxx_is_ts_session(rec) -> bool:
    return (rec.get("EventId") in (21, 24, 25)
            and "TerminalServices-LocalSessionManager" in str(rec.get("Channel", "")))


PREDICATES = {
    "evtxx_is_bits_transfer": evtxx_is_bits_transfer,
    "evtxx_is_ts_session": evtxx_is_ts_session,
}

"""(Re)generate the committed exemplar parity fixtures.

The records are extracted from the existing unit tests (tests/test_car.py's
inline _SEC_4624 family, tests/test_car_zeek_conn.py's _SF family) plus
reader edge cases (BOM, trailing commas, bad lines, '['/']' wrappers) and the
zeek edge shapes stage B must prove (epoch-float ts, ISO ts, naive/offset ts,
missing counters, string-typed duration).

    python tests/parity/gen_fixtures.py     # rewrites tests/parity/fixtures/*
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")


def _sec(event_id: int, payload_data: list[dict], **extra) -> dict:
    rec = {"EventId": event_id, "Channel": "Security",
           "Computer": "HOST1.example.com", "EventRecordId": 14,
           "TimeCreated": "2019-01-28T19:40:32+00:00", "UserName": "x",
           "Payload": json.dumps({"EventData": {"Data": payload_data}})}
    rec.update(extra)
    return rec


_SEC_4624 = _sec(4624, [
    {"@Name": "TargetUserName", "#text": "Steve"},
    {"@Name": "TargetUserSid", "#text": "S-1-5-21-1-2-3-1001"},
    {"@Name": "TargetDomainName", "#text": "DESKTOP-8"},
    {"@Name": "SubjectUserName", "#text": "-"},
    {"@Name": "AuthenticationPackageName", "#text": "Negotiate  "},
    {"@Name": "LogonProcessName", "#text": "User32"},
    {"@Name": "WorkstationName", "#text": "DESKTOP-8"},
    {"@Name": "TargetLogonId", "#text": "0x338F0"},
    {"@Name": "LogonType", "#text": "2"},
    {"@Name": "IpAddress", "#text": "-"},
    {"@Name": "ProcessId", "#text": "0x244"},
    {"@Name": "ProcessName", "#text": "C:\\Windows\\System32\\svchost.exe"},
])

_SEC_4625 = _sec(4625, [
    {"@Name": "TargetUserName", "#text": "admin"},
    {"@Name": "SubjectUserName", "#text": "NT AUTHORITY\\SYSTEM"},
    {"@Name": "Status", "#text": "0xC000006D"},
    {"@Name": "SubStatus", "#text": "0xC0000064"},
    {"@Name": "FailureReason", "#text": "%%2313"},
    {"@Name": "WorkstationName", "#text": ""},
], EventRecordId=15)

_SEC_4672 = _sec(4672, [
    {"@Name": "SubjectUserName", "#text": "SYSTEM"},
    {"@Name": "SubjectUserSid", "#text": "S-1-5-18"},
    {"@Name": "SubjectDomainName", "#text": "NT AUTHORITY"},
    {"@Name": "SubjectLogonId", "#text": "0x3E7"},
    {"@Name": "PrivilegeList", "#text": "SeDebugPrivilege, SeTcbPrivilege"},
], EventRecordId=16)

_SEC_4688 = _sec(4688, [{"@Name": "NewProcessName", "#text": "C:\\x.exe"}],
                 EventRecordId=17)
_SEC_4648 = _sec(4648, [{"@Name": "TargetUserName", "#text": "admin"}],
                 EventRecordId=18)

_HTTP_GET = {"ts": "2012-07-09T17:51:46.593202Z", "uid": "Cabc", "trans_depth": 1,
             "id.orig_h": "10.0.0.5", "id.resp_h": "1.2.3.4", "id.orig_p": 1024,
             "id.resp_p": 80, "method": "GET", "host": "www.example.com",
             "uri": "/x?q=1", "version": "1.1", "user_agent": "UA",
             "request_body_len": 0, "response_body_len": 100, "status_code": 200,
             "referrer": "-", "username": "jd@corp"}

_SF = {"ts": "2012-07-09T17:50:11.834184Z", "uid": "CtEReq24zLXEGt4V67",
       "id.orig_h": "10.10.1.116", "id.orig_p": 49207,
       "id.resp_h": "172.16.1.20", "id.resp_p": 80,
       "proto": "tcp", "service": "http", "duration": 1.5,
       "orig_bytes": 350, "resp_bytes": 4200, "conn_state": "SF",
       "local_orig": True, "local_resp": False, "missed_bytes": 0,
       "history": "ShADadFf", "orig_pkts": 6, "orig_ip_bytes": 590,
       "resp_pkts": 5, "resp_ip_bytes": 4400, "ip_proto": 6}


def _write(name: str, manifest: dict, lines: list[bytes]) -> None:
    d = os.path.join(FIX, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
        fh.write("\n")
    with open(os.path.join(d, manifest["input"]), "wb") as fh:
        fh.write(b"".join(lines))
    print(f"wrote fixtures/{name} ({len(lines)} raw lines)")


def j(rec) -> bytes:
    return json.dumps(rec).encode("utf-8")


def main() -> int:
    # --- core_evtx_security: the map exemplar + every reader edge -----------
    _write("core_evtx_security",
           {"artefacts": ["evtx_security"], "host": None,
            "adapter": "none", "input": "input.jsonl"},
           [b"\xef\xbb\xbf[\n",                    # BOM + '[' wrapper line
            j(_SEC_4624) + b",\n",                 # trailing comma
            j(_SEC_4625) + b",,\n",                # several trailing commas
            b"  " + j(_SEC_4672) + b"  \n",        # padded line
            b"{not json\n",                        # bad line: skipped silently
            b"\n   \n",                            # blank / whitespace lines
            j(_SEC_4688) + b"\n",                  # matched by no variant: dropped
            j(_SEC_4648) + b"\n",                  # deliberately unmapped: dropped
            b"]\n"])                               # ']' wrapper line

    # --- zeek_http: origin/tunnel variants + host fallback ------------------
    _write("zeek_http",
           {"artefacts": ["zeek_http"], "host": "vantage1",
            "adapter": "none", "input": "input.jsonl"},
           [j(_HTTP_GET) + b"\n",
            j(dict(_HTTP_GET, method="post", uid="Cpost", status_code=302)) + b"\n",
            j(dict(_HTTP_GET, method="CONNECT", uid="Ctun", host="proxy:443",
                   uri="proxy:443")) + b"\n",
            j(dict(_HTTP_GET, method="HEAD", uid="Chead")) + b"\n",     # dropped
            j(dict(_HTTP_GET, ts=1341856306.5, uid="Cepoch")) + b"\n",  # epoch ts
            j({"uid": "Cnometh", "trans_depth": 2}) + b"\n",            # dropped
            j(dict(_HTTP_GET, uid="Cnohost", host=None)) + b"\n"])      # url_full voided

    # --- zeek_conn: the mutating predicate + every ts/counter edge ----------
    _write("zeek_conn",
           {"artefacts": ["zeek_conn"], "host": "capture1",
            "adapter": "none", "input": "input.jsonl"},
           [j(_SF) + b"\n",
            j({"ts": "2012-07-09T17:50:11.834184Z", "uid": "C3b4",
               "id.orig_h": "10.10.1.107", "id.orig_p": 137,
               "id.resp_h": "10.10.1.255", "id.resp_p": 137,
               "proto": "udp", "service": "dns", "conn_state": "S0",
               "missed_bytes": 0, "history": "D", "orig_pkts": 1,
               "orig_ip_bytes": 78, "resp_pkts": 0, "resp_ip_bytes": 0,
               "ip_proto": 17}) + b"\n",                                # S0: no dur
            j(dict(_SF, uid="Cep", ts=1341856211.834184)) + b"\n",      # epoch float
            j(dict(_SF, uid="Cstrdur", duration="1.5")) + b"\n",        # STRING dur
            j(dict(_SF, uid="Cintdur", duration=5)) + b"\n",            # int dur
            j({k: v for k, v in dict(_SF, uid="Cnopkts").items()
               if k not in ("orig_pkts", "resp_pkts")}) + b"\n",        # no counters
            j(dict(_SF, uid="Cfloatpkts", orig_pkts=1.5)) + b"\n",      # float counter
            j(dict(_SF, uid="Coth", conn_state="OTH")) + b"\n",         # → message
            j(dict(_SF, uid="Crej", conn_state="REJ")) + b"\n",         # → end
            j(dict(_SF, uid="Cempty", conn_state="")) + b"\n",          # dropped
            j({k: v for k, v in dict(_SF, uid="Cnostate").items()
               if k != "conn_state"}) + b"\n",                          # dropped
            j(dict(_SF, uid="Cnaive", ts="2012-07-09T17:50:11.834184")) + b"\n",
            j(dict(_SF, uid="Coffset", ts="2012-07-09T17:50:11.834184+01:00")) + b"\n",
            j(dict(_SF, uid="Cfrac5", ts="2012-07-09T17:50:11.83418Z")) + b"\n",
            j(dict(_SF, uid="Cbadts", ts="not a time")) + b"\n"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

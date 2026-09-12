"""Parity vectors + fixtures for the `zeek_conn` family
(byakugan/mappings/zeek_conn.py — the conn.log map and its MUTATING gate).

zeek_conn_has_state stamps _zc_end_time (ts + duration, ISO-Z, µs-rounded) and
_zc_packet_count (int(orig_pkts + resp_pkts), type-gated: string counters do
not count) onto the record BEFORE resolve runs, so every case records the
record's post-state as well as the verdict.

    python tests/parity/genf/zeek_conn.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/zeek_conn.json
    tests/parity/fixtures/zeek_conn/
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "zeek_conn"

# a minimal state-bearing record: the predicate only reads conn_state, ts,
# duration and the two packet counters.
_MIN = {"ts": "2012-07-09T17:50:11.834184Z", "uid": "C1", "duration": 1.5,
        "orig_pkts": 6, "resp_pkts": 5, "conn_state": "SF"}

PREDICATE_CASES = [
    ("zeek_conn_has_state", dict(_MIN)),                            # ISO Z + float dur
    ("zeek_conn_has_state", dict(_MIN, ts=1341856211.834184)),      # epoch float
    ("zeek_conn_has_state", dict(_MIN, ts="1341856211.834184")),    # epoch string
    ("zeek_conn_has_state", dict(_MIN, duration=5)),                # int duration
    ("zeek_conn_has_state", dict(_MIN, duration="1.5")),            # STRING dur: no stamp
    ("zeek_conn_has_state", {k: v for k, v in _MIN.items() if k != "duration"}),
    ("zeek_conn_has_state", dict(_MIN, ts="2012-07-09T17:50:11.834184")),  # naive → no Z
    ("zeek_conn_has_state", dict(_MIN, ts="2012-07-09T17:50:11.834184+01:00")),
    ("zeek_conn_has_state", dict(_MIN, ts="2012-07-09T17:50:11.834")),     # 3-digit frac
    ("zeek_conn_has_state", dict(_MIN, ts="2012-07-09T17:50:11.83418Z")),  # 5 digits → invalid
    ("zeek_conn_has_state", dict(_MIN, ts="2012-07-09 17:50:11Z")),        # space sep OK (any sep)
    ("zeek_conn_has_state", dict(_MIN, ts="not a time")),
    ("zeek_conn_has_state", dict(_MIN, ts=None)),
    ("zeek_conn_has_state", dict(_MIN, duration=0.123456789)),      # µs round-half-even
    ("zeek_conn_has_state", dict(_MIN, duration=-1.25)),            # negative delta
    ("zeek_conn_has_state", {"conn_state": "S0", "ts": "2012-07-09T17:50:11.834184Z",
                             "orig_pkts": 1, "resp_pkts": 0}),
    ("zeek_conn_has_state", {"conn_state": "SF", "ts": "2012-07-09T17:50:11Z",
                             "duration": 2, "orig_pkts": 1.5}),    # float counter → trunc
    ("zeek_conn_has_state", {"conn_state": "SF", "orig_pkts": "6", "resp_pkts": 5}),  # str not counted
    ("zeek_conn_has_state", {"conn_state": "SF", "orig_pkts": True, "resp_pkts": 2}),  # bool is int
    ("zeek_conn_has_state", {"conn_state": "SF"}),                 # no counters, no stamp
    ("zeek_conn_has_state", {"conn_state": ""}),                   # falsy state
    ("zeek_conn_has_state", {}),
    ("zeek_conn_has_state", {"conn_state": "SF", "_zc_end_time": "preset",
                             "_zc_packet_count": 9, "ts": 1.0, "duration": 1.0}),  # already stamped
]

# the full conn.log row from tests/test_car_zeek_conn.py
_SF = {"ts": "2012-07-09T17:50:11.834184Z", "uid": "CtEReq24zLXEGt4V67",
       "id.orig_h": "10.10.1.116", "id.orig_p": 49207,
       "id.resp_h": "172.16.1.20", "id.resp_p": 80,
       "proto": "tcp", "service": "http", "duration": 1.5,
       "orig_bytes": 350, "resp_bytes": 4200, "conn_state": "SF",
       "local_orig": True, "local_resp": False, "missed_bytes": 0,
       "history": "ShADadFf", "orig_pkts": 6, "orig_ip_bytes": 590,
       "resp_pkts": 5, "resp_ip_bytes": 4400, "ip_proto": 6}

j = _lib.j


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    # --- zeek_conn: the mutating predicate + every ts/counter edge ----------
    _lib.write_fixture("zeek_conn",
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

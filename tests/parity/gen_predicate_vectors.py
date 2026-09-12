"""Generate the predicate parity vectors for the stage-B exemplar families
(mappings/core.py, mappings/zeek_conn.py) — each case records the REAL
Python predicate's verdict AND the record's post-state (zeek_conn_has_state
MUTATES the record: _zc_end_time / _zc_packet_count stamps).

    python tests/parity/gen_predicate_vectors.py   # writes go/internal/predicates/testdata/predicate_vectors.json
"""
from __future__ import annotations

import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from byakugan import mappings  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "..", "go", "internal", "predicates", "testdata",
                   "predicate_vectors.json")

_SF = {"ts": "2012-07-09T17:50:11.834184Z", "uid": "C1", "duration": 1.5,
       "orig_pkts": 6, "resp_pkts": 5, "conn_state": "SF"}

CASES = [
    # --- core.py: evtx_security gates ---------------------------------------
    ("is_sec_4624", {"EventId": 4624, "Channel": "Security"}),
    ("is_sec_4624", {"EventId": 4624, "Channel": "Microsoft-Windows-Security-Auditing"}),
    ("is_sec_4624", {"EventId": 4624, "Channel": "System"}),
    ("is_sec_4624", {"EventId": "4624", "Channel": "Security"}),   # str ≠ int
    ("is_sec_4624", {"EventId": 4624.0, "Channel": "Security"}),   # float == int
    ("is_sec_4624", {"EventId": 4624}),                            # Channel absent → ""
    ("is_sec_4624", {"EventId": 4624, "Channel": None}),           # str(None) = "None"
    ("is_sec_4625", {"EventId": 4625, "Channel": "Security"}),
    ("is_sec_4625", {"EventId": 4624, "Channel": "Security"}),
    ("is_sec_4672", {"EventId": 4672, "Channel": "Security"}),
    # --- core.py: zeek_http gates -------------------------------------------
    ("is_http_origin", {"method": "GET"}),
    ("is_http_origin", {"method": "post"}),
    ("is_http_origin", {"method": "Put"}),
    ("is_http_origin", {"method": "HEAD"}),
    ("is_http_origin", {"method": "CONNECT"}),
    ("is_http_origin", {}),
    ("is_http_origin", {"method": None}),          # "NONE" not in the tuple
    ("is_http_tunnel", {"method": "CONNECT"}),
    ("is_http_tunnel", {"method": "connect"}),
    ("is_http_tunnel", {"method": "GET"}),
    ("is_http_tunnel", {}),
    # --- zeek_conn.py: the mutating gate ------------------------------------
    ("zeek_conn_has_state", dict(_SF)),                            # ISO Z + float dur
    ("zeek_conn_has_state", dict(_SF, ts=1341856211.834184)),      # epoch float
    ("zeek_conn_has_state", dict(_SF, ts="1341856211.834184")),    # epoch string
    ("zeek_conn_has_state", dict(_SF, duration=5)),                # int duration
    ("zeek_conn_has_state", dict(_SF, duration="1.5")),            # STRING dur: no stamp
    ("zeek_conn_has_state", {k: v for k, v in _SF.items() if k != "duration"}),
    ("zeek_conn_has_state", dict(_SF, ts="2012-07-09T17:50:11.834184")),  # naive → no Z
    ("zeek_conn_has_state", dict(_SF, ts="2012-07-09T17:50:11.834184+01:00")),
    ("zeek_conn_has_state", dict(_SF, ts="2012-07-09T17:50:11.834")),     # 3-digit frac
    ("zeek_conn_has_state", dict(_SF, ts="2012-07-09T17:50:11.83418Z")),  # 5 digits → invalid
    ("zeek_conn_has_state", dict(_SF, ts="2012-07-09 17:50:11Z")),        # space sep OK (any sep)
    ("zeek_conn_has_state", dict(_SF, ts="not a time")),
    ("zeek_conn_has_state", dict(_SF, ts=None)),
    ("zeek_conn_has_state", dict(_SF, duration=0.123456789)),      # µs round-half-even
    ("zeek_conn_has_state", dict(_SF, duration=-1.25)),            # negative delta
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

_CACHE_KEY = "__car_parsed_payload__"


def main() -> int:
    cases = []
    for name, rec in CASES:
        after = copy.deepcopy(rec)
        result = mappings.PREDICATES[name](after)
        after.pop(_CACHE_KEY, None)
        cases.append({"predicate": name, "rec": rec, "result": result,
                      "rec_after": after})
    out_path = os.path.abspath(OUT)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"cases": cases}, fh, indent=1)
        fh.write("\n")
    print(f"wrote {out_path} ({len(cases)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

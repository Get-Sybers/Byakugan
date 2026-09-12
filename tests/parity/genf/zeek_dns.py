"""Parity vectors + fixtures for the `zeek_dns` family
(byakugan/mappings/zeek_dns.py — dns.log → flow, and its one gate).

zeek_dns_is_query is `bool(rec.get("query"))`: PLAIN Python truthiness, so ""
/ 0 / [] / {} / False / None / absent decline while "-" (a non-empty string)
CLAIMS — the resolver's blank rule ("-" is blank) is a separate layer and does
not apply to the gate. The fixture carries a "-" query row so the two layers
are pinned end to end: the row maps, and its `fqdn` prop is the literal "-"
(a plain field name resolves to rec.get(), unfiltered).

The guid is `flow-<uid>-<trans_id>` (a fields-guid): a None component voids the
whole guid, while "" and "-" are legitimate identity values that are str()'d
into the join — hence the absent-trans_id and 0-trans_id rows.

    python tests/parity/genf/zeek_dns.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/zeek_dns.json
    tests/parity/fixtures/zeek_dns/
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "zeek_dns"

# ---------------------------------------------------------------------------
# predicate vectors — zeek_dns_is_query: bool(rec.get("query"))
# ---------------------------------------------------------------------------
PREDICATE_CASES = [
    ("zeek_dns_is_query", {"query": "scoring-c2.berylia.org"}),
    ("zeek_dns_is_query", {"query": "a.example", "trans_id": 1}),
    ("zeek_dns_is_query", {"query": "-"}),        # non-empty str -> TRUE (not _blank)
    ("zeek_dns_is_query", {"query": " "}),        # whitespace is non-empty
    ("zeek_dns_is_query", {"query": ""}),
    ("zeek_dns_is_query", {"query": None}),
    ("zeek_dns_is_query", {}),                    # absent
    ("zeek_dns_is_query", {"query": 0}),          # int falsy
    ("zeek_dns_is_query", {"query": 1}),
    ("zeek_dns_is_query", {"query": 0.0}),        # float falsy
    ("zeek_dns_is_query", {"query": 1.5}),
    ("zeek_dns_is_query", {"query": False}),      # bool falsy
    ("zeek_dns_is_query", {"query": True}),
    ("zeek_dns_is_query", {"query": []}),         # empty list falsy
    ("zeek_dns_is_query", {"query": ["a.example"]}),
    ("zeek_dns_is_query", {"query": {}}),         # empty dict falsy
    ("zeek_dns_is_query", {"query": {"a": 1}}),
    ("zeek_dns_is_query", {"Query": "case-sensitive"}),   # wrong-case key: absent
]

# ---------------------------------------------------------------------------
# fixture — the dns.log rows of tests/test_car_zeek_dns.py, verbatim, plus the
# type/shape edges the module docstring implies (epoch vs ISO ts, the uid+
# trans_id join, dotted id.* literal keys, the answers evidence list).
# ---------------------------------------------------------------------------
_DNS = {"ts": "2024-04-21T06:35:26.141718Z", "uid": "CEVUbS3iLfbmi3l6Yi",
        "id.orig_h": "10.0.0.5", "id.orig_p": 49389,
        "id.resp_h": "10.0.0.1", "id.resp_p": 53, "proto": "udp",
        "trans_id": 23150, "query": "scoring-c2.berylia.org",
        "qtype_name": "A", "rcode_name": "NOERROR", "answers": ["100.101.0.42"]}

j = _lib.j


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    _lib.write_fixture("zeek_dns",
                       {"artefacts": ["zeek_dns"], "host": "cap",
                        "adapter": "none", "input": "input.jsonl"},
                       [j(_DNS) + b"\n",
                        # two queries on ONE connection stay distinct rows
                        j(dict(_DNS, trans_id=1, query="a.example")) + b"\n",
                        j(dict(_DNS, trans_id=2, query="b.example")) + b"\n",
                        # a CNAME answer (enrich ignores it; normalize keeps it)
                        j(dict(_DNS, trans_id=3, query="www.example.com",
                               answers=["cdn.example.net"])) + b"\n",
                        # --- ts variants ------------------------------------
                        j(dict(_DNS, trans_id=4, ts=1341856306.5)) + b"\n",
                        j(dict(_DNS, trans_id=5, ts="1341856306.5")) + b"\n",
                        j(dict(_DNS, trans_id=6, ts=1341856306)) + b"\n",
                        j(dict(_DNS, trans_id=7, ts="1970-01-01T00:00:00Z")) + b"\n",
                        j(dict(_DNS, trans_id=8, ts="-")) + b"\n",
                        j({k: v for k, v in dict(_DNS, trans_id=9).items()
                           if k != "ts"}) + b"\n",
                        # --- the fields-guid edges --------------------------
                        j({k: v for k, v in dict(_DNS, query="no.transid").items()
                           if k != "trans_id"}) + b"\n",        # guid voided
                        j(dict(_DNS, trans_id=0, query="zero.transid")) + b"\n",
                        j(dict(_DNS, trans_id="23150", query="str.transid")) + b"\n",
                        j(dict(_DNS, trans_id=11, uid="")) + b"\n",   # "" is a legit part
                        # --- the gate edges ---------------------------------
                        j(dict(_DNS, trans_id=12, query="-")) + b"\n",   # claims; fqdn "-"
                        j(dict(_DNS, trans_id=13, query="")) + b"\n",    # dropped
                        j({k: v for k, v in dict(_DNS, trans_id=14).items()
                           if k != "query"}) + b"\n",                    # dropped
                        j(dict(_DNS, trans_id=15, query=None)) + b"\n",  # dropped
                        # --- sparse / absent props --------------------------
                        j({"ts": "2024-04-21T06:35:26.141718Z", "uid": "Cbare",
                           "trans_id": 16, "query": "bare.example"}) + b"\n",
                        j(dict(_DNS, trans_id=17, proto=None, answers=[],
                               qtype_name="", rcode_name="-")) + b"\n"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

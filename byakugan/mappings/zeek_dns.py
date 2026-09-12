"""Zeek dns.log → CAR flow (B2).

Zeek's non-conn logs are per-connection detail records: each dns.log entry
shares the `uid` of the conn.log flow that carried the query (a UDP/TCP :53
connection). So a DNS record is a granular view OF a flow — mapped to `flow`
with the connection 5-tuple and, decisively, the queried **name** in `fqdn` and
the resolved **answers** kept in native.

The payoff is the domain↔IP resolution: `enrich._dns_resolution` reads the
(query → answer IPs) pairs and stamps `dest_fqdn`/`src_fqdn` on every flow whose
endpoint IP that query resolved — so a bare connection to `100.101.0.42` becomes
a connection to `scoring-c2.berylia.org` (the C2 chain the value hunt found,
which no CAR field carried). Normalisation only here; the stamping is enrich's.

`guid` is `flow-<uid>-<trans_id>` — the connection `uid` (shared with the
conn/http/… events of the SAME connection, run-scoped and never equated across
runs) PLUS the DNS transaction id, because one UDP :53 connection carries many
queries and `uid` alone would fold distinct resolutions into one row. The `uid`
still ties each DNS row back to its conn `flow`/end row — two honest facets of
one connection.
"""
from __future__ import annotations

from ..normalize import const, epoch_ts  # noqa: F401


def zeek_dns_is_query(rec) -> bool:
    """A dns.log row is CAR-worthy once it names a query (the resolved name);
    a malformed row with no query stays raw."""
    return bool(rec.get("query"))


PREDICATES = {"zeek_dns_is_query": zeek_dns_is_query}

MAPPINGS = {
    "zeek_dns": {
        "variants": [
            ("zeek_dns_is_query", {
                "object": "flow",
                # a DNS query/response is an observation of the connection, not
                # its start or teardown -> the flow `message` action
                "action": const("message"),
                "ts": epoch_ts("ts"),
                # a DNS transaction identity: the connection uid + the DNS
                # transaction id, because one UDP :53 connection carries MANY
                # queries — uid alone would fold distinct resolutions into one
                # (mirrors zeek_http's uid+trans_depth). uid still ties it to the
                # conn flow; trans_id keeps each query/answer a distinct row.
                "guid": {"fields": ["uid", "trans_id"]},
                "props": {
                    # the 5-tuple, src = originator (the querying client)
                    "src_ip": "id.orig_h", "src_port": "id.orig_p",
                    "dest_ip": "id.resp_h", "dest_port": "id.resp_p",
                    "transport_protocol": "proto",
                    "application_protocol": const("dns"),
                    # the queried name this flow resolves — the domain half of the
                    # domain↔IP map enrich builds
                    "fqdn": "query",
                    "start_time": epoch_ts("ts"),
                },
                # the resolution evidence + join key: uid (flow↔conn), the answers
                # (the IP half of the map), and the query metadata
                "keep": ["uid", "query", "qtype_name", "rcode_name", "answers",
                         "trans_id"],
            }),
        ],
        "default": None,   # no query → no canonical flow → stays raw
    },
}

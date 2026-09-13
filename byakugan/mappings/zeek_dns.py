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


def zeek_dns_is_query(rec) -> bool:
    """A dns.log row is CAR-worthy once it names a query (the resolved name);
    a malformed row with no query stays raw."""
    return bool(rec.get("query"))


PREDICATES = {"zeek_dns_is_query": zeek_dns_is_query}

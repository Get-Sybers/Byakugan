"""Zeek ssl.log → CAR flow (B2).

ssl.log is the TLS-handshake view of a connection: ONE record per TLS
connection (verified against the real corpus — every `uid` appears exactly
once, unlike dns/http which are many-per-conn), sharing the conn `uid`. So an
ssl record is a granular, encrypted-flow view OF a flow — mapped to `flow` with
the connection 5-tuple and, decisively, the requested **SNI** in `dest_fqdn`.

`server_name` (the SNI) is the other half of the DNS work: dns.log gave the
domain↔IP resolution (enrich stamps the resolved domain onto a bare flow by
IP); the SNI gives the domain DIRECTLY on the encrypted flow — the host the
client asked for by name on THIS connection, no resolution inference needed.
So the connection to `100.101.0.42` reads as `scoring-c2.berylia.org` from its
own TLS handshake (the C2 chain the value hunt found; cert/SNI both name it).

`guid` is the Zeek `uid` itself (`{"field": "uid"}`) — the sensor-minted
connection identity conn/dns/http/files all share, run-scoped and never equated
across runs (the registry's `zeek_uid` external form, already carried by
zeek_conn). uid alone is a correct identity here because ssl.log is 1:1 with the
connection (dns/http compose uid+trans_id/trans_depth precisely because they are
NOT). The ssl flow and the conn flow are two honest facets of one connection:
they share the guid, and where their car_action agrees the fold merges them.

Normalisation ONLY — the SNI-onto-conn stamping (dest_fqdn by shared uid) is
enrich's, mirroring the DNS fqdn stamping.
"""
from __future__ import annotations


def zeek_ssl_is_tls(rec) -> bool:
    """An ssl.log row is CAR-worthy once it identifies the TLS connection it
    observed — a `uid` (the flow it IS) or the requested `server_name` (the
    SNI). A malformed row with neither stays raw."""
    return bool(rec.get("uid") or rec.get("server_name"))


PREDICATES = {"zeek_ssl_is_tls": zeek_ssl_is_tls}

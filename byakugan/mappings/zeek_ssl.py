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

from ..normalize import const, epoch_ts, first  # noqa: F401


def zeek_ssl_is_tls(rec) -> bool:
    """An ssl.log row is CAR-worthy once it identifies the TLS connection it
    observed — a `uid` (the flow it IS) or the requested `server_name` (the
    SNI). A malformed row with neither stays raw."""
    return bool(rec.get("uid") or rec.get("server_name"))


PREDICATES = {"zeek_ssl_is_tls": zeek_ssl_is_tls}

MAPPINGS = {
    "zeek_ssl": {
        "variants": [
            ("zeek_ssl_is_tls", {
                "object": "flow",
                # a TLS handshake is an observation of the connection, not its
                # start or teardown -> the flow `message` action (as zeek_dns)
                "action": const("message"),
                "ts": epoch_ts("ts"),
                # the sensor-minted connection identity — run-scoped; shared
                # verbatim with the conn/dns/http/files events of the SAME
                # connection. uid alone is correct: ssl.log is 1:1 with the
                # connection (dns/http need uid+trans_id/depth; ssl does not).
                "guid": {"field": "uid"},
                "props": {
                    # the 5-tuple, src = originator (the connecting client)
                    "src_ip": "id.orig_h", "src_port": "id.orig_p",
                    "dest_ip": "id.resp_h", "dest_port": "id.resp_p",
                    # ssl.log carries no `proto` (TLS is TCP by definition — the
                    # real records are all TCP:443 with no proto field); prefer
                    # the sensor's own value where a config emits it, else assert
                    # the tcp the TLS handshake proves.
                    "transport_protocol": first("proto", const("tcp")),
                    "application_protocol": const("tls"),
                    # THE decisive datum: the SNI — the host the client asked for
                    # by name on this encrypted flow (the domain half, direct on
                    # the flow, that DNS gives only via the IP resolution).
                    "dest_fqdn": "server_name",
                    "start_time": epoch_ts("ts"),
                },
                # native evidence + the join key: uid (flow↔conn/http/files), the
                # raw SNI, and the TLS handshake metadata that has no CAR home —
                # version/cipher/curve/next_protocol, the cert-chain fingerprints
                # and validation, the JA3/JA3S fingerprints. Only present fields
                # are kept, so both this Zeek's names (ssl_history, cert_chain_fps,
                # sni_matches_cert) and classic names (ja3, validation_status,
                # cert_chain_fuids) are covered forward-compatibly.
                "keep": ["uid", "server_name", "version", "cipher", "curve",
                         "next_protocol", "resumed", "established", "ssl_history",
                         "cert_chain_fps", "cert_chain_fuids",
                         "client_cert_chain_fps", "sni_matches_cert",
                         "ja3", "ja3s", "validation_status"],
            }),
        ],
        "default": None,   # no uid and no SNI → no canonical flow → stays raw
    },
}

"""Zeek ssl.log -> flow, and the SNI-onto-connection enrichment (B2).

An ssl.log record is the TLS-handshake view of a connection (one record per
connection, sharing the conn uid): mapped to `flow` with the connection 5-tuple
and, decisively, the requested SNI (`server_name`) in `dest_fqdn` — the host the
client asked for by name on the encrypted flow. enrich then stamps that SNI onto
the bare conn flow of the same uid, so the connection to 100.101.0.42 reads as
scoring-c2.berylia.org from its own TLS handshake (the other half of the DNS
work: DNS gives domain↔IP, the SNI gives the domain directly on the flow).
"""
from piiat_mitrecar import enrich, normalize

# a real ssl.json record shape (DFIRdump FOR_200 capture): the berylia.org C2
_SSL = {"ts": "2024-04-21T06:34:48.868246Z", "uid": "CfPiyA3iI3URMDMEfd",
        "id.orig_h": "10.27.33.61", "id.orig_p": 43532,
        "id.resp_h": "100.101.0.42", "id.resp_p": 443,
        "version": "TLSv12", "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "curve": "x25519", "server_name": "scoring-c2.berylia.org",
        "resumed": False, "next_protocol": "h2", "established": True,
        "ssl_history": "CsxknGIi",
        "cert_chain_fps": ["bac9e9e2d4e38c7716fc17dcd701dd45e226cd9b623f21e9a145921fb5b6dc4d"],
        "client_cert_chain_fps": [], "sni_matches_cert": True}


def test_ssl_record_maps_to_a_flow_with_the_sni_in_dest_fqdn():
    ev = normalize.normalize("zeek_ssl", dict(_SSL))
    assert ev["car_object"] == "flow" and ev["car_action"] == "message"
    assert ev["application_protocol"] == "tls"
    # THE decisive datum: the SNI is the destination fqdn on the encrypted flow
    assert ev["dest_fqdn"] == "scoring-c2.berylia.org"
    # the 5-tuple, src = originator (the connecting client)
    assert ev["src_ip"] == "10.27.33.61" and ev["src_port"] == 43532
    assert ev["dest_ip"] == "100.101.0.42" and ev["dest_port"] == 443
    # TLS is TCP by definition — asserted where ssl.log carries no `proto`
    assert ev["transport_protocol"] == "tcp"
    # ssl.log is 1:1 with the connection -> guid is the uid directly (the
    # zeek_uid external form conn/http/files also carry)
    assert ev["guid"] == "CfPiyA3iI3URMDMEfd"
    # the TLS handshake evidence with no CAR home is kept in native
    nat = ev["_native"] or {}
    assert nat["version"] == "TLSv12" and nat["server_name"] == "scoring-c2.berylia.org"
    assert nat["cipher"] == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert nat["uid"] == "CfPiyA3iI3URMDMEfd"          # the flow↔conn join key


def test_transport_protocol_prefers_a_present_proto():
    ev = normalize.normalize("zeek_ssl", dict(_SSL, proto="tcp"))
    assert ev["transport_protocol"] == "tcp"           # the sensor's own value when present


def test_a_row_with_neither_uid_nor_sni_stays_raw():
    assert normalize.normalize("zeek_ssl", {"ts": "2024-04-21T06:34:48Z"}) is None


def test_enrich_stamps_the_sni_onto_the_connection_by_uid():
    ssl = normalize.normalize("zeek_ssl", dict(_SSL))
    ssl["source_host"] = "cap"
    # the bare conn flow of the SAME connection (shared uid) — no fqdn of its own,
    # a terminal action so it does not fold with the ssl `message` row
    conn = {"car_object": "flow", "car_action": "end", "guid": "CfPiyA3iI3URMDMEfd",
            "source_host": "cap", "timestamp": "2024-04-21T06:34:50Z",
            "dest_ip": "100.101.0.42", "dest_port": 443, "_native": {"uid": "CfPiyA3iI3URMDMEfd"}}
    out = enrich.enrich([conn, ssl])
    c = next(e for e in out if e["car_action"] == "end")
    assert c["dest_fqdn"] == "scoring-c2.berylia.org"  # the C2 chain, now on the conn flow
    # the ssl flow keeps its own SNI too
    s = next(e for e in out if e["car_action"] == "message")
    assert s["dest_fqdn"] == "scoring-c2.berylia.org"


def test_enrich_never_overwrites_an_existing_dest_fqdn():
    ssl = normalize.normalize("zeek_ssl", dict(_SSL))
    ssl["source_host"] = "cap"
    conn = {"car_object": "flow", "car_action": "end", "guid": "CfPiyA3iI3URMDMEfd",
            "source_host": "cap", "timestamp": "2024-04-21T06:34:50Z",
            "dest_ip": "100.101.0.42", "dest_fqdn": "already.example",
            "_native": {"uid": "CfPiyA3iI3URMDMEfd"}}
    out = enrich.enrich([conn, ssl])
    c = next(e for e in out if e["car_action"] == "end")
    assert c["dest_fqdn"] == "already.example"         # fill-only-null

"""Zeek dns.log -> flow, and the domain↔IP resolution enrichment (B2).

A DNS record is a granular view of its conn flow (shared uid): mapped to `flow`
with the queried name in `fqdn` and the answers in native. enrich then reads the
(query -> answer IPs) pairs and labels every flow to/from a resolved IP — so the
bare connection to 100.101.0.42 reads as scoring-c2.berylia.org (the C2 chain
the value hunt found, which no CAR field carried).
"""
from piiat_mitrecar import enrich, normalize

_DNS = {"ts": "2024-04-21T06:35:26.141718Z", "uid": "CEVUbS3iLfbmi3l6Yi",
        "id.orig_h": "10.0.0.5", "id.orig_p": 49389,
        "id.resp_h": "10.0.0.1", "id.resp_p": 53, "proto": "udp",
        "trans_id": 23150, "query": "scoring-c2.berylia.org",
        "qtype_name": "A", "rcode_name": "NOERROR", "answers": ["100.101.0.42"]}


def test_dns_record_maps_to_a_flow_with_the_query_and_answers():
    ev = normalize.normalize("zeek_dns", dict(_DNS))
    assert ev["car_object"] == "flow" and ev["car_action"] == "message"
    assert ev["application_protocol"] == "dns"
    assert ev["fqdn"] == "scoring-c2.berylia.org"          # the queried name
    assert ev["dest_ip"] == "10.0.0.1" and ev["dest_port"] == 53
    assert (ev["_native"] or {})["answers"] == ["100.101.0.42"]   # the resolution evidence
    # transaction identity = uid + trans_id (not uid alone) so queries stay distinct
    assert ev["guid"] == "flow-CEVUbS3iLfbmi3l6Yi-23150"


def test_two_queries_on_one_connection_are_distinct_rows():
    a = normalize.normalize("zeek_dns", dict(_DNS, trans_id=1, query="a.example"))
    b = normalize.normalize("zeek_dns", dict(_DNS, trans_id=2, query="b.example"))
    assert a["guid"] != b["guid"]                          # not folded into one


def test_enrich_stamps_the_resolved_domain_onto_the_connection():
    dns = normalize.normalize("zeek_dns", dict(_DNS))
    dns["source_host"] = "cap"
    # a bare conn flow to the resolved IP — no fqdn of its own
    conn = {"car_object": "flow", "car_action": "end", "guid": "conn-1",
            "source_host": "cap", "timestamp": "2024-04-21T06:35:27Z",
            "dest_ip": "100.101.0.42", "dest_port": 443}
    out = enrich.enrich([dns, conn])
    c = next(e for e in out if e["guid"] == "conn-1")
    assert c["dest_fqdn"] == "scoring-c2.berylia.org"      # the C2 chain, now queryable


def test_enrich_ignores_cname_answers_only_ips_resolve():
    dns = normalize.normalize("zeek_dns", dict(
        _DNS, query="www.example.com", answers=["cdn.example.net"]))   # a CNAME, not an IP
    dns["source_host"] = "cap"
    conn = {"car_object": "flow", "car_action": "end", "guid": "conn-2",
            "source_host": "cap", "timestamp": "2024-04-21T06:35:27Z",
            "dest_ip": "cdn.example.net"}   # not an IP -> never a resolution key
    out = enrich.enrich([dns, conn])
    c = next(e for e in out if e["guid"] == "conn-2")
    assert c.get("dest_fqdn") is None

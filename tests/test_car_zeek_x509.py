"""Zeek x509.log -> CAR file (a TLS certificate as content), and the flow↔cert
link (B2). The cert's fingerprint IS a SHA-256, so it becomes the file's
sha256_hash — giving free content-hash convergence — and enrich surfaces the
cert subject on the TLS flow that presented it (via ssl's cert_chain_fps)."""
from byakugan import crosssource, enrich, normalize, store

_FP = "bac9e9e2d4e38c7716fc17dcd701dd45e226cd9b623f21e9a145921fb5b6dc4d"
_X509 = {"ts": "2024-04-21T06:34:48.870004Z", "fingerprint": _FP,
         "certificate.subject": "CN=berylia.org",
         "certificate.issuer": "CN=ZeroSSL RSA Domain Secure Site CA,O=ZeroSSL,C=AT",
         "certificate.serial": "D37DDCE310141EF7B1415F4C5F5B90C8",
         "certificate.not_valid_after": "2024-05-22T23:59:59.000000Z",
         "san.dns": ["berylia.org", "*.berylia.org"], "host_cert": True}


def test_x509_maps_to_a_file_with_the_fingerprint_as_sha256():
    ev = normalize.normalize("zeek_x509", dict(_X509))
    assert ev["car_object"] == "file" and ev["car_action"] == "create"
    assert ev["sha256_hash"] == _FP                    # fingerprint IS the content hash
    assert ev["guid"] == _FP                            # the cert's stable identity
    nat = ev["_native"] or {}
    assert nat["certificate.subject"] == "CN=berylia.org"
    assert nat["san.dns"] == ["berylia.org", "*.berylia.org"]


def test_cert_converges_with_matching_content_by_hash(tmp_path):
    d = str(tmp_path)
    # the cert (x509 -> file, sha256 = fingerprint)
    ev = normalize.normalize("zeek_x509", dict(_X509))
    ev["source_host"] = "cap"
    dd = f"{d}/x509"; import os; os.makedirs(dd)
    st = store.CarStore(f"{dd}/car.db"); st.insert_events([ev]); st.close()
    # the same bytes seen elsewhere (e.g. a memory-carved file of that cert)
    other = {"car_object": "file", "car_action": "create", "guid": "mem-c",
             "source_host": "cap", "timestamp": "2024-04-21T06:34:49Z",
             "file_name": "berylia.crt", "sha256_hash": _FP.upper()}
    dm = f"{d}/mem"; os.makedirs(dm)
    st = store.CarStore(f"{dm}/car.db"); st.insert_events([other]); st.close()
    hits = [c for c in crosssource.converge(d) if c["tier"] == "definitive_content"]
    assert hits and set(hits[0]["sources"]) == {"x509", "mem"}   # same cert bytes converge


def test_enrich_surfaces_the_cert_subject_on_the_tls_flow():
    cert = normalize.normalize("zeek_x509", dict(_X509))
    cert["source_host"] = "cap"
    # the TLS flow that presented it — names the fingerprint in cert_chain_fps
    ssl_flow = {"car_object": "flow", "car_action": "message", "guid": "CfPiyA",
                "source_host": "cap", "timestamp": "2024-04-21T06:34:48Z",
                "application_protocol": "tls", "dest_ip": "100.101.0.42",
                "_native": {"uid": "CfPiyA", "cert_chain_fps": [_FP]}}
    out = enrich.enrich([cert, ssl_flow])
    f = next(e for e in out if e["guid"] == "CfPiyA")
    assert (f["_native"] or {})["server_cert_subject"] == "CN=berylia.org"

"""Parity vectors + fixtures for the `zeek_ssl` family
(byakugan/mappings/zeek_ssl.py — ssl.log → flow, and its one gate).

zeek_ssl_is_tls is `bool(rec.get("uid") or rec.get("server_name"))`. Python's
`or` yields the first truthy operand else the LAST one, and bool() collapses
it, so the gate is exactly truthy(uid) OR truthy(server_name) — a row with
neither stays raw (tests/test_car_zeek_ssl.py pins that).

Two seams the fixture pins that the gate alone does not:
  * transport_protocol = first("proto", const("tcp")) — ssl.log carries no
    `proto`, so the map ASSERTS the tcp the TLS handshake proves, but prefers
    the sensor's own value where a config emits one (and a BLANK proto — ""
    or "-" — falls through to the assertion, because `first` skips blanks).
  * guid = {"field": "uid"} — the field form, so a blank uid ("", "-", None)
    voids the guid even though the row still maps via its SNI.

    python tests/parity/genf/zeek_ssl.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/zeek_ssl.json
    tests/parity/fixtures/zeek_ssl/
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "zeek_ssl"

# ---------------------------------------------------------------------------
# predicate vectors — every branch of the `or` and every type edge
# ---------------------------------------------------------------------------
PREDICATE_CASES = [
    ("zeek_ssl_is_tls", {"uid": "CfPiyA3iI3URMDMEfd",
                         "server_name": "scoring-c2.berylia.org"}),
    ("zeek_ssl_is_tls", {"uid": "CfPiyA3iI3URMDMEfd"}),          # uid alone
    ("zeek_ssl_is_tls", {"server_name": "scoring-c2.berylia.org"}),  # SNI alone
    ("zeek_ssl_is_tls", {"ts": "2024-04-21T06:34:48Z"}),         # neither -> raw
    ("zeek_ssl_is_tls", {}),
    ("zeek_ssl_is_tls", {"uid": "", "server_name": ""}),
    ("zeek_ssl_is_tls", {"uid": "", "server_name": "sni.example"}),
    ("zeek_ssl_is_tls", {"uid": "C1", "server_name": ""}),
    ("zeek_ssl_is_tls", {"uid": None, "server_name": None}),
    ("zeek_ssl_is_tls", {"uid": "-"}),          # non-empty str -> TRUE
    ("zeek_ssl_is_tls", {"server_name": "-"}),
    ("zeek_ssl_is_tls", {"uid": 0}),            # int falsy, no SNI
    ("zeek_ssl_is_tls", {"uid": 0, "server_name": "sni.example"}),
    ("zeek_ssl_is_tls", {"uid": 1}),
    ("zeek_ssl_is_tls", {"uid": False, "server_name": False}),
    ("zeek_ssl_is_tls", {"uid": True}),
    ("zeek_ssl_is_tls", {"uid": 0.0, "server_name": 0.0}),
    ("zeek_ssl_is_tls", {"uid": [], "server_name": []}),
    ("zeek_ssl_is_tls", {"uid": ["C1"]}),
    ("zeek_ssl_is_tls", {"uid": {}, "server_name": {"a": 1}}),
]

# ---------------------------------------------------------------------------
# fixture — the real ssl.json record shape (DFIRdump FOR_200 capture: the
# berylia.org C2) from tests/test_car_zeek_ssl.py, verbatim, plus the classic-
# Zeek field names the keep-list covers forward-compatibly.
# ---------------------------------------------------------------------------
_SSL = {"ts": "2024-04-21T06:34:48.868246Z", "uid": "CfPiyA3iI3URMDMEfd",
        "id.orig_h": "10.27.33.61", "id.orig_p": 43532,
        "id.resp_h": "100.101.0.42", "id.resp_p": 443,
        "version": "TLSv12", "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "curve": "x25519", "server_name": "scoring-c2.berylia.org",
        "resumed": False, "next_protocol": "h2", "established": True,
        "ssl_history": "CsxknGIi",
        "cert_chain_fps": ["bac9e9e2d4e38c7716fc17dcd701dd45e226cd9b623f21e9a145921fb5b6dc4d"],
        "client_cert_chain_fps": [], "sni_matches_cert": True}

# a "classic" ssl.log row: ja3/ja3s/validation_status/cert_chain_fuids instead
# of this Zeek's ssl_history/cert_chain_fps/sni_matches_cert.
_SSL_CLASSIC = {"ts": 1341856306.5, "uid": "Cclassic",
                "id.orig_h": "10.10.1.116", "id.orig_p": 49207,
                "id.resp_h": "172.16.1.20", "id.resp_p": 443,
                "version": "TLSv10", "cipher": "TLS_RSA_WITH_RC4_128_SHA",
                "server_name": "www.example.com", "resumed": True,
                "established": True, "cert_chain_fuids": ["Fabc", "Fdef"],
                "ja3": "e7d705a3286e19ea42f587b344ee6865",
                "ja3s": "ec74a5c51106f0419184d0dd08fb05bc",
                "validation_status": "unable to get local issuer certificate"}

j = _lib.j


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    _lib.write_fixture("zeek_ssl",
                       {"artefacts": ["zeek_ssl"], "host": "cap",
                        "adapter": "none", "input": "input.jsonl"},
                       [j(_SSL) + b"\n",
                        # the sensor's own proto wins over the asserted tcp
                        j(dict(_SSL, uid="Cproto", proto="tcp")) + b"\n",
                        j(dict(_SSL, uid="Cproto6", proto="tcp6")) + b"\n",
                        # a BLANK proto falls through to the tcp assertion
                        j(dict(_SSL, uid="Cprotoblank", proto="")) + b"\n",
                        j(dict(_SSL, uid="Cprotodash", proto="-")) + b"\n",
                        j(dict(_SSL, uid="Cprotonull", proto=None)) + b"\n",
                        # --- the gate / guid edges --------------------------
                        j({"ts": "2024-04-21T06:34:48Z"}) + b"\n",       # dropped
                        j({"ts": "2024-04-21T06:34:48Z", "uid": "",
                           "server_name": ""}) + b"\n",                  # dropped
                        j({k: v for k, v in dict(_SSL).items()
                           if k != "server_name"}) + b"\n",              # uid alone
                        j({k: v for k, v in dict(_SSL, uid="Cnosni").items()
                           if k != "server_name"}) + b"\n",
                        j({k: v for k, v in dict(_SSL).items()
                           if k != "uid"}) + b"\n",           # SNI alone: guid voided
                        j(dict(_SSL, uid="")) + b"\n",        # "" uid: guid voided
                        j(dict(_SSL, uid="-")) + b"\n",       # "-" uid: claims, guid voided
                        # --- ts variants ------------------------------------
                        j(_SSL_CLASSIC) + b"\n",                          # epoch float
                        j(dict(_SSL, uid="Cepochstr", ts="1341856306")) + b"\n",
                        j(dict(_SSL, uid="Cepochint", ts=1341856306)) + b"\n",
                        j({k: v for k, v in dict(_SSL, uid="Conts").items()
                           if k != "ts"}) + b"\n",
                        j(dict(_SSL, uid="Cts1601", ts="1601-01-01T00:00:00")) + b"\n",
                        # --- sparse / blank props ---------------------------
                        j({"ts": "2024-04-21T06:34:48.868246Z", "uid": "Cbare",
                           "server_name": "bare.example"}) + b"\n",
                        j(dict(_SSL, uid="Cblanksni", server_name="-")) + b"\n",
                        j(dict(_SSL, uid="Cfalse", resumed=True, established=False,
                               sni_matches_cert=False, next_protocol="",
                               curve=None)) + b"\n"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

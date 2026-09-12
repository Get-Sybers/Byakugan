"""Parity vectors + fixtures for the `zeek_x509` family
(byakugan/mappings/zeek_x509.py — x509.log → file, and its one gate).

zeek_x509_has_fingerprint is `bool(rec.get("fingerprint"))`. The seam the
fixture pins is the promotion that makes a cert converge: Zeek's x509
`fingerprint` IS a SHA-256 of the DER cert, so `sha256_hash = lower(fingerprint)`
— LOWERCASED, one hash format across sources — while the guid is the
fingerprint VERBATIM ({"field": "fingerprint"}, so the raw casing and the raw
TYPE survive into the identity).

The keep-list is all DOTTED LITERAL keys (`certificate.subject`, `san.dns`,
`basic_constraints.ca`): they are flat record keys containing dots, never a
nested path — the fixture proves both engines treat them as literals.

Also note `"action": "create"` is a plain STRING in the map, which normalize
treats as a LITERAL action (`if not isinstance(m["action"], str)` guards the
_resolve call) — not a field name. Every other zeek map uses const("...").

    python tests/parity/genf/zeek_x509.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/zeek_x509.json
    tests/parity/fixtures/zeek_x509/
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "zeek_x509"

_FP = "bac9e9e2d4e38c7716fc17dcd701dd45e226cd9b623f21e9a145921fb5b6dc4d"

# ---------------------------------------------------------------------------
# predicate vectors — zeek_x509_has_fingerprint: bool(rec.get("fingerprint"))
# ---------------------------------------------------------------------------
PREDICATE_CASES = [
    ("zeek_x509_has_fingerprint", {"fingerprint": _FP}),
    ("zeek_x509_has_fingerprint", {"fingerprint": _FP.upper()}),
    ("zeek_x509_has_fingerprint", {"fingerprint": "-"}),   # non-empty str -> TRUE
    ("zeek_x509_has_fingerprint", {"fingerprint": ""}),
    ("zeek_x509_has_fingerprint", {"fingerprint": None}),
    ("zeek_x509_has_fingerprint", {}),
    ("zeek_x509_has_fingerprint", {"certificate.subject": "CN=berylia.org"}),
    ("zeek_x509_has_fingerprint", {"fingerprint": 0}),
    ("zeek_x509_has_fingerprint", {"fingerprint": 12345}),
    ("zeek_x509_has_fingerprint", {"fingerprint": 0.0}),
    ("zeek_x509_has_fingerprint", {"fingerprint": 1.5}),
    ("zeek_x509_has_fingerprint", {"fingerprint": False}),
    ("zeek_x509_has_fingerprint", {"fingerprint": True}),
    ("zeek_x509_has_fingerprint", {"fingerprint": []}),
    ("zeek_x509_has_fingerprint", {"fingerprint": [_FP]}),
    ("zeek_x509_has_fingerprint", {"fingerprint": {}}),
    ("zeek_x509_has_fingerprint", {"fingerprint": {"sha256": _FP}}),
    ("zeek_x509_has_fingerprint", {"Fingerprint": _FP}),   # wrong-case key: absent
]

# ---------------------------------------------------------------------------
# fixture — the real x509.json record from tests/test_car_zeek_x509.py
# verbatim, plus a full-field cert (every keep key present) and the edges.
# ---------------------------------------------------------------------------
_X509 = {"ts": "2024-04-21T06:34:48.870004Z", "fingerprint": _FP,
         "certificate.subject": "CN=berylia.org",
         "certificate.issuer": "CN=ZeroSSL RSA Domain Secure Site CA,O=ZeroSSL,C=AT",
         "certificate.serial": "D37DDCE310141EF7B1415F4C5F5B90C8",
         "certificate.not_valid_after": "2024-05-22T23:59:59.000000Z",
         "san.dns": ["berylia.org", "*.berylia.org"], "host_cert": True}

# every keep key present, and the fingerprint UPPERCASE so the lower() promotion
# is visible against the verbatim guid.
_X509_FULL = {"ts": 1341856306.5, "fingerprint": _FP.upper(),
              "certificate.subject": "CN=www.example.com,O=Example Inc,C=US",
              "certificate.issuer": "CN=Example CA,O=Example Inc,C=US",
              "certificate.serial": "0A1B2C3D",
              "certificate.version": 3,
              "certificate.not_valid_before": "2012-07-01T00:00:00.000000Z",
              "certificate.not_valid_after": "2013-07-01T00:00:00.000000Z",
              "certificate.key_alg": "rsaEncryption",
              "certificate.sig_alg": "sha256WithRSAEncryption",
              "certificate.key_type": "rsa", "certificate.key_length": 2048,
              "san.dns": ["www.example.com"],
              "basic_constraints.ca": False,
              "host_cert": True, "client_cert": False}

j = _lib.j


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    _lib.write_fixture("zeek_x509",
                       {"artefacts": ["zeek_x509"], "host": "cap",
                        "adapter": "none", "input": "input.jsonl"},
                       [j(_X509) + b"\n",
                        j(_X509_FULL) + b"\n",
                        # a CA cert, and the mixed-case fingerprint promotion
                        j(dict(_X509, fingerprint=_FP.upper(),
                               **{"basic_constraints.ca": True,
                                  "client_cert": False})) + b"\n",
                        # --- the gate edges ---------------------------------
                        j({k: v for k, v in dict(_X509).items()
                           if k != "fingerprint"}) + b"\n",     # dropped
                        j(dict(_X509, fingerprint="")) + b"\n",  # dropped
                        j(dict(_X509, fingerprint=None)) + b"\n",  # dropped
                        # "-" claims the variant, but voids the field-guid AND
                        # the lower() prop (both apply the blank rule)
                        j(dict(_X509, fingerprint="-")) + b"\n",
                        # a NUMERIC fingerprint: guid keeps the int, sha256_hash
                        # is str(v).lower()
                        j(dict(_X509, fingerprint=12345)) + b"\n",
                        # --- ts variants ------------------------------------
                        j(dict(_X509, fingerprint="a" * 64, ts=1341856306)) + b"\n",
                        j(dict(_X509, fingerprint="b" * 64, ts="1341856306.5")) + b"\n",
                        j({k: v for k, v in dict(_X509, fingerprint="c" * 64).items()
                           if k != "ts"}) + b"\n",
                        j(dict(_X509, fingerprint="d" * 64, ts="-")) + b"\n",
                        j(dict(_X509, fingerprint="e" * 64,
                               ts="1601-01-01T00:00:00")) + b"\n",
                        # --- sparse: the fingerprint alone ------------------
                        j({"fingerprint": "f" * 64}) + b"\n",
                        # blank / empty keep values are still PRESENT, so kept
                        j({"ts": "2024-04-21T06:34:48.870004Z",
                           "fingerprint": "0" * 64,
                           "certificate.subject": "", "san.dns": [],
                           "certificate.serial": "-", "host_cert": None}) + b"\n"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

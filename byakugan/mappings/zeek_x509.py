"""Zeek x509.log → CAR file (B2).

A TLS certificate is content — bytes with a hash — so it maps to `file`, and its
Zeek **fingerprint IS a SHA-256** of the DER cert: promoting it to `sha256_hash`
gives the cert a first-class identity AND free convergence (the definitive
content-hash tier joins the same cert across captures, and a cert whose bytes
also appear on disk/in memory). CAR has no certificate object; `file` is the
honest home, with the cert's subject / issuer / validity / SAN kept in native.

The value is the identity the cert vouches for — `certificate.subject`
(`CN=berylia.org`) and `san.dns` (`berylia.org`, `*.berylia.org`). ssl.log names
its chain in `cert_chain_fps` (the x509 `fingerprint`), so enrich ties a cert to
the TLS flow that presented it — the C2 flow's certificate identity, alongside
its SNI (`sni_matches_cert` is the mismatch tell).

`guid` is the `fingerprint` (the cert's stable per-cert identity — the registry's
`zeek_cert_fp` external form). Normalisation only; the flow↔cert link is enrich's.
"""
from __future__ import annotations


def zeek_x509_has_fingerprint(rec) -> bool:
    """An x509.log row is CAR-worthy once it carries the fingerprint that
    identifies the certificate; a malformed row without one stays raw."""
    return bool(rec.get("fingerprint"))


PREDICATES = {"zeek_x509_has_fingerprint": zeek_x509_has_fingerprint}

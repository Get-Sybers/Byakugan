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

from ..normalize import epoch_ts  # noqa: F401


def zeek_x509_has_fingerprint(rec) -> bool:
    """An x509.log row is CAR-worthy once it carries the fingerprint that
    identifies the certificate; a malformed row without one stays raw."""
    return bool(rec.get("fingerprint"))


PREDICATES = {"zeek_x509_has_fingerprint": zeek_x509_has_fingerprint}

MAPPINGS = {
    "zeek_x509": {
        "variants": [
            ("zeek_x509_has_fingerprint", {
                "object": "file",
                # a cert is content observed on the wire — `create` is the
                # closest honest file action (it exists / was presented); there
                # is no filesystem create here (file_path is honestly null).
                "action": "create",
                "ts": epoch_ts("ts"),
                # the certificate's stable identity: its fingerprint
                "guid": {"field": "fingerprint"},
                "props": {
                    # Zeek's x509 fingerprint is a SHA-256 of the DER cert, so it
                    # IS the content hash — this is what makes a cert converge
                    # (same bytes across captures / with an on-disk/in-memory copy)
                    "sha256_hash": "fingerprint",
                },
                # the cert identity + metadata that has no CAR file field — the
                # subject/issuer the cert vouches for, the SAN dns names, serial,
                # validity window, key/sig algorithms, and the CA/host/client
                # flags. Only present fields are kept.
                "keep": ["fingerprint", "certificate.subject", "certificate.issuer",
                         "certificate.serial", "certificate.version",
                         "certificate.not_valid_before", "certificate.not_valid_after",
                         "certificate.key_alg", "certificate.sig_alg",
                         "certificate.key_type", "certificate.key_length",
                         "san.dns", "basic_constraints.ca", "host_cert", "client_cert"],
            }),
        ],
        "default": None,   # no fingerprint → no certificate identity → stays raw
    },
}

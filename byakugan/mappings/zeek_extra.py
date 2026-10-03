"""Zeek logs beyond conn/http that carry a CAR object (epic #86).

Zeek is ONE source (all its per-protocol logs for a capture → one car.db). Of
the log types, four carry a CAR object: conn→flow (zeek_conn), http→http (core),
and here:

- **smtp → email**: an observed SMTP transaction. Mapped ONLY when the row
  carries actual message content (mailfrom/rcptto/from/subject) — a STARTTLS
  session exposes none of that (encrypted), so it stays raw rather than assert a
  phantom `deliver` with no recipient (matches CAR-Relations' email limits).
- **files → file**: a file object Zeek reconstructed from traffic. It is a
  NETWORK-OBSERVED file (source_artefact=zeek), not proven written to a host —
  `create` here means "the file object was first observed on the wire". Grabs
  mime_type (incl. application/x-dosexec = PE downloads), name/hash where the
  analyzers produced them, and the `uid`/`fuid` that tie it to its flow and its
  http/smtp transaction (the within-source cascade, by uid/fuid, is the
  end-stage).

The remaining Zeek logs (dns, ssl, x509, dhcp, ntp, snmp, ocsp, weird, pe,
packet_filter) have no dedicated CAR object; their per-flow detail can enrich the
flow by `uid` at the cascade stage, but they are not CAR objects and stay raw.
"""
from __future__ import annotations


def zeek_is_smtp_message(rec) -> bool:
    """An SMTP row with real message content — not an encrypted STARTTLS shell."""
    return any(rec.get(k) for k in ("mailfrom", "rcptto", "from", "to", "subject"))


def zeek_is_file(rec) -> bool:
    return bool(rec.get("fuid"))


PREDICATES = {
    "zeek_is_smtp_message": zeek_is_smtp_message,
    "zeek_is_file": zeek_is_file,
}

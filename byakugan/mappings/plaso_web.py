"""Plaso browser/download evidence → CAR http (epic #86).

Endpoint-side records that a URL was REQUESTED — browser history, browser cache,
Java download cache. Per CAR-Relations, `hostname` here is the host the request
was seen ON (these artefacts live on the requesting endpoint, so the imaged
host IS the vantage — unlike a pcap, where it stays null).

All maps consume the wrapped l2t row {SourceImage, Timestamp, Parser, Record}
(field access via the payload(..., "Record") shorthand). Field shapes verified
against real M57 records:

- **msiecf (IE index.dat)** → http/get. Only `msiecf:url` rows at their
  "Last Visited Time" map (the visit event); Expiration rows and the url-less
  msiecf:leak / cached-object rows stay raw. History entries render the url as
  "Visited: <user>@<url>" — the real URL is extracted; a non-URL target
  (about:Home) honestly yields null url_domain/scheme.
- **firefox_cache** → http, action from the RECORDED request_method (GET/POST/
  PUT — others raw); response_status_code parsed from "HTTP/1.1 200 OK"; the
  cache prefixes url with "HTTP:" which is stripped.
- **browser history (sqlite table)** → http/get: firefox places page_visited
  PLUS Chrome/Edge `chrome:history:page_visited` (Edge is Chromium, same
  data_type) — the visit record, with from_visit as the request_referrer (its
  " (host)" suffix stripped). Recorded client-side data, never proof of real
  navigation provenance. Chrome/Edge `chrome:history:file_downloaded` rows map
  too: a GET whose received_bytes are the response body size (total_bytes and
  the local target full_path native).
- **java_idx** → http/get: a Java download-cache record; the server IP the
  cache recorded stays native (CAR http has no dest_ip field).

Row identity (the spindle guid, docs/CAR-Pipeline.md §7): the database the
record lives in (Plaso's display_name) + the url + the visit time — the same
three on every browser artefact, so the maps share one identity shape.
"""
from __future__ import annotations

from ..normalize import (basename, const, domain_of, ext, first, hex_int,  # noqa: F401
                         host_label, map_value, payload, regex1)
from ._common import R as _r, spindle as _spindle


def _dt(rec) -> str:
    r = rec.get("Record")
    return str((r or {}).get("data_type") or "")


def _td(rec) -> str:
    r = rec.get("Record")
    return str((r or {}).get("timestamp_desc") or "")


def plasoweb_is_ie_visit(rec) -> bool:
    """msiecf:url at its Last Visited Time — the visit event (Expiration and
    the url-less leak/cached rows stay raw)."""
    return _dt(rec) == "msiecf:url" and "Last Visited" in _td(rec)


def plasoweb_is_ff_cache(rec) -> bool:
    return _dt(rec) == "firefox:cache:record"


# browser-history visit/download rows inside the generic sqlite table. Firefox
# places, PLUS Chrome/Edge history — Edge is Chromium and shares the
# `chrome:history:*` data_types (page_visited + file_downloaded). Every one is a
# client-recorded request the endpoint saw; the field derivations already fit
# (url, from_visit -> request_referrer, visit -> get), downloads add their bytes.
_HISTORY_VISIT_DTS = {
    "firefox:places:page_visited",
    "chrome:history:page_visited",
    "chrome:history:file_downloaded",
}


def plasoweb_is_ff_visit(rec) -> bool:
    """A browser-history visit/download row → http/get. Gated strictly by
    data_type (bookmarks/annotations and other sqlite plugins stay raw)."""
    return _dt(rec) in _HISTORY_VISIT_DTS


def plasoweb_is_javaidx(rec) -> bool:
    return _dt(rec) == "java:download:idx"


PREDICATES = {
    "plasoweb_is_ie_visit": plasoweb_is_ie_visit,
    "plasoweb_is_ff_cache": plasoweb_is_ff_cache,
    "plasoweb_is_ff_visit": plasoweb_is_ff_visit,
    "plasoweb_is_javaidx": plasoweb_is_javaidx,
}

# IE history renders "Visited: user@<url>"; plain cache rows carry the bare url.
# firefox cache prefixes the url with "HTTP:".


def _http_props(url_marker):
    """The shared derivations for an endpoint-recorded URL request."""
    return {
        "url_full": url_marker,
        "url_scheme": regex1(url_marker, r"^(https?)://"),
        "url_domain": regex1(url_marker, r"^https?://([^/?#:]+)"),
        "url_remainder": regex1(url_marker, r"^https?://[^/]+(/[^\s]*)"),
        # the imaged endpoint IS the vantage these artefacts were seen on
        "hostname": _r("image_hostname"),
    }

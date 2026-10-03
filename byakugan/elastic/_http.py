"""Shared stdlib-only HTTP plumbing for talking to Elasticsearch (and, for
`byakugan.elastic.load`, Kibana): auth headers, a TLS context, and the one
JSON request primitive every ES/Kibana call in this package goes through.

Split out of `byakugan.elastic.load` (epic #99 phase 5, `byakugan timeline
--elastic`'s own fetch needs the exact same auth/TLS/request handling load.py
already had, and the two must never drift into two different ways of
building an Authorization header or a CA-verified context) —
`byakugan.elastic.load` re-exports these three names unchanged
(`from . import _http` then `load.auth_headers is _http.auth_headers`,
etc.), so nothing that already imports them off `byakugan.elastic.load`
needs to change.

No elasticsearch client library: every network call in this package is
stdlib `urllib`.
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request


def auth_headers(api_key: str, user: str, password: str) -> dict:
    if api_key:
        return {"Authorization": f"ApiKey {api_key}"}
    if user:
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}
    return {}


def ssl_context(ca_file: str | None) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()


def http_json(url: str, method: str, body, headers: dict, context: ssl.SSLContext | None,
             timeout: float = 30.0):
    """(status, parsed-JSON-or-None, raw-bytes). An HTTP error response
    (4xx/5xx) is returned, not raised — the ES/Kibana APIs this package calls
    put their own error detail in the body. A genuine connection failure
    (DNS, refused, timeout, TLS) DOES raise `OSError`, for the caller to
    count as a whole chunk/stream/request failure."""
    data = None
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers))
    try:
        with urllib.request.urlopen(req, context=context, timeout=timeout) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else None
    except ValueError:
        parsed = None
    return status, parsed, raw

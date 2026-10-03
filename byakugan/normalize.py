"""Marker constructors + value resolvers for the CAR maps (epic #86).

The record-to-CAR-event map ENGINE is now the Go parse engine
(go/internal/normalize, run via byakugan-parse); the Python reference engine
(normalize()/_select/_identity/_spindle) was retired once the tests were
re-anchored onto Go (phase 4c). What remains here is the still-shared library:

- the marker CONSTRUCTORS (first/basename/regex1/payload/…) that name the small
  transforms — imported by byakugan/mappings and exercised by the map tests;
- `parse_ts`, the one tolerant ISO-8601 parser (timeline.py, stix.py, ts_before);
- the resolver `_resolve` and guid builder `_guid`, still used by spindle.py's
  external_vector to render a map's guid form; and the `_canon_user` well-known
  tables readers.py folds a principal through.

A canonical column is left null rather than filled with a near-miss — never faked.
"""
from __future__ import annotations

import ntpath
import posixpath
import re
from datetime import datetime, timedelta, timezone

# --- marker constructors (also importable by mappings.py) -------------------

def first(*srcs):
    """First non-empty of the given field names / markers."""
    return ("first", srcs)


def const(value):
    """A constant the observation itself proves."""
    return ("const", value)


def basename(src):
    """Windows-or-POSIX basename of a path field/marker."""
    return ("basename", src)


def ext(src):
    """Lowercase file extension (no dot) of a path field/marker."""
    return ("ext", src)


def lower(src):
    return ("lower", src)


def regex1(src, pattern):
    """First capture group of `pattern` against the field, or None."""
    return ("regex1", (src, pattern))


def domain_of(src):
    """The domain label of a dotted host/email/url field (after the first '@' or
    the host portion), lowercased — or None."""
    return ("domain_of", src)


def epoch_ts(src):
    """A timestamp field rendered as UTC ISO-8601: epoch-seconds (int/float) are
    converted; a value that is already an ISO string passes through (the zeek
    lane emits ISO8601 in processed json). The store's timestamp form —
    lexicographically ordered, comparable across artefacts."""
    return ("epoch_ts", src)


def map_value(src, table, upper=False):
    """Look the field's value up in a literal table ('GET' -> 'get'); None if
    absent. `upper=True` uppercases before the lookup."""
    return ("map_value", (src, table, upper))


def concat(*parts):
    """Concatenate resolved parts (field names or markers; use const("...") for
    literals) — null if ANY part is missing: a reconstruction made only from
    provable pieces."""
    return ("concat", parts)


def exe_path(src):
    """The executable path parsed out of an ImagePath-style command line
    ('"C:\\p q\\x.exe" -k net' -> 'C:\\p q\\x.exe'; unquoted svchost-style
    lines cut at .exe). Parsing, not guessing — the path is verbatim inside."""
    return ("exe_path", src)


def payload(key, field="Payload"):
    """A key out of an EvtxECmd `Payload` JSON string (EZ tools stamp the event
    data as a JSON blob) — the Python analogue of the KQL EvtxPayload().
    Handles the EventData.Data[] ({@Name,#text}) shape and a flat dict."""
    return ("payload", (field, key))


def userdata(key, field="Payload"):
    """A key out of the OTHER EvtxECmd payload shape — `UserData` with one nested
    child dict of named fields (TerminalServices, WMI-Activity, ...): Payload ->
    UserData -> <single child> -> key."""
    return ("userdata", (field, key))


def host_label(src):
    """The first DNS label of a hostname/FQDN ('HOST1.dom.com' -> 'HOST1')."""
    return ("host_label", src)


def hex_int(src):
    """A PID/handle rendered as an int, accepting decimal or Windows-hex form
    ('0x150' -> 336) so a CAR column is uniform whatever the source's rendering.
    Parsing, not a near-miss — the value is exact."""
    return ("hex_int", src)


def unescape_backslashes(src):
    """Collapse doubled backslashes to single ('C:\\\\x' -> 'C:\\x') — some Plaso
    renderings (lnk link_target) double them; a rendering artifact, not
    evidence."""
    return ("unescape_backslashes", src)


def replace(src, old, new):
    """Literal substring replacement on the resolved value ('2018-04-02 01:15' ->
    '2018-04-02T01:15') — a rendering normalisation, never a semantic change."""
    return ("replace", (src, old, new))


def at(src, index):
    """The element at `index` of a list-valued field/marker (Plaso exposes event-
    log EventData as a positional `strings` list, not named fields) — None if the
    list is absent or too short. Negative indices allowed."""
    return ("at", (src, index))


def ts_before(src, other):
    """True when the timestamp in `src` is strictly earlier than the one in
    `other`, False when it is not, None when either is blank or unparseable.
    Both sides are parsed to the true UTC instant (`parse_ts`: 'T' or ' '
    separator, any fraction width, 'Z'/offset/none) — a comparison of
    instants, never of string bytes. A verdict the two evidence values prove
    (Sysmon 11: CreationUtcTime before UtcTime = the file pre-existed)."""
    return ("ts_before", (src, other))


def win_program_path(src):
    """The executable PATH out of a Windows execution-artefact field (Amcache /
    AppCompatCache). A modern Store/UWP entry records a TAB-delimited PACKAGE
    DESCRIPTOR (``<seq>\\t<hex>\\t<hex>\\t<arch>\\t<PackageName>\\t<PublisherId>``
    [``\\t<res-arch>``]) in place of a path — a package moniker is NOT a
    filesystem path, so it yields None (never the raw tab blob); a real path
    passes through verbatim."""
    return ("win_program_path", src)


def win_program_name(src):
    """The executable NAME out of a Windows execution-artefact field (Amcache /
    AppCompatCache): the basename of a real path, or — for the TAB-delimited
    Store/UWP package descriptor ``win_program_path`` rejects — the Package
    Family Name ``<PackageName>_<PublisherId>`` (a clean identity), never the
    tab blob."""
    return ("win_program_name", src)


def user_canon(src):
    """A Windows principal canonicalized to ONE account-name form across sources
    (see ``_canon_user``): a well-known SID → its name (S-1-5-18 → SYSTEM), a
    leading well-known authority stripped (``NT AUTHORITY\\SYSTEM`` → SYSTEM,
    ``BUILTIN\\Administrators`` → ADMINISTRATORS), the memory friendly forms
    folded (``Local System`` → SYSTEM, ``Local``/``Network Service`` →
    LOCAL/NETWORK SERVICE), a real machine/AD domain KEPT (``DESKTOP-1\\jdoe``
    stays), and an unknown SID left as the SID string (never invented). The raw
    SID is untouched — the maps keep it in the ``sid``/``uid`` column."""
    return ("user_canon", src)


# --- timestamps -------------------------------------------------------------

# YYYY-MM-DD, T or space, HH:MM:SS, optional .fraction, optional Z or ±HH[:]MM.
_TS_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"(?:(Z)|([+-])(\d{2}):?(\d{2}))?$")


def parse_ts(value):
    """An ISO-8601 timestamp as an aware UTC ``datetime``, or ``None`` if it
    can't be parsed. Tolerant of a trailing ``Z``, a space date/time separator,
    and *any* fractional-second precision — cases ``datetime.fromisoformat``
    rejects before 3.11 (this repo targets 3.10). Events arrive in mixed shapes
    (the epoch_ts path emits ``+00:00``; passthrough lanes emit ``Z`` or other
    fraction widths; Sysmon stamps ``YYYY-MM-DD HH:MM:SS.fff``), so comparing
    and sorting on the true instant — not the string bytes — is what keeps the
    ts_before marker, the timeline's ordering and its --after/--before correct."""
    if not value:
        return None
    m = _TS_RE.match(str(value).strip())
    if not m:
        return None
    y, mo, d, hh, mm, ss, frac, _z, sign, oh, om = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss),
                      int((frac or "").ljust(6, "0")[:6]))
    except ValueError:
        return None
    if sign is None:            # Z or no zone → assume UTC (epoch_ts emits UTC)
        tz = timezone.utc
    else:
        off = timedelta(hours=int(oh), minutes=int(om))
        tz = timezone(off if sign == "+" else -off)
    return dt.replace(tzinfo=tz).astimezone(timezone.utc)


# --- resolver ---------------------------------------------------------------

def _blank(v) -> bool:
    return v is None or v == "" or v == "-"


def _basename(v):
    if _blank(v):
        return None
    s = str(v)
    return (ntpath.basename(s) if "\\" in s else posixpath.basename(s)) or None


_PARSE_CACHE_KEY = "__car_parsed_payload__"


def _parsed_payload(rec, field):
    """Parse-and-index a payload blob ONCE per (record, field) — the cache lives
    on the record dict, so it persists across the whole map family run over the
    same record (payload() was re-parsing the JSON per field access, the main
    real-data cost). Returns (names_map_or_None, data): names_map indexes an
    EventData.Data list by @Name (values pre-stripped); data is the parsed
    object for the other shapes."""
    cache = rec.get(_PARSE_CACHE_KEY)
    if cache is None:
        cache = {}
        rec[_PARSE_CACHE_KEY] = cache
    raw = rec.get(field)
    hit = cache.get(field)
    if hit is not None and hit[0] is raw:
        # valid only while the raw value is the SAME object — a replaced
        # Payload (or a copied record with a new one) reparses, never stale
        return hit[1], hit[2]
    names, data = None, None
    if not _blank(raw):
        try:
            import json as _json
            data = raw if isinstance(raw, dict) else _json.loads(raw)
            datas = (data.get("EventData") or {}).get("Data") if isinstance(data, dict) else None
            if isinstance(datas, list):
                names = {}
                for d in datas:
                    if isinstance(d, dict) and "@Name" in d:
                        v = d.get("#text")
                        if isinstance(v, str):
                            v = v.strip()      # MS pads values ('Advapi  ')
                        names[d["@Name"]] = None if _blank(v) else v
        except (ValueError, AttributeError, TypeError):
            names, data = None, None
    cache[field] = (raw, names, data)
    return names, data


# --- Windows principal canonicalization -------------------------------------

# well-known SIDs → the canonical ACCOUNT NAME (an uppercase token, so the SID
# form, the "NT AUTHORITY\\…"/"BUILTIN\\…" form and memory's friendly form all
# converge on ONE string). Only the STANDARD set; an unknown SID is left as the
# SID string by _canon_user — never invented into a name.
_WELLKNOWN_SIDS = {
    "S-1-0-0": "NULL SID",
    "S-1-1-0": "EVERYONE",
    "S-1-2-0": "LOCAL",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-3-1": "CREATOR GROUP",
    "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-11": "AUTHENTICATED USERS",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-544": "ADMINISTRATORS",
    "S-1-5-32-545": "USERS",
    "S-1-5-32-546": "GUESTS",
    "S-1-5-32-547": "POWER USERS",
    "S-1-5-32-551": "BACKUP OPERATORS",
    "S-1-5-32-555": "REMOTE DESKTOP USERS",
}

# well-known ACCOUNT NAMES (incl. memory's friendly + no-space renderings) → the
# canonical token the matching SID resolves to. Keyed on the uppercased name.
_WELLKNOWN_NAMES = {
    "SYSTEM": "SYSTEM",
    "LOCAL SYSTEM": "SYSTEM", "LOCALSYSTEM": "SYSTEM", "SYSTEMPROFILE": "SYSTEM",
    "LOCAL SERVICE": "LOCAL SERVICE", "LOCALSERVICE": "LOCAL SERVICE",
    "NETWORK SERVICE": "NETWORK SERVICE", "NETWORKSERVICE": "NETWORK SERVICE",
    "ADMINISTRATORS": "ADMINISTRATORS",
    "EVERYONE": "EVERYONE",
    "ANONYMOUS LOGON": "ANONYMOUS LOGON",
    "AUTHENTICATED USERS": "AUTHENTICATED USERS",
}

# domain prefixes that are a well-known AUTHORITY (never a real machine/AD
# domain) — stripped to the bare account name; a real host/AD domain is kept.
_WELLKNOWN_AUTHORITIES = {"NT AUTHORITY", "BUILTIN"}


def _canon_name(s):
    """A bare account name → its canonical well-known token, else unchanged (a
    real user name keeps its own case)."""
    return _WELLKNOWN_NAMES.get(str(s).strip().upper(), str(s))


def _canon_user(v):
    """The principal canonicalization `user_canon` documents — None for a blank."""
    if _blank(v):
        return None
    s = str(v).strip()
    if not s:
        return None
    name = _WELLKNOWN_SIDS.get(s.upper())
    if name:
        return name                            # a well-known SID → its name
    if "\\" in s:
        dom, _, acct = s.partition("\\")
        if dom.strip().upper() in _WELLKNOWN_AUTHORITIES:
            return _canon_name(acct)           # a well-known authority → strip it
        return s                               # a real machine/AD domain → keep DOMAIN\name
    return _canon_name(s)


def _pkg_family(v):
    """The Package Family Name ``<PackageName>_<PublisherId>`` out of a TAB-
    delimited AppCompatCache/Amcache Store/UWP descriptor, or None when the
    value does not have that shape (never the raw tab blob)."""
    parts = [p for p in str(v).split("\t") if p != ""]
    # <seq> <hex> <hex> <arch> <PackageName> <PublisherId> [<resource-arch>]
    if len(parts) >= 6 and "." in parts[4]:
        return f"{parts[4]}_{parts[5]}"
    return None


def _resolve(src, rec):
    """Resolve a plain field name or a (nestable) marker against a record."""
    if isinstance(src, str):
        return rec.get(src)
    kind, arg = src[0], src[1]
    if kind == "first":
        for f in arg:
            v = _resolve(f, rec)
            if not _blank(v):
                return v
        return None
    if kind == "const":
        return arg
    if kind == "basename":
        return _basename(_resolve(arg, rec))
    if kind == "ext":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        e = ntpath.splitext(_basename(v) or "")[1].lstrip(".").lower()
        return e or None
    if kind == "lower":
        v = _resolve(arg, rec)
        return str(v).lower() if not _blank(v) else None
    if kind == "regex1":
        field, pattern = arg
        v = _resolve(field, rec)
        if _blank(v):
            return None
        m = re.search(pattern, str(v))
        return m.group(1) if m else None
    if kind == "domain_of":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        s = str(v)
        if "@" in s:
            s = s.split("@", 1)[1]
        s = s.split("/")[0]                    # strip any URL path
        return s.lower() or None
    if kind == "concat":
        out = []
        for part in arg:
            v = _resolve(part, rec)
            if _blank(v):
                return None
            out.append(str(v))
        return "".join(out)
    if kind == "payload":
        field, key = arg
        names, data = _parsed_payload(rec, field)
        if names is not None:                  # EventData.Data indexed by @Name
            return names.get(key)
        if isinstance(data, dict):             # flat dict (e.g. the wrapped Record)
            v = data.get(key)
            if isinstance(v, str):
                v = v.strip()
            return None if _blank(v) else v
        return None
    if kind == "userdata":
        field, key = arg
        _names, data = _parsed_payload(rec, field)
        if not isinstance(data, dict):
            return None
        try:
            ud = data.get("UserData")
            if not isinstance(ud, dict):
                return None
            for child in ud.values():          # the single nested element
                if isinstance(child, dict) and key in child:
                    v = child[key]
                    if isinstance(v, str):
                        v = v.strip()
                    return None if _blank(v) else v
            return None
        except (ValueError, AttributeError, TypeError):
            return None
    if kind == "host_label":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        return str(v).split(".", 1)[0] or None
    if kind == "epoch_ts":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        try:
            import datetime as _dt
            return _dt.datetime.fromtimestamp(float(v), _dt.timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError):
            s2 = str(v)
            return s2 if s2[:4].isdigit() and "-" in s2 else None  # already ISO
    if kind == "exe_path":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        s2 = str(v).strip()
        if s2.startswith('"'):
            end = s2.find('"', 1)
            return s2[1:end] if end > 0 else s2.strip('"')
        i = s2.lower().find(".exe")
        if i >= 0:
            return s2[:i + 4]
        return s2.split(" ")[0]
    if kind == "map_value":
        field, table, upper = arg
        v = _resolve(field, rec)
        if _blank(v):
            return None
        s = str(v).upper() if upper else str(v)
        return table.get(s)
    if kind == "unescape_backslashes":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        return str(v).replace("\\\\", "\\")
    if kind == "replace":
        field, old, new = arg
        v = _resolve(field, rec)
        if _blank(v):
            return None
        return str(v).replace(old, new)
    if kind == "at":
        container, idx = arg
        v = _resolve(container, rec)
        if isinstance(v, (list, tuple)) and -len(v) <= idx < len(v):
            e = v[idx]
            if isinstance(e, str):
                e = e.strip()
            return None if _blank(e) else e
        return None
    if kind == "hex_int":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            try:
                return int(str(v), 16)
            except (TypeError, ValueError):
                return None
    if kind == "ts_before":
        a, b = (parse_ts(_resolve(s, rec)) for s in arg)
        return None if a is None or b is None else a < b
    if kind == "win_program_path":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        s = str(v)
        return None if "\t" in s else s        # a UWP package descriptor is not a path
    if kind == "win_program_name":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        s = str(v)
        return _pkg_family(s) if "\t" in s else _basename(s)
    if kind == "user_canon":
        return _canon_user(_resolve(arg, rec))
    raise ValueError(f"unknown source marker: {src!r}")


def _guid(spec, obj, rec):
    """The event's CAR guid: an existing field, a marker, `<object>-<fields>`, or
    None (assigned later / genuinely absent). A None component voids a
    fields-guid; "" is a legitimate identity value. The `spindle` form (a
    minted, deterministic identity) is _spindle."""
    if spec is None or spec.get("none"):
        return None
    if "marker" in spec:
        return _resolve(spec["marker"], rec)
    if "field" in spec:
        v = rec.get(spec["field"])
        return None if _blank(v) else v
    parts = [rec.get(f) for f in spec["fields"]]
    if any(p is None for p in parts):
        return None
    return f"{obj}-" + "-".join(str(p) for p in parts)

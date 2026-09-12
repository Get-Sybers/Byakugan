r"""Canonical native identifiers mined out of a row — the real cross-source join
keys the CAR guid columns (minted synthetic ids) never carried (B1).

The cross-source value hunt found the strongest keys on a Windows image survive
only as text inside `native`: the globally-unique **volume GUID**
(`\\?\Volume{GUID}`) ties the USN change journal, the event log, the registry,
the filesystem stat table, MountPoints2 and cloud-sync logs — 6 data_types on
real data — yet no CAR field carried it. This module is the ONE place that
mines it, so `enrich` (which lifts it to the first-class `volume_guid` column)
and `crosssource` (which converges on it) share a single, tested extractor.

Precision over recall, deliberately: only the token-gated `Volume{` class is
mined — a bare `{8-4-4-4-12}` GUID is never returned, because the ubiquitous COM
CLSID/interface/TypeLib GUIDs are pure linkage noise. The token lives INSIDE the
value string (the volume path), so a text scan is both precise and independent
of each parser's native shape. Values are case-folded — real data mixes
`09931F21…`/`09931f21…`.

B3 adds the **MAC address**: literal `xx:xx:xx:xx:xx:xx` values and the NIC MAC
embedded in a version-1 (time+MAC) GUID's node — the DLT birth-droid a LNK
carries — both lifted to the `mac_address` column and converged on. Synthetic /
RFC-random nodes (multicast bit set) and the OLE-family node are excluded.

B3 also adds the **USB device serial**: the iSerialNumber Windows records in a
USBSTOR device-instance path — `USBSTOR<sep>Disk&Ven_..&Prod_..&Rev_..<sep>
<serial>&0` (the separator is `\` in a registry key path, `#` in a setupapi /
WPDBUSENUM device-instance id, `/` in an Amcache InventoryDevicePnp key). The
serial is the instance-id segment after the `Disk&Ven_..` descriptor and before
the trailing `&0` interface suffix. It is the physical-device join key that ties
USBSTOR ↔ setupapi ↔ DeviceClasses ↔ WPDBUSENUM ↔ MountedDevices ↔ EMDMgmt rows
to one stick (real data: SanDisk `AA010215170355310594` / `AA010603160707470215`,
2,470× across the LoneWolf image). Precision over recall: the extractor is gated
on the USBSTOR + `Ven_` context and the `&0` suffix, so a Windows-minted
instance id (`7&1e8dc766&0&0`, an embedded `&`) and a bare alphanumeric string
are never mistaken for a serial. Case-folded to UPPER — the Windows-canonical
device-instance rendering — so the USBSTOR/setupapi upper form and the Amcache
lower form converge.
"""
from __future__ import annotations

import json
import re

_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_VOLUME_RE = re.compile(r"Volume\{(" + _GUID + r")\}", re.IGNORECASE)
_CANONICAL_RE = re.compile(r"^\{?(" + _GUID + r")\}?$")


def canonical(value) -> str | None:
    """`value` as a lower-cased canonical {8-4-4-4-12} GUID (optionally brace-
    wrapped), or None if it is not one. Use it to VALIDATE a stored `volume_guid`
    column before trusting it as a join key — a malformed value or a stray full
    path must never mint a bogus cross-source convergence."""
    if value is None:
        return None
    m = _CANONICAL_RE.match(str(value).strip())
    return m.group(1).lower() if m else None


def _as_text(native) -> str:
    if native is None:
        return ""
    return native if isinstance(native, str) else json.dumps(native, default=str)


def volume_guids(native) -> list[str]:
    """Every distinct volume GUID a row's `native` carries, case-folded (lower),
    in first-seen order. `native` may be a dict or an already-serialised str."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _VOLUME_RE.finditer(_as_text(native)):
        v = m.group(1).lower()
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


# --- MAC addresses (B3) ---------------------------------------------------- #
# A MAC survives in `native` two ways: as a literal `xx:xx:xx:xx:xx:xx` (a
# NetworkList gateway MAC, a Zeek L2 address) and — invisibly — inside the NODE
# of a version-1 (time+MAC) GUID: the DLT birth-droid a LNK carries, and the
# `-11e2-`/`-11e8-` volume/interface GUIDs, all embed the originating NIC's MAC
# in their last 6 bytes. No CAR field ever carried either, so a file opened via
# a shortcut could not be tied to the machine that created it.
# A literal MAC (6 hex pairs, ':' or '-' separated), folded to ':' lower-case:
_MAC_LITERAL_RE = re.compile(r"\b([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\b")
# a version-1 GUID: the version nibble (first char of the 3rd group) is '1':
_V1_GUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-1[0-9a-fA-F]{3}-[0-9a-fA-F]{4}-([0-9a-fA-F]{12})\b")
# nodes that are NOT a hardware MAC: the OLE `-c000-000000000046` family node,
# and the RFC 4122 synthetic placeholder. (A random/software node also sets the
# multicast bit of its first octet — RFC 4122 §4.5 — so those are excluded too.)
_NON_MAC_NODES = {"000000000046", "806e6f6e6963"}


def _node_to_mac(node: str) -> str | None:
    """A 12-hex v1-GUID node as a hardware MAC `xx:xx:xx:xx:xx:xx` (lower), or
    None if it is not one — a known synthetic node, or a node whose first octet
    has the I/G (multicast) bit set, which marks an RFC-random (non-hardware) id."""
    node = node.lower()
    if node in _NON_MAC_NODES:
        return None
    if int(node[0:2], 16) & 0x01:               # I/G bit set -> not a real NIC MAC
        return None
    return ":".join(node[i:i + 2] for i in range(0, 12, 2))


def mac_from_v1_guid(guid) -> str | None:
    """The originating NIC MAC embedded in a version-1 GUID's node, or None if
    `guid` is not a v1 GUID (or its node is not a hardware MAC)."""
    if guid is None:
        return None
    m = _V1_GUID_RE.search(str(guid).strip())
    return _node_to_mac(m.group(1)) if m else None


def mac_addresses(native) -> list[str]:
    """Every distinct hardware MAC a row's `native` carries — literal
    `xx:xx:xx:xx:xx:xx` values AND those embedded in a v1-GUID node — folded to
    ':' lower-case, in first-seen order. `native` may be a dict or a str."""
    text = _as_text(native)
    out: list[str] = []
    seen: set[str] = set()

    def add(mac):
        if mac and mac not in seen:
            seen.add(mac)
            out.append(mac)

    for m in _MAC_LITERAL_RE.finditer(text):
        add(m.group(1).replace("-", ":").lower())
    for m in _V1_GUID_RE.finditer(text):
        add(_node_to_mac(m.group(1)))
    return out


_MAC_ONLY_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")


def as_mac(value) -> str | None:
    """`value` as a canonical ':'-separated lower-case MAC, or None — used to
    VALIDATE a stored `mac_address` column before trusting it as a join key."""
    if value is None:
        return None
    v = str(value).strip().replace("-", ":").lower()
    return v if _MAC_ONLY_RE.match(v) else None


# --- USB device serials (B3) ----------------------------------------------- #
# A USB stick's iSerialNumber survives in `native` as the instance-id segment of
# a USBSTOR device path. The same serial is rendered three ways on real data —
#   registry key : USBSTOR\Disk&Ven_SanDisk&Prod_Extreme&Rev_0001\AA0102...94&0
#   setupapi /WPDBUSENUM : ..._??_USBSTOR#Disk&Ven_..&Prod_..&Rev_..#AA0102...94&0#{guid}
#   Amcache InventoryDevicePnp : usbstor/disk&ven_sandisk&prod_..&rev_../aa0102...94&0
# — so the separator between path parts is one of `\` `#` `/` (a serialised dict
# renders a lone `\` as `\\`, which the `+` still spans), and case varies.
# Precision over recall: the match is GATED on the USBSTOR enumerator + a `Ven_`
# device descriptor and the trailing `&0` interface suffix, so the ubiquitous
# `usb/vid_..&pid_..` PnP path (no `Ven_`), a bare alphanumeric string, and a
# Windows-MINTED instance id (`7&1e8dc766&0&0` — an embedded `&`, no hardware
# serial) are never returned as a serial. A false serial would mint bogus device
# convergence — worse than a null. Folded to UPPER (the Windows-canonical
# device-instance rendering) so the USBSTOR/setupapi and Amcache forms converge.
_USBSTOR_RE = re.compile(
    r"USBSTOR[\\#/]+"           # the USBSTOR enumerator + a path/instance separator
    r"[^\\#/]*Ven_[^\\#/]*"     # the Disk&Ven_..&Prod_..&Rev_.. device descriptor
    r"[\\#/]+"                  # separator before the device instance id
    r"([0-9A-Za-z]{4,})"        # the serial = the instance-id token
    r"&0(?![0-9A-Za-z&])",      # the &0 interface suffix (reject minted x&hex&0&0)
    re.IGNORECASE,
)


def device_serials(native) -> list[str]:
    """Every distinct USB device serial a row's `native` carries — the
    instance-id segment of a USBSTOR device path (USBSTOR + `Ven_` gated) —
    folded to UPPER, in first-seen order. `native` may be a dict or a str."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _USBSTOR_RE.finditer(_as_text(native)):
        v = m.group(1).upper()
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


_SERIAL_ONLY_RE = re.compile(r"^[0-9A-Za-z]{4,}$")


def as_serial(value) -> str | None:
    """`value` as a canonical UPPER bare device serial, or None — used to
    VALIDATE a stored `device_serial` column before trusting it as a join key.
    Rejects anything carrying a separator (a stray USBSTOR path, a GUID, a MAC),
    so a malformed column value never mints a bogus device convergence."""
    if value is None:
        return None
    v = str(value).strip().upper()
    return v if _SERIAL_ONLY_RE.match(v) else None

"""Value-normalization markers — CAR property VALUES rendered in ONE format
regardless of source (evtx / plaso-disk / volatility-memory), so hayabusa/Sigma
and CAR analytics detect consistently and cross-source convergence agrees. See
byakugan/normalize.py:

  * win_program_path / win_program_name — the AppCompatCache/Amcache Store-app
    (UWP) tab-delimited package descriptor fix (never the raw tab blob),
  * lower — hash lowercasing (Sysmon stamps hashes UPPERCASE),
  * user_canon — well-known-SID + friendly-form principal canonicalization.
"""
import json

from byakugan import normalize
from byakugan.normalize import (lower, user_canon, win_program_name,
                                       win_program_path)

_r = normalize._resolve


def _res(marker, value):
    return _r(marker, {"v": value})


# --- fix #1: the tab-delimited AppCompatCache/Amcache Store-app descriptor ----
# A modern Store/UWP AppCompatCache (or Amcache) entry records a TAB-delimited
# package descriptor — <seq>\t<hex>\t<hex>\t<arch>\t<PackageName>\t<PublisherId>
# [\t<res-arch>] — in place of a filesystem path (verified on the real LoneWolf
# DESKTOP-PM6C56D winreg/appcompatcache rows).
_UWP6 = "00000009\t000a42a75dd50000\t000a00003ad80000\t8664\tMicrosoft.ZuneVideo\t8wekyb3d8bbwe\t"
_UWP7 = "0000000b\t000a00003fab000f\t000a000000000000\t8664\tMicrosoft.Windows.SecureAssessmentBrowser\tcw5n1h2txyewy\tneutral"


def test_win_program_name_extracts_package_family_from_uwp_descriptor():
    # no filesystem path exists — the clean identity is the Package Family Name
    # <PackageName>_<PublisherId>, NEVER the raw tab-delimited blob
    assert _res(win_program_name("v"), _UWP6) == "Microsoft.ZuneVideo_8wekyb3d8bbwe"
    assert _res(win_program_name("v"), _UWP7) == \
        "Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy"
    assert "\t" not in _res(win_program_name("v"), _UWP6)


def test_win_program_path_is_null_for_uwp_descriptor():
    # a package moniker is not a filesystem path -> honest null (never the blob)
    assert _res(win_program_path("v"), _UWP6) is None
    assert _res(win_program_path("v"), _UWP7) is None


def test_win_program_markers_pass_real_paths_through():
    p = r"C:\Program Files\DellTPad\Apoint.exe"
    assert _res(win_program_path("v"), p) == p
    assert _res(win_program_name("v"), p) == "Apoint.exe"
    # an NT device path (BAM) is a real path too — unchanged
    nt = r"\Device\HarddiskVolume2\Windows\System32\notepad.exe"
    assert _res(win_program_path("v"), nt) == nt
    assert _res(win_program_name("v"), nt) == "notepad.exe"
    assert _res(win_program_path("v"), None) is None
    assert _res(win_program_name("v"), "-") is None


# --- fix #2: hash lowercasing -------------------------------------------------

def test_lower_canonicalizes_hash_case():
    assert _res(lower("v"), "64FDBD98584331982A15B1F2DF7F08DA") == \
        "64fdbd98584331982a15b1f2df7f08da"
    assert _res(lower("v"), None) is None


def _sysmon_rec(data):
    return {
        "Computer": "H", "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider": "Microsoft-Windows-Sysmon", "EventId": 1,
        "EventRecordId": "1", "TimeCreated": "2020-01-01T00:00:00+00:00",
        "Payload": json.dumps({"EventData": {"Data": [
            {"@Name": k, "#text": v} for k, v in data.items()]}}),
    }


def test_sysmon_hash_columns_lowercased_end_to_end():
    # a real Sysmon Hashes string is UPPERCASE; the map stores every hash column
    # (and the native Imphash a Sigma rule tests) LOWERCASE
    ev = normalize.normalize("evtx_sysmon", _sysmon_rec({
        "UtcTime": "2020-01-01 00:00:00.000", "ProcessGuid": "{g}",
        "ProcessId": "4", "Image": r"C:\x.exe",
        "Hashes": "MD5=AB12CD,SHA1=00FF,SHA256=DEADBEEF,IMPHASH=FF00AA"}))
    assert ev["md5_hash"] == "ab12cd"
    assert ev["sha1_hash"] == "00ff"
    assert ev["sha256_hash"] == "deadbeef"
    assert ev["_native"]["Imphash"] == "ff00aa"


# --- fix #3: user canonicalization (well-known SIDs + friendly forms) ---------

def test_user_canon_resolves_well_known_sids():
    assert _res(user_canon("v"), "S-1-5-18") == "SYSTEM"
    assert _res(user_canon("v"), "S-1-5-19") == "LOCAL SERVICE"
    assert _res(user_canon("v"), "S-1-5-20") == "NETWORK SERVICE"
    assert _res(user_canon("v"), "S-1-5-32-544") == "ADMINISTRATORS"


def test_user_canon_strips_wellknown_authority_keeps_real_domain():
    assert _res(user_canon("v"), r"NT AUTHORITY\SYSTEM") == "SYSTEM"
    assert _res(user_canon("v"), r"NT AUTHORITY\NETWORK SERVICE") == "NETWORK SERVICE"
    assert _res(user_canon("v"), r"BUILTIN\Administrators") == "ADMINISTRATORS"
    # a real machine / AD domain is KEPT verbatim (a real account, not a well-known one)
    assert _res(user_canon("v"), r"DESKTOP-M913391\JDH") == r"DESKTOP-M913391\JDH"
    assert _res(user_canon("v"), r"insecurebank\Administrator") == r"insecurebank\Administrator"


def test_user_canon_folds_memory_friendly_forms():
    assert _res(user_canon("v"), "Local System") == "SYSTEM"
    assert _res(user_canon("v"), "Local Service") == "LOCAL SERVICE"
    assert _res(user_canon("v"), "Network Service") == "NETWORK SERVICE"
    # the no-space renderings PIIAT-Mem's registry plugin emits
    assert _res(user_canon("v"), "LocalService") == "LOCAL SERVICE"
    assert _res(user_canon("v"), "NetworkService") == "NETWORK SERVICE"


def test_user_canon_leaves_ordinary_users_and_unknown_sids_honest():
    assert _res(user_canon("v"), "jcloudy") == "jcloudy"       # real user unchanged
    assert _res(user_canon("v"), "WIN-ABC$") == "WIN-ABC$"     # machine account unchanged
    # an unknown SID is NEVER invented into a name — left as the SID string
    assert _res(user_canon("v"), "S-1-5-21-1-2-3-1001") == "S-1-5-21-1-2-3-1001"
    assert _res(user_canon("v"), "-") is None
    assert _res(user_canon("v"), None) is None


def test_three_sources_converge_on_one_token():
    # evtx (NT AUTHORITY\SYSTEM), memory (Local System), disk SID (S-1-5-18) -> SYSTEM
    forms = [r"NT AUTHORITY\SYSTEM", "Local System", "S-1-5-18"]
    assert {_res(user_canon("v"), f) for f in forms} == {"SYSTEM"}
    svc = [r"NT AUTHORITY\NETWORK SERVICE", "Network Service", "NetworkService", "S-1-5-20"]
    assert {_res(user_canon("v"), f) for f in svc} == {"NETWORK SERVICE"}

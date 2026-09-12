"""A1 — user-from-path across the disk maps that previously left `user` null.

The Vista+ per-user convention: an artefact read out of ``\\Users\\<name>\\``
belongs to that account. ``recmd.py`` already mined the hive path this way; A1
adds the shared ``_common.user_from_path`` marker to the plaso registry,
userassist, shellbag/MRU shell-item, LNK and Recycle-Bin maps so the account
that was sitting in the path is now the canonical ``user`` — the pipeline's #1
disk-artefact win (userassist ~151 rows, registry ~31k rows on LoneWolf).

Records are shaped exactly as the real LoneWolf Win10 image renders them
(``data_store/processed/log2timeline/jsonl/DESKTOP-PM6C56D.jsonl``): the imaged
host is ``DESKTOP-PM6C56D`` and the sole interactive user ``jcloudy``, VSS
shadow copies prefix ``VSS1:/VSS2:``. Fill-only-null is verified — a real
recorded username is never overwritten, and a system-hive/system-path origin
stays an honest null.
"""
from __future__ import annotations

from byakugan import normalize


def _wrap(record, ts="2018-04-05T12:00:00.000000Z"):
    return {"SourceImage": "log2timeline/jsonl/DESKTOP-PM6C56D.jsonl",
            "RecordId": 1, "Timestamp": ts,
            "Parser": record.get("parser", "x"), "Record": record}


# --- registry (plaso_registry.py) -------------------------------------------

def test_registry_derives_user_from_per_user_hive_path():
    rec = {"data_type": "windows:registry:key_value",
           "key_path": r"HKEY_CURRENT_USER\Software\Foo",
           "display_name": r"VSS2:NTFS:\Users\jcloudy\NTUSER.DAT",
           "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
    ev = normalize.normalize("plaso_registry", _wrap(rec))
    assert ev is not None and ev["car_object"] == "registry"
    assert ev["user"] == "jcloudy"
    # the retired dead SID extract must not reappear
    assert "hive_user_sid" not in ev["_native"]


def test_registry_system_hive_has_no_user():
    rec = {"data_type": "windows:registry:key_value",
           "key_path": r"HKEY_LOCAL_MACHINE\System\ControlSet001\Services\foo",
           "display_name": r"NTFS:\Windows\System32\config\SYSTEM",
           "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
    ev = normalize.normalize("plaso_registry", _wrap(rec))
    assert ev is not None and ev.get("user") is None      # honest null


def test_registry_real_username_wins_over_path():
    # fill-only-null: a recorded username is never overwritten by the path
    rec = {"data_type": "windows:registry:key_value",
           "key_path": r"HKEY_CURRENT_USER\Software\Foo",
           "display_name": r"NTFS:\Users\jcloudy\NTUSER.DAT",
           "image_hostname": "DESKTOP-PM6C56D", "username": "REALDOM\\real"}
    ev = normalize.normalize("plaso_registry", _wrap(rec))
    assert ev["user"] == "REALDOM\\real"


# --- shell items (plaso_shellitem.py) ---------------------------------------

def test_shellitem_derives_user_from_artefact_path():
    rec = {"data_type": "windows:shell_item:file_entry",
           "timestamp_desc": "Creation Time",
           "display_name": (r"VSS2:NTFS:\Users\jcloudy\AppData\Roaming\Microsoft"
                            r"\Windows\Start Menu\Programs\Windows PowerShell"
                            r"\Windows PowerShell.lnk"),
           "origin": "Windows PowerShell.lnk",
           "shell_item_path": r"<My Computer> C:\Windows\System32\cmd.exe",
           "long_name": "cmd.exe", "name": "cmd.exe",
           "image_hostname": "DESKTOP-PM6C56D"}
    ev = normalize.normalize("plaso_shellitem", _wrap(rec))
    assert ev is not None and ev["car_object"] == "file"
    assert ev["user"] == "jcloudy"


def test_shellitem_system_origin_has_no_user():
    rec = {"data_type": "windows:shell_item:file_entry",
           "timestamp_desc": "Creation Time",
           "display_name": (r"NTFS:\Windows\WinSxS\amd64_x\Windows PowerShell "
                            r"(x86).lnk"),
           "origin": "Windows PowerShell (x86).lnk",
           "shell_item_path": r"<My Computer> C:\Windows\SysWOW64\cmd.exe",
           "long_name": "cmd.exe", "name": "cmd.exe",
           "image_hostname": "DESKTOP-PM6C56D"}
    ev = normalize.normalize("plaso_shellitem", _wrap(rec))
    assert ev is not None and ev.get("user") is None


# --- LNK (plaso_artifacts.py) -----------------------------------------------

def test_lnk_derives_user_from_recent_folder_path():
    rec = {"data_type": "windows:lnk:link", "timestamp_desc": "Creation Time",
           "link_target": r"<My Computer> C:\Windows\System32\notepad.exe",
           "display_name": (r"NTFS:\Users\jcloudy\AppData\Roaming\Microsoft"
                            r"\Windows\Recent\notepad.lnk"),
           "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
    ev = normalize.normalize("l2t_lnk", _wrap(rec))
    assert ev is not None and ev["car_object"] == "file"
    assert ev["user"] == "jcloudy"


# --- Recycle Bin (plaso_artifacts.py) ---------------------------------------

def test_recyclebin_derives_user_and_sid_uid_from_path():
    rec = {"data_type": "windows:metadata:deleted_item",
           "timestamp_desc": "Content Deletion Time",
           "original_filename": (r"C:\Users\jcloudy\Desktop\Larry King_ Time to "
                                 r"Repeal the Second Amendment_files"),
           "display_name": (r"NTFS:\$Recycle.Bin"
                            r"\S-1-5-21-2734969515-1644526556-1039763013-1001"
                            r"\$IQAU6NQ"),
           "file_size": 5092043, "record_index": 1,
           "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
    ev = normalize.normalize("l2t_recyclebin", _wrap(rec))
    assert ev is not None and ev["car_action"] == "delete"
    # the original path names the owning user…
    assert ev["user"] == "jcloudy"
    # …and the $Recycle.Bin per-user subdir IS the deleting account's SID
    assert ev["uid"] == "S-1-5-21-2734969515-1644526556-1039763013-1001"


# --- case-insensitivity (#55 review) ----------------------------------------
# Windows paths are case-insensitive and sources emit the segment in any case;
# the match must not be, or attribution silently fails on a casing difference.

def test_user_from_path_is_case_insensitive():
    rec = {"data_type": "windows:registry:key_value",
           "key_path": r"HKEY_CURRENT_USER\Software\Foo",
           "display_name": r"NTFS:\users\jcloudy\ntuser.dat",   # lower-case \users\
           "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
    ev = normalize.normalize("plaso_registry", _wrap(rec))
    # matched despite the casing; the captured name keeps its own case
    assert ev["user"] == "jcloudy"


def test_recyclebin_sid_uid_is_case_insensitive():
    rec = {"data_type": "windows:metadata:deleted_item",
           "timestamp_desc": "Content Deletion Time",
           "original_filename": r"C:\users\jcloudy\Desktop\x",
           "display_name": (r"NTFS:\$recycle.bin"      # lower-case bucket dir
                            r"\S-1-5-21-2734969515-1644526556-1039763013-1001"
                            r"\$IQAU6NQ"),
           "file_size": 1, "record_index": 1,
           "image_hostname": "DESKTOP-PM6C56D", "username": "-"}
    ev = normalize.normalize("l2t_recyclebin", _wrap(rec))
    assert ev["user"] == "jcloudy"
    assert ev["uid"] == "S-1-5-21-2734969515-1644526556-1039763013-1001"

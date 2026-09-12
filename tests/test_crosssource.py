"""Cross-source convergence (crosssource.py) — the same entity seen across
sources folds into one property view, tagged with which artefact supplied each
field and the confidence it was joined at. The per-source stores are untouched.

This is the 'grab different properties from different artefacts' payoff: a log
gives the command line + hash, memory the pid + recovered command line, a disk
execution artefact the run — converged into more than any one source held.
"""
import os

from byakugan import crosssource, store


def _store(case_dir, source, events):
    d = os.path.join(case_dir, source)
    os.makedirs(d, exist_ok=True)
    st = store.CarStore(os.path.join(d, "car.db"))
    st.insert_events(events)
    st.close()


def _proc(guid, host="WIN10", **kw):
    return dict({"car_object": "process", "car_action": "create", "guid": guid,
                 "source_host": host, "timestamp": "2026-01-01T00:00:00Z"}, **kw)


def _one(conv, obj="process"):
    got = [c for c in conv if c["car_object"] == obj]
    assert got, f"expected a {obj} convergence, got {conv}"
    return got[0]


# --------------------------------------------------------------------------- #
# heuristic_image: one binary, three artefacts, one merged view
# --------------------------------------------------------------------------- #
def test_heuristic_image_merges_properties_with_provenance(tmp_path):
    d = str(tmp_path)
    # a log: full-path image, the command line, the binary hash, the user
    _store(d, "evtx", [_proc("log-1", image_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                             exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                             command_line="powershell -enc SQBFAFgA", sha256_hash="ABC123",
                             user="WIN10\\jdh")])
    # memory: basename exe, recovered command line, a live pid (the log lacks it here)
    _store(d, "memory", [_proc("mem-1", exe="powershell.exe",
                               command_line="powershell -enc SQBFAFgA", pid=4242)])
    # a disk execution artefact (prefetch): just proves it RAN
    _store(d, "disk", [_proc("pf-1", exe="POWERSHELL.EXE")])

    c = _one(crosssource.converge(d))
    assert c["tier"] == "heuristic_image"                     # a lead, honestly labelled
    assert set(c["sources"]) == {"evtx", "memory", "disk"}
    # the binary basename joined a full path, a basename and an upper-case name
    assert c["join_key"][-1] == "powershell.exe"
    # each property records the artefact(s) that supplied it — the whole point
    assert c["property_sources"]["sha256_hash"] == ["evtx"]   # only the log had the hash
    assert c["property_sources"]["pid"] == ["memory"]         # only memory had the live pid
    assert set(c["property_sources"]["command_line"]) == {"evtx", "memory"}  # both agreed
    # the merged view holds more than any single source did
    for f in ("sha256_hash", "pid", "command_line", "user"):
        assert f in c["properties"]


# --------------------------------------------------------------------------- #
# definitive_content: same bytes across sources outranks a mere image lead
# --------------------------------------------------------------------------- #
def test_content_hash_convergence_is_host_independent(tmp_path):
    d = str(tmp_path)
    # the SAME file (by hash) on two different hosts — content identity is definitive
    _store(d, "amcache", [dict({"car_object": "file", "car_action": "create", "guid": "am-1",
                                "source_host": "HOSTA", "timestamp": "2026-01-01T00:00:00Z",
                                "file_path": r"C:\evil.exe", "sha256_hash": "DEADBEEF"})])
    _store(d, "memory-b", [dict({"car_object": "file", "car_action": "create", "guid": "mem-2",
                                 "source_host": "HOSTB", "timestamp": "2026-01-01T00:00:00Z",
                                 "file_name": "evil.exe", "sha256_hash": "DEADBEEF"})])
    c = _one(crosssource.converge(d), obj="file")
    assert c["tier"] == "definitive_content"
    assert set(c["sources"]) == {"amcache", "memory-b"}
    # both a path (amcache) and a name (memory) survive in the merged view
    assert "file_path" in c["properties"] and "file_name" in c["properties"]


# --------------------------------------------------------------------------- #
# A4: a disk PE's hash converges with — and hydrates — a module / driver
# --------------------------------------------------------------------------- #
def test_disk_pe_hash_hydrates_a_module(tmp_path):
    d = str(tmp_path)
    # a disk PE (pe_coff -> file): path + sha256 + PE metadata, no load context
    _store(d, "pe", [dict({"car_object": "file", "car_action": "create",
                           "guid": "pe-1", "source_host": "WIN10",
                           "timestamp": "2026-01-01T00:00:00Z",
                           "file_path": r"C:\Windows\System32\evil.dll",
                           "sha256_hash": "DEADBEEF"})])
    # a loaded module (Sysmon EID 7): module_path + name + the same bytes' hash
    _store(d, "sysmon", [dict({"car_object": "module", "car_action": "load",
                               "guid": "mod-1", "source_host": "WIN10",
                               "timestamp": "2026-01-01T00:00:00Z",
                               "module_path": r"C:\Windows\System32\evil.dll",
                               "module_name": "evil.dll",
                               "sha256_hash": "DEADBEEF"})])
    conv = crosssource.converge(d)
    hits = [c for c in conv if c["tier"] == "definitive_content"
            and set(c["sources"]) == {"pe", "sysmon"}]
    assert hits, f"module did not converge with the disk PE by hash: {conv}"
    c = hits[0]
    # the merged view holds BOTH the disk PE's path and the module's own path/name
    assert "file_path" in c["properties"] and "module_path" in c["properties"]
    assert c["property_sources"]["sha256_hash"] == ["pe", "sysmon"]  # same bytes
    # a mixed-object content group is labelled deterministically from the join
    # key (the content bucket = "file"), not by row iteration order (#55 review)
    assert c["car_object"] == "file"
    assert set(c["car_objects"]) == {"file", "module"}


def test_disk_pe_hash_hydrates_a_driver(tmp_path):
    d = str(tmp_path)
    _store(d, "pe", [dict({"car_object": "file", "car_action": "create",
                           "guid": "pe-2", "source_host": "WIN10",
                           "timestamp": "2026-01-01T00:00:00Z",
                           "file_path": r"C:\Windows\System32\drivers\wfplwfs.sys",
                           "sha256_hash": "CAFED00D"})])
    _store(d, "sysmon", [dict({"car_object": "driver", "car_action": "load",
                               "guid": "drv-1", "source_host": "WIN10",
                               "timestamp": "2026-01-01T00:00:00Z",
                               "module_name": "wfplwfs",
                               "sha256_hash": "CAFED00D"})])
    conv = crosssource.converge(d)
    hits = [c for c in conv if c["tier"] == "definitive_content"
            and set(c["sources"]) == {"pe", "sysmon"}]
    assert hits, f"driver did not converge with the disk PE by hash: {conv}"
    # the disk PE's sha256 hydrates the driver (same bytes across the two rows)
    assert hits[0]["property_sources"]["sha256_hash"] == ["pe", "sysmon"]


# --------------------------------------------------------------------------- #
# B1: the canonical native volume GUID bridges sources
# --------------------------------------------------------------------------- #
def _row(obj, action, guid, source_host, native):
    return {"car_object": obj, "car_action": action, "guid": guid,
            "source_host": source_host, "timestamp": "2026-01-01T00:00:00Z",
            "_native": native}


def test_native_volume_guid_bridges_sources_case_folded(tmp_path):
    d = str(tmp_path)
    # the same volume, seen lower-case in a registry mount and UPPER in a USN row
    _store(d, "registry", [_row("registry", "value_edit", "registry-1", "PM6C56D",
                                {"key_path": r"...\MountPoints2",
                                 "data": r"\??\Volume{09931f21-7faf-44a9-81d8-1e73c14b9eaf}"})])
    _store(d, "usn", [_row("file", "create", "file-1", "PM6C56D",
                           {"data_type": "fs:ntfs:usn_change",
                            "path": r"\\?\Volume{09931F21-7FAF-44A9-81D8-1E73C14B9EAF}\x"})])
    hits = [c for c in crosssource.converge(d) if c["tier"] == "definitive_native_id"]
    assert hits, "volume GUID did not bridge the two sources"
    c = hits[0]
    assert c["join_key"] == ["volume", "09931f21-7faf-44a9-81d8-1e73c14b9eaf"]  # folded
    assert set(c["sources"]) == {"registry", "usn"}
    assert set(c["car_objects"]) == {"file", "registry"}       # a mixed-object bridge
    assert c["car_object"] in c["car_objects"]                 # deterministic label


def test_native_id_uses_the_first_class_column(tmp_path):
    d = str(tmp_path)
    # the volume_guid column is authoritative — a row that carries it (with no
    # Volume{ token left in native) still converges on it
    _store(d, "a", [dict(_row("registry", "value_edit", "a-1", "H", {"k": "v"}),
                         volume_guid="09931f21-7faf-44a9-81d8-1e73c14b9eaf")])
    _store(d, "b", [dict(_row("file", "create", "b-1", "H", {"k": "w"}),
                         volume_guid="09931f21-7faf-44a9-81d8-1e73c14b9eaf")])
    hits = [c for c in crosssource.converge(d) if c["tier"] == "definitive_native_id"]
    assert hits and hits[0]["join_key"] == ["volume", "09931f21-7faf-44a9-81d8-1e73c14b9eaf"]
    assert set(hits[0]["sources"]) == {"a", "b"}


def test_native_mac_bridges_a_lnk_droid_and_a_networklist_entry(tmp_path):
    d = str(tmp_path)
    # a LNK carries the origin NIC MAC inside its DLT droid (v1 GUID); a registry
    # NetworkList row carries the same MAC literally — they converge on it
    _store(d, "lnk", [_row("file", "create", "f-1", "PM6C56D",
                           {"data_type": "windows:lnk:link",
                            "droid_file_id": "5c2307d9-3369-11e2-be70-001cc42df40b"})])
    _store(d, "registry", [_row("registry", "value_edit", "r-1", "PM6C56D",
                                {"key_path": r"...\NetworkList\Signatures",
                                 "DefaultGatewayMac": "00:1C:C4:2D:F4:0B"})])
    hits = [c for c in crosssource.converge(d)
            if c["tier"] == "definitive_native_id" and c["join_key"][0] == "mac"]
    assert hits, "the NIC MAC did not bridge the LNK droid and the NetworkList entry"
    assert hits[0]["join_key"] == ["mac", "00:1c:c4:2d:f4:0b"]
    assert set(hits[0]["sources"]) == {"lnk", "registry"}


def test_native_serial_bridges_usbstor_and_setupapi(tmp_path):
    d = str(tmp_path)
    # the SAME SanDisk stick: a registry USBSTOR key names it one way, a setupapi
    # device-install log another (# separators, {guid} suffix) — they converge on
    # the mined iSerialNumber even though neither carries a device_serial column.
    _store(d, "usbstor", [_row("registry", "value_edit", "r-1", "PM6C56D",
                               {"key_path": r"...\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Extreme"
                                            r"&Rev_0001\AA010215170355310594&0"})])
    _store(d, "setupapi", [_row("registry", "value_edit", "r-2", "PM6C56D",
                                {"message": r"Device Install ... _??_USBSTOR#Disk&Ven_SanDisk"
                                            r"&Prod_Extreme&Rev_0001#AA010215170355310594&0"
                                            r"#{53f56307-b6bf-11d0-94f2-00a0c91efb8b} - SUCCESS"})])
    hits = [c for c in crosssource.converge(d)
            if c["tier"] == "definitive_native_id" and c["join_key"][0] == "serial"]
    assert hits, "the USB serial did not bridge the USBSTOR and setupapi rows"
    assert hits[0]["join_key"] == ["serial", "AA010215170355310594"]
    assert set(hits[0]["sources"]) == {"usbstor", "setupapi"}


def test_native_serial_column_must_validate(tmp_path):
    d = str(tmp_path)
    # a malformed device_serial column value (a stray USBSTOR path, not a bare
    # serial) must NOT mint a join — as_serial rejects it, and native carries
    # nothing else to converge on.
    bad = r"USBSTOR\Disk&Ven_SanDisk&Prod_Extreme&Rev_0001\AA010215170355310594&0"
    _store(d, "a", [dict(_row("registry", "value_edit", "a-1", "H", {"k": "v"}), device_serial=bad)])
    _store(d, "b", [dict(_row("file", "create", "b-1", "H", {"k": "w"}), device_serial=bad)])
    assert [c for c in crosssource.converge(d) if c["tier"] == "definitive_native_id"] == []


def test_native_id_column_must_validate_as_canonical(tmp_path):
    d = str(tmp_path)
    # a malformed volume_guid column value (a stray path) must NOT mint a join —
    # it is validated as a canonical GUID first, else ignored (falls back to
    # native, which here carries nothing)
    bad = r"\\?\Volume{not-a-guid}"
    _store(d, "a", [dict(_row("registry", "value_edit", "a-1", "H", {"k": "v"}), volume_guid=bad)])
    _store(d, "b", [dict(_row("file", "create", "b-1", "H", {"k": "w"}), volume_guid=bad)])
    assert [c for c in crosssource.converge(d) if c["tier"] == "definitive_native_id"] == []


def test_native_id_ignores_com_clsid_noise(tmp_path):
    d = str(tmp_path)
    # bare canonical GUIDs with NO Volume{ token — pure COM noise, and the same
    # {8-4-4-4-12} shape a MachineGuid embedded in a crypto-key path would show;
    # neither must ever create a native-id convergence.
    clsid = "f750e6c3-38ee-11d1-85e5-00c04fc295ee"
    _store(d, "a", [_row("registry", "value_edit", "a-1", "H", {"clsid": clsid})])
    _store(d, "b", [_row("registry", "value_edit", "b-1", "H",
                         {"key": r"...\Crypto\SystemKeys\0d8b_8b9b9f31-6016-4b10-83ef-324b62a37898"})])
    assert [c for c in crosssource.converge(d)
            if c["tier"] == "definitive_native_id"] == []


def test_native_id_single_source_is_not_a_convergence(tmp_path):
    d = str(tmp_path)
    vol = r"\\?\Volume{09931f21-7faf-44a9-81d8-1e73c14b9eaf}"
    _store(d, "only", [_row("registry", "value_edit", "x", "H", {"a": vol}),
                       _row("file", "create", "y", "H", {"b": vol})])
    assert [c for c in crosssource.converge(d)
            if c["tier"] == "definitive_native_id"] == []   # one source ≠ cross-source


# --------------------------------------------------------------------------- #
# a single-source group is NOT a convergence; no cross-source noise
# --------------------------------------------------------------------------- #
def test_single_source_is_not_a_convergence(tmp_path):
    d = str(tmp_path)
    _store(d, "only", [_proc("a", exe="cmd.exe"), _proc("b", exe="cmd.exe")])
    assert crosssource.converge(d) == []


# --------------------------------------------------------------------------- #
# different hosts never image-converge (instance identity is host-scoped)
# --------------------------------------------------------------------------- #
def test_image_lead_never_crosses_hosts(tmp_path):
    d = str(tmp_path)
    _store(d, "s1", [_proc("x", host="HOSTA", exe="cmd.exe")])
    _store(d, "s2", [_proc("y", host="HOSTB", exe="cmd.exe")])
    # no shared hash, different hosts -> no image convergence
    assert [c for c in crosssource.converge(d) if c["tier"] == "heuristic_image"] == []

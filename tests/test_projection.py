"""The CAR->ECS forward projector (byakugan/elastic/projection.py), driven by
the elastic/projection/ contract (epic #99 phase 2)."""
import hashlib

from byakugan.elastic import projection as pj


def _process_event(**over):
    ev = {
        "car_object": "process", "timestamp": "2024-01-01 00:00:00.123", "car_action": "create",
        "guid": "P1", "owning_guid": None, "volume_guid": "Volume{abc}",
        "mac_address": "AA:BB:CC:DD:EE:FF", "device_serial": "SN123",
        "link_confidence": "definitive", "source_artefact": "evtx_sysmon", "source_host": "HOST1",
        "native": {"EventId": 1},
        "fqdn": "host1.corp.example", "hostname": "HOST1",
        "command_line": "cmd.exe /c whoami", "exe": "cmd.exe",
        "image_path": r"C:\Windows\System32\cmd.exe",
        "md5_hash": "deadbeef", "sha1_hash": None, "sha256_hash": None,
        "parent_exe": "explorer.exe", "parent_image_path": r"C:\Windows\explorer.exe",
        "pid": "4536", "ppid": "notanumber", "sid": "S-1-5-18", "signer": None,
        "user": r"NT AUTHORITY\SYSTEM", "integrity_level": "System",
        "parent_command_line": None, "current_working_directory": r"C:\ ".strip(),
        "env_vars": "A=1\nB=2", "access_level": None, "call_trace": None,
        "parent_guid": "PP1", "signature_valid": 1, "target_guid": None,
        "target_pid": None, "target_address": None, "target_name": None, "uid": None,
    }
    ev.update(over)
    return ev


def test_header_identity_timestamp_guid_confidence_provenance_native():
    stream, doc_id, doc = pj.project_event(_process_event(), "default")
    assert stream == "logs-car.process-default"
    # timestamp: normalised (UTC, 'T'/'Z') at @timestamp, exact original kept verbatim
    assert doc["@timestamp"] == "2024-01-01T00:00:00.123000Z"
    assert doc["car"]["timestamp"] == "2024-01-01 00:00:00.123"
    # guid -> event.id always; owning_guid absent -> guid also wins process.entity_id (process only)
    assert doc["event"]["id"] == "P1"
    assert doc["process"]["entity_id"] == "P1"
    # car_action -> event.action (verbatim verb)
    assert doc["event"]["action"] == "create"
    # source_artefact -> event.provider, source_host -> host.name
    assert doc["event"]["provider"] == "evtx_sysmon"
    assert doc["host"]["name"] == "HOST1"
    # link_confidence: the pipeline word -> a float, kept verbatim as a label too
    assert doc["car"]["link_confidence"] == 1.0
    assert doc["labels"]["link_confidence"] == "definitive"
    # volume_guid/mac_address/device_serial -> car.*
    assert doc["car"]["volume_guid"] == "Volume{abc}"
    assert doc["car"]["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert doc["car"]["device_serial"] == "SN123"
    # native -> car.native, verbatim JSON object
    assert doc["car"]["native"] == {"EventId": 1}
    # constants + data_stream shape
    assert doc["event"]["kind"] == "event" and doc["event"]["module"] == "car"
    assert doc["event"]["dataset"] == "car.process"
    assert doc["data_stream"] == {"type": "logs", "dataset": "car.process", "namespace": "default"}
    assert doc["ecs"]["version"] == "8.11.0"
    assert doc["car"]["object"] == "process"


def test_owning_guid_wins_process_entity_id_over_the_process_fallback():
    _, _, doc = pj.project_event(_process_event(owning_guid="ACTOR"), "default")
    assert doc["event"]["id"] == "P1"                  # guid still names the row
    assert doc["process"]["entity_id"] == "ACTOR"       # but owning_guid (the actor) wins the link


def test_ecs_also_fallback_native_and_related_pivots():
    _, _, doc = pj.project_event(_process_event(), "default")
    # ecs: primary mapping
    assert doc["process"]["command_line"] == "cmd.exe /c whoami"
    assert doc["process"]["name"] == "cmd.exe"
    assert doc["process"]["parent"]["entity_id"] == "PP1"
    # also: unconditional copies (process.hash.md5 -> related.hash)
    assert doc["process"]["hash"]["md5"] == "deadbeef"
    assert doc["related"]["hash"] == ["deadbeef"]
    assert doc["related"]["user"] == [r"NT AUTHORITY\SYSTEM"]
    # fallback: hostname (primary, no fallback:) fills host.hostname; fqdn
    # (fallback: true) loses it but its also: (related.hosts) still lands,
    # AND its own value is preserved verbatim at car.process.fqdn
    assert doc["host"]["hostname"] == "HOST1"
    assert doc["related"]["hosts"] == ["HOST1", "host1.corp.example"]
    assert doc["car"]["process"]["fqdn"] == "host1.corp.example"
    # sid (primary, no fallback:) fills user.id; uid (fallback) is null here,
    # so nothing is lost and nothing is captured for it
    assert doc["user"]["id"] == "S-1-5-18"
    assert "uid" not in doc["car"]["process"]
    # native: true (no ECS home)
    assert doc["car"]["process"]["integrity_level"] == "System"
    # process.env_vars: the one process.yml normalisation note — split on \n
    assert doc["process"]["env_vars"] == ["A=1", "B=2"]
    # a null CAR value projects to an absent field, never an empty string
    assert "subject_name" not in doc["process"].get("code_signature", {})
    assert "sha1" not in doc["process"]["hash"] and "sha256" not in doc["process"]["hash"]


def test_authentication_fallback_losers_keep_their_also_copies_and_native_capture():
    """Two fields sharing a target (rules.fallback): the PRIMARY (no
    `fallback:` key) wins the ECS target; a losing `fallback: true` entry's
    own `also:` copies still land unconditionally, and its raw value is
    preserved verbatim at car.<object>.<field> rather than dropped."""
    ev = {"car_object": "authentication", "timestamp": "2024-01-01T00:00:00Z",
         "car_action": "success", "guid": "A1", "source_host": "H",
         "target_user": "alice", "user": "bob",
         "target_ad_domain": "CORP", "ad_domain": "OTHERDOM",
         "target_uid": "S-1-TGT", "uid": "S-1-SRC"}
    _, _, doc = pj.project_event(ev, "default")
    assert doc["user"]["name"] == "alice"                       # target_user: primary
    assert doc["source"]["user"]["name"] == "bob"                # user: also:, unconditional
    assert doc["related"]["user"] == ["alice", "bob"]
    assert doc["car"]["authentication"]["user"] == "bob"         # the fallback loser, preserved
    assert doc["user"]["domain"] == "CORP"
    assert doc["car"]["authentication"]["ad_domain"] == "OTHERDOM"
    assert doc["source"]["user"]["id"] == "S-1-SRC"               # uid's also:, unconditional
    assert doc["car"]["authentication"]["uid"] == "S-1-SRC"


def test_event_defaults_category_type_and_outcome_from_action():
    _, _, doc = pj.project_event(_process_event(car_action="terminate"), "default")
    assert doc["event"]["category"] == ["process"]
    assert doc["event"]["type"] == ["end"]                       # process.yml type_by_action.terminate

    auth_ok = {"car_object": "authentication", "timestamp": "2024-01-01T00:00:00Z",
              "car_action": "success", "guid": "A1", "source_host": "H"}
    _, _, doc2 = pj.project_event(auth_ok, "default")
    assert doc2["event"]["outcome"] == "success"
    auth_err = dict(auth_ok, car_action="error", guid="A2")
    _, _, doc3 = pj.project_event(auth_err, "default")
    assert doc3["event"]["outcome"] == "unknown"


def test_event_defaults_outcome_from_a_boolean_object_field():
    """socket/user_session derive event.outcome from their own boolean field
    (event_defaults.outcome_from_field) — never a plain verbatim copy of the
    boolean into the keyword event.outcome (rules.event_action)."""
    ok = {"car_object": "socket", "timestamp": "2024-01-01T00:00:00Z", "car_action": "bind",
         "guid": "S1", "source_host": "H", "success": 1}
    _, _, doc = pj.project_event(ok, "default")
    assert doc["event"]["outcome"] == "success"
    fail = dict(ok, success=0, guid="S2")
    _, _, doc2 = pj.project_event(fail, "default")
    assert doc2["event"]["outcome"] == "failure"


def test_derived_http_request_method():
    tunnel = {"car_object": "http", "timestamp": "2024-01-01T00:00:00Z", "car_action": "tunnel",
             "guid": "H1", "source_host": "H"}
    _, _, doc = pj.project_event(tunnel, "default")
    assert doc["http"]["request"]["method"] == "CONNECT"
    get = dict(tunnel, car_action="get", guid="H2")
    _, _, doc2 = pj.project_event(get, "default")
    assert doc2["http"]["request"]["method"] == "GET"


def test_verbatim_normalisations_hive_protocol_direction_extension():
    reg = {"car_object": "registry", "timestamp": "2024-01-01T00:00:00Z", "car_action": "create",
          "guid": "R1", "source_host": "H", "hive": "HKEY_LOCAL_MACHINE"}
    assert pj.project_event(reg, "default")[2]["registry"]["hive"] == "HKLM"

    flow = {"car_object": "flow", "timestamp": "2024-01-01T00:00:00Z", "car_action": "start",
           "guid": "F1", "source_host": "H", "application_protocol": "HTTP",
           "transport_protocol": "TCP", "network_direction": "in"}
    _, _, fdoc = pj.project_event(flow, "default")
    assert fdoc["network"]["protocol"] == "http"
    assert fdoc["network"]["transport"] == "tcp"
    assert fdoc["network"]["direction"] == "inbound"
    # a value outside the in/out vocabulary passes through verbatim
    other = dict(flow, network_direction="internal", guid="F2")
    assert pj.project_event(other, "default")[2]["network"]["direction"] == "internal"

    f = {"car_object": "file", "timestamp": "2024-01-01T00:00:00Z", "car_action": "create",
        "guid": "FL1", "source_host": "H", "extension": ".docx"}
    assert pj.project_event(f, "default")[2]["file"]["extension"] == "docx"


def test_coercion_long_ip_boolean_date_success_and_failure():
    # long: a real pid string coerces; a non-numeric ppid keeps its native home
    _, _, doc = pj.project_event(_process_event(), "default")
    assert doc["process"]["pid"] == 4536 and isinstance(doc["process"]["pid"], int)
    assert "pid" not in doc["car"]["process"]                    # coerced fine, nothing to preserve
    assert doc["car"]["process"]["ppid"] == "notanumber"
    assert "parent" not in doc["process"] or "pid" not in doc["process"]["parent"]

    # ip: a bad address is kept verbatim, the ECS ip field left unset
    sock = {"car_object": "socket", "timestamp": "2024-01-01T00:00:00Z", "car_action": "bind",
           "guid": "S1", "source_host": "H", "remote_address": "not-an-ip"}
    _, _, sdoc = pj.project_event(sock, "default")
    assert "ip" not in sdoc.get("destination", {})
    assert sdoc["car"]["socket"]["remote_address"] == "not-an-ip"
    good_sock = dict(sock, remote_address="10.0.0.1", guid="S2")
    _, _, sdoc2 = pj.project_event(good_sock, "default")
    assert sdoc2["destination"]["ip"] == "10.0.0.1"

    # boolean: SQLite round-trips a mapping-asserted True as the int 1 (see
    # byakugan/store.py) — must still coerce to a real boolean
    proc_sig = _process_event(signature_valid=1)
    assert pj.project_event(proc_sig, "default")[2]["process"]["code_signature"]["valid"] is True

    # date: a real ISO timestamp coerces; a garbage one keeps its native home
    good = {"car_object": "file", "timestamp": "2024-01-01T00:00:00Z", "car_action": "create",
           "guid": "F1", "source_host": "H", "creation_time": "2024-01-01T00:00:00Z"}
    assert pj.project_event(good, "default")[2]["file"]["created"] == "2024-01-01T00:00:00Z"
    bad = dict(good, creation_time="not-a-date", guid="F2")
    _, _, bdoc = pj.project_event(bad, "default")
    assert "created" not in bdoc.get("file", {})
    assert bdoc["car"]["file"]["creation_time"] == "not-a-date"


def test_no_parseable_timestamp_returns_none():
    missing = _process_event(timestamp=None)
    assert pj.project_event(missing, "default") is None
    garbage = _process_event(timestamp="not-a-timestamp")
    assert pj.project_event(garbage, "default") is None


def test_unknown_car_object_raises():
    import pytest
    with pytest.raises(ValueError):
        pj.project_event({"car_object": "not_a_real_object", "timestamp": "2024-01-01T00:00:00Z"},
                         "default")


# --- relationships / inferred ------------------------------------------------

def _rel_row(**over):
    row = {"id": 7, "timestamp": "2024-01-01T00:00:01Z", "source_host": "HOST1",
          "relationship": "loaded", "source_object": "process", "source_guid": "P1",
          "target_object": "module", "target_guid": "M1", "confidence": "definitive",
          "method": "native_guid", "class": "declared", "identity_key": None,
          "inferred_end": None, "corroborated_by": None}
    row.update(over)
    return row


def test_project_relationship():
    stream, doc_id, doc = pj.project_relationship(_rel_row(), "default")
    assert stream == "logs-car.rel-default"
    assert doc["car"]["rel"] == {
        "relationship": "loaded", "source": {"object": "process", "guid": "P1"},
        "target": {"object": "module", "guid": "M1"}, "confidence": "definitive",
        "method": "native_guid", "class": "declared", "timestamp": "2024-01-01T00:00:01Z"}
    assert doc["host"]["name"] == "HOST1"
    assert doc["@timestamp"] == "2024-01-01T00:00:01Z"
    assert doc["event"]["dataset"] == "car.rel" and "object" not in doc["car"]
    expected = pj.sha1_id("HOST1", "P1", "loaded", "M1", "2024-01-01T00:00:01Z", "declared", None)
    assert doc_id == expected

    derived = _rel_row(source_guid="G1", target_guid=None, target_object="process",
                       corroborated_by=["G2", "G3"], **{"class": "derived", "identity_key": "hash"})
    _, _, ddoc = pj.project_relationship(derived, "default")
    assert ddoc["car"]["rel"]["corroborated_by"] == ["G2", "G3"]
    assert ddoc["car"]["rel"]["identity_key"] == "hash"


def test_project_relationship_no_timestamp_is_none():
    assert pj.project_relationship(_rel_row(timestamp="garbage"), "default") is None
    assert pj.project_relationship(_rel_row(timestamp=None), "default") is None


def _inferred_row(**over):
    row = {"id": 3, "node_id": "proc-deadbeef", "source_host": "HOST1", "object": "process",
          "identity_key": "guid", "identity_value": "X",
          "reason": "derived: referenced by 2 records", "method": "native_guid",
          "corroborated_by": ["G1", "G2"], "properties": {"pid": 100},
          "first_seen": "2024-01-01T00:00:00Z", "last_seen": "2024-01-01T00:05:00Z"}
    row.update(over)
    return row


def test_project_inferred():
    stream, doc_id, doc = pj.project_inferred(_inferred_row(), "default")
    assert stream == "logs-car.inferred-default"
    assert doc_id == "proc-deadbeef"                    # node_id verbatim, never hashed
    assert doc["@timestamp"] == "2024-01-01T00:00:00Z"
    # first_seen's also: (car.inferred.first_seen, also_type date == type date)
    # takes the SAME coerced value as @timestamp, unlike the rel/header
    # verbatim-string companions (their also_type is keyword, differs)
    assert doc["car"]["inferred"]["first_seen"] == doc["@timestamp"]
    assert doc["car"]["inferred"]["last_seen"] == "2024-01-01T00:05:00Z"
    assert doc["car"]["inferred"]["node_id"] == "proc-deadbeef"
    assert doc["car"]["inferred"]["corroborated_by"] == ["G1", "G2"]
    assert doc["car"]["inferred"]["properties"] == {"pid": 100}
    assert doc["event"]["dataset"] == "car.inferred" and "object" not in doc["car"]


def test_project_inferred_no_timestamp_is_none_and_missing_node_id_raises():
    import pytest
    assert pj.project_inferred(_inferred_row(first_seen=""), "default") is None
    with pytest.raises(ValueError):
        pj.project_inferred(_inferred_row(node_id=None), "default")


def _content_row(**kw):
    return dict({"node_id": "sid:S-1-5-21-1-2-3-1001", "kind": "user_account",
                 "identity_key": "sid", "identity_value": "S-1-5-21-1-2-3-1001",
                 "ref_count": 3, "properties": {"user": ["alice"]},
                 "first_seen": "2024-01-01T00:00:00Z",
                 "last_seen": "2024-01-01T00:05:00Z"}, **kw)


def test_project_content():
    stream, doc_id, doc = pj.project_content(_content_row(), "default")
    assert stream == "logs-car.content-default"
    assert doc_id == "sid:S-1-5-21-1-2-3-1001"          # node_id verbatim, never hashed
    assert doc["@timestamp"] == "2024-01-01T00:00:00Z"
    c = doc["car"]["content"]
    assert (c["node_id"], c["kind"], c["identity_key"], c["identity_value"]) == (
        "sid:S-1-5-21-1-2-3-1001", "user_account", "sid", "S-1-5-21-1-2-3-1001")
    assert c["ref_count"] == 3 and c["properties"] == {"user": ["alice"]}
    assert doc["event"]["dataset"] == "car.content"
    # global by content: no host on the document
    assert "host" not in doc


def test_project_content_no_timestamp_is_none_and_missing_node_id_raises():
    import pytest
    assert pj.project_content(_content_row(first_seen=""), "default") is None
    with pytest.raises(ValueError):
        pj.project_content(_content_row(node_id=None), "default")


# --- the shared document_id helper ------------------------------------------

def test_sha1_id_hand_computed_vector():
    # a hand-computed vector: sha1("a|b||d") with the third component null
    # (renders as an empty string, never dropped — the joiner position holds)
    expected = hashlib.sha1(b"a|b||d").hexdigest()
    assert pj.sha1_id("a", "b", None, "d") == expected
    assert expected == "9815380074d38c06e70d29c40d36f6832410b2a9"


def test_object_document_id_matches_the_conventions_recipe():
    ev = _process_event()
    _, doc_id, _ = pj.project_event(ev, "default")
    expected = pj.sha1_id("HOST1", "process", "P1", "create", "2024-01-01 00:00:00.123", None, None)
    assert doc_id == expected


def test_known_objects_covers_the_thirteen_car_objects():
    objs = pj.known_objects()
    assert len(objs) == 13
    assert {"process", "file", "http", "authentication"} <= objs

"""JLECmd jump lists -> file/read via the flattening adapter (real LoneWolf shape).

The flatten step runs in the Go parse engine now (go/internal/adapt); the
behaviour asserted here — one record per DestListEntry, app context merged in,
/Date(ms)/ rendered ISO — is the artefact contract, exercised end-to-end through
the Go engine's own jlecmd adapter (phase 4c); the adapter's field-level shaping
is additionally covered by the Go adapter's unit tests (go/internal/adapt).
"""
from go_engine import go_events


_RECORD = {
    "AppId": {"AppId": "fb3b0dbfee58fac8", "Description": "Microsoft Word 2016 64-bit"},
    "SourceFile": "/in/AutomaticDestinations/fb3b0dbfee58fac8.automaticDestinations-ms",
    "DestListEntries": [
        {"Path": r"C:\Users\jcloudy\Desktop\Planning.docx", "EntryNumber": 1,
         "CreatedOn": "/Date(1522187139502)/", "LastModified": "/Date(1522917168677)/",
         "Hostname": "desktop-pm6c56d", "InteractionCount": 13, "MRUPosition": 0,
         "Pinned": False, "MacAddress": "28:e3:47:01:77:77", "VolumeDroid": "bc75"},
    ],
}


def test_flatten_and_dotnet_dates():
    # the Go jlecmd adapter fans one jump list out to one event per DestListEntry,
    # merges the app context, and renders both /Date(ms)/ stamps ISO
    evs = go_events("jlecmd_dest", _RECORD, adapter="jlecmd")
    assert len(evs) == 1
    ev = evs[0]
    assert ev["_native"]["AppDescription"] == "Microsoft Word 2016 64-bit"
    assert ev["timestamp"].startswith("2018-04-05T")            # LastModified ISO
    assert ev["_native"]["CreatedOn"].startswith("2018-03-27T")  # /Date(ms)/ -> ISO
    # an empty jump list produces no rows
    assert go_events("jlecmd_dest", {"AppId": {}, "DestListEntries": []},
                     adapter="jlecmd") == []


def test_dest_entry_is_file_read():
    ev = go_events("jlecmd_dest", _RECORD, adapter="jlecmd")[0]
    assert ev["car_object"] == "file" and ev["car_action"] == "read"
    assert ev["file_name"] == "Planning.docx" and ev["extension"] == "docx"
    assert ev["hostname"] == "desktop-pm6c56d"
    assert ev["source_host"] == "desktop-pm6c56d"
    assert ev["_native"]["InteractionCount"] == 13
    assert ev["_native"]["AppDescription"] == "Microsoft Word 2016 64-bit"
    assert ev["timestamp"].startswith("2018-04-05T")       # last interaction

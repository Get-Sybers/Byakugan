"""The Anamnesis interchange contract (docs/Anamnesis-Interchange.md): the CAR
object model both repos must agree on, and the `readers.load_anamnesis_car`
translation from Anamnesis's own `car.db` schema into this store's event
shape. Two drift guards:

  (a) the CAR object model — `byakugan.carmodel.load()` (reconstructed LIVE
      from the pinned `third_party/car` submodule) vs.
      `tests/fixtures/anamnesis_car_data_model.json` (a committed COPY of
      Anamnesis's own embedded, statically-compiled copy of the same model,
      `internal/carmodel/car_data_model.json`) — must match exactly, in
      both directions: an object or a field/action added or removed on
      EITHER side fails this test until the fixture is refreshed;
  (b) the translation itself — a fixture `car.db` built with ANAMNESIS's
      OWN schema (the documented header + the fixture model's fields, never
      byakugan's own store.py schema, which differs — see store.py's
      `HEADER`) is translated by `readers.load_anamnesis_car`, then the
      SAME file is run through the full per-file pipeline passthrough
      (`pipeline.process_file`), and every documented translation rule is
      asserted against both the translated events and the exported
      `car_<object>.jsonl` / `car_relationships.jsonl`.

Fixture source: github.com/Get-Sybers/Anamnesis,
internal/carmodel/car_data_model.json, pinned at commit
afb06ae7a97d6acb18da88f5b0b7ef52bc6c0d88 (afb06ae). Refresh
tests/fixtures/anamnesis_car_data_model.json by re-copying that file
VERBATIM from a current Anamnesis checkout whenever either side's CAR model
changes (a car submodule pin bump on either repo) — this test fails until
you do. See docs/Anamnesis-Interchange.md "Drift guards".
"""
from __future__ import annotations

import json
import os
import sqlite3

from byakugan import carmodel, pipeline, readers, superset

_FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
_MODEL_FIXTURE = os.path.join(_FIXTURES, "anamnesis_car_data_model.json")

# Anamnesis's car.db header, VERBATIM from internal/store/store.go's `header`
# var — the 12 columns every one of its 13 CAR object tables carries ahead of
# its own CAR properties (plus the `event_id` SQLite autoincrement PK, which
# is not one of these 12 but is present on every table too).
_ANAMNESIS_HEADER = ["timestamp", "car_action", "guid", "owning_pid", "owning_offset",
                     "owning_guid", "parent_pid", "parent_guid", "link_confidence",
                     "source_plugin", "source_image", "native"]


def _load_fixture_model() -> dict:
    """{object: {"fields": [...], "actions": [...]}} from the committed
    Anamnesis car_data_model.json fixture — same shape as carmodel.load()."""
    with open(_MODEL_FIXTURE, encoding="utf-8") as fh:
        doc = json.load(fh)
    out = {}
    for o in doc["objects"]:
        name = o["name"][0] if isinstance(o["name"], list) else o["name"]
        out[name] = {"fields": list(o["fields"]), "actions": list(o["actions"])}
    return out


def _anamnesis_cols(obj: str, model: dict) -> list:
    """store.go's `cols()`: the header, then the object's own CAR fields,
    minus any that collide with a header name (process's `guid`/`parent_guid`
    are already header columns)."""
    header_set = set(_ANAMNESIS_HEADER)
    return list(_ANAMNESIS_HEADER) + [f for f in model[obj]["fields"] if f not in header_set]


def _make_anamnesis_car_db(path: str, model: dict, tables: dict) -> None:
    """A car.db with ANAMNESIS's exact schema (`event_id` PK + `_anamnesis_cols()`
    per object table, derived from the FIXTURE model — never byakugan's own
    store.py) + the `image_context` side table, populated with `tables`
    ({object: [{col: val, ...}, ...]}) plus one synthetic image_context row."""
    conn = sqlite3.connect(path)
    for obj, rows in tables.items():
        cols = _anamnesis_cols(obj, model)
        coldefs = ", ".join(f'"{c}"' for c in cols)
        conn.execute(f'CREATE TABLE "{obj}" (event_id INTEGER PRIMARY KEY, {coldefs})')
        colsql = ", ".join(f'"{c}"' for c in cols)
        placeholders = ", ".join("?" for _ in cols)
        for row in rows:
            conn.execute(f'INSERT INTO "{obj}" ({colsql}) VALUES ({placeholders})',
                        [row.get(c) for c in cols])
    # the raw-output side table for plugins with no CAR map — never translated
    conn.execute("CREATE TABLE image_context (source_image TEXT, source_plugin TEXT, record TEXT)")
    conn.execute("INSERT INTO image_context VALUES (?, ?, ?)",
                ("IMG-7", "cmdline", json.dumps({"raw": "some non-CAR plugin output"})))
    conn.commit()
    conn.close()


# A parent (P1) + child (P2) process, a module spoke (M1) owned by P2, and a
# standalone driver (D1) — every link (P2.parent_guid, M1.owning_guid) already
# resolved by ANAMNESIS itself (memory-offset-based), exactly as its store
# writes it. P1/P2/M1 share one host, so the pipeline-passthrough test's
# owner/parent re-resolution has a candidate to find (see that test's
# docstring); D1 carries no `hostname` of its own and no owner, in a family
# the other rows don't touch, purely to exercise the image-name fallback in
# isolation (translation-only test, below — it never reaches enrich there).
_P1_GUID = "proc-fffff8a000001040"
_P2_GUID = "proc-fffff8a000002080"
_M1_GUID = "mod-fffff8a000003000"
_D1_GUID = "drv-fffff8a000004500"


def _fixture_tables() -> dict:
    return {
        "process": [
            {"timestamp": "2024-06-01T00:00:00Z", "car_action": "create", "guid": _P1_GUID,
             "link_confidence": None, "source_plugin": "pslist", "source_image": "IMG-7",
             "native": json.dumps({"offset": "0xfffff8a000001040"}),
             "pid": 100, "ppid": 4, "exe": "winlogon.exe",
             "image_path": r"C:\Windows\winlogon.exe", "hostname": "WORKSTATION1",
             "user": "Local System"},
            {"timestamp": "2024-06-01T00:00:05Z", "car_action": "create", "guid": _P2_GUID,
             "parent_pid": 100, "parent_guid": _P1_GUID, "link_confidence": "definitive",
             "source_plugin": "pslist", "source_image": "IMG-7", "native": "{}",
             "pid": 200, "ppid": 100, "exe": "evil.exe",
             "image_path": r"C:\Users\bob\evil.exe", "hostname": "WORKSTATION1", "user": "bob"},
        ],
        "module": [
            {"timestamp": "2024-06-01T00:00:06Z", "car_action": "load", "guid": _M1_GUID,
             "owning_pid": 200, "owning_offset": 2147483648, "owning_guid": _P2_GUID,
             "link_confidence": "definitive", "source_plugin": "ldrmodules",
             "source_image": "IMG-7", "native": json.dumps({"foo": "bar"}),
             "pid": 200, "module_name": "evil.dll", "image_path": r"C:\Users\bob\evil.dll",
             "base_address": "0x7ffe0000", "hostname": "WORKSTATION1"},
        ],
        "driver": [
            {"timestamp": "2024-06-01T00:00:02Z", "car_action": "load", "guid": _D1_GUID,
             "link_confidence": None, "source_plugin": "modules", "source_image": "IMG-7",
             "native": "{}", "module_name": "evildrv.sys",
             "image_path": r"C:\Windows\System32\drivers\evildrv.sys"},   # no hostname, no owner
        ],
    }


# --------------------------------------------------------------------------- #
# (a) model pin
# --------------------------------------------------------------------------- #
def test_car_model_matches_the_anamnesis_fixture_exactly():
    live = carmodel.load()
    fixture = _load_fixture_model()

    live_objs, fixture_objs = set(live), set(fixture)
    assert live_objs == fixture_objs, (
        "byakugan.carmodel.load() and tests/fixtures/anamnesis_car_data_model.json disagree "
        f"on the CAR OBJECT SET — byakugan-only: {sorted(live_objs - fixture_objs)}, "
        f"fixture-only: {sorted(fixture_objs - live_objs)}. Refresh "
        "tests/fixtures/anamnesis_car_data_model.json from a current Anamnesis checkout "
        "(internal/carmodel/car_data_model.json) once both repos pin the same car submodule "
        "revision — see docs/Anamnesis-Interchange.md 'Drift guards'. This test intentionally "
        "fails until that refresh is a conscious, reviewed act.")

    problems = []
    for obj in sorted(live_objs & fixture_objs):
        lf, ff = set(live[obj]["fields"]), set(fixture[obj]["fields"])
        la, fa = set(live[obj]["actions"]), set(fixture[obj]["actions"])
        if lf != ff:
            problems.append(f"{obj}: FIELDS differ — byakugan-only {sorted(lf - ff)}, "
                            f"fixture-only {sorted(ff - lf)}")
        if la != fa:
            problems.append(f"{obj}: ACTIONS differ — byakugan-only {sorted(la - fa)}, "
                            f"fixture-only {sorted(fa - la)}")
    assert not problems, (
        "byakugan.carmodel.load() and the Anamnesis fixture disagree per-object:\n  "
        + "\n  ".join(problems) +
        "\nRefresh tests/fixtures/anamnesis_car_data_model.json from a current Anamnesis "
        "checkout (internal/carmodel/car_data_model.json) — see "
        "docs/Anamnesis-Interchange.md 'Drift guards'.")


# --------------------------------------------------------------------------- #
# (b) translation contract — readers.load_anamnesis_car in isolation
# --------------------------------------------------------------------------- #
def test_load_anamnesis_car_translation_rules(tmp_path):
    model = _load_fixture_model()
    image_dir = tmp_path / "memory" / "IMG-7"
    image_dir.mkdir(parents=True)
    car_db = str(image_dir / "car.db")
    _make_anamnesis_car_db(car_db, model, _fixture_tables())

    events = readers.load_anamnesis_car(car_db)
    assert len(events) == 4                              # image_context is never translated
    by_guid = {e["guid"]: e for e in events}
    p1, p2, m1, d1 = (by_guid[_P1_GUID], by_guid[_P2_GUID],
                     by_guid[_M1_GUID], by_guid[_D1_GUID])

    # event_id (Anamnesis's own SQLite PK) is dropped, never carried through
    for ev in (p1, p2, m1, d1):
        assert "event_id" not in ev

    # car_object = the table name; car_action passes through verbatim
    assert p1["car_object"] == "process" and p1["car_action"] == "create"
    assert m1["car_object"] == "module" and m1["car_action"] == "load"
    assert d1["car_object"] == "driver" and d1["car_action"] == "load"

    # source_artefact = "memory/" + source_plugin
    assert p1["source_artefact"] == "memory/pslist"
    assert m1["source_artefact"] == "memory/ldrmodules"
    assert d1["source_artefact"] == "memory/modules"

    # source_host: the row's OWN hostname property wins when present (P1/P2/M1);
    # falls back to the image name (the car.db's parent directory) when absent (D1)
    assert p1["source_host"] == "WORKSTATION1" and p2["source_host"] == "WORKSTATION1"
    assert m1["source_host"] == "WORKSTATION1"
    assert d1["source_host"] == "IMG-7"

    # native: JSON-decoded into `_native`; the raw `native` column name is gone
    assert p1["_native"] == {"offset": "0xfffff8a000001040"}
    assert m1["_native"] == {"foo": "bar"}
    assert p2["_native"] == {}                            # an empty native blob decodes to {}
    for ev in (p1, p2, m1, d1):
        assert "native" not in ev

    # owning_guid_native is ALWAYS None: Anamnesis's OWN resolved owning_guid
    # is a finished link (memory-offset-based), never a raw native identifier
    # on the spoke's own record the way e.g. Sysmon's ProcessGuid is — so the
    # translation must not let the second enrich pass treat it as tier-1
    # definitive (see docs/Anamnesis-Interchange.md "The second enrich pass")
    for ev in (p1, p2, m1, d1):
        assert ev["owning_guid_native"] is None

    # links Anamnesis minted are passed through 1:1 at this stage, verbatim,
    # confidence included
    assert p2["parent_guid"] == _P1_GUID and p2["link_confidence"] == "definitive"
    assert m1["owning_guid"] == _P2_GUID and m1["link_confidence"] == "definitive"
    assert m1["owning_pid"] == 200

    # every other Anamnesis column passes through as a CAR property, verbatim
    assert p1["exe"] == "winlogon.exe" and p1["pid"] == 100
    assert m1["module_name"] == "evil.dll" and m1["base_address"] == "0x7ffe0000"

    # memory's friendly principal rendering folds to the shared canonical
    # token (readers.py's own normalize._canon_user pass); a real account
    # name is untouched
    assert p1["user"] == "SYSTEM"                         # "Local System" -> SYSTEM
    assert p2["user"] == "bob"


# --------------------------------------------------------------------------- #
# (b) translation contract — the FULL pipeline passthrough
# --------------------------------------------------------------------------- #
def test_anamnesis_passthrough_survives_the_full_pipeline(tmp_path):
    """readers.load_anamnesis_car feeds `pipeline.process_file` (the "name ==
    car.db" passthrough route) exactly like every other source feeds it: the
    SAME second enrich pass (fold, null-only inheritance, owner/parent
    resolution) runs over these rows too — memory rows join the relationship
    timeline and logs-car.* through the same one pipeline, not a special
    case. The pass RE-DERIVES owner/parent via its own pid+time-window tier
    (owning_guid_native is always None for Anamnesis rows — see the test
    above), but over an unambiguous single-owner-per-pid fixture like this
    one it re-derives the SAME guid Anamnesis already minted: the LINK's
    IDENTITY survives unchanged. `link_confidence`, by contrast, is NOT
    preserved — the pass has no way to know Anamnesis's own link was
    memory-offset-based, so it re-stamps it "heuristic" (its own pid-window
    tier), even though Anamnesis's original confidence was "definitive".
    Document this precisely; it is the actual, verified behaviour, not
    merely the sensible-sounding one.
    """
    model = _load_fixture_model()
    image_dir = tmp_path / "memory" / "IMG-7"
    image_dir.mkdir(parents=True)
    car_db = str(image_dir / "car.db")
    _make_anamnesis_car_db(car_db, model, _fixture_tables())

    out_dir = str(tmp_path / "out")
    result = pipeline.process_file(car_db, out_dir)
    assert result["artefacts"] == ["memory (passthrough)"]
    assert result["objects"] == {"process": 2, "module": 1, "driver": 1}

    with open(os.path.join(out_dir, "car_process.jsonl"), encoding="utf-8") as fh:
        procs = {row["guid"]: row for row in (json.loads(line) for line in fh)}
    with open(os.path.join(out_dir, "car_module.jsonl"), encoding="utf-8") as fh:
        modules = {row["guid"]: row for row in (json.loads(line) for line in fh)}

    p1, p2, m1 = procs[_P1_GUID], procs[_P2_GUID], modules[_M1_GUID]

    # the guids/owning_guid/parent_guid Anamnesis minted survive UNCHANGED
    # into the exported car_<object>.jsonl
    assert p1["guid"] == _P1_GUID and p2["guid"] == _P2_GUID and m1["guid"] == _M1_GUID
    assert p2["parent_guid"] == _P1_GUID          # re-derived by pid+window, same target
    assert m1["owning_guid"] == _P2_GUID          # re-derived by pid+window, same target
    assert p1["parent_guid"] is None              # ppid 4 matches no process in this source: honest null

    # ... but link_confidence is RE-STAMPED by the pass's own pid-window
    # tier, not preserved from Anamnesis's own (stronger) resolution
    assert p2["link_confidence"] == "heuristic"
    assert m1["link_confidence"] == "heuristic"

    # the superset edges reference the SAME (unchanged) guids
    rel_path = os.path.join(out_dir, "car_relationships.jsonl")
    with open(rel_path, encoding="utf-8") as fh:
        edges = [json.loads(line) for line in fh]
    by_pair = {(e["source_object"], e["source_guid"], e["target_object"], e["target_guid"]): e
              for e in edges}

    parent_verb = superset._edge_verb("parent_process")           # noqa: SLF001
    owner_verb = superset._spoke_verb("module", "load")           # noqa: SLF001
    assert ("process", _P1_GUID, "process", _P2_GUID) in by_pair
    assert by_pair[("process", _P1_GUID, "process", _P2_GUID)]["relationship"] == parent_verb
    assert ("process", _P2_GUID, "module", _M1_GUID) in by_pair
    assert by_pair[("process", _P2_GUID, "module", _M1_GUID)]["relationship"] == owner_verb

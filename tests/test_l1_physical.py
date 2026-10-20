"""The L1-physical registry: the DDL byakugan owns and its Python read path.

Holds the schema source of truth and the reader honest — the DDL executes, the
committed artifact matches the renderer (the drift gate the Go module and the
Python reader both depend on), the per-asset key is the flat leaf, and R2's
host reconciliation reuses byakugan.native_ids over the as-is rows.
"""
from __future__ import annotations

import os
import sqlite3

import pytest

from byakugan import l1physical


def test_render_ddl_executes():
    conn = sqlite3.connect(":memory:")
    conn.executescript(l1physical.render_ddl())
    cols = [r[1] for r in conn.execute("PRAGMA table_info(spindle)")]
    assert cols == [name for name, _decl, _p in l1physical.COLUMNS]
    assert conn.execute("PRAGMA user_version").fetchone()[0] == l1physical.SCHEMA_VERSION
    conn.close()


def test_committed_ddl_in_sync():
    # The drift gate: `python model/generate.py` must have been run. The Go
    # module embeds this very file, so a stale commit would ship a wrong schema.
    assert l1physical.verify_ddl() == [], (
        "go/l1physical/schema.sql is stale — run `python model/generate.py` "
        "(or `python -m byakugan.l1physical --out go/l1physical/schema.sql`)")
    assert os.path.exists(l1physical.DDL_PATH)


def test_asset_id_precedence():
    assert l1physical.asset_id("SER", "VOL", "SHA", "n.jsonl") == "SER"
    assert l1physical.asset_id("", "VOL", "SHA", "n") == "VOL"
    assert l1physical.asset_id(" ", "-", "SHA", "n") == "SHA"
    assert l1physical.asset_id("", "", "", "Users/Jake/NTUSER.DAT") == "NTUSER.DAT"
    assert l1physical.asset_id("-", "", "", "weird name!.evtx") == "weird_name_.evtx"
    assert l1physical.asset_id("", "-", "  ", "") == ""


def test_clean_name():
    assert l1physical.clean_name("C:\\Windows\\foo.evtx") == "foo.evtx"
    assert l1physical.clean_name("a/b/c.log") == "c.log"
    assert l1physical.clean_name("weird name!.evtx") == "weird_name_.evtx"
    assert l1physical.clean_name("---") == ""
    assert l1physical.clean_name(None) == ""


def _make_db(path: str, rows: list[dict]) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(l1physical.render_ddl())
    for r in rows:
        conn.execute(
            "INSERT INTO spindle (case_id, asset_id, host_id, host_label, "
            "disk_serial, volume_guid, image_sha256, name, registered_at, updated_at) "
            "VALUES (:case_id, :asset_id, :host_id, :host_label, :disk_serial, "
            ":volume_guid, :image_sha256, :name, :ts, :ts)",
            {"host_id": None, "host_label": None, "disk_serial": None,
             "volume_guid": None, "image_sha256": None, "name": None,
             "ts": "2026-10-21T00:00:00Z", **r})
    conn.commit()
    conn.close()


def test_read_path_round_trips(tmp_path):
    db = str(tmp_path / l1physical.DB_FILE_NAME)
    _make_db(db, [
        {"case_id": "case-A", "asset_id": "SER123", "host_id": "mg-1",
         "host_label": "WIN-1M3263ACE5D", "disk_serial": "SER123"},
        {"case_id": "case-A", "asset_id": "VOLX", "host_id": "mg-1",
         "volume_guid": "VOLX"},
    ])
    conn = l1physical.connect(db)
    try:
        rows = l1physical.spindles(conn, "case-A")
        assert [r["asset_id"] for r in rows] == ["SER123", "VOLX"]
        one = l1physical.get(conn, "case-A", "SER123")
        assert one["host_id"] == "mg-1" and one["host_label"] == "WIN-1M3263ACE5D"
        assert l1physical.get(conn, "case-A", "missing") is None
    finally:
        conn.close()


def test_connect_is_read_only(tmp_path):
    db = str(tmp_path / l1physical.DB_FILE_NAME)
    _make_db(db, [{"case_id": "c", "asset_id": "SER", "disk_serial": "SER"}])
    conn = l1physical.connect(db)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO spindle (case_id, asset_id, registered_at, "
                         "updated_at) VALUES ('c', 'x', 't', 't')")
    finally:
        conn.close()


def test_connect_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        l1physical.connect(str(tmp_path / "nope.db"))


def test_reconcile_hosts_reuses_native_ids(tmp_path):
    # Two fragmented labels for ONE stable host_id (the master blocker), a real
    # volume GUID that native_ids canonicalises (upper -> lower), and a row with
    # no host_id (un-joinable, grouped under "").
    db = str(tmp_path / l1physical.DB_FILE_NAME)
    _make_db(db, [
        {"case_id": "c", "asset_id": "a1", "host_id": "mg-1",
         "host_label": "WIN-1M3263ACE5D",
         "volume_guid": "09931F21-AAAA-BBBB-CCCC-DDDDDDDDDDDD"},
        {"case_id": "c", "asset_id": "a2", "host_id": "mg-1",
         "host_label": "DESKTOP-PM6C56D",
         "volume_guid": "09931f21-aaaa-bbbb-cccc-dddddddddddd"},
        {"case_id": "c", "asset_id": "a3", "host_label": "orphan"},
    ])
    conn = l1physical.connect(db)
    try:
        hosts = l1physical.reconcile_hosts(conn, "c")
    finally:
        conn.close()
    assert set(hosts) == {"mg-1", ""}
    mg1 = hosts["mg-1"]
    assert mg1["labels"] == {"WIN-1M3263ACE5D", "DESKTOP-PM6C56D"}
    assert sorted(mg1["assets"]) == ["a1", "a2"]
    # both volume GUIDs canonicalise to one lower-case value (native_ids).
    assert mg1["volume_guids"] == {"09931f21-aaaa-bbbb-cccc-dddddddddddd"}
    assert hosts[""]["assets"] == ["a3"]


def test_db_file_name_is_dot_prefixed():
    assert l1physical.DB_FILE_NAME == ".L1-physical.db"
    assert l1physical.DB_FILE_NAME.startswith(".")

"""relationships.yml / inferred.yml (model/projection/) declare the exact
column lists of superset.db's `relationship` / `inferred_node` tables (minus
the `id` autoincrement). model/projection/validate.py checks that declaration
is internally consistent (no dup, no unknown key, every column covered)
against a list it hardcodes, since it stays pyyaml-only and cannot import
byakugan. This is the other half: it derives the REAL, live column list from
the engine itself (PRAGMA table_info on a freshly created SupersetStore) and
proves the contract matches it -- so a schema change in byakugan/superset.py
fails HERE until the two projection files (and validate.py's own hardcoded
list) get a decision, exactly as a CAR model refresh fails validate.py until
objects/*.yml gets one.
"""
import pathlib
import sqlite3

import yaml

from byakugan import superset

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PROJECTION = REPO_ROOT / "model" / "projection"


def _table_columns(conn: sqlite3.Connection, table: str) -> list:
    """A live table's column names, in schema order, minus the SQLite `id` autoincrement."""
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})") if row[1] != "id"]


def _declared_columns(contract_file: str) -> list:
    doc = yaml.safe_load((PROJECTION / contract_file).read_text(encoding="utf-8"))
    return [e["car"] for e in doc["fields"]]


def test_relationships_yml_matches_the_live_relationship_schema(tmp_path):
    st = superset.SupersetStore(str(tmp_path / "superset.db"))
    live = _table_columns(st.conn, "relationship")
    st.close()

    declared = _declared_columns("relationships.yml")
    assert len(declared) == len(set(declared)), "relationships.yml: duplicate car: entries"
    assert set(declared) == set(live), (
        "model/projection/relationships.yml is out of step with byakugan.superset's live "
        f"`relationship` schema -- missing {sorted(set(live) - set(declared))}, "
        f"extra {sorted(set(declared) - set(live))}")


def test_inferred_yml_matches_the_live_inferred_node_schema(tmp_path):
    st = superset.SupersetStore(str(tmp_path / "superset.db"))
    live = _table_columns(st.conn, "inferred_node")
    st.close()

    declared = _declared_columns("inferred.yml")
    assert len(declared) == len(set(declared)), "inferred.yml: duplicate car: entries"
    assert set(declared) == set(live), (
        "model/projection/inferred.yml is out of step with byakugan.superset's live "
        f"`inferred_node` schema -- missing {sorted(set(live) - set(declared))}, "
        f"extra {sorted(set(declared) - set(live))}")

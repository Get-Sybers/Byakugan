"""relationships.yml / inferred.yml (elastic/projection/) declare the exact
column lists of SupersetStore's `relationships` / `inferred_nodes` row shapes
(the former SQLite `relationship`/`inferred_node` tables' columns, minus the
`id` autoincrement — there is no SQLite, and no surrogate key, any more).
elastic/projection/validate.py checks that declaration is internally
consistent (no dup, no unknown key, every column covered) against a list it
hardcodes, since it stays pyyaml-only and cannot import byakugan. This is the
other half: it derives the REAL, live column list from the engine itself
(byakugan.superset.REL_COLUMNS / INFERRED_COLUMNS — the authoritative row
shapes the exporters write) and proves the contract matches it, in BOTH
directions -- so a schema change in byakugan/superset.py fails HERE until the
two projection files (and validate.py's own hardcoded list) get a decision,
exactly as a CAR model refresh fails validate.py until objects/*.yml gets one.
"""
import pathlib

import yaml

from byakugan import superset

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PROJECTION = REPO_ROOT / "elastic" / "projection"


def _declared_columns(contract_file: str) -> list:
    doc = yaml.safe_load((PROJECTION / contract_file).read_text(encoding="utf-8"))
    return [e["car"] for e in doc["fields"]]


def test_relationships_yml_matches_the_live_relationship_schema():
    live = list(superset.REL_COLUMNS)

    declared = _declared_columns("relationships.yml")
    assert len(declared) == len(set(declared)), "relationships.yml: duplicate car: entries"
    assert set(declared) == set(live), (
        "elastic/projection/relationships.yml is out of step with byakugan.superset.REL_COLUMNS -- "
        f"missing {sorted(set(live) - set(declared))}, extra {sorted(set(declared) - set(live))}")


def test_inferred_yml_matches_the_live_inferred_node_schema():
    live = list(superset.INFERRED_COLUMNS)

    declared = _declared_columns("inferred.yml")
    assert len(declared) == len(set(declared)), "inferred.yml: duplicate car: entries"
    assert set(declared) == set(live), (
        "elastic/projection/inferred.yml is out of step with byakugan.superset.INFERRED_COLUMNS -- "
        f"missing {sorted(set(live) - set(declared))}, extra {sorted(set(declared) - set(live))}")


def test_content_yml_matches_the_live_content_node_schema():
    live = list(superset.CONTENT_COLUMNS)

    declared = _declared_columns("content.yml")
    assert len(declared) == len(set(declared)), "content.yml: duplicate car: entries"
    assert set(declared) == set(live), (
        "elastic/projection/content.yml is out of step with byakugan.superset.CONTENT_COLUMNS -- "
        f"missing {sorted(set(live) - set(declared))}, extra {sorted(set(declared) - set(live))}")

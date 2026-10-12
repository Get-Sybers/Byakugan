"""model/projection/rel_lookup.yml — the `car-relationships-<ns>` LOOKUP index:
a native-Elastic join layer over the same declared+derived edges logs-car.rel-*
holds (in ADDITION to that stream and to `byakugan timeline`, never replacing
them). byakugan.elastic.projection.project_relationship_lookup fans one edge out
to one lookup row PER ENDPOINT so an ES|QL `LOOKUP JOIN car-relationships-<ns>
ON event.id` resolves an object to its relationships from either end.

These tests prove the per-endpoint shape, the join keys, the deterministic ids
and the skip gate, and — the load-bearing one — BIND the transform (code) to the
contract (data): every field path the projector emits must be declared in
rel_lookup.yml, because the rendered lookup index is `dynamic: strict` and would
reject an undeclared path at index time.
"""
import pathlib

import yaml

from byakugan.elastic import projection as pj

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
REL_LOOKUP = yaml.safe_load(
    (REPO_ROOT / "model" / "projection" / "rel_lookup.yml").read_text(encoding="utf-8"))


def _edge(**over):
    """A declared process--loaded-->module edge (every REL_COLUMNS column), the
    shape byakugan.superset exports to car_relationships.jsonl."""
    row = {"timestamp": "2024-01-01T00:00:05Z", "source_host": "H", "relationship": "loaded",
           "source_object": "process", "source_guid": "P1", "target_object": "module",
           "target_guid": "M1", "confidence": "definitive", "method": "native_guid",
           "class": "declared", "identity_key": None, "inferred_end": None,
           "corroborated_by": None, "properties": None}
    row.update(over)
    return row


def _leaf_paths(doc: dict, prefix: str = "") -> set[str]:
    out: set[str] = set()
    for k, v in doc.items():
        p = f"{prefix}{k}"
        out |= _leaf_paths(v, p + ".") if isinstance(v, dict) else {p}
    return out


def test_one_edge_fans_out_to_an_out_row_and_an_in_row():
    rows = pj.project_relationship_lookup(_edge(), "default")
    assert [idx for idx, _, _ in rows] == ["car-relationships-default"] * 2
    by_dir = {doc["car"]["related"]["direction"]: doc for _, _, doc in rows}
    assert set(by_dir) == {"out", "in"}

    out = by_dir["out"]                               # keyed on the SOURCE endpoint
    assert out["event"]["id"] == "P1"
    assert out["process"]["entity_id"] == "P1"        # the source endpoint IS a process -> cascade key
    assert out["car"]["related"]["object"] == "module" and out["car"]["related"]["guid"] == "M1"
    assert out["car"]["related"]["endpoint_object"] == "process"
    assert out["car"]["related"]["relationship"] == "loaded"
    assert out["car"]["related"]["class"] == "declared"
    assert out["car"]["related"]["timestamp"] == "2024-01-01T00:00:05Z"   # verbatim, NOT @timestamp
    assert "@timestamp" not in _leaf_paths(out)        # must not overwrite the joined object's own time

    inn = by_dir["in"]                                # keyed on the TARGET endpoint
    assert inn["event"]["id"] == "M1"
    assert "process" not in inn                        # the target (module) is NOT a process -> no cascade key
    assert inn["car"]["related"]["object"] == "process" and inn["car"]["related"]["guid"] == "P1"
    assert inn["car"]["related"]["endpoint_object"] == "module"


def test_namespace_scopes_the_index():
    rows = pj.project_relationship_lookup(_edge(), "case-42")
    assert all(idx == "car-relationships-case-42" for idx, _, _ in rows)


def test_ids_are_deterministic_and_the_two_directions_never_collide():
    a = pj.project_relationship_lookup(_edge(), "default")
    b = pj.project_relationship_lookup(_edge(), "default")
    assert [i for _, i, _ in a] == [i for _, i, _ in b]        # pure: same input -> same ids
    assert a[0][1] != a[1][1]                                   # out vs in differ in the key (direction)


def test_a_timeless_edge_is_skipped_like_the_edge_stream():
    assert pj.project_relationship_lookup(_edge(timestamp=None), "default") == []
    assert pj.project_relationship_lookup(_edge(timestamp="not-a-timestamp"), "default") == []


def test_an_endpoint_without_a_guid_yields_only_the_other_row():
    rows = pj.project_relationship_lookup(_edge(source_guid=None), "default")
    assert len(rows) == 1
    doc = rows[0][2]
    assert doc["event"]["id"] == "M1" and doc["car"]["related"]["direction"] == "in"


def test_inferred_flag_marks_the_related_endpoint_only():
    # inferred_end=target: the OUT row's related end (the target) is the inferred
    # node; the IN row's related end (the source) is observed.
    by_dir = {d["car"]["related"]["direction"]: d
              for _, _, d in pj.project_relationship_lookup(_edge(inferred_end="target"), "default")}
    assert by_dir["out"]["car"]["related"]["inferred"] is True
    assert by_dir["in"]["car"]["related"]["inferred"] is False


def test_every_emitted_path_is_declared_in_the_contract():
    """dynamic: strict (render_elastic.render_rel_lookup) — a path the projector
    emits that rel_lookup.yml does not declare would be REJECTED at index time.
    This binds the code transform to the data mapping the renderer also reads."""
    declared = {e["path"] for e in REL_LOOKUP["fields"]}
    emitted: set[str] = set()
    for _, _, doc in pj.project_relationship_lookup(_edge(identity_key="guid", inferred_end="source"), "default"):
        emitted |= _leaf_paths(doc)
    assert emitted <= declared, f"undeclared lookup path(s): {sorted(emitted - declared)}"
    # and the declared join keys are really produced (event.id on every row,
    # process.entity_id on the process endpoint).
    assert set(REL_LOOKUP["join_keys"]) <= emitted

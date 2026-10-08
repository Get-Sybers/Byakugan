"""The routing table exists twice — `pipeline.ROUTES` / `pipeline.EVTX_MAPS`
(what the Python side routes a discovered file by, and what `sources/` records
as each manifest's input_pattern) and the IR's `routes` / `evtx_maps` (what the
Go authoring layer declares in go/internal/authoring/ir_sections.go, and what
model/schema/mappings/routes.yaml is generated from). Nothing else holds the
two statements together, and they drifted once (the Go-tool filenames landed
on the Python side only): this test is the gate. Edit both, in the same order.
"""
import json
import os

from byakugan import pipeline

_IR = os.path.join(os.path.dirname(__file__), "..", "go", "internal", "ir", "ir.json")


def _ir() -> dict:
    with open(_IR, encoding="utf-8") as fh:
        return json.load(fh)


def test_routes_match_the_ir():
    assert [[pattern, list(keys)] for pattern, keys in pipeline.ROUTES] == _ir()["routes"]


def test_evtx_maps_match_the_ir():
    assert list(pipeline.EVTX_MAPS) == _ir()["evtx_maps"]

"""The MITRE CAR object model — the 13 canonical CAR objects, as THIS engine
publishes it (model/car/objects): fields from the pinned car submodule, actions
from the CAR + ATT&CK superset (build_data_model.build_superset) — the same
union model/generate.py writes into model/car/objects/*.yml. Reconstructed LIVE
from the pinned submodules — no committed copy, so the model is always the
pinned source and cannot drift. A model refresh is a submodule-pin change.
"""
from __future__ import annotations

_cache: dict | None = None


def load() -> dict[str, dict]:
    """{object_name: {"fields": [...], "actions": [...]}} — fields from the
    pinned car submodule, actions overlaid from the CAR+ATT&CK superset, so the
    loaded model equals the published model/car/objects."""
    global _cache
    if _cache is None:
        from . import build_data_model
        doc = build_data_model.build_car()
        sup, _ = build_data_model.build_superset()
        sup_actions = {(o["name"][0] if isinstance(o["name"], list) else o["name"]):
                       list(o.get("actions", [])) for o in sup["objects"]}
        out = {}
        for o in doc["objects"]:
            name = o["name"][0] if isinstance(o["name"], list) else o["name"]
            out[name] = {"fields": list(o["fields"]),
                         "actions": sup_actions.get(name, list(o["actions"]))}
        _cache = out
    return _cache


def objects() -> list[str]:
    return sorted(load())


def fields(obj: str) -> list[str]:
    return load()[obj]["fields"]


def actions(obj: str) -> list[str]:
    return load()[obj]["actions"]


def all_fields() -> list[str]:
    out: set[str] = set()
    for spec in load().values():
        out.update(spec["fields"])
    return sorted(out)

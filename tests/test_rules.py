"""The rules-as-code gate, in-suite (rules/ lives with the engine now).

Two legs. The first runs the same validator the image build runs
(``rules/validate.py``): structure, the query checks, the car-detections
contract and the ``PINNED_IDS`` set — a rule can neither be dropped silently
nor added unnoticed. The second is what sharing a home restores: the cti
indicator-match rule cross-checked against the REAL ``byakugan.exchange.cti``
index template and pattern mapping — every ``threat_mapping`` value a field
the cti-* copy fills, every ``threat_index`` pattern one the template covers —
checks that were homeless while rule and template lived in different
repositories.
"""
import copy
import importlib.util
from pathlib import Path

import pytest

from byakugan.exchange.cti import indicators as ind

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "rules"

# rules/validate.py is a standalone script (it is also the image build gate),
# so it is imported by path, not as a package.
_spec = importlib.util.spec_from_file_location("rules_validate", RULES / "validate.py")
rv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rv)


def test_the_committed_set_validates_and_is_pinned(capsys):
    assert rv.main([]) == 0, capsys.readouterr().err
    assert sorted(r["id"] for r in rv.list_rules()) == sorted(rv.PINNED_IDS)


def test_indicator_match_agrees_with_the_real_cti_template():
    rule, _ = rv.load_cti_contract()
    template = ind.load_template()
    rv.validate_indicator_match(rule, template)          # the full cross-checks
    mapping = ind.load_pattern_mapping()
    values = {e["value"] for g in rule["threat_mapping"] for e in g["entries"]}
    assert values <= mapping.ecs_fields                  # every match target is one a STIX comparison lands in
    assert {"threat.indicator.ip", "threat.indicator.file.hash.sha256",
            "threat.indicator.url.domain"} <= values
    fields = {e["field"] for g in rule["threat_mapping"] for e in g["entries"]}
    assert {"source.ip", "destination.ip", "file.hash.sha256", "dns.question.name"} <= fields
    tf = ind.template_fields(template)                   # the threat_query reads mapped fields
    assert tf["stix.revoked"] == "boolean" and tf["stix.valid_until"] == "date"
    assert "stix.revoked" in rule["threat_query"] and "stix.valid_until" in rule["threat_query"]


@pytest.mark.parametrize("patch", [
    {"threat_index": ["logs-*"]},                        # not what the template covers
    {"threat_mapping": [{"entries": [
        {"field": "source.ip", "type": "mapping", "value": "threat.indicator.nope"}]}],
     },                                                  # not a field the copy fills
])
def test_template_cross_checks_reject_drift(patch):
    rule, _ = rv.load_cti_contract()
    with pytest.raises(ValueError):
        rv.validate_indicator_match({**copy.deepcopy(rule), **patch}, ind.load_template())


def test_every_rule_resolves_through_the_engine_reader():
    # the same reader stix-export uses at run time accepts the committed set:
    # a ported rule yields its indicator source, a stub the counted reason
    from byakugan.exchange import export
    rules = export.rules_source(str(RULES))
    for r in rv.list_rules():
        loaded, reason = rules._load(r["id"])
        if r["status"] == "ported":
            assert loaded is not None, f"{r['id']}: {reason}"
        else:
            assert loaded is None and reason == "stub_rule"
    assert export.RULE_URL.startswith("https://github.com/Get-Sybers/byakugan/blob/main/rules/")

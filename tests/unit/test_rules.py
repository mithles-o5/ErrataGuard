"""Unit tests for rule loading, YAML validation, and schema checks."""

import pytest
from pathlib import Path

from errataguard.rules.loader import load_rules, load_rule_from_file
from errataguard.errors import RuleLoadError, InvalidRuleSchemaError


def test_load_demo_rules():
    rules_dir = Path("rules/demo")
    rules = load_rules(rules_dir)
    assert len(rules) >= 2
    errata_ids = [r.erratum_id for r in rules]
    assert "A53-DEMO-001" in errata_ids
    assert "A53-DEMO-002" in errata_ids

    rule1 = next(r for r in rules if r.erratum_id == "A53-DEMO-001")
    assert rule1.authoritative is False
    assert "r0p2" in rule1.affected_revisions
    assert "adrp" in rule1.candidate.mnemonics


def test_load_non_existent_rules():
    with pytest.raises(RuleLoadError, match="does not exist"):
        load_rules("non_existent_rules_dir")


def test_invalid_yaml_schema(tmp_path: Path):
    bad_rule = tmp_path / "bad.yaml"
    bad_rule.write_text("not_a_valid_mapping: [1, 2, 3]\n", encoding="utf-8")
    with pytest.raises(InvalidRuleSchemaError, match="Missing or invalid 'erratum'"):
        load_rule_from_file(bad_rule)


def test_revision_matching():
    rules = load_rules(Path("rules/demo"))
    rule1 = next(r for r in rules if r.erratum_id == "A53-DEMO-001")

    # Affected (r0p0 to r0p4)
    assert rule1.is_revision_affected("r0p0") is True
    assert rule1.is_revision_affected("r0p2") is True
    assert rule1.is_revision_affected("r0p4") is True
    # Unaffected (r1p0, r0p5)
    assert rule1.is_revision_affected("r1p0") is False
    assert rule1.is_revision_affected("r0p5") is False
    # Missing / None
    assert rule1.is_revision_affected(None) is None


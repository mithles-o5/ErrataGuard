"""Rule management and evaluation module."""

from errataguard.rules.schema import (
    Rule,
    CandidateSpec,
    ConditionSpec,
    WorkaroundSpec,
    SequencePatternItem,
)
from errataguard.rules.loader import load_rules, load_rule_from_file
from errataguard.rules.evaluator import RuleEvaluator, MatchResult

__all__ = [
    "Rule",
    "CandidateSpec",
    "ConditionSpec",
    "WorkaroundSpec",
    "SequencePatternItem",
    "load_rules",
    "load_rule_from_file",
    "RuleEvaluator",
    "MatchResult",
]

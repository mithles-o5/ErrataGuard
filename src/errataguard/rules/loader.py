"""YAML rule loader and validator."""

import logging
from pathlib import Path
from typing import Any, Sequence

import yaml

from errataguard.rules.schema import (
    Rule,
    CandidateSpec,
    ConditionSpec,
    WorkaroundSpec,
)
from errataguard.errors import RuleLoadError, InvalidRuleSchemaError

logger = logging.getLogger(__name__)


def _parse_rule_dict(raw: dict[str, Any], source_path: Path) -> Rule:
    """Parse and validate a dictionary into a Rule instance."""
    if not isinstance(raw, dict):
        raise InvalidRuleSchemaError(f"Rule in {source_path} must be a YAML mapping")

    erratum_id = raw.get("erratum") or raw.get("erratum_id")
    if not erratum_id or not isinstance(erratum_id, str):
        raise InvalidRuleSchemaError(f"Missing or invalid 'erratum' in {source_path}")

    title = raw.get("title")
    if not title or not isinstance(title, str):
        raise InvalidRuleSchemaError(f"Missing or invalid 'title' in {source_path}")

    architecture = raw.get("architecture", "AArch64")
    cpu = raw.get("cpu", "Cortex-A53")
    authoritative = bool(raw.get("authoritative", False))

    revisions_raw = raw.get("affected_revisions", [])
    if isinstance(revisions_raw, list):
        affected_revisions = tuple(str(r) for r in revisions_raw)
    elif isinstance(revisions_raw, str):
        affected_revisions = (revisions_raw,)
    else:
        affected_revisions = ()

    # Candidate spec
    candidate_raw = raw.get("candidate", {})
    if not isinstance(candidate_raw, dict):
        raise InvalidRuleSchemaError(f"'candidate' in {source_path} must be a mapping")

    mnemonics = candidate_raw.get("mnemonics", [])
    if isinstance(mnemonics, str):
        mnemonics = [mnemonics]
    elif not isinstance(mnemonics, list):
        mnemonics = []

    classes = candidate_raw.get("classes", [])
    if isinstance(classes, str):
        classes = [classes]
    elif not isinstance(classes, list):
        classes = []

    candidate_spec = CandidateSpec(
        mnemonics=tuple(str(m).lower() for m in mnemonics),
        instruction_classes=tuple(str(c).lower() for c in classes),
        require_destination_register=bool(candidate_raw.get("require_dest_reg", False)),
    )

    # Conditions spec
    conditions_raw = raw.get("conditions", [])
    if not isinstance(conditions_raw, list):
        raise InvalidRuleSchemaError(f"'conditions' in {source_path} must be a list")

    conditions: list[ConditionSpec] = []
    for idx, cond_data in enumerate(conditions_raw):
        if not isinstance(cond_data, dict):
            raise InvalidRuleSchemaError(f"Condition #{idx} in {source_path} must be a mapping")
        cond_type = cond_data.get("type")
        if not cond_type or not isinstance(cond_type, str):
            raise InvalidRuleSchemaError(f"Condition #{idx} missing 'type' in {source_path}")

        desc = cond_data.get("description", "")
        # Filter out type and description to store extra params
        params = {k: v for k, v in cond_data.items() if k not in ("type", "description")}
        conditions.append(ConditionSpec(type=cond_type, description=desc, params=params))

    # Workaround spec
    workaround_raw = raw.get("workaround", {})
    if isinstance(workaround_raw, str):
        workaround_spec = WorkaroundSpec(description=workaround_raw.strip())
    elif isinstance(workaround_raw, dict):
        desc = workaround_raw.get("description", "No workaround description provided.")
        sugg = workaround_raw.get("suggestion")
        workaround_spec = WorkaroundSpec(description=str(desc).strip(), suggestion=str(sugg) if sugg else None)
    else:
        workaround_spec = WorkaroundSpec(description="No workaround details specified.")

    # References
    refs_raw = raw.get("references", [])
    if isinstance(refs_raw, list):
        references = tuple(str(r) for r in refs_raw)
    elif isinstance(refs_raw, str):
        references = (refs_raw,)
    else:
        references = ()

    severity = raw.get("severity", "warning")

    return Rule(
        erratum_id=erratum_id,
        title=title,
        architecture=architecture,
        cpu=cpu,
        affected_revisions=affected_revisions,
        candidate=candidate_spec,
        conditions=tuple(conditions),
        workaround=workaround_spec,
        references=references,
        authoritative=authoritative,
        severity=severity,
    )


def load_rule_from_file(file_path: Path | str) -> Rule:
    """Load a single rule from a YAML file."""
    path = Path(file_path).resolve()
    if not path.is_file():
        raise RuleLoadError(f"Rule file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as ex:
        raise InvalidRuleSchemaError(f"Failed to read/parse YAML in {path}: {ex}") from ex

    return _parse_rule_dict(data, path)


def load_rules(source: Path | str) -> list[Rule]:
    """Load rules from a file or directory containing YAML files."""
    path = Path(source).resolve()

    if not path.exists():
        raise RuleLoadError(f"Rules path does not exist: {path}")

    rules: list[Rule] = []

    if path.is_file():
        rules.append(load_rule_from_file(path))
    elif path.is_dir():
        # Scan for .yaml and .yml files
        yaml_files = sorted(list(path.glob("*.yaml")) + list(path.glob("*.yml")))
        if not yaml_files:
            # Also search subdirectories
            yaml_files = sorted(list(path.rglob("*.yaml")) + list(path.rglob("*.yml")))
        for yf in yaml_files:
            try:
                rule = load_rule_from_file(yf)
                rules.append(rule)
                logger.debug("Loaded rule %s from %s", rule.erratum_id, yf.name)
            except Exception as ex:
                logger.error("Failed loading rule from %s: %s", yf, ex)
                raise

    if not rules:
        raise RuleLoadError(f"No valid rule files found at: {path}")

    logger.info("Loaded %d rules from %s", len(rules), path)
    return rules

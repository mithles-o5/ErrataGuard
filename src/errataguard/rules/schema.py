"""Rule schema models and specification dataclasses."""

from dataclasses import dataclass, field
from typing import Any, Optional, Sequence


@dataclass(frozen=True)
class CandidateSpec:
    """Fast candidate filtering criteria."""
    mnemonics: tuple[str, ...] = ()
    instruction_classes: tuple[str, ...] = ()
    require_destination_register: bool = False

    def matches_mnemonic(self, mnemonic: str) -> bool:
        if not self.mnemonics:
            return True
        return mnemonic.lower() in [m.lower() for m in self.mnemonics]


@dataclass(frozen=True)
class SequencePatternItem:
    """One expected step in an instruction sequence."""
    mnemonic: str
    max_distance: int = 1  # 1 means immediate next instruction
    match_register: Optional[str] = None  # e.g. "same_as_cand_dest"


@dataclass(frozen=True)
class ConditionSpec:
    """Contextual condition specification to verify erratum presence."""
    type: str
    description: str = ""
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WorkaroundSpec:
    """Mitigation and workaround information."""
    description: str
    suggestion: Optional[str] = None


@dataclass(frozen=True)
class Rule:
    """Independent erratum detection rule."""
    erratum_id: str
    title: str
    architecture: str
    cpu: str
    affected_revisions: tuple[str, ...]
    candidate: CandidateSpec
    conditions: tuple[ConditionSpec, ...]
    workaround: WorkaroundSpec
    references: tuple[str, ...]
    authoritative: bool
    severity: str = "warning"

    def is_cpu_applicable(self, cpu_arch: str, cpu_model: str) -> bool:
        """Check if target CPU architecture and model match the rule."""
        if self.architecture.lower() != cpu_arch.lower():
            return False
        # Normalize CPU models e.g. "cortex-a53"
        target_model = cpu_model.replace(" ", "-").replace("_", "-").lower()
        rule_model = self.cpu.replace(" ", "-").replace("_", "-").lower()
        return target_model == rule_model or rule_model in target_model

    def is_revision_affected(self, revision: Optional[str]) -> Optional[bool]:
        """
        Check if CPU revision is affected.
        Returns:
            True: revision is explicitly in affected list
            False: revision is specified and not affected
            None: revision is missing/unspecified (incomplete information)
        """
        if not self.affected_revisions:
            return True
        if revision is None:
            return None
        rev_norm = revision.strip().lower()
        affected_norms = [r.strip().lower() for r in self.affected_revisions]
        return rev_norm in affected_norms

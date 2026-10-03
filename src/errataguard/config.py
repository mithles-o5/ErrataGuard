"""Configuration and CPU metadata structures for ErrataGuard."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class CPUInfo:
    """Target CPU architecture and revision details."""
    architecture: str = "AArch64"
    model: str = "cortex-a53"
    revision: Optional[str] = None

    def normalized_model(self) -> str:
        return self.model.strip().lower()

    def normalized_revision(self) -> Optional[str]:
        return self.revision.strip().lower() if self.revision else None


@dataclass(frozen=True)
class Config:
    """General configuration settings for an analysis run."""
    cpu: CPUInfo
    rules_path: Path
    output_format: str = "terminal"
    verbose: bool = False
    baseline: bool = False

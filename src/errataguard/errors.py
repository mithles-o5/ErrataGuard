"""Explicit domain exception hierarchy for ErrataGuard."""

class ErrataGuardError(Exception):
    """Base exception for all ErrataGuard errors."""
    exit_code: int = 2


class ConfigurationError(ErrataGuardError):
    """Raised when command-line arguments or configuration parameters are invalid."""
    pass


class ELFError(ErrataGuardError):
    """Base exception for ELF handling errors."""
    pass


class InvalidELFError(ELFError):
    """Raised when the target file is not a valid ELF binary."""
    pass


class UnsupportedArchitectureError(ELFError):
    """Raised when the ELF architecture is not AArch64."""
    pass


class MissingExecutableSectionError(ELFError):
    """Raised when the ELF binary contains no executable sections."""
    pass


class DisassemblyError(ErrataGuardError):
    """Raised when instruction decoding fails unexpectedly."""
    pass


class RuleError(ErrataGuardError):
    """Base exception for rule definitions and loading."""
    pass


class RuleLoadError(RuleError):
    """Raised when rule files cannot be found or read."""
    pass


class InvalidRuleSchemaError(RuleError):
    """Raised when a rule file does not conform to the required schema."""
    pass


class DWARFError(ErrataGuardError):
    """Raised when debug information is malformed."""
    pass

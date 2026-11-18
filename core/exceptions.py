"""
ZYRON Cybersecurity Framework - Exceptions
Custom structured exceptions for error handling across all modules.
"""

class ZyronException(Exception):
    """Base exception for all ZYRON errors."""
    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class DatabaseError(ZyronException):
    """Raised when a database connection or query execution fails."""
    pass


class ScopeViolationError(ZyronException):
    """Raised when an operation targets an asset outside approved scope."""
    pass


class ValidationError(ZyronException):
    """Raised when user or programmatic input fails validation checks."""
    pass


class ModuleExecutionError(ZyronException):
    """Raised when a specific cybersecurity module encounters a runtime error."""
    pass


class ConfigurationError(ZyronException):
    """Raised when configuration loading or verification fails."""
    pass


class EvidenceError(ZyronException):
    """Raised when evidence verification, hashing, or storage fails."""
    pass


class AuthorizationError(ZyronException):
    """Raised when an action lacks explicit authorization approval."""
    pass

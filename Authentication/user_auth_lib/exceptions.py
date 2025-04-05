"""
Custom exceptions for the user authentication library.
"""

class AuthLibBaseException(Exception):
    """Base exception class for the authentication library."""
    pass

class InvalidPasswordFormatError(AuthLibBaseException):
    """Raised when a password doesn't meet the required format criteria."""
    pass

class OTPVerificationError(AuthLibBaseException):
    """Raised when OTP verification fails."""
    pass

class TokenGenerationError(AuthLibBaseException):
    """Raised when secure token generation fails."""
    pass

class RateLimitExceededError(AuthLibBaseException):
    """Raised when rate limit is exceeded."""
    def __init__(self, message: str, retry_after: int):
        self.message = message
        self.retry_after = retry_after  # Time in seconds until next attempt is allowed
        super().__init__(message)

class MFAError(AuthLibBaseException):
    """Raised when MFA operations fail."""
    pass

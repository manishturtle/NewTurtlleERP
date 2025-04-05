"""
A stateless user management library providing core authentication functionality.
"""

from .hashing import hash_password, verify_password
from .otp import generate_mfa_secret, generate_otp_uri, verify_otp_code
from .tokens import generate_secure_token
from .exceptions import (
    InvalidPasswordFormatError,
    OTPVerificationError,
    TokenGenerationError
)

__version__ = "0.1.0"
__all__ = [
    'hash_password',
    'verify_password',
    'generate_mfa_secret',
    'generate_otp_uri',
    'verify_otp_code',
    'generate_secure_token',
    'InvalidPasswordFormatError',
    'OTPVerificationError',
    'TokenGenerationError'
]

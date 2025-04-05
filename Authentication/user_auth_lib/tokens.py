"""
Secure token generation functionality using Python's secrets module.
"""

import secrets
from .exceptions import TokenGenerationError

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure, URL-safe token.

    Args:
        length (int, optional): The desired length of the token in bytes. 
                              Defaults to 32 bytes (resulting in a longer base64 string).

    Returns:
        str: A URL-safe token string.

    Raises:
        TokenGenerationError: If length is less than 16 or token generation fails.
    """
    if length < 16:
        raise TokenGenerationError("Token length must be at least 16 bytes for security")

    try:
        return secrets.token_urlsafe(length)
    except Exception as e:
        raise TokenGenerationError(f"Failed to generate secure token: {str(e)}")

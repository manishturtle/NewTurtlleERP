"""
Password hashing and verification functionality using bcrypt.
"""

import bcrypt
from typing import Union
from .exceptions import InvalidPasswordFormatError

def hash_password(plain_password: str) -> str:
    """
    Hash a plain text password using bcrypt.

    Args:
        plain_password (str): The plain text password to hash.

    Returns:
        str: The hashed password as a string.

    Raises:
        InvalidPasswordFormatError: If the password is empty or not a string.
    """
    if not isinstance(plain_password, str) or not plain_password:
        raise InvalidPasswordFormatError("Password must be a non-empty string")

    # Convert the password to bytes and hash it
    password_bytes = plain_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    
    # Return the hash as a string
    return hashed.decode('utf-8')

def verify_password(plain_password: str, stored_hash: str) -> bool:
    """
    Verify a plain text password against a stored hash.

    Args:
        plain_password (str): The plain text password to verify.
        stored_hash (str): The stored hash to verify against.

    Returns:
        bool: True if the password matches, False otherwise.

    Raises:
        InvalidPasswordFormatError: If either argument is empty or not a string.
    """
    if not isinstance(plain_password, str) or not plain_password:
        raise InvalidPasswordFormatError("Password must be a non-empty string")
    if not isinstance(stored_hash, str) or not stored_hash:
        raise InvalidPasswordFormatError("Stored hash must be a non-empty string")

    try:
        # Convert inputs to bytes for bcrypt
        password_bytes = plain_password.encode('utf-8')
        hash_bytes = stored_hash.encode('utf-8')
        
        # Verify the password
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except (ValueError, TypeError):
        raise InvalidPasswordFormatError("Invalid hash format")

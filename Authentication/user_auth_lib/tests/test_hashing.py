"""
Tests for password hashing functionality.
"""

import pytest
from user_auth_lib.hashing import hash_password, verify_password
from user_auth_lib.exceptions import InvalidPasswordFormatError

def test_hash_password_valid():
    password = "MySecurePassword123"
    hashed = hash_password(password)
    assert isinstance(hashed, str)
    assert hashed != password

def test_hash_password_invalid():
    with pytest.raises(InvalidPasswordFormatError):
        hash_password("")
    with pytest.raises(InvalidPasswordFormatError):
        hash_password(None)

def test_verify_password_valid():
    password = "MySecurePassword123"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

def test_verify_password_invalid():
    with pytest.raises(InvalidPasswordFormatError):
        verify_password("", "hash")
    with pytest.raises(InvalidPasswordFormatError):
        verify_password("password", "")

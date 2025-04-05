"""
Tests for secure token functionality.
"""

import pytest
from user_auth_lib.tokens import generate_secure_token
from user_auth_lib.exceptions import TokenGenerationError

def test_generate_secure_token():
    token = generate_secure_token()
    assert isinstance(token, str)
    assert len(token) > 0

def test_generate_secure_token_custom_length():
    token = generate_secure_token(length=64)
    assert isinstance(token, str)
    assert len(token) > 0

def test_generate_secure_token_invalid_length():
    with pytest.raises(TokenGenerationError):
        generate_secure_token(length=8)

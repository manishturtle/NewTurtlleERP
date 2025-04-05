"""
Tests for JWT authentication functionality.
"""

import pytest
import jwt
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from user_auth_lib.jwt_auth import JWTAuth

# Test data
TEST_SECRET_KEY = 'test-secret-key'
TEST_USER_ID = 1
TEST_EMAIL = 'test@example.com'

@pytest.fixture
def jwt_auth():
    return JWTAuth(secret_key=TEST_SECRET_KEY)

def test_generate_tokens(jwt_auth):
    # Generate tokens
    access_token, refresh_token = jwt_auth.generate_tokens(TEST_USER_ID, TEST_EMAIL)
    
    # Verify access token
    access_payload = jwt.decode(access_token, TEST_SECRET_KEY, algorithms=['HS256'])
    assert access_payload['user_id'] == TEST_USER_ID
    assert access_payload['email'] == TEST_EMAIL
    assert access_payload['token_type'] == 'access'
    assert 'exp' in access_payload
    
    # Verify refresh token
    refresh_payload = jwt.decode(refresh_token, TEST_SECRET_KEY, algorithms=['HS256'])
    assert refresh_payload['user_id'] == TEST_USER_ID
    assert refresh_payload['token_type'] == 'refresh'
    assert 'exp' in refresh_payload

def test_verify_token(jwt_auth):
    # Generate token
    access_token, _ = jwt_auth.generate_tokens(TEST_USER_ID, TEST_EMAIL)
    
    # Verify valid token
    payload = jwt_auth.verify_token(access_token, 'access')
    assert payload['user_id'] == TEST_USER_ID
    assert payload['email'] == TEST_EMAIL

def test_verify_token_invalid_type(jwt_auth):
    # Generate token
    access_token, _ = jwt_auth.generate_tokens(TEST_USER_ID, TEST_EMAIL)
    
    # Try to verify access token as refresh token
    with pytest.raises(jwt.InvalidTokenError):
        jwt_auth.verify_token(access_token, 'refresh')

def test_verify_token_expired():
    # Create JWT auth with very short lifetime
    jwt_auth = JWTAuth(secret_key=TEST_SECRET_KEY)
    jwt_auth.access_token_lifetime = -1  # Expired immediately
    
    # Generate token
    access_token, _ = jwt_auth.generate_tokens(TEST_USER_ID, TEST_EMAIL)
    
    # Verify expired token
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt_auth.verify_token(access_token, 'access')

@patch('user_auth_lib.jwt_auth.User')
def test_refresh_access_token(mock_user, jwt_auth):
    # Mock user
    mock_user_instance = MagicMock()
    mock_user_instance.id = TEST_USER_ID
    mock_user_instance.email = TEST_EMAIL
    mock_user.objects.get.return_value = mock_user_instance
    
    # Generate tokens
    _, refresh_token = jwt_auth.generate_tokens(TEST_USER_ID, TEST_EMAIL)
    
    # Refresh access token
    new_access_token = jwt_auth.refresh_access_token(refresh_token)
    
    # Verify new access token
    payload = jwt.decode(new_access_token, TEST_SECRET_KEY, algorithms=['HS256'])
    assert payload['user_id'] == TEST_USER_ID
    assert payload['email'] == TEST_EMAIL
    assert payload['token_type'] == 'access'

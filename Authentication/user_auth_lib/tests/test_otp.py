"""
Tests for OTP functionality.
"""

import pytest
import pyotp
from user_auth_lib.otp import generate_mfa_secret, generate_otp_uri, verify_otp_code
from user_auth_lib.exceptions import OTPVerificationError

def test_generate_mfa_secret():
    secret = generate_mfa_secret()
    assert isinstance(secret, str)
    assert len(secret) > 0

def test_generate_otp_uri():
    secret = generate_mfa_secret()
    uri = generate_otp_uri(secret, "testuser", "TestApp")
    assert isinstance(uri, str)
    assert uri.startswith("otpauth://")
    assert "testuser" in uri
    assert "TestApp" in uri

def test_generate_otp_uri_invalid():
    with pytest.raises(OTPVerificationError):
        generate_otp_uri("", "", "")

def test_verify_otp_code():
    secret = generate_mfa_secret()
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    
    assert verify_otp_code(valid_code, secret) is True
    assert verify_otp_code("000000", secret) is False

def test_verify_otp_code_invalid():
    with pytest.raises(OTPVerificationError):
        verify_otp_code("", "")

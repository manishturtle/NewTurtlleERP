"""
OTP (One-Time Password) generation, verification, and email functionality.
"""

import random
from datetime import datetime, timedelta
from typing import Optional, Tuple
import pyotp
from .exceptions import OTPVerificationError
from .email_service import email_service
from .sms_service import sms_service
from .validation import validate_phone_number
from .template_manager import template_manager
from . import constants as const

def send_otp_via_sms(phone_number: str, otp: str) -> None:
    """
    Send OTP via SMS using Fast2SMS.
    
    Args:
        phone_number (str): Recipient's phone number
        otp (str): The OTP to send
        
    Raises:
        ValueError: If phone number format is invalid
        Exception: If SMS sending fails
    """
    # Validate phone number
    is_valid, error_message = validate_phone_number(phone_number)
    if not is_valid:
        raise ValueError(error_message)
        
    # Send SMS
    sms_service.send_sms(phone_number, otp)

def generate_numeric_otp() -> Tuple[str, datetime]:
    """
    Generate a 6-digit OTP with expiration time.
    
    Returns:
        Tuple[str, datetime]: The OTP and its expiration time
    """
    otp = str(random.randint(100000, 999999))
    expire_time = datetime.now() + timedelta(minutes=const.OTP_EXPIRY_MINUTES)
    return otp, expire_time

def send_otp_email(email: str, otp: str, first_name: str, last_name: str) -> None:
    """
    Send OTP verification email using the email service.
    
    Args:
        email (str): Recipient's email address
        otp (str): The OTP to send
        first_name (str): Recipient's first name
        last_name (str): Recipient's last name
    """
    subject = "Verify Your Identity on Visaboard with This OTP"
    
    # Create individual spans for OTP digits
    otp_spans = "".join(f"<span>{digit}</span>" for digit in str(otp))
    
    # Prepare template context
    context = {
        'first_name': first_name,
        'last_name': last_name,
        'otp_spans': otp_spans,
        'expiry_minutes': const.OTP_EXPIRY_MINUTES,
        'support_email': const.SUPPORT_EMAIL
    }
    
    # Render the template
    html_content = template_manager.render_template('otp_email.html', context)
    
    # Send the email
    email_service.send_email(email, subject, html_content)

def generate_mfa_secret() -> str:
    """
    Generate a random base32 secret for TOTP-based MFA.

    Returns:
        str: A random base32 encoded secret.
    """
    return pyotp.random_base32()

def generate_otp_uri(secret: str, username: str, issuer_name: str) -> str:
    """
    Generate an otpauth URI for QR code generation.

    Args:
        secret (str): The base32 encoded secret.
        username (str): The username or account name.
        issuer_name (str): The name of the service/application.

    Returns:
        str: An otpauth:// URI suitable for QR code generation.

    Raises:
        OTPVerificationError: If any of the input parameters are invalid.
    """
    if not all([secret, username, issuer_name]):
        raise OTPVerificationError("All parameters (secret, username, issuer_name) are required")

    try:
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(username, issuer_name=issuer_name)
    except Exception as e:
        raise OTPVerificationError(f"Failed to generate OTP URI: {str(e)}")

def verify_otp_code(submitted_code: str, secret: str, tolerance: Optional[int] = 1) -> bool:
    """
    Verify a submitted OTP code against a secret.

    Args:
        submitted_code (str): The OTP code submitted by the user.
        secret (str): The base32 encoded secret.
        tolerance (int, optional): Time steps to check before and after the current time.
                                Defaults to 1, meaning it checks the current time step
                                and one step before and after.

    Returns:
        bool: True if the code is valid, False otherwise.

    Raises:
        OTPVerificationError: If the submitted code or secret is invalid.
    """
    if not submitted_code or not secret:
        raise OTPVerificationError("Both submitted_code and secret are required")

    try:
        # Convert submitted code to string if it's a number
        if isinstance(submitted_code, int):
            submitted_code = str(submitted_code)

        # Remove any spaces from the submitted code
        submitted_code = submitted_code.replace(" ", "")

        # Verify the code
        totp = pyotp.TOTP(secret)
        return totp.verify(submitted_code, valid_window=tolerance)
    except Exception as e:
        raise OTPVerificationError(f"OTP verification failed: {str(e)}")

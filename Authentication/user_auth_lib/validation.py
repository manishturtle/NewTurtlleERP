"""
Validation utilities for email, password, and other user inputs.
"""

import os
import re
from typing import Tuple, Dict
from . import constants as const

def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate password against security requirements.
    
    Args:
        password (str): Password to validate
        
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if len(password) < const.MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {const.MIN_PASSWORD_LENGTH} characters long."
        
    if len(password) > const.MAX_PASSWORD_LENGTH:
        return False, f"Password cannot be longer than {const.MAX_PASSWORD_LENGTH} characters."
        
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
        
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
        
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
        
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
        
    return True, ""

def is_disposable_email(email: str) -> bool:
    """
    Check if the email domain is in the disposable email blocklist.
    
    Args:
        email (str): Email address to check
        
    Returns:
        bool: True if email is valid (not disposable), False if disposable
    """
    try:
        # Get the blocklist file path
        blocklist_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "Utils",
            "disposable_email_blocklist.conf"
        )
        
        # Read the blocklist
        with open(blocklist_path, "r") as blocklist:
            blocklist_content = {line.rstrip() for line in blocklist.readlines()}
        
        # Extract and check the domain
        domain = email.split("@")[-1].lower()
        return domain not in blocklist_content  # True if email is valid
        
    except Exception as e:
        # If there's any error reading the blocklist, log it and allow the email
        # You might want to add proper logging here
        return True

def validate_phone_number(phone_number: str) -> Tuple[bool, str]:
    """
    Validate phone number format.
    
    Args:
        phone_number (str): Phone number to validate
        
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    # Remove country code if present
    if phone_number.startswith("+91"):
        phone_number = phone_number[3:]
        
    if not re.match(r'^\d{10}$', phone_number):
        return False, "Phone number must be 10 digits long."
        
    return True, ""

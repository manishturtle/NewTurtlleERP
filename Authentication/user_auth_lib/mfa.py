"""
Multi-Factor Authentication (MFA) functionality using TOTP.
"""

import pyotp
import qrcode
import io
import base64
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from django.contrib.auth import get_user_model
from .exceptions import MFAError
from . import constants as const
from .template_manager import template_manager
from .email_service import email_service

User = get_user_model()

class MFAManager:
    def __init__(self):
        self.issuer = const.MFA_ISSUER_NAME
        self.algorithm = const.MFA_ALGORITHM
        self.digits = const.MFA_DIGITS
        self.interval = const.MFA_INTERVAL
        self.max_attempts = const.MFA_MAX_ATTEMPTS
        self.lockout_time = const.MFA_LOCKOUT_TIME
        self.backup_code_length = const.MFA_BACKUP_CODE_LENGTH
        self.recovery_code_length = const.MFA_RECOVERY_CODE_LENGTH
        self.trusted_device_days = const.MFA_TRUSTED_DEVICE_DAYS
        
    def _get_attempt_cache_key(self, user_id: int) -> str:
        """Get cache key for MFA attempts."""
        return f"mfa_attempts_{user_id}"
        
    def _get_device_cache_key(self, user_id: int, device_id: str) -> str:
        """Get cache key for trusted device."""
        return f"mfa_device_{user_id}_{device_id}"

    def generate_secret(self) -> Dict[str, str]:
        """
        Generate new MFA secrets including backup and recovery codes.
        
        Returns:
            Dict[str, str]: Dictionary containing secret key, backup codes, and recovery code
        """
        secret = pyotp.random_base32()
        backup_codes = self._generate_backup_codes()
        recovery_code = secrets.token_urlsafe(self.recovery_code_length)
        
        # Hash recovery code before storing
        recovery_hash = hashlib.sha256(recovery_code.encode()).hexdigest()
        
        return {
            'secret': secret,
            'backup_codes': backup_codes,
            'recovery_code': recovery_code,
            'recovery_hash': recovery_hash
        }
        
    def generate_totp(self, secret: str) -> pyotp.TOTP:
        """
        Create a TOTP object for generating and verifying codes.
        
        Args:
            secret (str): Base32 encoded secret key
            
        Returns:
            pyotp.TOTP: TOTP object
        """
        return pyotp.TOTP(
            secret,
            digits=self.digits,
            interval=self.interval,
            algorithm=self.algorithm
        )
        
    def verify_code(self, user_id: int, secret: str, code: str, device_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Verify a TOTP code with rate limiting and device trust.
        
        Args:
            user_id (int): User's ID
            secret (str): Base32 encoded secret key
            code (str): Code to verify
            device_id (Optional[str]): Device identifier for trust
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, device_trust_token)
            
        Raises:
            MFAError: If verification fails or user is locked out
        """
        cache_key = self._get_attempt_cache_key(user_id)
        
        # Check rate limiting
        allowed, retry_after = rate_limiter.check_rate_limit('mfa', str(user_id))
        if not allowed:
            raise MFAError(
                f"Too many failed attempts. Try again in {retry_after.total_seconds()} seconds"
            )
            
        # Check if device is already trusted
        if device_id:
            device_key = self._get_device_cache_key(user_id, device_id)
            if cache.get(device_key):
                return True, None
        
        try:
            totp = self.generate_totp(secret)
            valid = totp.verify(code, valid_window=const.MFA_CODE_TOLERANCE)
            
            if valid:
                # Reset attempts on success
                cache.delete(cache_key)
                
                # Generate device trust token if requested
                if device_id:
                    trust_token = secrets.token_urlsafe(32)
                    device_key = self._get_device_cache_key(user_id, device_id)
                    cache.set(
                        device_key,
                        trust_token,
                        timeout=self.trusted_device_days * 24 * 60 * 60
                    )
                    return True, trust_token
                    
                return True, None
            else:
                # Increment failed attempts
                attempts = cache.get(cache_key, 0) + 1
                if attempts >= self.max_attempts:
                    cache.set(cache_key, attempts, timeout=self.lockout_time)
                    raise MFAError(f"Account locked for {self.lockout_time} seconds")
                cache.set(cache_key, attempts)
                return False, None
                
        except Exception as e:
            if not isinstance(e, MFAError):
                e = MFAError(f"Failed to verify MFA code: {str(e)}")
            raise e
            
    def generate_qr_code(self, secret: str, username: str) -> str:
        """
        Generate a QR code for setting up MFA in authenticator apps.
        
        Args:
            secret (str): Base32 encoded secret key
            username (str): Username to identify the account
            
        Returns:
            str: Base64 encoded QR code image
            
        Raises:
            MFAError: If QR code generation fails
        """
        try:
            totp = self.generate_totp(secret)
            provisioning_uri = totp.provisioning_uri(
                username,
                issuer_name=self.issuer
            )
            
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            # Create image and convert to base64
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            return base64.b64encode(buffer.getvalue()).decode()
            
        except Exception as e:
            raise MFAError(f"Failed to generate QR code: {str(e)}")
            
    def send_setup_email(self, email: str, username: str, qr_code: str) -> None:
        """
        Send MFA setup instructions via email.
        
        Args:
            email (str): User's email address
            username (str): Username
            qr_code (str): Base64 encoded QR code image
            
        Raises:
            MFAError: If email sending fails
        """
        try:
            context = {
                'username': username,
                'qr_code': qr_code,
                'issuer': self.issuer,
                'digits': self.digits,
                'interval': self.interval
            }
            
            subject = f"Set Up Two-Factor Authentication for {self.issuer}"
            html_content = template_manager.render_template('mfa_setup.html', context)
            email_service.send_email(email, subject, html_content)
            
        except Exception as e:
            raise MFAError(f"Failed to send MFA setup email: {str(e)}")
            
    def _generate_backup_codes(self) -> List[Dict[str, Any]]:
        """
        Generate backup codes with metadata.
        
        Returns:
            List[Dict[str, Any]]: List of backup codes with usage info
        """
        codes = []
        for _ in range(const.MFA_BACKUP_CODE_COUNT):
            code = secrets.token_hex(self.backup_code_length)
            # Store hash of the code
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            codes.append({
                'code': code,
                'hash': code_hash,
                'used': False,
                'used_at': None
            })
        return codes
        
    def verify_backup_code(self, provided_code: str, stored_codes: List[Dict[str, Any]]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Verify a backup code and mark it as used.
        
        Args:
            provided_code (str): Code provided by user
            stored_codes (List[Dict[str, Any]]): List of stored backup codes
            
        Returns:
            Tuple[bool, List[Dict[str, Any]]]: (is_valid, updated_codes)
        """
        provided_hash = hashlib.sha256(provided_code.encode()).hexdigest()
        
        for code in stored_codes:
            if not code['used'] and code['hash'] == provided_hash:
                code['used'] = True
                code['used_at'] = datetime.utcnow().isoformat()
                return True, stored_codes
        return False, stored_codes
        
    def verify_recovery_code(self, user_id: int, provided_code: str, stored_hash: str) -> bool:
        """
        Verify a recovery code with rate limiting.
        
        Args:
            user_id (int): User's ID
            provided_code (str): Code provided by user
            stored_hash (str): Stored hash of recovery code
            
        Returns:
            bool: True if code is valid
        """
        # Check rate limiting
        allowed, retry_after = rate_limiter.check_rate_limit('recovery', str(user_id))
        if not allowed:
            raise MFAError(
                f"Too many recovery attempts. Try again in {retry_after.total_seconds()} seconds"
            )
            
        provided_hash = hashlib.sha256(provided_code.encode()).hexdigest()
        return provided_hash == stored_hash

# Singleton instance
mfa_manager = MFAManager()

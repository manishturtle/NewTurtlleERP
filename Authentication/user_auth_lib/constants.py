"""
Constants and configuration settings for the authentication library.
All values can be overridden using environment variables.
"""

from decouple import config

# JWT Settings
JWT_ALGORITHM = config('JWT_ALGORITHM', default='HS256')
JWT_ACCESS_TOKEN_LIFETIME = int(config('JWT_ACCESS_TOKEN_LIFETIME', default=60 * 24))  # 1 day in minutes
JWT_REFRESH_TOKEN_LIFETIME = int(config('JWT_REFRESH_TOKEN_LIFETIME', default=60 * 24 * 14))  # 14 days in minutes

# Token Types
TOKEN_TYPE_ACCESS = 'access'
TOKEN_TYPE_REFRESH = 'refresh'

# Cookie Settings
REFRESH_TOKEN_COOKIE_NAME = config('REFRESH_TOKEN_COOKIE_NAME', default='refresh_token')
REFRESH_TOKEN_COOKIE_SECURE = config('REFRESH_TOKEN_COOKIE_SECURE', default=True, cast=bool)
REFRESH_TOKEN_COOKIE_HTTPONLY = config('REFRESH_TOKEN_COOKIE_HTTPONLY', default=True, cast=bool)
REFRESH_TOKEN_COOKIE_SAMESITE = config('REFRESH_TOKEN_COOKIE_SAMESITE', default='Strict')

# Error Messages
ERROR_MESSAGES = {
    'TOKEN_EXPIRED': 'Token has expired',
    'TOKEN_INVALID': 'Invalid token: {}',
    'TOKEN_TYPE_INVALID': 'Invalid token type. Expected {}',
    'USER_NOT_FOUND': 'User not found',
    'REFRESH_TOKEN_INVALID': 'Invalid refresh token: {}'
}

# Security Settings
MIN_PASSWORD_LENGTH = int(config('MIN_PASSWORD_LENGTH', default=8))
MAX_PASSWORD_LENGTH = int(config('MAX_PASSWORD_LENGTH', default=128))
MIN_TOKEN_LENGTH = int(config('MIN_TOKEN_LENGTH', default=16))

# OTP Settings
OTP_DIGITS = int(config('OTP_DIGITS', default=6))
OTP_INTERVAL = int(config('OTP_INTERVAL', default=30))  # seconds
OTP_TOLERANCE = int(config('OTP_TOLERANCE', default=1))  # intervals before/after
OTP_EXPIRY_MINUTES = int(config('OTP_EXPIRY_MINUTES', default=5))

# Email Settings
SMTP_HOST = config('SMTP_HOST', default='smtp.zeptomail.com')
SMTP_PORT = int(config('SMTP_PORT', default=587))
SMTP_USER = config('SMTP_USER')
SMTP_PASSWORD = config('SMTP_PASSWORD')
FROM_EMAIL = config('FROM_EMAIL')
FROM_NAME = config('FROM_NAME', default='VisaBoard12121123')
SUPPORT_EMAIL = config('SUPPORT_EMAIL', default='pune1231231@visaboard.in')

# SMS Settings
SMS_HOST = config('SMS_HOST', default='https://www.fast2sms.com/dev/bulk')
SMS_AUTH_KEY = config('SMS_AUTH_KEY')

# Password Settings
MIN_PASSWORD_LENGTH = int(config('MIN_PASSWORD_LENGTH', default=8))
MAX_PASSWORD_LENGTH = int(config('MAX_PASSWORD_LENGTH', default=128))
PASSWORD_SPECIAL_CHARS = r'[!@#$%^&*(),.?":{}|<>]'

# Rate Limiting Settings
# Login attempts
MAX_LOGIN_ATTEMPTS = int(config('MAX_LOGIN_ATTEMPTS', default=5))
LOGIN_ATTEMPT_TIMEOUT = int(config('LOGIN_ATTEMPT_TIMEOUT', default=15))  # minutes

# OTP attempts
MAX_OTP_ATTEMPTS = int(config('MAX_OTP_ATTEMPTS', default=3))
OTP_ATTEMPT_TIMEOUT = int(config('OTP_ATTEMPT_TIMEOUT', default=10))  # minutes

# Token refresh attempts
MAX_TOKEN_REQUESTS = int(config('MAX_TOKEN_REQUESTS', default=10))
TOKEN_REQUEST_TIMEOUT = int(config('TOKEN_REQUEST_TIMEOUT', default=60))  # minutes

# MFA Settings
MFA_ISSUER_NAME = config('MFA_ISSUER_NAME', default='VisaBoard')
MFA_ALGORITHM = config('MFA_ALGORITHM', default='SHA1')
MFA_DIGITS = int(config('MFA_DIGITS', default=6))
MFA_INTERVAL = int(config('MFA_INTERVAL', default=30))  # seconds
MFA_BACKUP_CODE_COUNT = int(config('MFA_BACKUP_CODE_COUNT', default=8))
MFA_CODE_TOLERANCE = int(config('MFA_CODE_TOLERANCE', default=1))  # intervals

# MFA Security Settings
MFA_MAX_ATTEMPTS = int(config('MFA_MAX_ATTEMPTS', default=5))
MFA_LOCKOUT_TIME = int(config('MFA_LOCKOUT_TIME', default=300))  # seconds
MFA_BACKUP_CODE_LENGTH = int(config('MFA_BACKUP_CODE_LENGTH', default=8))
MFA_RECOVERY_CODE_LENGTH = int(config('MFA_RECOVERY_CODE_LENGTH', default=16))
MFA_TRUSTED_DEVICE_DAYS = int(config('MFA_TRUSTED_DEVICE_DAYS', default=30))

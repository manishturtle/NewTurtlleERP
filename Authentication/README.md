# User Authentication Library

A stateless user management library providing core authentication functionality for Django applications.

## Features

- JWT-based authentication with access and refresh tokens
- Configurable token lifetimes via environment variables

- Password hashing and verification using bcrypt
- TOTP-based MFA (Multi-Factor Authentication)
- Secure token generation
- No database dependencies
- Comprehensive error handling
- Fully tested

## Installation

```bash
pip install -e .
```

## Usage

### Password Hashing

```python
from user_auth_lib import hash_password, verify_password

# Hash a password
hashed_password = hash_password("my_secure_password")

# Verify a password
is_valid = verify_password("my_secure_password", hashed_password)
```

### OTP (One-Time Password)

```python
from user_auth_lib import generate_mfa_secret, generate_otp_uri, verify_otp_code

# Generate a new MFA secret
secret = generate_mfa_secret()

# Generate QR code URI
uri = generate_otp_uri(secret, "username", "MyApp")

# Verify OTP code
is_valid = verify_otp_code("123456", secret)
```

### JWT Authentication

```python
from user_auth_lib import JWTAuth

# Initialize JWT authentication
jwt_auth = JWTAuth()

# Generate access and refresh tokens
access_token, refresh_token = jwt_auth.generate_tokens(user.id, user.email)

# Verify a token
try:
    payload = jwt_auth.verify_token(access_token, 'access')
    user_id = payload['user_id']
    email = payload['email']
except jwt.ExpiredSignatureError:
    # Handle expired token
    pass

# Refresh an access token
try:
    new_access_token = jwt_auth.refresh_access_token(refresh_token)
except jwt.InvalidTokenError:
    # Handle invalid refresh token
    pass
```

### Environment Variables

Create a `.env` file based on `.env.example`:

```env
JWT_SECRET_KEY=your-secret-key-here
JWT_ACCESS_TOKEN_LIFETIME=1440  # 24 hours in minutes
JWT_REFRESH_TOKEN_LIFETIME=20160  # 14 days in minutes
```

### Secure Tokens

```python
from user_auth_lib import generate_secure_token

# Generate a secure token
token = generate_secure_token(length=32)
```

## Error Handling

The library provides custom exceptions for different error cases:

```python
from user_auth_lib import (
    InvalidPasswordFormatError,
    OTPVerificationError,
    TokenGenerationError
)

try:
    hash_password("")
except InvalidPasswordFormatError as e:
    print(f"Invalid password: {e}")
```

## Testing

Run the tests using pytest:

```bash
pytest
```

## Dependencies

- bcrypt>=4.0.0
- pyotp>=2.8.0

## Security Notes

1. Always use HTTPS in production
2. Store hashed passwords, never plain text
3. Keep MFA secrets secure
4. Use sufficient token lengths (minimum 32 bytes recommended)
5. Handle exceptions appropriately in your application

## License

MIT License

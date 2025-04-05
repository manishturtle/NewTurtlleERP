"""
JWT token generation and verification functionality.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from decouple import config
from . import constants as const

User = get_user_model()

class JWTAuth:
    def __init__(self, secret_key: Optional[str] = None):
        """
        Initialize JWT authentication with optional secret key.
        If not provided, will try to get from settings or .env
        """
        self.secret_key = secret_key or config('JWT_SECRET_KEY', default=settings.SECRET_KEY)
        self.access_token_lifetime = const.JWT_ACCESS_TOKEN_LIFETIME
        self.refresh_token_lifetime = const.JWT_REFRESH_TOKEN_LIFETIME
        self.algorithm = const.JWT_ALGORITHM

    def _get_token_expiry(self, minutes: int) -> datetime:
        """Calculate token expiry time."""
        return datetime.utcnow() + timedelta(minutes=minutes)

    def generate_tokens(self, user_id: int, email: str) -> Tuple[str, str]:
        """
        Generate both access and refresh tokens for a user.

        Args:
            user_id (int): The user's ID
            email (str): The user's email

        Returns:
            Tuple[str, str]: A tuple of (access_token, refresh_token)
        """
        # Generate access token
        access_token_payload = {
            'user_id': user_id,
            'email': email,
            'exp': self._get_token_expiry(self.access_token_lifetime),
            'token_type': const.TOKEN_TYPE_ACCESS
        }
        
        # Generate refresh token
        refresh_token_payload = {
            'user_id': user_id,
            'exp': self._get_token_expiry(self.refresh_token_lifetime),
            'token_type': const.TOKEN_TYPE_REFRESH
        }

        access_token = jwt.encode(
            access_token_payload,
            self.secret_key,
            algorithm=self.algorithm
        )
        
        refresh_token = jwt.encode(
            refresh_token_payload,
            self.secret_key,
            algorithm=self.algorithm
        )

        return access_token, refresh_token

    def verify_token(self, token: str, token_type: str = 'access') -> Dict:
        """
        Verify and decode a JWT token.

        Args:
            token (str): The token to verify
            token_type (str): The expected token type ('access' or 'refresh')

        Returns:
            Dict: The decoded token payload

        Raises:
            jwt.InvalidTokenError: If token is invalid
            jwt.ExpiredSignatureError: If token has expired
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            
            # Verify token type
            if payload.get('token_type') != token_type:
                raise jwt.InvalidTokenError(const.ERROR_MESSAGES['TOKEN_TYPE_INVALID'].format(token_type))
                
            return payload
        except jwt.ExpiredSignatureError:
            raise jwt.ExpiredSignatureError(const.ERROR_MESSAGES['TOKEN_EXPIRED'])
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(const.ERROR_MESSAGES['TOKEN_INVALID'].format(str(e)))

    def refresh_access_token(self, refresh_token: str) -> str:
        """
        Generate a new access token using a valid refresh token.

        Args:
            refresh_token (str): The refresh token to use

        Returns:
            str: A new access token

        Raises:
            jwt.InvalidTokenError: If refresh token is invalid
        """
        try:
            # Verify the refresh token
            payload = self.verify_token(refresh_token, token_type='refresh')
            
            # Get user details
            user = User.objects.get(id=payload['user_id'])
            
            # Generate new access token
            access_token_payload = {
                'user_id': user.id,
                'email': user.email,
                'exp': self._get_token_expiry(self.access_token_lifetime),
                'token_type': const.TOKEN_TYPE_ACCESS
            }
            
            return jwt.encode(
                access_token_payload,
                self.secret_key,
                algorithm=self.algorithm
            )
        except User.DoesNotExist:
            raise jwt.InvalidTokenError(const.ERROR_MESSAGES['USER_NOT_FOUND'])
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(const.ERROR_MESSAGES['REFRESH_TOKEN_INVALID'].format(str(e)))

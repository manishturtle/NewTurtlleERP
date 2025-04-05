"""
Rate limiting functionality using a token bucket algorithm.
"""

import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional
from . import constants as const
from .exceptions import RateLimitExceededError

@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    capacity: int  # Maximum number of tokens
    refill_rate: float  # Tokens per second
    tokens: float  # Current number of tokens
    last_refill: float  # Last refill timestamp

class RateLimiter:
    def __init__(self):
        # Store buckets for different operations
        self._buckets: Dict[str, Dict[str, TokenBucket]] = {
            'login': {},  # Key: IP address
            'otp': {},    # Key: email/phone
            'token': {}   # Key: user_id
        }
        
        # Configure limits from constants
        self.limits = {
            'login': {
                'capacity': const.MAX_LOGIN_ATTEMPTS,
                'window': const.LOGIN_ATTEMPT_TIMEOUT * 60  # Convert minutes to seconds
            },
            'otp': {
                'capacity': const.MAX_OTP_ATTEMPTS,
                'window': const.OTP_ATTEMPT_TIMEOUT * 60
            },
            'token': {
                'capacity': const.MAX_TOKEN_REQUESTS,
                'window': const.TOKEN_REQUEST_TIMEOUT * 60
            }
        }

    def _get_bucket(self, operation: str, key: str) -> TokenBucket:
        """Get or create a token bucket for the operation and key."""
        if key not in self._buckets[operation]:
            limit = self.limits[operation]
            self._buckets[operation][key] = TokenBucket(
                capacity=limit['capacity'],
                refill_rate=limit['capacity'] / limit['window'],
                tokens=float(limit['capacity']),
                last_refill=time.time()
            )
        return self._buckets[operation][key]

    def _refill_tokens(self, bucket: TokenBucket) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - bucket.last_refill
        new_tokens = elapsed * bucket.refill_rate
        bucket.tokens = min(bucket.capacity, bucket.tokens + new_tokens)
        bucket.last_refill = now

    def check_rate_limit(self, operation: str, key: str, cost: int = 1) -> Tuple[bool, Optional[timedelta]]:
        """
        Check if an operation is allowed under rate limiting rules.
        
        Args:
            operation (str): Type of operation ('login', 'otp', 'token')
            key (str): Unique identifier for rate limiting (IP, email, user_id)
            cost (int): Number of tokens to consume, defaults to 1
            
        Returns:
            Tuple[bool, Optional[timedelta]]: (allowed, time_remaining)
            - allowed: Whether the operation is allowed
            - time_remaining: If not allowed, time until next token is available
            
        Raises:
            ValueError: If operation type is invalid
        """
        if operation not in self._buckets:
            raise ValueError(f"Invalid operation type: {operation}")

        bucket = self._get_bucket(operation, key)
        self._refill_tokens(bucket)

        if bucket.tokens >= cost:
            bucket.tokens -= cost
            return True, None
        else:
            # Calculate time until next token is available
            tokens_needed = cost - bucket.tokens
            time_needed = tokens_needed / bucket.refill_rate
            return False, timedelta(seconds=int(time_needed))

    def reset_limits(self, operation: str, key: str) -> None:
        """
        Reset rate limits for a specific operation and key.
        
        Args:
            operation (str): Type of operation ('login', 'otp', 'token')
            key (str): Unique identifier to reset
        """
        if operation in self._buckets and key in self._buckets[operation]:
            del self._buckets[operation][key]

# Singleton instance
rate_limiter = RateLimiter()

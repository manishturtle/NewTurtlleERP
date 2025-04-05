"""
SMS service configuration and utilities using Fast2SMS.
"""

import re
import requests
from decouple import config
from . import constants as const

class SMSService:
    def __init__(self):
        self.host = config('SMS_HOST', default='https://www.fast2sms.com/dev/bulk')
        self.auth_key = config('SMS_AUTH_KEY')

    def send_sms(self, phone_number: str, otp: str) -> None:
        """
        Send OTP via SMS using Fast2SMS API.
        
        Args:
            phone_number (str): Recipient's phone number (10 digits)
            otp (str): The OTP to send
            
        Raises:
            ValueError: If phone number format is invalid
            Exception: If SMS sending fails
        """
        try:
            # Validate phone number format
            if not re.match(r'^\d{10}$', phone_number):
                raise ValueError(const.ERROR_MESSAGES['INVALID_PHONE_NUMBER'])

            headers = {
                'Authorization': self.auth_key
            }

            payload = {
                'variables_values': otp,
                'route': 'otp',
                'numbers': phone_number
            }

            response = requests.post(self.host, headers=headers, data=payload)
            if response.status_code != 200:
                raise Exception(const.ERROR_MESSAGES['SMS_BLOCKED'])
                
        except Exception as e:
            raise Exception(f"Failed to send SMS: {str(e)}")

# Singleton instance
sms_service = SMSService()

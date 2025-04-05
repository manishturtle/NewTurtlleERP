"""
Email service configuration and utilities.
"""

from decouple import config
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from . import constants as const

class EmailService:
    def __init__(self):
        self.host = config('SMTP_HOST', default='smtp.zeptomail.com')
        self.port = int(config('SMTP_PORT', default=587))
        self.user = config('SMTP_USER')
        self.password = config('SMTP_PASSWORD')
        self.from_email = config('FROM_EMAIL')
        self.from_name = config('FROM_NAME', default='VisaBoard')

    def send_email(self, to_email: str, subject: str, html_content: str) -> None:
        """
        Send an HTML email using SMTP.
        
        Args:
            to_email (str): Recipient email address
            subject (str): Email subject
            html_content (str): HTML content of the email
            
        Raises:
            Exception: If email sending fails
        """
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(html_content, "html"))

            with smtplib.SMTP(self.host, self.port) as server:
                server.starttls()
                server.login(self.user, self.password)
                server.sendmail(self.from_email, to_email, msg.as_string())
        except Exception as e:
            raise Exception(f"Failed to send email: {str(e)}")

# Singleton instance
email_service = EmailService()

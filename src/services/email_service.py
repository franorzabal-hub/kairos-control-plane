"""
Email Service for sending validation and notification emails.

TODO: Integrate with SendGrid or AWS SES for production email delivery.
The current implementation logs emails for development/testing purposes.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Configuration for email service
# TODO: Move these to environment variables when integrating with real email provider
BASE_URL = "https://kairos.app"


class EmailService:
    """
    Service for sending emails.

    Currently logs emails for development. In production, this will integrate
    with SendGrid or AWS SES.

    TODO: Add methods for:
    - send_welcome_email(to_email, school_name, tenant_url)
    - send_password_reset_email(to_email, reset_token)
    - send_trial_expiry_reminder(to_email, days_remaining)
    """

    def __init__(self, base_url: str = BASE_URL):
        """
        Initialize the email service.

        Args:
            base_url: Base URL for generating validation links
        """
        self.base_url = base_url
        # TODO: Initialize email provider client (SendGrid/SES) here
        # self.sendgrid_client = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        # or
        # self.ses_client = boto3.client('ses', region_name='us-east-1')
        logger.info("EmailService initialized (logging mode - no actual emails sent)")

    async def send_validation_email(
        self,
        to_email: str,
        validation_token: str,
        school_name: str,
    ) -> dict:
        """
        Send a validation email for a pending signup.

        Args:
            to_email: Recipient email address
            validation_token: Token for email validation
            school_name: Name of the school (for personalization)

        Returns:
            dict with:
                - success: bool
                - message: Status message
                - error: Error message (on failure)
        """
        validation_link = f"{self.base_url}/validate/{validation_token}"

        # Log the email that would be sent
        logger.info(
            f"Would send validation email to {to_email} with link: {validation_link}"
        )

        # TODO: Replace with actual email sending when integrating SendGrid/SES
        # Example SendGrid implementation:
        # message = Mail(
        #     from_email='noreply@kairos.app',
        #     to_emails=to_email,
        #     subject=f'Validate your Kairos account for {school_name}',
        #     html_content=self._render_validation_template(school_name, validation_link)
        # )
        # try:
        #     response = self.sendgrid_client.send(message)
        #     return {"success": True, "message": "Validation email sent"}
        # except Exception as e:
        #     logger.error(f"Failed to send validation email: {e}")
        #     return {"success": False, "error": str(e)}

        # For now, always return success (email is logged)
        return {
            "success": True,
            "message": f"Validation email logged for {to_email}",
            "validation_link": validation_link,  # Useful for development/testing
        }

    def _render_validation_template(
        self,
        school_name: str,
        validation_link: str,
    ) -> str:
        """
        Render the HTML template for validation emails.

        TODO: Use proper templating (Jinja2) for production

        Args:
            school_name: Name of the school
            validation_link: Full validation URL

        Returns:
            HTML string for the email body
        """
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Validate Your Kairos Account</title>
        </head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #333;">Welcome to Kairos!</h1>
            <p>Thank you for signing up {school_name} for Kairos.</p>
            <p>Please click the button below to validate your email address and activate your account:</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{validation_link}"
                   style="background-color: #4CAF50; color: white; padding: 15px 30px;
                          text-decoration: none; border-radius: 5px; display: inline-block;">
                    Validate My Account
                </a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #666;">{validation_link}</p>
            <p style="color: #999; font-size: 12px; margin-top: 30px;">
                This link will expire in 48 hours. If you didn't request this email,
                you can safely ignore it.
            </p>
        </body>
        </html>
        """

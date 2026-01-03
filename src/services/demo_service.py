"""
Demo Service for managing trial users in the demo tenant.

This service handles trial signups by creating users in the shared demo tenant
(demo.kairos.app) instead of provisioning new tenants.

TODO: Replace mock implementation with actual Frappe API calls to demo tenant.
"""

import logging
from typing import Optional
from uuid import uuid4

from ..models import TrialSignupRequest, TrialSignupResponse

logger = logging.getLogger(__name__)

# Demo tenant configuration
DEMO_TENANT_URL = "https://demo.kairos.app"
DEMO_TENANT_API_URL = f"{DEMO_TENANT_URL}/api"


class DemoService:
    """
    Service for managing trial users in the demo tenant.

    Handles:
    - Trial user creation in demo tenant
    - User authentication via Frappe API
    - Session token generation
    """

    def __init__(self, demo_tenant_url: str = DEMO_TENANT_URL):
        """
        Initialize the demo service.

        Args:
            demo_tenant_url: URL of the demo tenant
        """
        self.demo_tenant_url = demo_tenant_url
        self.api_url = f"{demo_tenant_url}/api"

    async def create_trial_user(self, data: TrialSignupRequest) -> dict:
        """
        Create a trial user in the demo tenant.

        This method creates a new user in the shared demo tenant and returns
        the authentication token for immediate login.

        Args:
            data: Trial signup request data containing user info and credentials

        Returns:
            dict with:
                - success: bool
                - tenant_url: URL of demo tenant
                - token: Session token for the user
                - user_id: ID of the created user
                - message: Success/error message
                - error: Error message (only on failure)

        TODO: Implement actual Frappe API integration:
            1. Call Frappe API to create user with:
               - email, first_name, last_name
               - role: Trial User
               - school_name as custom field
            2. If google_token provided:
               - Verify token with Google
               - Link Google account to user
            3. If password provided:
               - Set user password via Frappe API
            4. Generate session token via Frappe auth
            5. Return token for immediate login
        """
        logger.info(f"Creating trial user for: {data.email}")

        # TODO: Replace with actual Frappe API calls
        # For now, return mock data for development/testing

        # Generate mock user ID
        user_id = str(uuid4())

        # Generate mock session token
        # In production, this would come from Frappe's auth system
        mock_token = f"mock_session_{uuid4().hex[:16]}"

        auth_method = "google" if data.google_token else "password"
        logger.info(
            f"Trial user created (mock): {data.email}, "
            f"school: {data.school_name}, auth: {auth_method}"
        )

        return {
            "success": True,
            "tenant_url": self.demo_tenant_url,
            "token": mock_token,
            "user_id": user_id,
            "message": f"Trial account created successfully. Welcome to Kairos, {data.first_name}!",
        }

    async def verify_google_token(self, token: str) -> Optional[dict]:
        """
        Verify a Google OAuth token and extract user info.

        Args:
            token: Google OAuth token

        Returns:
            dict with user info (email, name, etc.) or None if invalid

        TODO: Implement actual Google token verification:
            1. Call Google's tokeninfo endpoint
            2. Verify token is valid and not expired
            3. Extract user email and profile info
            4. Return user info or None
        """
        # TODO: Implement actual Google token verification
        logger.warning("Google token verification not implemented - returning mock data")

        return {
            "email": "user@example.com",
            "name": "Mock User",
            "verified": True,
        }

    async def check_user_exists(self, email: str) -> bool:
        """
        Check if a user with the given email already exists in demo tenant.

        Args:
            email: Email address to check

        Returns:
            True if user exists, False otherwise

        TODO: Implement actual Frappe API call to check user existence.
        """
        # TODO: Implement actual Frappe API call
        logger.warning("User existence check not implemented - returning False")
        return False

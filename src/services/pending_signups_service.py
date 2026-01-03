"""
Pending Signups Service for managing email/password signups awaiting validation.

TODO: Replace _pending_signups_db in-memory storage with Firestore for production.
The current in-memory dict is for demo/development purposes only.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import uuid4

import bcrypt

from ..models import PendingSignup

logger = logging.getLogger(__name__)

# In-memory storage for pending signups
# TODO: Replace with Firestore in production
_pending_signups_db: dict[str, dict] = {}

# Expiration time for pending signups (48 hours)
SIGNUP_EXPIRATION_HOURS = 48


class PendingSignupsService:
    """
    Service for managing pending email/password signups.

    Handles:
    - Creating pending signups with hashed passwords
    - Looking up signups by validation token
    - Deleting signups after validation
    - Cleaning up expired signups
    """

    def __init__(self):
        """Initialize the pending signups service."""
        pass

    def _hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt.

        Args:
            password: Plain text password

        Returns:
            str: Bcrypt-hashed password
        """
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password
            password_hash: Bcrypt-hashed password

        Returns:
            bool: True if password matches, False otherwise
        """
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

    async def create_pending_signup(
        self,
        school_name: str,
        email: str,
        password: str,
    ) -> dict:
        """
        Create a new pending signup.

        Args:
            school_name: Name of the school
            email: Email address
            password: Plain text password (will be hashed)

        Returns:
            dict with:
                - success: bool
                - pending_signup: PendingSignup data (on success)
                - validation_token: Token for email validation (on success)
                - error: Error message (on failure)
        """
        # Check if email already has a pending signup
        for signup in _pending_signups_db.values():
            if signup["email"].lower() == email.lower():
                # Check if expired
                if signup["expires_at"] > datetime.now(timezone.utc):
                    return {
                        "success": False,
                        "error": "A pending signup already exists for this email. Please check your inbox for the validation link.",
                    }
                # Expired - delete it and continue
                del _pending_signups_db[signup["id"]]
                break

        # Generate IDs and timestamps
        signup_id = str(uuid4())
        validation_token = str(uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=SIGNUP_EXPIRATION_HOURS)

        # Hash the password
        password_hash = self._hash_password(password)

        # Create pending signup record
        pending_signup = {
            "id": signup_id,
            "school_name": school_name,
            "email": email,
            "password_hash": password_hash,
            "validation_token": validation_token,
            "expires_at": expires_at,
            "created_at": now,
        }

        _pending_signups_db[signup_id] = pending_signup
        logger.info(f"Created pending signup: {signup_id} for email: {email}")

        return {
            "success": True,
            "pending_signup": pending_signup,
            "validation_token": validation_token,
        }

    async def get_by_token(self, validation_token: str) -> Optional[dict]:
        """
        Get a pending signup by its validation token.

        Args:
            validation_token: The validation token

        Returns:
            Pending signup data or None if not found
        """
        for signup in _pending_signups_db.values():
            if signup["validation_token"] == validation_token:
                # Check if expired
                if signup["expires_at"] <= datetime.now(timezone.utc):
                    logger.info(f"Pending signup expired: {signup['id']}")
                    return None
                return signup
        return None

    async def get_by_email(self, email: str) -> Optional[dict]:
        """
        Get a pending signup by email address.

        Args:
            email: Email address to search for

        Returns:
            Pending signup data or None if not found
        """
        email_lower = email.lower()
        for signup in _pending_signups_db.values():
            if signup["email"].lower() == email_lower:
                # Check if expired
                if signup["expires_at"] <= datetime.now(timezone.utc):
                    return None
                return signup
        return None

    async def delete_by_id(self, signup_id: str) -> bool:
        """
        Delete a pending signup by ID.

        Args:
            signup_id: The signup ID to delete

        Returns:
            True if deleted, False if not found
        """
        if signup_id in _pending_signups_db:
            del _pending_signups_db[signup_id]
            logger.info(f"Deleted pending signup: {signup_id}")
            return True
        return False

    async def cleanup_expired(self) -> int:
        """
        Remove all expired pending signups.

        Returns:
            Number of expired signups removed
        """
        now = datetime.now(timezone.utc)
        expired_ids = [
            signup_id
            for signup_id, signup in _pending_signups_db.items()
            if signup["expires_at"] <= now
        ]

        for signup_id in expired_ids:
            del _pending_signups_db[signup_id]

        if expired_ids:
            logger.info(f"Cleaned up {len(expired_ids)} expired pending signups")

        return len(expired_ids)

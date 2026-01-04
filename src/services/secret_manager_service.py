"""
Secret Manager Service for secure credential storage.

This service provides secure storage and retrieval of tenant credentials
using Google Cloud Secret Manager instead of Kubernetes Secrets.
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Configuration
SECRET_MANAGER_ENABLED = os.environ.get("SECRET_MANAGER_ENABLED", "false").lower() == "true"
GCP_PROJECT = os.environ.get("GCP_PROJECT", "kairos-escuela-app")

if SECRET_MANAGER_ENABLED:
    try:
        from google.cloud import secretmanager
        from google.api_core import exceptions as gcp_exceptions

        SECRET_MANAGER_AVAILABLE = True
    except ImportError:
        logger.warning("google-cloud-secret-manager not installed")
        SECRET_MANAGER_AVAILABLE = False
else:
    SECRET_MANAGER_AVAILABLE = False


class SecretManagerService:
    """
    Service for managing secrets in Google Cloud Secret Manager.

    Provides methods to create, read, and delete tenant credentials
    with automatic versioning and IAM-based access control.
    """

    def __init__(self, project_id: str = GCP_PROJECT):
        """
        Initialize the Secret Manager service.

        Args:
            project_id: GCP project ID
        """
        if not SECRET_MANAGER_AVAILABLE:
            raise RuntimeError("Secret Manager is not available")

        self._client = secretmanager.SecretManagerServiceClient()
        self._project_id = project_id
        self._parent = f"projects/{project_id}"
        logger.info(f"SecretManagerService initialized for project {project_id}")

    def _secret_path(self, secret_id: str) -> str:
        """Get the full resource path for a secret."""
        return f"{self._parent}/secrets/{secret_id}"

    def _version_path(self, secret_id: str, version: str = "latest") -> str:
        """Get the full resource path for a secret version."""
        return f"{self._secret_path(secret_id)}/versions/{version}"

    async def create_tenant_credentials(
        self,
        tenant_id: str,
        admin_password: str,
        db_password: Optional[str] = None,
    ) -> dict:
        """
        Create credentials for a tenant in Secret Manager.

        Args:
            tenant_id: Unique tenant identifier
            admin_password: Admin password for the tenant
            db_password: Optional database password

        Returns:
            dict with success status and secret name
        """
        secret_id = f"tenant-{tenant_id[:8]}-credentials"

        try:
            # Create the secret
            secret = self._client.create_secret(
                request={
                    "parent": self._parent,
                    "secret_id": secret_id,
                    "secret": {
                        "replication": {"automatic": {}},
                        "labels": {
                            "tenant-id": tenant_id[:8],
                            "managed-by": "kairos-control-plane",
                        },
                    },
                }
            )
            logger.info(f"Created secret: {secret.name}")

            # Add the secret version with the password
            import json

            payload = json.dumps(
                {
                    "admin_password": admin_password,
                    "db_password": db_password,
                    "tenant_id": tenant_id,
                }
            ).encode("UTF-8")

            version = self._client.add_secret_version(
                request={
                    "parent": secret.name,
                    "payload": {"data": payload},
                }
            )
            logger.info(f"Added secret version: {version.name}")

            return {"success": True, "secret_name": secret_id}

        except gcp_exceptions.AlreadyExists:
            logger.info(f"Secret {secret_id} already exists, adding new version")
            # Add new version to existing secret
            import json

            payload = json.dumps(
                {
                    "admin_password": admin_password,
                    "db_password": db_password,
                    "tenant_id": tenant_id,
                }
            ).encode("UTF-8")

            version = self._client.add_secret_version(
                request={
                    "parent": self._secret_path(secret_id),
                    "payload": {"data": payload},
                }
            )
            return {"success": True, "secret_name": secret_id, "updated": True}

        except Exception as e:
            logger.error(f"Failed to create secret {secret_id}: {e}")
            return {"success": False, "error": str(e)}

    async def get_tenant_credentials(self, tenant_id: str) -> Optional[dict]:
        """
        Retrieve credentials for a tenant.

        Args:
            tenant_id: Unique tenant identifier

        Returns:
            dict with credentials or None if not found
        """
        secret_id = f"tenant-{tenant_id[:8]}-credentials"

        try:
            response = self._client.access_secret_version(
                request={"name": self._version_path(secret_id)}
            )
            import json

            payload = response.payload.data.decode("UTF-8")
            return json.loads(payload)

        except gcp_exceptions.NotFound:
            logger.warning(f"Secret {secret_id} not found")
            return None
        except Exception as e:
            logger.error(f"Failed to get secret {secret_id}: {e}")
            return None

    async def delete_tenant_credentials(self, tenant_id: str) -> dict:
        """
        Delete credentials for a tenant.

        Args:
            tenant_id: Unique tenant identifier

        Returns:
            dict with success status
        """
        secret_id = f"tenant-{tenant_id[:8]}-credentials"

        try:
            self._client.delete_secret(request={"name": self._secret_path(secret_id)})
            logger.info(f"Deleted secret: {secret_id}")
            return {"success": True}

        except gcp_exceptions.NotFound:
            logger.info(f"Secret {secret_id} not found, already deleted")
            return {"success": True, "not_found": True}
        except Exception as e:
            logger.error(f"Failed to delete secret {secret_id}: {e}")
            return {"success": False, "error": str(e)}

    async def rotate_tenant_credentials(
        self,
        tenant_id: str,
        new_admin_password: str,
        new_db_password: Optional[str] = None,
    ) -> dict:
        """
        Rotate credentials for a tenant by adding a new version.

        Args:
            tenant_id: Unique tenant identifier
            new_admin_password: New admin password
            new_db_password: New database password (optional)

        Returns:
            dict with success status
        """
        # Get existing credentials to preserve db_password if not provided
        existing = await self.get_tenant_credentials(tenant_id)
        if existing and new_db_password is None:
            new_db_password = existing.get("db_password")

        return await self.create_tenant_credentials(
            tenant_id, new_admin_password, new_db_password
        )


class InMemorySecretService:
    """In-memory implementation for development/testing."""

    def __init__(self):
        self._secrets: dict[str, dict] = {}

    async def create_tenant_credentials(
        self,
        tenant_id: str,
        admin_password: str,
        db_password: Optional[str] = None,
    ) -> dict:
        secret_id = f"tenant-{tenant_id[:8]}-credentials"
        self._secrets[secret_id] = {
            "admin_password": admin_password,
            "db_password": db_password,
            "tenant_id": tenant_id,
        }
        return {"success": True, "secret_name": secret_id}

    async def get_tenant_credentials(self, tenant_id: str) -> Optional[dict]:
        secret_id = f"tenant-{tenant_id[:8]}-credentials"
        return self._secrets.get(secret_id)

    async def delete_tenant_credentials(self, tenant_id: str) -> dict:
        secret_id = f"tenant-{tenant_id[:8]}-credentials"
        if secret_id in self._secrets:
            del self._secrets[secret_id]
        return {"success": True}

    async def rotate_tenant_credentials(
        self,
        tenant_id: str,
        new_admin_password: str,
        new_db_password: Optional[str] = None,
    ) -> dict:
        return await self.create_tenant_credentials(
            tenant_id, new_admin_password, new_db_password
        )


def get_secret_service():
    """
    Factory function to get the appropriate secret service.

    Returns SecretManagerService if enabled and available,
    otherwise returns InMemorySecretService.
    """
    if SECRET_MANAGER_ENABLED and SECRET_MANAGER_AVAILABLE:
        logger.info("Using SecretManagerService for production")
        return SecretManagerService()
    else:
        logger.info("Using InMemorySecretService for development")
        return InMemorySecretService()

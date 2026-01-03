"""
Tenant Service for managing tenant lifecycle.
"""

import logging
import secrets
import string
from datetime import datetime
from typing import Optional
from uuid import uuid4

from ..models import TenantStatus, TenantResponse, TenantCreate
from .gke_service import GKEService

logger = logging.getLogger(__name__)


# In-memory storage for demo purposes
# In production, use Cloud SQL or Firestore
_tenants_db: dict[str, dict] = {}


class TenantService:
    """
    Service for managing tenant lifecycle.

    Handles:
    - Tenant creation and validation
    - Status tracking
    - Coordination with GKE for provisioning
    """

    def __init__(self, gke_service: GKEService, base_domain: str = "kairos.app"):
        """
        Initialize the tenant service.

        Args:
            gke_service: GKE service instance for Kubernetes operations
            base_domain: Base domain for tenant sites
        """
        self.gke = gke_service
        self.base_domain = base_domain

    def _generate_password(self, length: int = 16) -> str:
        """Generate a secure random password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    async def create_tenant(self, data: TenantCreate) -> dict:
        """
        Create a new tenant.

        Args:
            data: Tenant creation data

        Returns:
            dict with tenant info or error
        """
        # Check if subdomain already exists
        for tenant in _tenants_db.values():
            if tenant["subdomain"] == data.subdomain:
                return {
                    "success": False,
                    "error": f"Subdomain '{data.subdomain}' is already taken",
                }

        # Generate unique ID and password
        tenant_id = str(uuid4())
        admin_password = self._generate_password()
        now = datetime.utcnow()

        # Create tenant record
        tenant = {
            "id": tenant_id,
            "organization": data.organization,
            "subdomain": data.subdomain,
            "email": data.email,
            "status": TenantStatus.QUEUED,
            "site_url": None,
            "error_message": None,
            "created_at": now,
            "updated_at": now,
            "job_name": None,
        }

        _tenants_db[tenant_id] = tenant
        logger.info(f"Created tenant record: {tenant_id} ({data.subdomain})")

        # Create secret in Kubernetes
        if self.gke.is_connected:
            secret_result = await self.gke.create_tenant_secret(
                tenant_id, admin_password
            )
            if not secret_result["success"]:
                tenant["status"] = TenantStatus.FAILED
                tenant["error_message"] = f"Failed to create credentials: {secret_result['error']}"
                tenant["updated_at"] = datetime.utcnow()
                return {
                    "success": False,
                    "error": tenant["error_message"],
                }

            # Start provisioning job
            tenant["status"] = TenantStatus.PROVISIONING
            tenant["updated_at"] = datetime.utcnow()

            job_result = await self.gke.create_site_provisioning_job(
                tenant_id=tenant_id,
                subdomain=data.subdomain,
                organization=data.organization,
                admin_email=data.email,
                base_domain=self.base_domain,
            )

            if job_result["success"]:
                tenant["job_name"] = job_result["job_name"]
            else:
                tenant["status"] = TenantStatus.FAILED
                tenant["error_message"] = job_result["error"]
                tenant["updated_at"] = datetime.utcnow()
                return {
                    "success": False,
                    "error": tenant["error_message"],
                }
        else:
            # Demo mode without GKE
            logger.warning("GKE not connected, running in demo mode")
            tenant["status"] = TenantStatus.PROVISIONING

        return {
            "success": True,
            "id": tenant_id,
            "subdomain": data.subdomain,
            "status": tenant["status"],
            "message": "Tenant creation started. Poll status endpoint for updates.",
        }

    async def get_tenant(self, tenant_id: str) -> Optional[dict]:
        """
        Get a tenant by ID.

        Args:
            tenant_id: Unique tenant identifier

        Returns:
            Tenant data or None
        """
        return _tenants_db.get(tenant_id)

    async def get_tenant_by_subdomain(self, subdomain: str) -> Optional[dict]:
        """
        Get a tenant by subdomain.

        Args:
            subdomain: Tenant subdomain

        Returns:
            Tenant data or None
        """
        for tenant in _tenants_db.values():
            if tenant["subdomain"] == subdomain:
                return tenant
        return None

    async def list_tenants(
        self, skip: int = 0, limit: int = 100
    ) -> tuple[list[dict], int]:
        """
        List all tenants with pagination.

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            Tuple of (tenants list, total count)
        """
        all_tenants = list(_tenants_db.values())
        # Sort by creation date (newest first)
        all_tenants.sort(key=lambda x: x["created_at"], reverse=True)

        total = len(all_tenants)
        tenants = all_tenants[skip : skip + limit]

        return tenants, total

    async def get_tenant_status(self, tenant_id: str) -> Optional[dict]:
        """
        Get tenant status with optional refresh from GKE.

        Args:
            tenant_id: Unique tenant identifier

        Returns:
            Status info or None
        """
        tenant = _tenants_db.get(tenant_id)
        if not tenant:
            return None

        # If provisioning, check job status
        if (
            tenant["status"] == TenantStatus.PROVISIONING
            and tenant.get("job_name")
            and self.gke.is_connected
        ):
            job_status = await self.gke.get_job_status(tenant["job_name"])

            if job_status["success"]:
                if job_status["status"] == "completed":
                    tenant["status"] = TenantStatus.ACTIVE
                    site_name = f"{tenant['subdomain']}.{self.base_domain}"
                    tenant["site_url"] = f"https://{site_name}"
                    tenant["updated_at"] = datetime.utcnow()
                elif job_status["status"] == "failed":
                    tenant["status"] = TenantStatus.FAILED
                    tenant["error_message"] = "Provisioning job failed"
                    tenant["updated_at"] = datetime.utcnow()

        return {
            "id": tenant["id"],
            "subdomain": tenant["subdomain"],
            "status": tenant["status"],
            "site_url": tenant["site_url"],
            "error_message": tenant["error_message"],
        }

    async def update_tenant_status(
        self,
        tenant_id: str,
        status: TenantStatus,
        site_url: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> bool:
        """
        Update tenant status.

        Args:
            tenant_id: Unique tenant identifier
            status: New status
            site_url: Site URL (for active tenants)
            error_message: Error message (for failed tenants)

        Returns:
            True if updated, False if not found
        """
        tenant = _tenants_db.get(tenant_id)
        if not tenant:
            return False

        tenant["status"] = status
        tenant["updated_at"] = datetime.utcnow()

        if site_url:
            tenant["site_url"] = site_url
        if error_message:
            tenant["error_message"] = error_message

        return True

    async def delete_tenant(self, tenant_id: str) -> dict:
        """
        Delete a tenant and its resources.

        Args:
            tenant_id: Unique tenant identifier

        Returns:
            dict with success status
        """
        tenant = _tenants_db.get(tenant_id)
        if not tenant:
            return {"success": False, "error": "Tenant not found"}

        # Mark as deleting
        tenant["status"] = TenantStatus.DELETING
        tenant["updated_at"] = datetime.utcnow()

        # Delete GKE resources
        if self.gke.is_connected:
            result = await self.gke.delete_tenant_resources(
                tenant_id, tenant["subdomain"]
            )
            if not result["success"]:
                logger.warning(f"Failed to delete some GKE resources: {result}")

        # Remove from database
        del _tenants_db[tenant_id]
        logger.info(f"Deleted tenant: {tenant_id}")

        return {"success": True}

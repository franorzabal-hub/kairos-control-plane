"""
Firestore Service for persistent tenant storage.

This service provides a TenantRepository implementation using Google Cloud Firestore,
replacing the in-memory storage used in development.
"""

import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Check if Firestore is available
FIRESTORE_ENABLED = os.environ.get("FIRESTORE_ENABLED", "false").lower() == "true"
GCP_PROJECT = os.environ.get("GCP_PROJECT", "kairos-escuela-app")

if FIRESTORE_ENABLED:
    try:
        from google.cloud import firestore
        from google.cloud.firestore_v1 import AsyncClient

        FIRESTORE_AVAILABLE = True
    except ImportError:
        logger.warning("google-cloud-firestore not installed, Firestore disabled")
        FIRESTORE_AVAILABLE = False
else:
    FIRESTORE_AVAILABLE = False


class TenantRepository(ABC):
    """Abstract base class for tenant storage."""

    @abstractmethod
    async def create(self, tenant: dict) -> dict:
        """Create a new tenant record."""
        pass

    @abstractmethod
    async def get(self, tenant_id: str) -> Optional[dict]:
        """Get a tenant by ID."""
        pass

    @abstractmethod
    async def get_by_subdomain(self, subdomain: str) -> Optional[dict]:
        """Get a tenant by subdomain."""
        pass

    @abstractmethod
    async def get_by_email(self, email: str) -> list[dict]:
        """Get all tenants by email."""
        pass

    @abstractmethod
    async def update(self, tenant_id: str, updates: dict) -> Optional[dict]:
        """Update a tenant record."""
        pass

    @abstractmethod
    async def delete(self, tenant_id: str) -> bool:
        """Delete a tenant record."""
        pass

    @abstractmethod
    async def list(self, skip: int = 0, limit: int = 100) -> tuple[list[dict], int]:
        """List all tenants with pagination."""
        pass


class InMemoryTenantRepository(TenantRepository):
    """In-memory implementation for development/testing."""

    def __init__(self):
        self._tenants: dict[str, dict] = {}

    async def create(self, tenant: dict) -> dict:
        tenant_id = tenant["id"]
        self._tenants[tenant_id] = tenant
        return tenant

    async def get(self, tenant_id: str) -> Optional[dict]:
        return self._tenants.get(tenant_id)

    async def get_by_subdomain(self, subdomain: str) -> Optional[dict]:
        for tenant in self._tenants.values():
            if tenant["subdomain"] == subdomain:
                return tenant
        return None

    async def get_by_email(self, email: str) -> list[dict]:
        email_lower = email.lower()
        return [t for t in self._tenants.values() if t["email"].lower() == email_lower]

    async def update(self, tenant_id: str, updates: dict) -> Optional[dict]:
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return None
        tenant.update(updates)
        tenant["updated_at"] = datetime.now(timezone.utc)
        return tenant

    async def delete(self, tenant_id: str) -> bool:
        if tenant_id in self._tenants:
            del self._tenants[tenant_id]
            return True
        return False

    async def list(self, skip: int = 0, limit: int = 100) -> tuple[list[dict], int]:
        all_tenants = list(self._tenants.values())
        all_tenants.sort(key=lambda x: x["created_at"], reverse=True)
        total = len(all_tenants)
        return all_tenants[skip : skip + limit], total


class FirestoreTenantRepository(TenantRepository):
    """Firestore implementation for production."""

    COLLECTION = "tenants"

    def __init__(self, project_id: str = GCP_PROJECT):
        if not FIRESTORE_AVAILABLE:
            raise RuntimeError("Firestore is not available")
        self._db = AsyncClient(project=project_id)
        self._collection = self._db.collection(self.COLLECTION)
        logger.info(f"FirestoreTenantRepository initialized for project {project_id}")

    def _serialize_tenant(self, tenant: dict) -> dict:
        """Convert tenant dict for Firestore storage."""
        data = tenant.copy()
        # Firestore handles datetime natively
        return data

    def _deserialize_tenant(self, doc_id: str, data: dict) -> dict:
        """Convert Firestore document to tenant dict."""
        tenant = data.copy()
        tenant["id"] = doc_id
        # Convert Firestore timestamps to datetime if needed
        if hasattr(tenant.get("created_at"), "isoformat"):
            pass  # Already datetime
        return tenant

    async def create(self, tenant: dict) -> dict:
        tenant_id = tenant["id"]
        data = self._serialize_tenant(tenant)
        await self._collection.document(tenant_id).set(data)
        logger.info(f"Created tenant in Firestore: {tenant_id}")
        return tenant

    async def get(self, tenant_id: str) -> Optional[dict]:
        doc = await self._collection.document(tenant_id).get()
        if doc.exists:
            return self._deserialize_tenant(doc.id, doc.to_dict())
        return None

    async def get_by_subdomain(self, subdomain: str) -> Optional[dict]:
        query = self._collection.where("subdomain", "==", subdomain).limit(1)
        docs = await query.get()
        for doc in docs:
            return self._deserialize_tenant(doc.id, doc.to_dict())
        return None

    async def get_by_email(self, email: str) -> list[dict]:
        # Firestore queries are case-sensitive, so we store email lowercase
        query = self._collection.where("email", "==", email.lower())
        docs = await query.get()
        return [self._deserialize_tenant(doc.id, doc.to_dict()) for doc in docs]

    async def update(self, tenant_id: str, updates: dict) -> Optional[dict]:
        doc_ref = self._collection.document(tenant_id)
        doc = await doc_ref.get()
        if not doc.exists:
            return None

        updates["updated_at"] = datetime.now(timezone.utc)
        await doc_ref.update(updates)
        logger.info(f"Updated tenant in Firestore: {tenant_id}")

        # Return updated document
        updated_doc = await doc_ref.get()
        return self._deserialize_tenant(updated_doc.id, updated_doc.to_dict())

    async def delete(self, tenant_id: str) -> bool:
        doc_ref = self._collection.document(tenant_id)
        doc = await doc_ref.get()
        if not doc.exists:
            return False

        await doc_ref.delete()
        logger.info(f"Deleted tenant from Firestore: {tenant_id}")
        return True

    async def list(self, skip: int = 0, limit: int = 100) -> tuple[list[dict], int]:
        # Get total count (Firestore doesn't have built-in count, so we estimate)
        # For production, consider using a counter document or aggregation
        all_docs = await self._collection.order_by(
            "created_at", direction=firestore.Query.DESCENDING
        ).get()
        total = len(all_docs)

        # Get paginated results
        query = (
            self._collection.order_by("created_at", direction=firestore.Query.DESCENDING)
            .offset(skip)
            .limit(limit)
        )
        docs = await query.get()
        tenants = [self._deserialize_tenant(doc.id, doc.to_dict()) for doc in docs]

        return tenants, total


def get_tenant_repository() -> TenantRepository:
    """
    Factory function to get the appropriate tenant repository.

    Returns FirestoreTenantRepository if Firestore is enabled and available,
    otherwise returns InMemoryTenantRepository.
    """
    if FIRESTORE_ENABLED and FIRESTORE_AVAILABLE:
        logger.info("Using FirestoreTenantRepository for production")
        return FirestoreTenantRepository()
    else:
        logger.info("Using InMemoryTenantRepository for development")
        return InMemoryTenantRepository()

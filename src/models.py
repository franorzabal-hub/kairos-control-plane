"""
Pydantic models for Kairos Control Plane API.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator
import re


class TenantStatus(str, Enum):
    """Possible status values for a tenant."""
    QUEUED = "queued"
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    FAILED = "failed"
    SUSPENDED = "suspended"
    DELETING = "deleting"


# Reserved subdomains that cannot be used for tenants
RESERVED_SUBDOMAINS = [
    "www", "api", "admin", "app", "mail", "smtp", "ftp", "test",
    "staging", "dev", "demo", "support", "help", "status", "cdn",
    "assets", "static", "control", "panel", "dashboard"
]


class TenantCreate(BaseModel):
    """Request model for creating a new tenant."""
    organization: str = Field(..., min_length=2, max_length=100, description="Organization name")
    subdomain: str = Field(..., min_length=3, max_length=30, description="Subdomain for the tenant")
    email: EmailStr = Field(..., description="Admin email address")

    @field_validator("organization")
    @classmethod
    def validate_organization(cls, v: str) -> str:
        """
        Validate organization name format.
        Only allows letters, numbers, spaces, hyphens, periods, and accented characters.
        This prevents shell injection when used in GKE commands.
        """
        v = v.strip()
        pattern = r'^[\w\s\-\.áéíóúñÁÉÍÓÚÑüÜ]+$'
        if not re.match(pattern, v):
            raise ValueError(
                "Organization name can only contain letters, numbers, spaces, "
                "hyphens, periods, and accented characters"
            )
        return v

    @field_validator("subdomain")
    @classmethod
    def validate_subdomain(cls, v: str) -> str:
        """Validate subdomain format and availability."""
        subdomain = v.lower().strip()

        # Only alphanumeric characters allowed
        if not subdomain.isalnum():
            raise ValueError("Subdomain must be alphanumeric only")

        # Check against reserved subdomains
        if subdomain in RESERVED_SUBDOMAINS:
            raise ValueError(f"Subdomain '{subdomain}' is reserved and cannot be used")

        return subdomain


class TenantUpdate(BaseModel):
    """Request model for updating a tenant."""
    organization: Optional[str] = Field(None, min_length=2, max_length=100)
    email: Optional[EmailStr] = None


class TenantResponse(BaseModel):
    """Response model for a tenant."""
    id: str = Field(..., description="Unique tenant identifier")
    organization: str = Field(..., description="Organization name")
    subdomain: str = Field(..., description="Tenant subdomain")
    email: str = Field(..., description="Admin email address")
    status: TenantStatus = Field(..., description="Current tenant status")
    site_url: Optional[str] = Field(None, description="URL of the tenant site when active")
    error_message: Optional[str] = Field(None, description="Error message if provisioning failed")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    class Config:
        from_attributes = True


class TenantStatusResponse(BaseModel):
    """Response model for tenant status check."""
    id: str
    subdomain: str
    status: TenantStatus
    site_url: Optional[str] = None
    error_message: Optional[str] = None


class TenantListResponse(BaseModel):
    """Response model for listing tenants."""
    tenants: list[TenantResponse]
    total: int
    skip: int = 0
    limit: int = 100
    has_more: bool = False


class CreateTenantResponse(BaseModel):
    """Response model for tenant creation."""
    success: bool
    id: str
    subdomain: str
    status: TenantStatus
    message: str


class JobStatusWebhook(BaseModel):
    """Webhook payload for job status updates."""
    tenant_id: str = Field(..., description="Tenant ID")
    status: str = Field(..., description="New status value")
    site_url: Optional[str] = Field(None, description="Site URL if active")
    error_message: Optional[str] = Field(None, description="Error if failed")


class APIInfo(BaseModel):
    """API information response."""
    name: str = "Kairos Control Plane"
    version: str
    docs: str = "/docs"


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    database: bool
    gke_connection: bool
    version: str


class ErrorResponse(BaseModel):
    """Standard error response."""
    success: bool = False
    error: str
    detail: Optional[str] = None

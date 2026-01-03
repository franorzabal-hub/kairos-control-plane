"""
Pydantic models for Kairos Control Plane API.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
import re
import unicodedata


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
    "www", "api", "app", "admin", "mail", "ftp", "demo", "test",
    "staging", "dev", "beta", "cdn", "static", "assets", "help",
    "support", "docs", "status", "smtp", "control", "panel", "dashboard"
]


def generate_subdomain_from_name(name: str) -> str:
    """
    Generate a valid subdomain from a school/organization name.

    - Normalizes unicode characters (removes accents)
    - Converts to lowercase
    - Removes non-alphanumeric characters
    - Truncates to max 30 characters
    """
    # Normalize unicode (NFD) and remove diacritics
    normalized = unicodedata.normalize('NFD', name)
    ascii_name = ''.join(c for c in normalized if unicodedata.category(c) != 'Mn')

    # Convert to lowercase and keep only alphanumeric
    subdomain = ''.join(c.lower() for c in ascii_name if c.isalnum())

    # Ensure minimum length
    if len(subdomain) < 3:
        subdomain = subdomain + "school"

    # Truncate to max 30 characters
    return subdomain[:30]


def generate_auto_subdomain() -> str:
    """
    Generate a unique auto-subdomain using UUID.

    Format: org-{uuid[:8]} (e.g., org-a1b2c3d4)

    Returns:
        str: Auto-generated subdomain
    """
    short_uuid = str(uuid4()).replace('-', '')[:8]
    return f"org{short_uuid}"


class TenantCreate(BaseModel):
    """
    Request model for creating a new tenant.

    Supports two formats (backwards compatible):

    1. Original format:
       {"organization": "...", "subdomain": "...", "email": "..."}

    2. New signup format:
       {"school_name": "...", "first_name": "...", "last_name": "...", "email": "..."}

    When using the new format, organization is derived from school_name,
    and subdomain is auto-generated if not provided.
    """
    # Original fields (now optional, validated after model_validator)
    organization: Optional[str] = Field(None, min_length=2, max_length=100, description="Organization name")
    subdomain: Optional[str] = Field(None, min_length=3, max_length=30, description="Subdomain for the tenant")
    email: EmailStr = Field(..., description="Admin email address")
    is_trial: bool = Field(False, description="Whether this is a trial tenant")

    # New signup fields (optional, for new format)
    school_name: Optional[str] = Field(None, min_length=2, max_length=100, description="School name (alternative to organization)")
    first_name: Optional[str] = Field(None, min_length=1, max_length=50, description="Admin first name")
    last_name: Optional[str] = Field(None, min_length=1, max_length=50, description="Admin last name")

    @model_validator(mode='before')
    @classmethod
    def handle_signup_format(cls, data: dict) -> dict:
        """
        Process new signup format and derive organization/subdomain if needed.

        If school_name is provided:
        - Use it as organization (if organization not set)
        - Auto-generate subdomain as org-{uuid[:8]} (if subdomain not set)
        """
        if isinstance(data, dict):
            school_name = data.get('school_name')

            # If school_name is provided, use it for organization
            if school_name and not data.get('organization'):
                data['organization'] = school_name

            # Auto-generate subdomain if not provided
            if not data.get('subdomain'):
                data['subdomain'] = generate_auto_subdomain()

        return data

    @model_validator(mode='after')
    def validate_required_fields(self):
        """Ensure required fields are present after processing."""
        if not self.organization:
            raise ValueError("Either 'organization' or 'school_name' must be provided")
        # subdomain is now auto-generated if not provided
        return self

    @field_validator("organization")
    @classmethod
    def validate_organization(cls, v: Optional[str]) -> Optional[str]:
        """
        Validate organization name format.
        Only allows letters, numbers, spaces, hyphens, periods, and accented characters.
        This prevents shell injection when used in GKE commands.
        """
        if v is None:
            return v
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
    def validate_subdomain(cls, v: Optional[str]) -> Optional[str]:
        """Validate subdomain format and availability."""
        if v is None:
            return v
        subdomain = v.lower().strip()

        # Only alphanumeric characters allowed
        if not subdomain.isalnum():
            raise ValueError("Subdomain must be alphanumeric only")

        # Check against reserved subdomains
        if subdomain in RESERVED_SUBDOMAINS:
            raise ValueError(f"Subdomain '{subdomain}' is reserved and cannot be used")

        return subdomain

    @field_validator("school_name")
    @classmethod
    def validate_school_name(cls, v: Optional[str]) -> Optional[str]:
        """Validate school name format (same rules as organization)."""
        if v is None:
            return v
        v = v.strip()
        pattern = r'^[\w\s\-\.áéíóúñÁÉÍÓÚÑüÜ]+$'
        if not re.match(pattern, v):
            raise ValueError(
                "School name can only contain letters, numbers, spaces, "
                "hyphens, periods, and accented characters"
            )
        return v


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
    site_url: Optional[str] = Field(None, description="URL of the tenant site (available when active)")
    tenant_url: Optional[str] = Field(None, description="URL of the tenant site (alias for site_url)")


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


class TrialSignupRequest(BaseModel):
    """Request model for trial signup (demo tenant)."""
    school_name: str = Field(..., min_length=2, max_length=100, description="Name of the school")
    first_name: str = Field(..., min_length=1, max_length=50, description="User's first name")
    last_name: str = Field(..., min_length=1, max_length=50, description="User's last name")
    email: EmailStr = Field(..., description="User's email address")
    password: Optional[str] = Field(None, min_length=8, max_length=128, description="Password for local auth")
    google_token: Optional[str] = Field(None, description="Google OAuth token for SSO auth")

    @field_validator("school_name")
    @classmethod
    def validate_school_name(cls, v: str) -> str:
        """Validate school name format."""
        v = v.strip()
        pattern = r'^[\w\s\-\.áéíóúñÁÉÍÓÚÑüÜ]+$'
        if not re.match(pattern, v):
            raise ValueError(
                "School name can only contain letters, numbers, spaces, "
                "hyphens, periods, and accented characters"
            )
        return v

    @field_validator("first_name", "last_name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate name format."""
        v = v.strip()
        # Allow letters, spaces, hyphens, and accented characters
        pattern = r'^[a-zA-ZáéíóúñÁÉÍÓÚÑüÜ\s\-]+$'
        if not re.match(pattern, v):
            raise ValueError(
                "Name can only contain letters, spaces, hyphens, and accented characters"
            )
        return v

    @model_validator(mode='after')
    def validate_auth_method(self) -> 'TrialSignupRequest':
        """Ensure either password or google_token is provided, but not both."""
        if not self.password and not self.google_token:
            raise ValueError("Either password or google_token must be provided")
        if self.password and self.google_token:
            raise ValueError("Only one of password or google_token should be provided")
        return self


class TrialSignupResponse(BaseModel):
    """Response model for trial signup."""
    tenant_url: str = Field(..., description="URL of the demo tenant")
    token: str = Field(..., description="Session token for the user")
    message: str = Field(..., description="Success message")
    user_id: str = Field(..., description="ID of the created user")


class TenantInfo(BaseModel):
    """Tenant info for user lookup response."""
    name: str = Field(..., description="Organization name")
    slug: str = Field(..., description="Tenant subdomain/slug")
    url: str = Field(..., description="Full URL of the tenant site")


class UserLookupResponse(BaseModel):
    """Response model for user lookup by email."""
    tenants: list[TenantInfo] = Field(
        default_factory=list,
        description="List of tenants associated with the email"
    )


class PendingSignup(BaseModel):
    """
    Model for storing pending email/password signups awaiting validation.

    These signups require email validation before a tenant is created.
    """
    id: str = Field(..., description="Unique identifier for the pending signup")
    school_name: str = Field(..., description="Name of the school")
    email: str = Field(..., description="Email address for the signup")
    password_hash: str = Field(..., description="Bcrypt-hashed password")
    validation_token: str = Field(..., description="Token for email validation")
    expires_at: datetime = Field(..., description="Expiration timestamp for the signup")
    created_at: datetime = Field(..., description="Creation timestamp")


class SignupRequest(BaseModel):
    """
    Request model for the new signup flow.

    Supports two authentication methods:
    - Google OAuth (immediate tenant creation)
    - Email/password (requires email validation)
    """
    school_name: str = Field(..., min_length=2, max_length=100, description="Name of the school")
    email: Optional[EmailStr] = Field(None, description="Email address (required for email/password auth)")
    password: Optional[str] = Field(None, min_length=8, max_length=128, description="Password (required for email/password auth)")
    google_token: Optional[str] = Field(None, description="Google OAuth token (for immediate tenant creation)")

    @field_validator("school_name")
    @classmethod
    def validate_school_name(cls, v: str) -> str:
        """Validate school name format."""
        v = v.strip()
        pattern = r'^[\w\s\-\.áéíóúñÁÉÍÓÚÑüÜ]+$'
        if not re.match(pattern, v):
            raise ValueError(
                "School name can only contain letters, numbers, spaces, "
                "hyphens, periods, and accented characters"
            )
        return v

    @model_validator(mode='after')
    def validate_auth_method(self) -> 'SignupRequest':
        """
        Ensure valid authentication method is provided.

        Either:
        - google_token alone (Google OAuth)
        - email + password (email/password auth)
        """
        if self.google_token:
            # Google auth - no email/password required
            return self

        # Email/password auth requires both
        if not self.email or not self.password:
            raise ValueError(
                "Either 'google_token' must be provided, or both 'email' and 'password'"
            )

        return self


class SignupResponse(BaseModel):
    """
    Response model for signup endpoint.

    Can indicate either:
    - Immediate success (Google OAuth) with tenant_url
    - Pending validation (email/password) with pending=True
    """
    pending: bool = Field(False, description="True if email validation is required")
    message: str = Field(..., description="Status message")
    tenant_url: Optional[str] = Field(None, description="URL of the created tenant (for immediate signups)")
    tenant_id: Optional[str] = Field(None, description="ID of the created tenant (for immediate signups)")


class ValidateSignupResponse(BaseModel):
    """Response model for signup validation endpoint."""
    success: bool = Field(..., description="Whether validation was successful")
    tenant_url: str = Field(..., description="URL of the created tenant")
    tenant_id: str = Field(..., description="ID of the created tenant")
    message: str = Field(..., description="Status message")


class SubdomainChangeRequest(BaseModel):
    """Request model for changing a tenant's subdomain."""
    new_subdomain: str = Field(
        ...,
        min_length=3,
        max_length=30,
        description="New subdomain for the tenant (3-30 chars, alphanumeric + hyphens)"
    )

    @field_validator("new_subdomain")
    @classmethod
    def validate_new_subdomain(cls, v: str) -> str:
        """
        Validate new subdomain format.

        Rules:
        - Only alphanumeric characters and hyphens allowed
        - Must start and end with alphanumeric character
        - 3-30 characters (enforced by Field constraints)
        - Not in reserved list
        """
        subdomain = v.lower().strip()

        # Check for valid characters (alphanumeric and hyphens only)
        if not re.match(r'^[a-z0-9-]+$', subdomain):
            raise ValueError("Subdomain can only contain lowercase letters, numbers, and hyphens")

        # Must start with alphanumeric
        if not subdomain[0].isalnum():
            raise ValueError("Subdomain must start with a letter or number")

        # Must end with alphanumeric
        if not subdomain[-1].isalnum():
            raise ValueError("Subdomain must end with a letter or number")

        # Check against reserved subdomains
        if subdomain in RESERVED_SUBDOMAINS:
            raise ValueError(f"Subdomain '{subdomain}' is reserved and cannot be used")

        return subdomain


class SubdomainChangeResponse(BaseModel):
    """Response model for subdomain change operation."""
    success: bool = Field(..., description="Whether the subdomain change was successful")
    old_url: str = Field(..., description="Previous tenant URL")
    new_url: str = Field(..., description="New tenant URL after subdomain change")
    message: str = Field(..., description="Status message")

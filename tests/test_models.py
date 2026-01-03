"""
Tests for Pydantic models.
"""

import pytest
from pydantic import ValidationError
from src.models import (
    TenantCreate,
    TenantUpdate,
    TenantStatus,
    JobStatusWebhook,
    TenantListResponse,
)


class TestTenantCreate:
    """Tests for TenantCreate model."""

    def test_valid_tenant_create(self):
        """Test valid tenant creation data."""
        tenant = TenantCreate(
            organization="Test School",
            subdomain="testschool",
            email="admin@test.com"
        )
        assert tenant.organization == "Test School"
        assert tenant.subdomain == "testschool"
        assert tenant.email == "admin@test.com"

    def test_subdomain_lowercase(self):
        """Test that subdomain is converted to lowercase."""
        tenant = TenantCreate(
            organization="Test",
            subdomain="TestSchool",
            email="admin@test.com"
        )
        assert tenant.subdomain == "testschool"

    def test_subdomain_alphanumeric_only(self):
        """Test that subdomain rejects non-alphanumeric characters."""
        with pytest.raises(ValidationError) as exc_info:
            TenantCreate(
                organization="Test",
                subdomain="test-school",
                email="admin@test.com"
            )
        assert "alphanumeric" in str(exc_info.value).lower()

    def test_reserved_subdomain(self):
        """Test that reserved subdomains are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            TenantCreate(
                organization="Test",
                subdomain="admin",
                email="admin@test.com"
            )
        assert "reserved" in str(exc_info.value).lower()

    def test_organization_with_special_chars(self):
        """Test that organization rejects dangerous characters."""
        with pytest.raises(ValidationError) as exc_info:
            TenantCreate(
                organization="Test; rm -rf /",
                subdomain="testschool",
                email="admin@test.com"
            )
        assert "organization" in str(exc_info.value).lower()

    def test_organization_with_accents(self):
        """Test that organization allows accented characters."""
        tenant = TenantCreate(
            organization="Escuela Niños Felices",
            subdomain="escuela",
            email="admin@test.com"
        )
        assert tenant.organization == "Escuela Niños Felices"

    def test_invalid_email(self):
        """Test that invalid email is rejected."""
        with pytest.raises(ValidationError):
            TenantCreate(
                organization="Test",
                subdomain="test",
                email="not-an-email"
            )


class TestTenantUpdate:
    """Tests for TenantUpdate model."""

    def test_partial_update(self):
        """Test partial update with only organization."""
        update = TenantUpdate(organization="New Name")
        assert update.organization == "New Name"
        assert update.email is None

    def test_empty_update(self):
        """Test empty update is valid."""
        update = TenantUpdate()
        assert update.organization is None
        assert update.email is None


class TestJobStatusWebhook:
    """Tests for JobStatusWebhook model."""

    def test_valid_webhook(self):
        """Test valid webhook payload."""
        webhook = JobStatusWebhook(
            tenant_id="abc-123",
            status="active",
            site_url="https://test.kairos.app"
        )
        assert webhook.tenant_id == "abc-123"
        assert webhook.status == "active"

    def test_minimal_webhook(self):
        """Test webhook with only required fields."""
        webhook = JobStatusWebhook(
            tenant_id="abc-123",
            status="failed"
        )
        assert webhook.site_url is None
        assert webhook.error_message is None


class TestTenantListResponse:
    """Tests for TenantListResponse model."""

    def test_pagination_defaults(self):
        """Test pagination default values."""
        response = TenantListResponse(tenants=[], total=0)
        assert response.skip == 0
        assert response.limit == 100
        assert response.has_more is False

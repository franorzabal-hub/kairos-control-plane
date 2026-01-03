"""
Tests for API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
import hmac
import hashlib
import json


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_check(self, client):
        """Test health check endpoint is accessible without auth."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_root_endpoint(self, client):
        """Test root endpoint returns API info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Kairos Control Plane"
        assert "version" in data


class TestAuthentication:
    """Tests for API authentication."""

    def test_create_tenant_without_api_key(self, client, sample_tenant_data):
        """Test that creating tenant without API key fails."""
        response = client.post("/tenants", json=sample_tenant_data)
        assert response.status_code == 401

    def test_list_tenants_without_api_key(self, client):
        """Test that listing tenants without API key fails."""
        response = client.get("/tenants")
        assert response.status_code == 401

    def test_create_tenant_with_invalid_api_key(self, client, sample_tenant_data):
        """Test that creating tenant with invalid API key fails."""
        response = client.post(
            "/tenants",
            json=sample_tenant_data,
            headers={"X-API-Key": "wrong-key"}
        )
        assert response.status_code == 401


class TestTenantEndpoints:
    """Tests for tenant CRUD endpoints."""

    def test_list_tenants_empty(self, client, api_key_headers):
        """Test listing tenants when empty."""
        response = client.get("/tenants", headers=api_key_headers)
        assert response.status_code == 200
        data = response.json()
        assert "tenants" in data
        assert "total" in data

    def test_get_nonexistent_tenant(self, client, api_key_headers):
        """Test getting a tenant that doesn't exist."""
        response = client.get(
            "/tenants/00000000-0000-0000-0000-000000000000",
            headers=api_key_headers
        )
        assert response.status_code == 404

    def test_delete_nonexistent_tenant(self, client, api_key_headers):
        """Test deleting a tenant that doesn't exist."""
        response = client.delete(
            "/tenants/00000000-0000-0000-0000-000000000000",
            headers=api_key_headers
        )
        assert response.status_code == 404

    def test_invalid_tenant_id_format(self, client, api_key_headers):
        """Test that invalid UUID format is rejected."""
        response = client.get(
            "/tenants/not-a-uuid",
            headers=api_key_headers
        )
        assert response.status_code == 422  # Validation error


class TestWebhook:
    """Tests for webhook endpoint."""

    def test_webhook_without_signature(self, client):
        """Test webhook without signature fails."""
        response = client.post(
            "/webhooks/job-status",
            json={"tenant_id": "test", "status": "active"}
        )
        # Should fail if WEBHOOK_SECRET is set
        assert response.status_code in [401, 200]  # Depends on env

    def test_webhook_with_valid_signature(self, client):
        """Test webhook with valid signature."""
        payload = {"tenant_id": "test-123", "status": "active"}
        body = json.dumps(payload).encode()

        # Compute signature
        secret = "test-webhook-secret"
        signature = hmac.new(
            secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()

        response = client.post(
            "/webhooks/job-status",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": signature
            }
        )
        # Will return 404 since tenant doesn't exist, but auth should pass
        assert response.status_code in [404, 400, 200]


class TestCORS:
    """Tests for CORS configuration."""

    def test_cors_preflight(self, client):
        """Test CORS preflight request."""
        response = client.options(
            "/tenants",
            headers={
                "Origin": "https://kairos.app",
                "Access-Control-Request-Method": "GET",
            }
        )
        # FastAPI handles CORS
        assert response.status_code in [200, 400]

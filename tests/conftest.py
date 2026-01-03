"""
Pytest configuration and fixtures for Kairos Control Plane tests.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock

# Set environment variables before importing app
import os
os.environ["API_KEY"] = "test-api-key"
os.environ["WEBHOOK_SECRET"] = "test-webhook-secret"
os.environ["USE_IN_CLUSTER"] = "false"
os.environ["ENVIRONMENT"] = "development"

from src.main import app, gke_service, tenant_service
from src.services.gke_service import GKEService
from src.services.tenant_service import TenantService


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
def api_key_headers():
    """Headers with valid API key."""
    return {"X-API-Key": "test-api-key"}


@pytest.fixture
def mock_gke_service():
    """Create a mock GKE service."""
    mock = MagicMock(spec=GKEService)
    mock.is_connected = True
    mock.create_tenant_secret = AsyncMock(return_value={"success": True, "secret_name": "test-secret"})
    mock.create_site_provisioning_job = AsyncMock(return_value={"success": True, "job_name": "test-job"})
    mock.get_job_status = AsyncMock(return_value={"success": True, "status": "completed"})
    mock.delete_tenant_resources = AsyncMock(return_value={"success": True})
    mock.check_health = AsyncMock(return_value=True)
    return mock


@pytest.fixture
def sample_tenant_data():
    """Sample tenant creation data."""
    return {
        "organization": "Test School",
        "subdomain": "testschool",
        "email": "admin@testschool.com"
    }

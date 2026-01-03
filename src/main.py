"""
Kairos Control Plane - FastAPI Application

Main API for managing Frappe SaaS tenant provisioning on GKE.
"""

import contextvars
import hashlib
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from .models import (
    CreateTenantResponse,
    ErrorResponse,
    HealthResponse,
    TenantCreate,
    TenantListResponse,
    TenantResponse,
    TenantStatus,
    TenantStatusResponse,
    TenantUpdate,
)
from .services import GKEService, TenantService


# Structured JSON logging
class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add request_id if available
        try:
            request_id = request_id_var.get()
            if request_id:
                log_data["request_id"] = request_id
        except LookupError:
            pass

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


# Configure logging with JSON formatter
json_handler = logging.StreamHandler()
json_handler.setFormatter(JSONFormatter())

logging.basicConfig(
    level=logging.INFO,
    handlers=[json_handler],
)
logger = logging.getLogger(__name__)

# Correlation ID context variable
request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "request_id", default=None
)

# Configuration from environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "production")

# CORS configuration
DEFAULT_ALLOWED_ORIGINS = [
    "https://kairos.app",
    "https://admin.kairos.app",
    "https://landing.kairos.app",
]

# Add localhost for development
if ENVIRONMENT == "development":
    DEFAULT_ALLOWED_ORIGINS.append("http://localhost:3000")

CONFIG = {
    "base_domain": os.environ.get("BASE_DOMAIN", "kairos.app"),
    "gke_namespace": os.environ.get("GKE_NAMESPACE", "frappe"),
    "frappe_image": os.environ.get("FRAPPE_IMAGE", "frappe/frappe-worker:v15"),
    "use_in_cluster": os.environ.get("USE_IN_CLUSTER", "true").lower() == "true",
    "allowed_origins": os.environ.get("ALLOWED_ORIGINS", ",".join(DEFAULT_ALLOWED_ORIGINS)).split(","),
}

# API Key configuration
API_KEY = os.environ.get("API_KEY")
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Webhook secret for signature verification
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Global services
gke_service: Optional[GKEService] = None
tenant_service: Optional[TenantService] = None


# Security dependencies
async def verify_api_key(api_key: Optional[str] = Security(API_KEY_HEADER)) -> str:
    """
    Verify the API key from the X-API-Key header.

    Raises HTTPException 401 if the key is missing or invalid.
    """
    if not API_KEY:
        # If no API_KEY is configured, skip authentication (development mode warning)
        logger.warning("API_KEY not configured - authentication is disabled")
        return "no-auth"

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not hmac.compare_digest(api_key, API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key


async def verify_webhook_signature(
    request: Request,
    x_webhook_signature: Optional[str] = Header(None, alias="X-Webhook-Signature"),
) -> bool:
    """
    Verify webhook signature using HMAC-SHA256.

    The signature should be computed as: HMAC-SHA256(WEBHOOK_SECRET, request_body)
    """
    if not WEBHOOK_SECRET:
        logger.warning("WEBHOOK_SECRET not configured - webhook signature verification is disabled")
        return True

    if not x_webhook_signature:
        raise HTTPException(
            status_code=401,
            detail="Missing webhook signature",
        )

    # Get the raw body
    body = await request.body()

    # Compute expected signature
    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    # Compare signatures using constant-time comparison
    if not hmac.compare_digest(x_webhook_signature, expected_signature):
        raise HTTPException(
            status_code=401,
            detail="Invalid webhook signature",
        )

    return True


# Correlation ID middleware
class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Middleware to handle correlation IDs for request tracing."""

    async def dispatch(self, request: Request, call_next):
        # Get or generate request ID
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            import uuid
            request_id = str(uuid.uuid4())

        # Set in context var
        request_id_var.set(request_id)

        # Process request
        response = await call_next(request)

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler for startup/shutdown.
    """
    global gke_service, tenant_service

    # Startup
    logger.info("Starting Kairos Control Plane...")

    # Initialize GKE service
    gke_service = GKEService(
        namespace=CONFIG["gke_namespace"],
        frappe_image=CONFIG["frappe_image"],
        use_in_cluster=CONFIG["use_in_cluster"],
    )

    # Initialize tenant service
    tenant_service = TenantService(
        gke_service=gke_service,
        base_domain=CONFIG["base_domain"],
    )

    logger.info(f"Control Plane initialized - GKE connected: {gke_service.is_connected}")

    yield

    # Shutdown
    logger.info("Shutting down Kairos Control Plane...")


# Create FastAPI app
app = FastAPI(
    title="Kairos Control Plane",
    description="API for managing Frappe SaaS tenant provisioning on GKE",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add rate limiter to app state
app.state.limiter = limiter

# Add rate limit exceeded exception handler
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add Correlation ID middleware
app.add_middleware(CorrelationIDMiddleware)

# Add CORS middleware with restricted settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=CONFIG["allowed_origins"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
)


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "error": exc.detail},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "Internal server error"},
    )


# Health check endpoint (public - no auth required)
@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """
    Health check endpoint for Cloud Run and load balancers.

    Returns the status of the API and its connections.
    """
    return HealthResponse(
        status="healthy",
        database=True,  # In-memory for now
        gke_connection=gke_service.is_connected if gke_service else False,
        version="0.1.0",
    )


@app.get("/", tags=["Health"])
async def root():
    """Root endpoint with API info."""
    return {
        "name": "Kairos Control Plane",
        "version": "0.1.0",
        "docs": "/docs",
    }


# Tenant endpoints (protected with API key authentication)
@app.post(
    "/tenants",
    response_model=CreateTenantResponse,
    status_code=201,
    tags=["Tenants"],
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    dependencies=[Depends(verify_api_key)],
)
@limiter.limit("10/minute")
async def create_tenant(request: Request, data: TenantCreate):
    """
    Create a new tenant.

    This endpoint starts the tenant provisioning process asynchronously.
    Poll GET /tenants/{id}/status to check provisioning progress.

    - **organization**: Name of the organization
    - **subdomain**: Unique subdomain for the tenant (alphanumeric only)
    - **email**: Admin email address

    Requires X-API-Key header for authentication.
    Rate limited to 10 requests per minute.
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    result = await tenant_service.create_tenant(data)

    if not result["success"]:
        if "already taken" in result["error"]:
            raise HTTPException(status_code=409, detail=result["error"])
        raise HTTPException(status_code=400, detail=result["error"])

    return CreateTenantResponse(
        success=True,
        id=result["id"],
        subdomain=result["subdomain"],
        status=result["status"],
        message=result["message"],
    )


@app.get(
    "/tenants",
    response_model=TenantListResponse,
    tags=["Tenants"],
    responses={
        401: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    dependencies=[Depends(verify_api_key)],
)
@limiter.limit("100/minute")
async def list_tenants(
    request: Request,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
):
    """
    List all tenants with pagination.

    Returns a list of all tenants sorted by creation date (newest first).

    Requires X-API-Key header for authentication.
    Rate limited to 100 requests per minute.
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    tenants, total = await tenant_service.list_tenants(skip=skip, limit=limit)

    return TenantListResponse(
        tenants=[
            TenantResponse(
                id=t["id"],
                organization=t["organization"],
                subdomain=t["subdomain"],
                email=t["email"],
                status=t["status"],
                site_url=t["site_url"],
                error_message=t["error_message"],
                created_at=t["created_at"],
                updated_at=t["updated_at"],
            )
            for t in tenants
        ],
        total=total,
    )


@app.get(
    "/tenants/{tenant_id}",
    response_model=TenantResponse,
    tags=["Tenants"],
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    dependencies=[Depends(verify_api_key)],
)
@limiter.limit("100/minute")
async def get_tenant(request: Request, tenant_id: UUID):
    """
    Get a specific tenant by ID.

    Returns full tenant details including status and site URL.

    Requires X-API-Key header for authentication.
    Rate limited to 100 requests per minute.
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    tenant = await tenant_service.get_tenant(str(tenant_id))

    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    return TenantResponse(
        id=tenant["id"],
        organization=tenant["organization"],
        subdomain=tenant["subdomain"],
        email=tenant["email"],
        status=tenant["status"],
        site_url=tenant["site_url"],
        error_message=tenant["error_message"],
        created_at=tenant["created_at"],
        updated_at=tenant["updated_at"],
    )


@app.patch(
    "/tenants/{tenant_id}",
    response_model=TenantResponse,
    tags=["Tenants"],
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    dependencies=[Depends(verify_api_key)],
)
@limiter.limit("10/minute")
async def update_tenant(request: Request, tenant_id: UUID, data: TenantUpdate):
    """
    Update a tenant's organization and/or email.

    Only the provided fields will be updated.

    - **organization**: New organization name (optional)
    - **email**: New admin email address (optional)

    Requires X-API-Key header for authentication.
    Rate limited to 10 requests per minute.
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Get existing tenant
    tenant = await tenant_service.get_tenant(str(tenant_id))

    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Update only provided fields
    update_data = data.model_dump(exclude_unset=True)

    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    updated_tenant = await tenant_service.update_tenant(str(tenant_id), **update_data)

    if not updated_tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    return TenantResponse(
        id=updated_tenant["id"],
        organization=updated_tenant["organization"],
        subdomain=updated_tenant["subdomain"],
        email=updated_tenant["email"],
        status=updated_tenant["status"],
        site_url=updated_tenant["site_url"],
        error_message=updated_tenant["error_message"],
        created_at=updated_tenant["created_at"],
        updated_at=updated_tenant["updated_at"],
    )


@app.get(
    "/tenants/{tenant_id}/status",
    response_model=TenantStatusResponse,
    tags=["Tenants"],
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    dependencies=[Depends(verify_api_key)],
)
@limiter.limit("100/minute")
async def get_tenant_status(request: Request, tenant_id: UUID):
    """
    Get the current status of a tenant.

    Use this endpoint to poll for provisioning status.
    Possible status values:
    - **queued**: Waiting to be processed
    - **provisioning**: Site is being created
    - **active**: Site is ready and accessible
    - **failed**: Provisioning failed (check error_message)
    - **suspended**: Tenant is suspended
    - **deleting**: Tenant is being deleted

    Requires X-API-Key header for authentication.
    Rate limited to 100 requests per minute.
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    status = await tenant_service.get_tenant_status(str(tenant_id))

    if not status:
        raise HTTPException(status_code=404, detail="Tenant not found")

    return TenantStatusResponse(
        id=status["id"],
        subdomain=status["subdomain"],
        status=status["status"],
        site_url=status["site_url"],
        error_message=status["error_message"],
    )


@app.delete(
    "/tenants/{tenant_id}",
    tags=["Tenants"],
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    dependencies=[Depends(verify_api_key)],
)
@limiter.limit("5/minute")
async def delete_tenant(request: Request, tenant_id: UUID):
    """
    Delete a tenant and all associated resources.

    This will:
    - Remove the Frappe site from GKE
    - Delete associated Kubernetes resources
    - Remove the tenant record

    Requires X-API-Key header for authentication.
    Rate limited to 5 requests per minute.
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    result = await tenant_service.delete_tenant(str(tenant_id))

    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["error"])

    return {"success": True, "message": "Tenant deleted successfully"}


# Webhook endpoint for GKE job status updates (protected with signature verification)
@app.post(
    "/webhooks/job-status",
    tags=["Webhooks"],
    responses={
        401: {"model": ErrorResponse},
    },
    dependencies=[Depends(verify_webhook_signature)],
)
async def job_status_webhook(request: Request):
    """
    Webhook endpoint for receiving job status updates from GKE.

    This is called by Kubernetes when provisioning jobs complete or fail.

    Requires X-Webhook-Signature header with HMAC-SHA256 signature of the request body.
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    data = await request.json()
    logger.info(f"Received job status webhook: {data}")

    tenant_id = data.get("tenant_id")
    status = data.get("status")
    site_url = data.get("site_url")
    error_message = data.get("error_message")

    if not tenant_id or not status:
        raise HTTPException(status_code=400, detail="Missing required fields")

    try:
        new_status = TenantStatus(status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    updated = await tenant_service.update_tenant_status(
        tenant_id=tenant_id,
        status=new_status,
        site_url=site_url,
        error_message=error_message,
    )

    if not updated:
        raise HTTPException(status_code=404, detail="Tenant not found")

    return {"success": True, "message": "Status updated"}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)

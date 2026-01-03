"""
Kairos Control Plane - FastAPI Application

Main API for managing Frappe SaaS tenant provisioning on GKE.
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .models import (
    CreateTenantResponse,
    ErrorResponse,
    HealthResponse,
    TenantCreate,
    TenantListResponse,
    TenantResponse,
    TenantStatus,
    TenantStatusResponse,
)
from .services import GKEService, TenantService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Configuration from environment
CONFIG = {
    "base_domain": os.environ.get("BASE_DOMAIN", "kairos.app"),
    "gke_namespace": os.environ.get("GKE_NAMESPACE", "frappe"),
    "frappe_image": os.environ.get("FRAPPE_IMAGE", "frappe/frappe-worker:v15"),
    "use_in_cluster": os.environ.get("USE_IN_CLUSTER", "true").lower() == "true",
    "allowed_origins": os.environ.get("ALLOWED_ORIGINS", "*").split(","),
}

# Global services
gke_service: Optional[GKEService] = None
tenant_service: Optional[TenantService] = None


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

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CONFIG["allowed_origins"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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


# Health check endpoint
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


# Tenant endpoints
@app.post(
    "/tenants",
    response_model=CreateTenantResponse,
    status_code=201,
    tags=["Tenants"],
    responses={
        400: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
    },
)
async def create_tenant(data: TenantCreate):
    """
    Create a new tenant.

    This endpoint starts the tenant provisioning process asynchronously.
    Poll GET /tenants/{id}/status to check provisioning progress.

    - **organization**: Name of the organization
    - **subdomain**: Unique subdomain for the tenant (alphanumeric only)
    - **email**: Admin email address
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
)
async def list_tenants(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
):
    """
    List all tenants with pagination.

    Returns a list of all tenants sorted by creation date (newest first).
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
    responses={404: {"model": ErrorResponse}},
)
async def get_tenant(tenant_id: str):
    """
    Get a specific tenant by ID.

    Returns full tenant details including status and site URL.
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    tenant = await tenant_service.get_tenant(tenant_id)

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


@app.get(
    "/tenants/{tenant_id}/status",
    response_model=TenantStatusResponse,
    tags=["Tenants"],
    responses={404: {"model": ErrorResponse}},
)
async def get_tenant_status(tenant_id: str):
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
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    status = await tenant_service.get_tenant_status(tenant_id)

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
    responses={404: {"model": ErrorResponse}},
)
async def delete_tenant(tenant_id: str):
    """
    Delete a tenant and all associated resources.

    This will:
    - Remove the Frappe site from GKE
    - Delete associated Kubernetes resources
    - Remove the tenant record
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    result = await tenant_service.delete_tenant(tenant_id)

    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["error"])

    return {"success": True, "message": "Tenant deleted successfully"}


# Webhook endpoint for GKE job status updates
@app.post("/webhooks/job-status", tags=["Webhooks"])
async def job_status_webhook(request: Request):
    """
    Webhook endpoint for receiving job status updates from GKE.

    This is called by Kubernetes when provisioning jobs complete or fail.
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

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
from urllib.parse import urlencode
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from pydantic import EmailStr, ValidationError, validate_email

from .models import (
    CreateTenantResponse,
    ErrorResponse,
    HealthResponse,
    RESERVED_SUBDOMAINS,
    SignupRequest,
    SignupResponse,
    SubdomainChangeRequest,
    SubdomainChangeResponse,
    TenantCreate,
    TenantInfo,
    TenantListResponse,
    TenantResponse,
    TenantStatus,
    TenantStatusResponse,
    TenantUpdate,
    TrialSignupRequest,
    TrialSignupResponse,
    UserLookupResponse,
    ValidateSignupResponse,
    generate_auto_subdomain,
)
from .services import GKEService, TenantService, DemoService, PendingSignupsService, EmailService

# Demo tenant configuration
DEMO_TENANT_URL = os.environ.get("DEMO_TENANT_URL", "https://demo.1kairos.com")

# Landing page URL for redirects
LANDING_PAGE_URL = os.environ.get("LANDING_PAGE_URL", "https://1kairos.com")


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
    "https://1kairos.com",
    "https://admin.1kairos.com",
    "https://landing.1kairos.com",
]

# Add localhost for development
if ENVIRONMENT == "development":
    DEFAULT_ALLOWED_ORIGINS.extend([
        "http://localhost:3000",
        "http://localhost:4321",  # Astro landing page
        "http://localhost:8080",
    ])

CONFIG = {
    "base_domain": os.environ.get("BASE_DOMAIN", "1kairos.com"),
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
demo_service: Optional[DemoService] = None
pending_signups_service: Optional[PendingSignupsService] = None
email_service: Optional[EmailService] = None


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
    global gke_service, tenant_service, demo_service, pending_signups_service, email_service

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

    # Initialize demo service for trial signups
    demo_service = DemoService(demo_tenant_url=DEMO_TENANT_URL)

    # Initialize pending signups service
    pending_signups_service = PendingSignupsService()

    # Initialize email service
    email_service = EmailService(base_url=f"https://{CONFIG['base_domain']}")

    logger.info(f"Control Plane initialized - GKE connected: {gke_service.is_connected}")

    # TODO: Add a scheduled task to clean up expired pending signups periodically.
    # This could be done using:
    # - APScheduler: https://apscheduler.readthedocs.io/
    # - Cloud Scheduler (GCP) to call a cleanup endpoint
    # - A background asyncio task that runs every hour
    # Example:
    #   async def cleanup_task():
    #       while True:
    #           await asyncio.sleep(3600)  # Run every hour
    #           await pending_signups_service.cleanup_expired()

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
# In development, allow all origins for easier testing
cors_origins = ["*"] if ENVIRONMENT == "development" else CONFIG["allowed_origins"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False if ENVIRONMENT == "development" else True,  # credentials can't be used with "*"
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


# User lookup endpoint (public - no auth required)
@app.get(
    "/api/user/lookup",
    response_model=UserLookupResponse,
    tags=["Users"],
    responses={
        400: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
@limiter.limit("20/minute")
async def user_lookup(
    request: Request,
    email: str = Query(..., description="Email address to look up"),
):
    """
    Look up tenants associated with an email address.

    This is a public endpoint (no authentication required) that allows users
    to find which tenants they belong to based on their email address.

    - **email**: Email address to search for

    Returns a list of tenants associated with the email.
    Rate limited to 20 requests per minute.
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Validate email format
    try:
        validate_email(email)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid email format")

    # Search for tenants by email
    tenants = await tenant_service.get_tenants_by_email(email)

    # Build response with tenant info
    tenant_infos = []
    for tenant in tenants:
        # Build the URL - use site_url if available, otherwise construct from subdomain
        url = tenant.get("site_url")
        if not url:
            url = f"https://{tenant['subdomain']}.{CONFIG['base_domain']}"

        tenant_infos.append(
            TenantInfo(
                name=tenant["organization"],
                slug=tenant["subdomain"],
                url=url,
            )
        )

    return UserLookupResponse(tenants=tenant_infos)


# Trial signup endpoint (public - no auth required)
@app.post(
    "/api/signup/trial",
    response_model=TrialSignupResponse,
    status_code=201,
    tags=["Users"],
    responses={
        400: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
@limiter.limit("10/minute")
async def trial_signup(request: Request, data: TrialSignupRequest):
    """
    Sign up for a trial account in the demo tenant.

    This endpoint creates a new user in the shared demo tenant (demo.1kairos.com)
    instead of provisioning a new tenant. All trial users share the same demo
    environment.

    Authentication can be via:
    - **password**: Local password authentication (min 8 characters)
    - **google_token**: Google OAuth token for SSO authentication

    Exactly one of password or google_token must be provided.

    Returns the demo tenant URL and a session token for immediate login.
    Rate limited to 10 requests per minute.
    """
    if not demo_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Check if user already exists
    user_exists = await demo_service.check_user_exists(data.email)
    if user_exists:
        raise HTTPException(
            status_code=409,
            detail="A user with this email already exists. Please login instead."
        )

    # Create trial user in demo tenant
    result = await demo_service.create_trial_user(data)

    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to create trial user"))

    return TrialSignupResponse(
        tenant_url=result["tenant_url"],
        token=result["token"],
        message=result["message"],
        user_id=result["user_id"],
    )


# New signup flow endpoints (public - no auth required)
@app.post(
    "/api/tenants/signup",
    response_model=SignupResponse,
    status_code=201,
    tags=["Signup"],
    responses={
        400: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
@limiter.limit("10/minute")
async def tenant_signup(request: Request, data: SignupRequest):
    """
    Sign up to create a new tenant.

    This endpoint supports two authentication methods:

    1. **Google OAuth** (google_token provided):
       - Validates the Google token
       - Creates tenant immediately with auto-generated subdomain (org-{uuid[:8]})
       - Returns tenant_url for immediate access

    2. **Email/Password** (email + password provided):
       - Creates a pending signup
       - Returns pending=True with instructions to validate email
       - Tenant is created after email validation via /api/tenants/validate/{token}

    Rate limited to 10 requests per minute.
    """
    if not tenant_service or not pending_signups_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Handle Google OAuth signup (immediate tenant creation)
    if data.google_token:
        # TODO: Validate Google token and extract email
        # For now, we'll use a placeholder email from the token validation
        if demo_service:
            google_info = await demo_service.verify_google_token(data.google_token)
            if not google_info:
                raise HTTPException(status_code=400, detail="Invalid Google token")
            email = google_info.get("email", "user@example.com")
        else:
            email = "user@example.com"

        # Create tenant with auto-generated subdomain
        tenant_data = TenantCreate(
            school_name=data.school_name,
            email=email,
            is_trial=True,
        )

        result = await tenant_service.create_tenant(tenant_data)

        if not result["success"]:
            if "already taken" in result.get("error", ""):
                raise HTTPException(status_code=409, detail=result["error"])
            raise HTTPException(status_code=400, detail=result.get("error", "Failed to create tenant"))

        tenant_url = f"https://{result['subdomain']}.{CONFIG['base_domain']}"

        return SignupResponse(
            pending=False,
            message="Tenant created successfully. You can now access your site.",
            tenant_url=tenant_url,
            tenant_id=result["id"],
        )

    # Handle email/password signup (pending validation)
    if data.email and data.password:
        # Check if email already has an active tenant
        existing_tenants = await tenant_service.get_tenants_by_email(data.email)
        if existing_tenants:
            raise HTTPException(
                status_code=409,
                detail="A tenant with this email already exists. Please login instead."
            )

        # Create pending signup
        result = await pending_signups_service.create_pending_signup(
            school_name=data.school_name,
            email=data.email,
            password=data.password,
        )

        if not result["success"]:
            raise HTTPException(status_code=400, detail=result.get("error", "Failed to create signup"))

        # Send validation email
        if email_service:
            email_result = await email_service.send_validation_email(
                to_email=data.email,
                validation_token=result["validation_token"],
                school_name=data.school_name,
            )
            if not email_result["success"]:
                logger.warning(f"Failed to send validation email: {email_result.get('error')}")
        else:
            logger.info(f"Pending signup created. Validation token: {result['validation_token']}")

        return SignupResponse(
            pending=True,
            message="Please check your email to validate your account. The validation link will expire in 48 hours.",
        )

    # Should not reach here due to model validation, but just in case
    raise HTTPException(
        status_code=400,
        detail="Either google_token or email+password must be provided"
    )


@app.get(
    "/api/tenants/validate/{token}",
    tags=["Signup"],
    responses={
        302: {"description": "Redirect to tenant URL on success or landing page with error on failure"},
        429: {"model": ErrorResponse},
    },
)
@limiter.limit("20/minute")
async def validate_signup(request: Request, token: str):
    """
    Validate a pending signup and create the tenant.

    This endpoint is called when a user clicks the validation link in their email.

    - **token**: The validation token from the email

    On success:
    - Creates the tenant with auto-generated subdomain (org-{uuid[:8]})
    - Deletes the pending signup
    - Redirects (302) to the tenant URL

    On failure (token invalid/expired or tenant creation failed):
    - Redirects (302) to the landing page with error message in query param

    Rate limited to 20 requests per minute.
    """
    if not tenant_service or not pending_signups_service:
        error_params = urlencode({"error": "Service temporarily unavailable. Please try again later."})
        return RedirectResponse(
            url=f"{LANDING_PAGE_URL}/signup?{error_params}",
            status_code=302,
        )

    # Find pending signup by token
    pending_signup = await pending_signups_service.get_by_token(token)

    if not pending_signup:
        error_params = urlencode({"error": "Invalid or expired validation token. Please sign up again."})
        return RedirectResponse(
            url=f"{LANDING_PAGE_URL}/signup?{error_params}",
            status_code=302,
        )

    # Create tenant with auto-generated subdomain
    tenant_data = TenantCreate(
        school_name=pending_signup["school_name"],
        email=pending_signup["email"],
        is_trial=True,
    )

    result = await tenant_service.create_tenant(tenant_data)

    if not result["success"]:
        error_message = result.get("error", "Failed to create tenant")
        if "already taken" in error_message:
            # Clean up the pending signup since tenant exists
            await pending_signups_service.delete_by_id(pending_signup["id"])
        error_params = urlencode({"error": error_message})
        return RedirectResponse(
            url=f"{LANDING_PAGE_URL}/signup?{error_params}",
            status_code=302,
        )

    # Delete pending signup
    await pending_signups_service.delete_by_id(pending_signup["id"])

    tenant_url = f"https://{result['subdomain']}.{CONFIG['base_domain']}"

    logger.info(f"Tenant validated and created: {result['id']} ({result['subdomain']})")

    # Redirect to the newly created tenant
    return RedirectResponse(url=tenant_url, status_code=302)


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

    Supports two formats (backwards compatible):

    1. Original format:
       - **organization**: Name of the organization
       - **subdomain**: Unique subdomain for the tenant (alphanumeric only)
       - **email**: Admin email address

    2. New signup format:
       - **school_name**: Name of the school (used as organization)
       - **first_name**: Admin first name
       - **last_name**: Admin last name
       - **email**: Admin email address
       - subdomain is auto-generated from school_name

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

    # Build tenant URL
    tenant_url = f"https://{result['subdomain']}.{CONFIG['base_domain']}"

    return CreateTenantResponse(
        success=True,
        id=result["id"],
        subdomain=result["subdomain"],
        status=result["status"],
        message=result["message"],
        site_url=result.get("site_url"),
        tenant_url=tenant_url,
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


@app.put(
    "/api/tenants/{tenant_id}/subdomain",
    response_model=SubdomainChangeResponse,
    tags=["Tenants"],
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    dependencies=[Depends(verify_api_key)],
)
@limiter.limit("5/minute")
async def change_subdomain(
    request: Request,
    tenant_id: UUID,
    data: SubdomainChangeRequest,
):
    """
    Change a tenant's subdomain.

    This endpoint allows changing the subdomain for an existing tenant.

    Validation rules:
    - Only alphanumeric characters and hyphens allowed
    - Must start and end with alphanumeric character
    - 3-30 characters
    - Cannot be a reserved subdomain (www, api, app, admin, etc.)
    - Cannot be already in use by another tenant

    Requires X-API-Key header for authentication.
    Rate limited to 5 requests per minute.
    """
    if not tenant_service:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Get existing tenant
    tenant = await tenant_service.get_tenant(str(tenant_id))

    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    new_subdomain = data.new_subdomain

    # Check if subdomain is the same as current
    if new_subdomain == tenant["subdomain"]:
        raise HTTPException(
            status_code=400,
            detail="New subdomain is the same as the current subdomain"
        )

    # Check if subdomain is already taken by another tenant
    existing_tenant = await tenant_service.get_tenant_by_subdomain(new_subdomain)
    if existing_tenant and existing_tenant["id"] != str(tenant_id):
        raise HTTPException(
            status_code=409,
            detail=f"Subdomain '{new_subdomain}' is already in use"
        )

    # Store old URL for response
    old_url = f"https://{tenant['subdomain']}.{CONFIG['base_domain']}"

    # Update the tenant's subdomain
    updated_tenant = await tenant_service.update_tenant_subdomain(
        str(tenant_id),
        new_subdomain
    )

    if not updated_tenant:
        raise HTTPException(
            status_code=500,
            detail="Failed to update subdomain"
        )

    # Build new URL
    new_url = f"https://{new_subdomain}.{CONFIG['base_domain']}"

    return SubdomainChangeResponse(
        success=True,
        old_url=old_url,
        new_url=new_url,
        message=f"Subdomain successfully changed from '{tenant['subdomain']}' to '{new_subdomain}'"
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)

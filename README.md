# Kairos Control Plane

Control Plane API for Kairos SaaS - Manages tenant provisioning on GKE.

## Overview

This is an independent FastAPI service that manages Frappe SaaS tenant lifecycle:

- **Create tenants**: Provisions new Frappe sites on GKE
- **List tenants**: View all registered tenants
- **Check status**: Poll tenant provisioning status
- **Delete tenants**: Remove tenants and associated resources

## Architecture

```
                                    +------------------+
                                    |   Cloud Run      |
                                    |   Control Plane  |
                                    +--------+---------+
                                             |
                    +------------------------+------------------------+
                    |                        |                        |
            +-------v-------+       +--------v--------+       +-------v-------+
            |   Firestore   |       |      GKE        |       |   Cloud SQL   |
            |   (Tenants)   |       | (Frappe Sites)  |       |   (MariaDB)   |
            +---------------+       +-----------------+       +---------------+
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/tenants` | Create a new tenant |
| GET | `/tenants` | List all tenants |
| GET | `/tenants/{id}` | Get tenant details |
| GET | `/tenants/{id}/status` | Get tenant status |
| DELETE | `/tenants/{id}` | Delete a tenant |

## Quick Start

### Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export BASE_DOMAIN=localhost
export USE_IN_CLUSTER=false

# Run the server
uvicorn src.main:app --reload --port 8080
```

### Docker

```bash
# Build
docker build -t kairos-control-plane .

# Run
docker run -p 8080:8080 \
  -e BASE_DOMAIN=kairos.app \
  -e USE_IN_CLUSTER=false \
  kairos-control-plane
```

### Deploy to Cloud Run

```bash
# Using Cloud Build
gcloud builds submit --config cloudbuild.yaml

# Or manually
gcloud run deploy kairos-control-plane \
  --source . \
  --region us-central1 \
  --allow-unauthenticated
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `BASE_DOMAIN` | Base domain for tenant sites | `kairos.app` |
| `GKE_NAMESPACE` | Kubernetes namespace for Frappe | `frappe` |
| `FRAPPE_IMAGE` | Frappe worker Docker image | `frappe/frappe-worker:v15` |
| `USE_IN_CLUSTER` | Use in-cluster Kubernetes config | `true` |
| `ALLOWED_ORIGINS` | CORS allowed origins | `*` |
| `PORT` | Server port | `8080` |

## API Documentation

Once running, access interactive API docs at:
- Swagger UI: http://localhost:8080/docs
- ReDoc: http://localhost:8080/redoc

## Tenant Lifecycle

```
1. POST /tenants -> status: "queued"
2. GKE Job starts -> status: "provisioning"
3. Site created -> status: "active", site_url available
   OR
3. Error occurs -> status: "failed", error_message available
```

## Development

```bash
# Run tests
pytest

# Format code
black src/
isort src/

# Type checking
mypy src/
```

## License

MIT

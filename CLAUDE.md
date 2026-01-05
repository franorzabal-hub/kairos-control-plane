# Control Plane Kairos

## Qué es este repo

API para gestión de tenants (colegios). Orquesta la creación/eliminación de instancias Frappe en GKE.

## Stack

- **Framework**: FastAPI 0.109
- **Runtime**: Python 3.11
- **Cloud**: Google Cloud (GKE, Cloud Run, Firestore, Secret Manager)
- **Deploy**: Cloud Run

## Funcionalidades

- Crear nuevos tenants (colegios)
- Provisioning de sites Frappe en GKE via Kubernetes Jobs
- Gestión de trials (14 días)
- Validación de emails para signup
- Lookup de tenants por email
- Webhooks de estado de jobs K8s

## Estructura

```
control-plane/
├── src/
│   ├── main.py              # FastAPI app, endpoints
│   ├── models.py            # Pydantic models
│   └── services/
│       ├── tenant_service.py      # CRUD tenants
│       ├── gke_service.py         # Kubernetes orchestration
│       ├── demo_service.py        # Trial users
│       ├── email_service.py       # Emails validación
│       ├── pending_signups_service.py
│       ├── firestore_service.py   # Persistencia
│       └── secret_manager_service.py
├── tests/
├── Dockerfile
├── cloudbuild.yaml
└── requirements.txt
```

## Endpoints Principales

```bash
# Públicos (sin auth)
GET  /health                      # Health check
GET  /api/user/lookup?email=...   # Buscar tenants por email
POST /api/signup/trial            # Trial en tenant demo
POST /api/tenants/signup          # Crear nuevo tenant
GET  /api/tenants/validate/{token} # Validar email

# Protegidos (API Key)
POST   /tenants                   # Crear tenant
GET    /tenants                   # Listar tenants
GET    /tenants/{id}              # Obtener tenant
PATCH  /tenants/{id}              # Actualizar
DELETE /tenants/{id}              # Eliminar
GET    /tenants/{id}/status       # Estado provisioning
PUT    /api/tenants/{id}/subdomain # Cambiar subdomain

# Webhook
POST /webhooks/job-status         # Callback de K8s jobs
```

## Desarrollo

```bash
# Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run
uvicorn src.main:app --reload --port 8080

# Con Docker
docker build -t control-plane .
docker run -p 8080:8080 control-plane
```

## Variables de Entorno

```bash
# Core
ENVIRONMENT=development
PORT=8080
BASE_DOMAIN=1kairos.com
API_KEY=your-api-key

# GKE
GKE_PROJECT=kairos-escuela-app
GKE_LOCATION=us-central1
GKE_CLUSTER=kairos-cluster-dev
GKE_NAMESPACE=frappe

# Opcionales
FIRESTORE_ENABLED=false
SECRET_MANAGER_ENABLED=false
WEBHOOK_SECRET=hmac-secret
```

## Flujo de Provisioning

```
1. POST /api/tenants/signup
   └── Valida datos, genera subdomain (org-{uuid})

2. Si Google OAuth → crea inmediatamente
   Si email/pass → guarda en pending_signups, envía email

3. Crea Kubernetes Job:
   - bench new-site {subdomain}.1kairos.com
   - bench install-app kairos
   - bench add-user admin

4. Job reporta status via webhook
   └── Estado: queued → provisioning → active/failed

5. Usuario recibe redirect a su tenant
```

## Testing

```bash
pytest
pytest --cov=src
```

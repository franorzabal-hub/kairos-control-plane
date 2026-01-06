# Control Plane Kairos

## Qué es este repo

API para gestión de tenants (colegios). Orquesta la creación/eliminación de instancias Frappe en GKE.

## Stack

- **Framework**: FastAPI 0.109
- **Runtime**: Python 3.11
- **Cloud**: Google Cloud (GKE, Cloud Run, Firestore, Secret Manager)
- **Deploy**: Cloud Run

---

## Desarrollo y Deploy

> **Documentación completa**: Ver [infra/docs/DEVELOPMENT.md](https://github.com/franorzabal-hub/frappe-saas-platform/blob/main/docs/DEVELOPMENT.md)

### Ambientes

| Ambiente | URL | Trigger |
|----------|-----|---------|
| **Dev** | `api-dev.1kairos.com` | Push a `main` |
| **Prod** | `api.1kairos.com` | Tag `v*` |

### Desarrollo (sin Docker local)

```bash
# Configurar ambiente
cat > .env << 'EOF'
FRAPPE_URL=https://dev.1kairos.com
ENVIRONMENT=development
GCP_PROJECT=kairos-escuela-app
EOF

# Desarrollar
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8001
# → http://localhost:8001 (conecta a dev.1kairos.com)
```

### Deploy

```bash
# Deploy a Dev (automático)
git add . && git commit -m "feat: ..." && git push
# → Automático a api-dev.1kairos.com

# Deploy a Prod
git tag v1.0.0 -m "Release 1.0.0"
git push origin v1.0.0
# → Automático a api.1kairos.com
```

---

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

## Variables de Entorno

| Variable | Dev | Prod |
|----------|-----|------|
| `ENVIRONMENT` | `development` | `production` |
| `FRAPPE_URL` | `https://dev.1kairos.com` | (dinámico) |
| `GCP_PROJECT` | `kairos-escuela-app` | `kairos-escuela-app` |
| `GKE_CLUSTER` | `kairos-cluster-dev` | `kairos-cluster-prod` |
| `BASE_DOMAIN` | `1kairos.com` | `1kairos.com` |

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

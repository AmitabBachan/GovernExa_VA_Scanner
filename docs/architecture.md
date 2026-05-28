# VulnScope Architecture

## Full Project Structure

```text
vulnscope/
├── backend/
│   ├── api/            # FastAPI REST endpoints
│   ├── auth/           # Authentication and RBAC
│   ├── core/           # Configuration and settings
│   ├── migrations/     # Alembic database migrations
│   ├── models/         # SQLAlchemy models
│   ├── reporting/      # Report generation engines
│   ├── scanner/        # Core scanning engines (Discovery, Fingerprint, Auth)
│   └── services/       # Business logic linking API and Scanner
├── docs/               # System documentation and build state
├── frontend/           # React + TypeScript + Tailwind UI
├── docker/             # Dockerfiles and docker-compose configurations
├── k8s/                # Kubernetes deployment manifests
└── README.md
```

## Repository Layout
The repository follows a monorepo structure separating the Python backend, React frontend, and infrastructure-as-code deployments.

## Service Boundaries
1. **API Service**: Handles incoming HTTP requests, manages authentication, triggers scan jobs, and returns formatted data to the frontend.
2. **Scanner Service**: An asynchronous distributed worker pool (Celery) executing long-running scan tasks independently from the API thread.
3. **Reporting Service**: A sub-system dedicated to aggregating scan results into distributable formats (PDF, CSV).
4. **Database Service**: PostgreSQL providing transactional persistence for configuration, state, and results.
5. **Cache/Message Broker**: Redis managing Celery task queues and rate limiting.

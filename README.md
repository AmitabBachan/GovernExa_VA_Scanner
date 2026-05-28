# GovernExa Vulnerability Scanner

GovernExa Vulnerability Scanner is an enterprise-grade platform built to orchestrate deep network discovery, service fingerprinting, authenticated vulnerability scanning, and risk prioritization.

This repository contains the complete system including the React Frontend, FastAPI Backend, Celery Scanning Engine, PostgreSQL Database (with pre-loaded CVEs), and Redis message broker.

---

## 📋 Prerequisites

To deploy this platform, you must have the following installed on your machine:
- **Docker**
- **Docker Compose**
- **Git**

---

## 🚀 Deployment Instructions

The entire platform is heavily orchestrated using Docker Compose to ensure an identical environment regardless of the host OS.

### 1. Clone the Repository
```bash
git clone https://github.com/AmitabBachan/GovernExa_VA_Scanner.git
cd GovernExa_VA_Scanner
```

### 2. Start the Platform
Run the following command to build the images and launch the infrastructure in the background:
```bash
docker-compose up -d
```
*Note: The first time you run this, it will take several minutes to build the frontend/backend containers and automatically restore the 200,000+ CVE database using the bundled `init.sql` script.*

### 3. Access the Application
Once the containers are healthy, open your web browser and navigate to:
```
http://localhost:5173
```

*(Note: The Backend API documentation is accessible at `http://localhost:8000/docs`)*

---

## 🔐 Authentication

The application enforces Role-Based Access Control (RBAC). You can log in using any of the following pre-configured internal accounts:

| Role | Username | Password | Permissions |
|---|---|---|---|
| **Administrator** | `admin` | `password` | Full system access, settings, and scan execution. |
| **Operator** | `operator` | `operator123` | Can execute scans and view findings. |
| **Viewer** | `viewer` | `viewer123` | Read-only access to dashboards and reports. |

---

## 🔑 Licensing & Activation

To prevent unauthorized usage, the GovernExa Scanner utilizes a strict offline cryptographic licensing model. 

1. Upon first login, you will be redirected to the **Activation Screen**.
2. The screen will display your unique **Machine Fingerprint**.
3. You must provide this fingerprint to your Vendor/Administrator, who will generate a `.json` License File for you via the standalone **License Console**.
4. Upload the generated `.json` license file to the Activation Screen. 
5. The application will cryptographically verify the signature against its embedded public key. If valid, the system will unlock!

---

## 🏗️ Architecture Overview

The platform uses a microservice-inspired modular architecture:

- **Frontend (`/frontend`)**: React 18 + TypeScript + TailwindCSS + Vite. 
- **Backend API (`/backend/api`)**: FastAPI providing synchronous REST endpoints and JWT authentication.
- **Scanner Engine (`/backend/scanner`)**: Asynchronous Celery workers executing Nmap, SSH/WinRM, and CVE correlation pipelines.
- **Database (`db`)**: PostgreSQL 15 storing all assets, scan history, vulnerabilities, and configurations.
- **Message Broker (`redis`)**: Redis 7 managing the Celery task queues.

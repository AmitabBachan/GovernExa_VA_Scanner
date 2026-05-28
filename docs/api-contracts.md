# VulnScope API Contracts

This document defines the core REST API contracts exposed by the FastAPI backend to the Frontend or external consumers.

## POST `/scan/start`
Triggers a new vulnerability scan.

**Request Body:**
```json
{
  "target": "192.168.1.0/24",
  "scan_type": "full",
  "auth_profile_id": "opt-uuid-123"
}
```

**Response (202 Accepted):**
```json
{
  "scan_job_id": "uuid-456",
  "status": "pending"
}
```

---

## POST `/scan/bulk`
Triggers multiple scans in parallel.

**Request Body:**
```json
{
  "targets": ["10.0.0.1", "10.0.0.2"],
  "scan_type": "discovery"
}
```

**Response (202 Accepted):**
```json
{
  "job_ids": ["uuid-1", "uuid-2"]
}
```

---

## GET `/scan/{id}`
Retrieves the status of an ongoing or completed scan.

**Response (200 OK):**
```json
{
  "scan_job_id": "uuid-456",
  "status": "completed",
  "progress": 100,
  "started_at": "2026-05-26T10:00:00Z",
  "completed_at": "2026-05-26T10:05:00Z"
}
```

---

## GET `/devices`
Retrieves a paginated list of all discovered devices in the inventory.

**Response (200 OK):**
```json
{
  "total": 150,
  "page": 1,
  "data": [
    {
      "id": 1,
      "ip_address": "192.168.1.10",
      "hostname": "web-server-01",
      "os_details": "Ubuntu 22.04"
    }
  ]
}
```

---

## GET `/vulnerabilities`
Retrieves a consolidated list of discovered vulnerabilities across all assets.

**Response (200 OK):**
```json
{
  "total": 5,
  "data": [
    {
      "id": 1,
      "cve_id": "CVE-2023-1234",
      "device_id": 1,
      "severity": "Critical",
      "risk_score": 95
    }
  ]
}
```

---

## GET `/reports/{id}`
Generates and downloads a report based on a scan job. Query parameters can define the format (`?format=pdf`).

**Response (200 OK):**
Returns a binary file blob (e.g., `application/pdf` or `text/csv`).

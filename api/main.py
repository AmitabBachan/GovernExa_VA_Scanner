from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
from scanner.orchestrator import run_scan_pipeline
import uuid

app = FastAPI(
    title="VulnScope Scanner Core API",
    description="API for managing vulnerability scans",
    version="1.0.0"
)

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full" # discovery, fingerprint, auth, full

@app.post("/api/v1/scans", status_code=202)
def create_scan(request: ScanRequest):
    """
    Trigger a new scan job asynchronously.
    """
    scan_job_id = str(uuid.uuid4())
    
    # Send to Celery worker
    task = run_scan_pipeline.delay(request.target, request.scan_type, scan_job_id)
    
    return {
        "message": "Scan job submitted successfully",
        "scan_job_id": scan_job_id,
        "task_id": task.id
    }

@app.get("/api/v1/scans/{scan_job_id}")
def get_scan_status(scan_job_id: str):
    """
    Retrieve the status of a scan job.
    """
    # In a real app, query the database (models.ScanJob)
    return {
        "scan_job_id": scan_job_id,
        "status": "PENDING_OR_RUNNING" 
    }

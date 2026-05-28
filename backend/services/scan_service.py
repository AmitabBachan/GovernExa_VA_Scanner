import uuid
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from scanner.tasks import run_scan_pipeline
from models.scans import ScanJob

class ScanService:
    """
    Business logic layer for scan orchestration.
    """
    def __init__(self, db: Session):
        self.db = db

    def start_scan(self, target: str, scan_type: str = "full", cloud_integration: str = None, credential_id: int = None) -> Dict[str, str]:
        scan_job_id = str(uuid.uuid4())
        
        # Save ScanJob to DB here with status PENDING
        job = ScanJob(
            id=scan_job_id,
            target=target,
            status="PENDING",
            scan_type=scan_type
        )
        self.db.add(job)
        self.db.commit()
        
        # Trigger Celery task
        task = run_scan_pipeline.delay(
            target=target,
            scan_type=scan_type,
            scan_job_id=scan_job_id,
            cloud_integration=cloud_integration,
            credential_id=credential_id
        )
        
        job.task_id = task.id
        self.db.commit()
        
        return {
            "scan_job_id": scan_job_id,
            "task_id": task.id,
            "status": "pending"
        }

    def start_bulk_scan(self, targets: List[str], scan_type: str = "full") -> Dict[str, Any]:
        job_ids = []
        for target in targets:
            job_info = self.start_scan(target, scan_type)
            job_ids.append(job_info["scan_job_id"])
            
        return {"job_ids": job_ids}

    def get_scan_status(self, scan_job_id: str) -> Dict[str, Any]:
        job = self.db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return {"error": "Scan job not found"}
            
        return {
            "scan_job_id": job.id,
            "status": job.status,
            "target": job.target,
            "scan_type": job.scan_type,
            "started_at": job.started_at,
            "completed_at": job.completed_at
        }

    def get_active_scan(self) -> Dict[str, Any]:
        job = self.db.query(ScanJob).filter(ScanJob.status.in_(["PENDING", "PROCESSING"])).order_by(ScanJob.started_at.desc()).first()
        if not job:
            return {}
            
        return {
            "scan_job_id": job.id,
            "status": job.status,
            "target": job.target,
            "scan_type": job.scan_type,
            "started_at": job.started_at,
            "completed_at": job.completed_at
        }

    def stop_scan(self, scan_job_id: str) -> Dict[str, Any]:
        job = self.db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return {"error": "Scan job not found"}
            
        if job.status in ["COMPLETED", "FAILED", "STOPPED"]:
            return {"error": f"Scan is already {job.status}"}
            
        # Revoke Celery Task
        if job.task_id:
            from celery_app import celery_app
            celery_app.control.revoke(job.task_id, terminate=True)
            
        job.status = "STOPPED"
        from datetime import datetime
        job.completed_at = datetime.now()
        self.db.commit()
        
        return {"status": "STOPPED", "scan_job_id": job.id}

    def get_scan_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        jobs = self.db.query(ScanJob).filter(ScanJob.is_archived.isnot(True)).order_by(ScanJob.started_at.desc()).limit(limit).all()
        return [
            {
                "scan_job_id": job.id,
                "status": job.status,
                "target": job.target,
                "scan_type": job.scan_type,
                "started_at": job.started_at,
                "completed_at": job.completed_at
            }
            for job in jobs
        ]

    def get_archived_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        jobs = self.db.query(ScanJob).filter(ScanJob.is_archived == True).order_by(ScanJob.started_at.desc()).limit(limit).all()
        return [
            {
                "scan_job_id": job.id,
                "status": job.status,
                "target": job.target,
                "scan_type": job.scan_type,
                "started_at": job.started_at,
                "completed_at": job.completed_at
            }
            for job in jobs
        ]

    def archive_scan(self, scan_job_id: str) -> Dict[str, Any]:
        job = self.db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return {"error": "Scan job not found"}
        job.is_archived = True
        self.db.commit()
        return {"status": "ARCHIVED", "scan_job_id": job.id}

    def unarchive_scan(self, scan_job_id: str) -> Dict[str, Any]:
        job = self.db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return {"error": "Scan job not found"}
        job.is_archived = False
        self.db.commit()
        return {"status": "UNARCHIVED", "scan_job_id": job.id}

    def delete_scan(self, scan_job_id: str) -> Dict[str, Any]:
        job = self.db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return {"error": "Scan job not found"}
            
        from models.enumeration import EnumerationResult
        from models.vulnerability_scan import VulnerabilityScanFinding
        from models.auth_scan import AuthScanFinding
        from models.risk_scoring import RiskScoringResult
        from models.validation import ValidationResult
        from models.asset_discovery import AssetDiscoveryResult
        from models.port_scan import PortScanResult, PortScanSummary
        from models.service_fingerprint import ServiceFingerprintResult
        
        # Explicitly delete child dependencies due to lack of DB-level CASCADE
        self.db.query(AssetDiscoveryResult).filter(AssetDiscoveryResult.scan_job_id == scan_job_id).delete()
        self.db.query(PortScanResult).filter(PortScanResult.scan_job_id == scan_job_id).delete()
        self.db.query(PortScanSummary).filter(PortScanSummary.scan_job_id == scan_job_id).delete()
        self.db.query(ServiceFingerprintResult).filter(ServiceFingerprintResult.scan_job_id == scan_job_id).delete()
        
        self.db.query(EnumerationResult).filter(EnumerationResult.scan_job_id == scan_job_id).delete()
        self.db.query(VulnerabilityScanFinding).filter(VulnerabilityScanFinding.scan_job_id == scan_job_id).delete()
        self.db.query(AuthScanFinding).filter(AuthScanFinding.scan_job_id == scan_job_id).delete()
        self.db.query(ValidationResult).filter(ValidationResult.scan_job_id == scan_job_id).delete()
        self.db.query(RiskScoringResult).filter(RiskScoringResult.scan_job_id == scan_job_id).delete()
        
        self.db.delete(job)
        self.db.commit()
        return {"status": "DELETED", "scan_job_id": scan_job_id}

    def pause_scan(self, scan_job_id: str) -> Dict[str, Any]:
        job = self.db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return {"error": "Scan job not found"}
            
        if job.status not in ["PENDING", "PROCESSING"]:
            return {"error": f"Cannot pause scan in {job.status} state"}
            
        job.status = "PAUSED"
        self.db.commit()
        return {"status": "PAUSED", "scan_job_id": job.id}

    def resume_scan(self, scan_job_id: str) -> Dict[str, Any]:
        job = self.db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return {"error": "Scan job not found"}
            
        if job.status != "PAUSED":
            return {"error": f"Cannot resume scan in {job.status} state"}
            
        job.status = "PROCESSING"
        self.db.commit()
        return {"status": "PROCESSING", "scan_job_id": job.id}

    def generate_scan_report(self, scan_job_id: str) -> Dict[str, Any]:
        from models.scans import ScanResult
        from models.vulnerabilities import Vulnerability, CveCatalog
        from models.assets import Device
        
        job = self.db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return {"error": "Scan job not found"}
            
        results = self.db.query(ScanResult).filter(ScanResult.scan_job_id == scan_job_id).all()
        
        devices = []
        findings = []
        
        for result in results:
            device = self.db.query(Device).filter(Device.id == result.device_id).first()
            if device and device not in devices:
                devices.append({
                    "id": device.id,
                    "ip_address": device.ip_address,
                    "os_name": device.os_family
                })
                
            vulns = self.db.query(Vulnerability).filter(Vulnerability.scan_result_id == result.id).all()
            for vuln in vulns:
                cve = self.db.query(CveCatalog).filter(CveCatalog.cve_id == vuln.cve_id).first()
                findings.append({
                    "cve_id": vuln.cve_id,
                    "affected_ip": device.ip_address if device else "Unknown",
                    "severity": cve.severity if cve else "Unknown",
                    "risk_score": vuln.risk_score,
                    "description": cve.description if cve else "No description available",
                    "remediation": vuln.remediation_plan
                })
                
        return {
            "scan_job_id": job.id,
            "target": job.target,
            "scan_type": job.scan_type,
            "status": job.status,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "devices": devices,
            "findings": findings
        }

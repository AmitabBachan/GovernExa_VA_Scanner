from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
from auth.rbac import require_role
from services.scan_service import ScanService
from api.deps import get_db
from sqlalchemy.orm import Session
from licensing.dependencies import verify_license

router = APIRouter(prefix="/scan", tags=["Scanning"], dependencies=[Depends(verify_license)])

class ScanStartRequest(BaseModel):
    target: str
    scan_type: str = "full"
    cloud_integration: Optional[str] = None
    credential_id: Optional[int] = None

class BulkScanRequest(BaseModel):
    targets: List[str]
    scan_type: str = "full"

@router.post("/start", status_code=202)
def start_scan(
    request: ScanStartRequest, 
    current_user: dict = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    service = ScanService(db)
    
    # SSRF Protection
    restricted_targets = ['127.0.0.1', 'localhost', '0.0.0.0', '::1']
    for t in request.target.replace(',', ' ').split():
        if t.lower() in restricted_targets or t.startswith('127.'):
            raise HTTPException(status_code=400, detail="Scanning localhost/loopback addresses is restricted for security reasons.")
            
    # Clean up comma-separated targets into space-separated for Nmap
    cleaned_target = request.target.replace(',', ' ')
    
    result = service.start_scan(
        target=cleaned_target,
        scan_type=request.scan_type,
        cloud_integration=request.cloud_integration,
        credential_id=request.credential_id
    )
    return result

@router.post("/bulk-start", status_code=202)
def start_bulk_scan(
    request: BulkScanRequest, 
    current_user: dict = Depends(require_role("operator")),
    db: Session = Depends(get_db)
):
    service = ScanService(db)
    return service.start_bulk_scan(request.targets, request.scan_type)

@router.get("/active", tags=["Scanning"])
def get_active_scan(
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    scan_service = ScanService(db)
    result = scan_service.get_active_scan()
    return result

@router.get("/history", tags=["Scanning"])
def get_scan_history(
    limit: int = 10,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    scan_service = ScanService(db)
    result = scan_service.get_scan_history(limit=limit)
    return result

@router.get("/archived", tags=["Scanning"])
def get_archived_scans(
    limit: int = 50,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    scan_service = ScanService(db)
    result = scan_service.get_archived_scans(limit=limit)
    return result

@router.post("/{scan_job_id}/archive", tags=["Scanning"])
def archive_scan(
    scan_job_id: str,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    scan_service = ScanService(db)
    result = scan_service.archive_scan(scan_job_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.post("/{scan_job_id}/unarchive", tags=["Scanning"])
def unarchive_scan(
    scan_job_id: str,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    scan_service = ScanService(db)
    result = scan_service.unarchive_scan(scan_job_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.get("/{scan_job_id}", tags=["Scanning"])
def get_scan_status(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    scan_service = ScanService(db)
    result = scan_service.get_scan_status(scan_job_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.post("/{scan_job_id}/stop", tags=["Scanning"])
def stop_scan(
    scan_job_id: str,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    scan_service = ScanService(db)
    result = scan_service.stop_scan(scan_job_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.delete("/{scan_job_id}", tags=["Scanning"])
def delete_scan(
    scan_job_id: str,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    scan_service = ScanService(db)
    result = scan_service.delete_scan(scan_job_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.post("/{scan_job_id}/pause", tags=["Scanning"])
def pause_scan(
    scan_job_id: str,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    scan_service = ScanService(db)
    result = scan_service.pause_scan(scan_job_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.post("/{scan_job_id}/resume", tags=["Scanning"])
def resume_scan(
    scan_job_id: str,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    scan_service = ScanService(db)
    result = scan_service.resume_scan(scan_job_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.get("/{scan_job_id}/logs", tags=["Scanning"])
def get_logs(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer"))
):
    from utils.logger import get_scan_logs
    logs = get_scan_logs(scan_job_id)
    return logs

@router.get("/{scan_job_id}/report", tags=["Scanning"])
def get_scan_report(
    scan_job_id: str,
    format: str = "json",
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    from fastapi.responses import PlainTextResponse
    import io
    import csv
    
    scan_service = ScanService(db)
    result = scan_service.generate_scan_report(scan_job_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
        
    if format.lower() == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Target IP", "OS Name", "CVE ID", "Severity", "Risk Score", "Description"])
        
        # If there are no findings, just list the devices
        if not result.get("findings"):
            for d in result.get("devices", []):
                writer.writerow([d.get("ip_address"), d.get("os_name"), "N/A", "N/A", "N/A", "No Vulnerabilities"])
        else:
            for f in result.get("findings", []):
                writer.writerow([
                    f.get("affected_ip", "Unknown"), 
                    "Unknown", # Could map OS here, but keeping it simple for CSV
                    f.get("cve_id"), 
                    f.get("severity"), 
                    f.get("risk_score"), 
                    f.get("description")
                ])
                
        return PlainTextResponse(content=output.getvalue(), media_type="text/csv")
        
    return result

@router.get("/{scan_job_id}/asset-discovery", tags=["Scanning"])
def get_asset_discovery_results(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    """Return all asset-discovery records for a given scan job."""
    from models.asset_discovery import AssetDiscoveryResult
    records = db.query(AssetDiscoveryResult).filter(
        AssetDiscoveryResult.scan_job_id == scan_job_id
    ).all()
    return [
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "hostname": r.hostname,
            "mac_address": r.mac_address,
            "vendor": r.vendor,
            "os_name": r.os_name,
            "os_family": r.os_family,
            "os_accuracy": r.os_accuracy,
            "device_type": r.device_type,
            "role": r.role,
            "open_ports": r.open_ports or [],
            "web_apps": r.web_apps or [],
            "containers": r.containers or [],
            "cloud_instance": r.cloud_instance,
            "discovered_at": r.discovered_at.isoformat() if r.discovered_at else None,
        }
        for r in records
    ]

@router.get("/{scan_job_id}/port-scan", tags=["Scanning"])
def get_port_scan_results(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    """Return detailed port scan results + per-host summaries for a scan job."""
    from models.port_scan import PortScanResult, PortScanSummary

    ports = db.query(PortScanResult).filter(
        PortScanResult.scan_job_id == scan_job_id
    ).order_by(PortScanResult.ip_address, PortScanResult.port).all()

    summaries = db.query(PortScanSummary).filter(
        PortScanSummary.scan_job_id == scan_job_id
    ).order_by(PortScanSummary.ip_address).all()

    return {
        "summaries": [
            {
                "id": s.id,
                "ip_address": s.ip_address,
                "hostname": s.hostname,
                "os_name": s.os_name,
                "os_family": s.os_family,
                "os_accuracy": s.os_accuracy,
                "device_type": s.device_type,
                "total_open_ports": s.total_open_ports,
                "tcp_open": s.tcp_open,
                "udp_open": s.udp_open,
                "critical_ports": s.critical_ports,
                "high_risk_ports": s.high_risk_ports,
                "overall_risk": s.overall_risk,
                "discovered_at": s.discovered_at.isoformat() if s.discovered_at else None,
            }
            for s in summaries
        ],
        "ports": [
            {
                "id": p.id,
                "ip_address": p.ip_address,
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service,
                "product": p.product,
                "version": p.version,
                "extrainfo": p.extrainfo,
                "cpe": p.cpe,
                "banner": p.banner,
                "scan_method": p.scan_method,
                "risk": p.risk,
                "reason": p.reason,
                "scripts": p.scripts,
                "discovered_at": p.discovered_at.isoformat() if p.discovered_at else None,
            }
            for p in ports
        ],
    }

@router.get("/{scan_job_id}/service-fingerprint", tags=["Scanning"])
def get_service_fingerprint_results(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    """Return service fingerprinting results for a scan job."""
    from models.service_fingerprint import ServiceFingerprintResult

    services = db.query(ServiceFingerprintResult).filter(
        ServiceFingerprintResult.scan_job_id == scan_job_id
    ).order_by(ServiceFingerprintResult.ip_address, ServiceFingerprintResult.port).all()

    return [
        {
            "id": s.id,
            "ip_address": s.ip_address,
            "port": s.port,
            "protocol": s.protocol,
            "service": s.service,
            "product": s.product,
            "version": s.version,
            "extrainfo": s.extrainfo,
            "cpe": s.cpe,
            "banner": s.banner,
            "http_server": s.http_server,
            "discovered_at": s.discovered_at.isoformat() if s.discovered_at else None,
        }
        for s in services
    ]



@router.get("/{scan_job_id}/enumeration", tags=["Scanning"])
def get_enumeration_results(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    """Return enumeration results for a scan job."""
    from models.enumeration import EnumerationResult

    records = db.query(EnumerationResult).filter(
        EnumerationResult.scan_job_id == scan_job_id
    ).order_by(EnumerationResult.ip_address).all()

    return [
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "smb_shares": r.smb_shares,
            "smb_users": r.smb_users,
            "snmp_sysdescr": r.snmp_sysdescr,
            "snmp_interfaces": r.snmp_interfaces,
            "dns_records": r.dns_records,
            "ssl_certs": r.ssl_certs,
            "os_info": r.os_info,
            "discovered_at": r.discovered_at.isoformat() if r.discovered_at else None,
        }
        for r in records
    ]

@router.get("/{scan_job_id}/vulnerability-scan", tags=["Scanning"])
def get_vulnerability_scan_results(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    """Return vulnerability scan results for a specific scan job."""
    from models.vulnerability_scan import VulnerabilityScanFinding

    records = db.query(VulnerabilityScanFinding).filter(
        VulnerabilityScanFinding.scan_job_id == scan_job_id
    ).order_by(VulnerabilityScanFinding.ip_address, VulnerabilityScanFinding.port).all()

    return [
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "port": r.port,
            "protocol": r.protocol,
            "service": r.service,
            "product": r.product,
            "cves": r.cves,
            "misconfigurations": r.misconfigurations,
            "discovered_at": r.discovered_at.isoformat() if r.discovered_at else None,
        }
        for r in records
    ]

@router.get("/{scan_job_id}/auth-scan", tags=["Scanning"])
def get_auth_scan_results(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    """Return authenticated scan results for a specific scan job."""
    from models.auth_scan import AuthScanFinding

    records = db.query(AuthScanFinding).filter(
        AuthScanFinding.scan_job_id == scan_job_id
    ).order_by(AuthScanFinding.ip_address).all()

    return [
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "os_details": r.os_details,
            "packages": r.packages,
            "local_users": r.local_users,
            "patch_levels": r.patch_levels,
            "discovered_at": r.discovered_at.isoformat() if r.discovered_at else None,
        }
        for r in records
    ]

@router.get("/{scan_job_id}/risk-scoring", tags=["Scanning"])
def get_risk_scoring_results(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    """Return risk scoring results for a specific scan job."""
    from models.risk_scoring import RiskScoringResult

    records = db.query(RiskScoringResult).filter(
        RiskScoringResult.scan_job_id == scan_job_id
    ).order_by(RiskScoringResult.adjusted_score.desc()).all()

    return [
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "vulnerability_id": r.vulnerability_id,
            "description": r.description,
            "base_severity": r.base_severity,
            "base_score": r.base_score,
            "environmental_factors": r.environmental_factors,
            "adjusted_score": r.adjusted_score,
            "final_severity": r.final_severity,
            "calculated_at": r.calculated_at.isoformat() if r.calculated_at else None,
        }
        for r in records
    ]

@router.get("/{scan_job_id}/validation", tags=["Scanning"])
def get_validation_results(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    """Return validation & verification results for a specific scan job."""
    from models.validation import ValidationResult

    records = db.query(ValidationResult).filter(
        ValidationResult.scan_job_id == scan_job_id
    ).order_by(ValidationResult.ip_address).all()

    return [
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "vulnerability_id": r.vulnerability_id,
            "is_confirmed": r.is_confirmed,
            "is_false_positive": r.is_false_positive,
            "verification_method": r.verification_method,
            "proof_of_concept": r.proof_of_concept,
            "discovered_at": r.discovered_at.isoformat() if r.discovered_at else None,
        }
        for r in records
    ]

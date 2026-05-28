from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from auth.rbac import require_role
from api.deps import get_db
from models.vulnerabilities import Vulnerability
from models.scans import ScanResult
from models.assets import Device
from licensing.dependencies import verify_license
import csv
import io
from sqlalchemy.orm import joinedload

router = APIRouter(prefix="/reports", tags=["Reporting"], dependencies=[Depends(verify_license)])

@router.get("/generate")
def generate_report(format: str = "json", current_user: dict = Depends(require_role("viewer")), db: Session = Depends(get_db)):
    """
    Generate and download a report dynamically from the database.
    """
    from models.vulnerabilities import CveCatalog
    vulns = db.query(Vulnerability, ScanResult, Device, CveCatalog).join(
        ScanResult, Vulnerability.scan_result_id == ScanResult.id
    ).join(
        Device, ScanResult.device_id == Device.id
    ).outerjoin(
        CveCatalog, Vulnerability.cve_id == CveCatalog.cve_id
    ).all()
    
    if format.lower() == "json":
        data = [
            {
                "cve_id": v.Vulnerability.cve_id,
                "ip": v.Device.ip_address,
                "severity": v.CveCatalog.severity if v.CveCatalog else "Unknown",
                "risk_score": v.Vulnerability.risk_score
            }
            for v in vulns
        ]
        return data
        
    elif format.lower() == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["CVE_ID", "IP_Address", "Severity", "Risk_Score", "Description"])
        
        for v in vulns:
            writer.writerow([
                v.Vulnerability.cve_id,
                v.Device.ip_address,
                v.CveCatalog.severity if v.CveCatalog else "Unknown",
                v.Vulnerability.risk_score,
                v.CveCatalog.description if v.CveCatalog else "Unknown"
            ])
            
        return Response(
            content=output.getvalue(), 
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=vulnerability_report.csv"}
        )
        
    else:
        return {"error": "Format not supported. Use json or csv."}

@router.post("/")
def save_report(
    name: str,
    scan_job_ids: str, # comma separated
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    from models.reports import Report
    r = Report(
        report_type=name,
        file_path=scan_job_ids,
        generated_by=current_user.get("id")
    )
    db.add(r)
    db.commit()
    return {"status": "ok"}

@router.get("/saved")
def list_reports(
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    from models.reports import Report
    reports = db.query(Report).all()
    return [{"id": r.id, "name": r.report_type, "scans": r.file_path, "created_at": r.generated_at} for r in reports]

@router.delete("/{report_id}")
def delete_report(
    report_id: int,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    from models.reports import Report
    r = db.query(Report).filter(Report.id == report_id).first()
    if r:
        db.delete(r)
        db.commit()
    return {"status": "ok"}

@router.put("/{report_id}")
def update_report(
    report_id: int,
    name: str,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    from models.reports import Report
    r = db.query(Report).filter(Report.id == report_id).first()
    if r:
        r.report_type = name
        db.commit()
    return {"status": "ok"}

from pydantic import BaseModel
from typing import List
class CollateRequest(BaseModel):
    scan_job_ids: List[str]

@router.post("/export/{format}")
def export_report(
    format: str,
    request: CollateRequest,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    import os
    import tempfile
    from fastapi.responses import Response
    from reporting.writer.executive_summary_builder import build_executive_summary
    from reporting.writer.finding_formatter import format_findings
    from reporting.ai.ai_enrichment_engine import AIEnrichmentEngine
    from reporting.charts.chart_generator import generate_severity_pie_chart
    from reporting.exporters.exporter_factory import ExporterFactory
    
    if not request.scan_job_ids:
        return {"error": "No scan job IDs provided"}
        
    scan_job_id = request.scan_job_ids[0] # Build for primary selected scan
    
    exec_summary = build_executive_summary(db, scan_job_id)
    findings = format_findings(db, scan_job_id)
    
    from models.settings import SystemSetting
    
    settings_records = db.query(SystemSetting).all()
    config = {s.key: s.value for s in settings_records}
    
    ai_engine = AIEnrichmentEngine(config)
    for finding in findings:
        enrichment = ai_engine.enrich_finding(finding)
        if enrichment:
            finding.update(enrichment)
            
    severity_counts = exec_summary.get("severity_counts", {})
    charts = {
        "severity_pie": generate_severity_pie_chart(severity_counts)
    }
    report_data = {
        "title": "Comprehensive Vulnerability Scan Report",
        "date": "2026-05-28",
        "client_name": "GovernExa Client",
        "metadata": {
            "scan_profile_name": "Unified Scan",
            "date": "2026-05-28",
            "target_ips": ["Selected Assets"],
            "duration": "Automated",
            "engine_version": "1.0.0"
        },
        "scan_profiles": [],
        "findings": findings,
        "detailed_findings": findings,
        "charts": charts
    }
    report_data.update(exec_summary)
    
    exporter = ExporterFactory.get_exporter(format, template_dir="reporting/templates")
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{format}") as tmp:
        output_path = tmp.name
        
    exporter.export(report_data, output_path)
    
    with open(output_path, "rb") as f:
        content = f.read()
        
    os.remove(output_path)
    
    mime_types = {
        "pdf": "application/pdf",
        "html": "text/html",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "csv": "text/csv",
        "json": "application/json"
    }
    
    return Response(
        content=content,
        media_type=mime_types.get(format.lower(), "application/octet-stream"),
        headers={"Content-Disposition": f"attachment; filename=govern_exa_report.{format}"}
    )

@router.post("/collate")
def collate_reports(request: CollateRequest, db: Session = Depends(get_db)):
    from models.scans import ScanJob, ScanResult
    from models.assets import Device
    from models.vulnerabilities import CveCatalog
    
    devices_discovered = {}
    findings = []
    
    for job_id in request.scan_job_ids:
        results = db.query(ScanResult).filter(ScanResult.scan_job_id == job_id).all()
        for res in results:
            if res.device:
                devices_discovered[res.device.ip_address] = {
                    "ip_address": res.device.ip_address,
                    "os_name": res.device.os_name,
                    "os_version": res.device.os_version,
                    "mac_address": res.device.mac_address
                }
            
            vulns = db.query(Vulnerability).options(joinedload(Vulnerability.cve)).filter(Vulnerability.scan_result_id == res.id).all()
            for v in vulns:
                findings.append({
                    "cve_id": v.cve_id,
                    "severity": v.cve.severity if v.cve else "Unknown",
                    "risk_score": v.risk_score,
                    "description": v.cve.description if v.cve else "No description available",
                    "affected_ip": res.device.ip_address if res.device else "Unknown",
                    "source_scan": job_id
                })
                
    return {
        "summary": {
            "total_devices_discovered": len(devices_discovered),
            "total_vulnerabilities_found": len(findings)
        },
        "devices": list(devices_discovered.values()),
        "findings": findings
    }

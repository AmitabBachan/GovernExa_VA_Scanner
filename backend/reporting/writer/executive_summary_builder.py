from sqlalchemy.orm import Session
from sqlalchemy import func
from models.scans import ScanJob, ScanResult
from models.vulnerabilities import Vulnerability, CveCatalog
from models.assets import Device

def build_executive_summary(db: Session, scan_job_id: str):
    """
    Aggregates scan metrics including total assets, total vulnerabilities,
    findings by severity, critical findings, and risk score summary.
    """
    # Total Assets
    total_assets = db.query(ScanResult.device_id).filter(ScanResult.scan_job_id == scan_job_id).distinct().count()
    
    # Total Vulnerabilities
    total_vulns = db.query(Vulnerability).join(ScanResult).filter(ScanResult.scan_job_id == scan_job_id).count()
    
    # Findings by Severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    vulns_with_severity = db.query(CveCatalog.severity, func.count(Vulnerability.id)).\
        join(Vulnerability, Vulnerability.cve_id == CveCatalog.cve_id).\
        join(ScanResult, ScanResult.id == Vulnerability.scan_result_id).\
        filter(ScanResult.scan_job_id == scan_job_id).\
        group_by(CveCatalog.severity).all()
        
    for sev, count in vulns_with_severity:
        if sev:
            sev_normalized = sev.lower()
            if sev_normalized in severity_counts:
                severity_counts[sev_normalized] += count
            else:
                severity_counts[sev_normalized] = count
                
    # Critical findings
    critical_findings_query = db.query(Vulnerability, CveCatalog).\
        join(CveCatalog, Vulnerability.cve_id == CveCatalog.cve_id).\
        join(ScanResult, ScanResult.id == Vulnerability.scan_result_id).\
        filter(ScanResult.scan_job_id == scan_job_id).\
        filter(func.lower(CveCatalog.severity) == 'critical').all()
        
    critical_findings = []
    for vuln, cve in critical_findings_query:
        critical_findings.append({
            "cve_id": cve.cve_id,
            "description": cve.description,
            "cvss_score": cve.cvss_score,
            "risk_score": vuln.risk_score
        })
        
    # Risk score summary
    max_risk = db.query(func.max(Vulnerability.risk_score)).\
        join(ScanResult).\
        filter(ScanResult.scan_job_id == scan_job_id).scalar()
    
    avg_risk = db.query(func.avg(Vulnerability.risk_score)).\
        join(ScanResult).\
        filter(ScanResult.scan_job_id == scan_job_id).scalar()
        
    overview = f"The scan assessed {total_assets} assets and discovered a total of {total_vulns} vulnerabilities. "
    if max_risk:
        overview += f"The highest risk score among the findings was {max_risk:.2f}."
    else:
        overview += "No risk scores were assigned to the findings."

    return {
        "metrics": severity_counts,
        "executive_summary": {
            "total_assets": total_assets,
            "total_vulnerabilities": total_vulns,
            "findings_by_severity": severity_counts,
            "critical_findings": critical_findings,
            "risk_score_summary": {
                "max_risk_score": float(max_risk) if max_risk else 0.0,
                "average_risk_score": float(avg_risk) if avg_risk else 0.0
            },
            "overview": overview,
            "ai_synthesis": "This executive summary provides a high-level overview of the recent scan execution, highlighting the overall risk posture and critical vulnerabilities requiring immediate attention."
        }
    }

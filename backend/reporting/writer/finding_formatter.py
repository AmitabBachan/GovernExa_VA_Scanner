import json
from sqlalchemy.orm import Session
from models.vulnerabilities import Vulnerability, RemediationLibrary
from models.scans import ScanResult

def format_findings(db: Session, scan_job_id: str):
    """
    Retrieves and structures individual findings for a given scan job.
    Pulls details including remediation data, CVE, CVSS, and evidence.
    """
    findings = []
    
    # Query all vulnerabilities for this scan job
    vulns = db.query(Vulnerability).\
        join(ScanResult).\
        filter(ScanResult.scan_job_id == scan_job_id).\
        all()
        
    for vuln in vulns:
        scan_result = vuln.scan_result
        device = scan_result.device
        cve = vuln.cve
        
        # Format remediation block
        remediation_text = "No remediation information available."
        if vuln.remediations:
            rem = vuln.remediations[0] # assuming one remediation record per vuln
            rem_parts = []
            if rem.recommended_update:
                rem_parts.append(f"Recommended Patch: {rem.recommended_update}")
            if rem.patch_version:
                rem_parts.append(f"Patch Version: {rem.patch_version}")
            if rem.workaround:
                rem_parts.append(f"Workaround: {rem.workaround}")
            if rem.mitigation:
                rem_parts.append(f"Mitigation: {rem.mitigation}")
            if getattr(rem, 'rollback_plan', None):
                rem_parts.append(f"Rollback Plan: {rem.rollback_plan}")
            if getattr(rem, 'validation_steps', None):
                rem_parts.append(f"Validation Steps: {rem.validation_steps}")
                
            if rem_parts:
                remediation_text = "\n\n".join(rem_parts)

        # Build evidence
        evidence_text = f"Device: {device.ip_address}\nService: {scan_result.service_name}\n"
        if scan_result.port:
            evidence_text += f"Port: {scan_result.port}/{scan_result.protocol}\n"
        if scan_result.service_version:
            evidence_text += f"Version Detected: {scan_result.service_version}\n"
            
        if cve and cve.json_data:
            try:
                cve_json = json.loads(cve.json_data) if isinstance(cve.json_data, str) else cve.json_data
                if 'evidence' in cve_json:
                    evidence_text += f"\nAdditional Evidence:\n{cve_json['evidence']}"
            except Exception:
                pass
                
        # Generate a title
        title = "Unknown Vulnerability"
        if cve and cve.description:
            title = cve.description.split('.')[0]
            if len(title) > 80:
                title = title[:77] + "..."

        finding_data = {
            "profile_type": scan_result.scan_job.scan_type if scan_result.scan_job else "vulnerability",
            "severity": cve.severity.capitalize() if cve and cve.severity else "Medium",
            "name": title,
            "host": device.ip_address if device else "Unknown Host",
            "port": scan_result.port or "N/A",
            "service": scan_result.service_name or "N/A",
            "cvss": cve.cvss_score if cve else "N/A",
            "cve": cve.cve_id if cve else "N/A",
            "description": cve.description if cve else "No description available.",
            "software_version": scan_result.service_version or "Unknown",
            "ai_explanation": f"The target system is vulnerable to {cve.cve_id if cve else 'a known security flaw'}. If exploited, this could compromise the integrity, confidentiality, or availability of the service.",
            "remediation": remediation_text,
            "evidence": evidence_text
        }
        
        findings.append(finding_data)
        
    return findings

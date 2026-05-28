from sqlalchemy.orm import Session
from sqlalchemy import func
from models.scan import ScanJob, ScanResult
from models.vulnerability import Vulnerability
from models.device import Device

def get_scan_profile_narrative(profile_type: str):
    narratives = {
        "discovery": {
            "name": "Discovery",
            "description": "A Discovery Scan identifies active hosts and devices on the network. This provides an initial understanding of the attack surface.",
            "execution_summary": "Executed to map the network topology and identify live assets.",
            "assessed": "Network segments and live IP addresses.",
            "expected_output": "A list of active hosts, their IP addresses, and basic identification details."
        },
        "port_scan": {
            "name": "Port",
            "description": "A Port Scan identifies open ports and services running on active hosts. This determines available entry points on the network.",
            "execution_summary": "Executed to discover listening services and potential network exposure.",
            "assessed": "TCP and UDP ports on active hosts.",
            "expected_output": "A list of open ports, associated services, and service banners."
        },
        "vulnerability": {
            "name": "Vulnerability",
            "description": "A Vulnerability Scan assesses discovered services for known security flaws. It matches service banners and configurations against a database of known vulnerabilities (CVEs).",
            "execution_summary": "Executed to identify security weaknesses in network services.",
            "assessed": "Network services, software versions, and configurations.",
            "expected_output": "A list of identified vulnerabilities, including severity ratings and remediation guidance."
        },
        "authenticated": {
            "name": "Authenticated",
            "description": "An Authenticated Scan uses provided credentials to log into target systems. This allows for a deeper inspection of installed software, local configurations, and missing patches.",
            "execution_summary": "Executed to perform an in-depth assessment of host internals.",
            "assessed": "Local file systems, registry keys, installed packages, and local user configurations.",
            "expected_output": "Detailed vulnerability findings, patch status, and software inventory."
        },
        "compliance": {
            "name": "Compliance",
            "description": "A Compliance Scan evaluates target systems against industry security standards and frameworks.",
            "execution_summary": "Executed to ensure systems adhere to required regulatory or organizational standards.",
            "assessed": "System configurations, password policies, access controls, and logging settings.",
            "expected_output": "A pass/fail report for specific compliance controls and recommendations for remediation."
        },
        "config": {
            "name": "Configuration",
            "description": "A Configuration Review assesses the specific settings of devices to ensure secure baselines are met.",
            "execution_summary": "Executed to identify misconfigurations that could weaken security posture.",
            "assessed": "Device configuration files, routing tables, and firewall rule sets.",
            "expected_output": "Identified misconfigurations and recommended secure configuration practices."
        }
    }
    
    return narratives.get(profile_type.lower(), {
        "name": profile_type.capitalize(),
        "description": f"A {profile_type} scan was executed.",
        "execution_summary": "Executed to assess specific target properties.",
        "assessed": "Defined scope of the scan.",
        "expected_output": "Relevant findings based on the scan type."
    })

def build_scan_profiles(db: Session, scan_job_ids: list[str]):
    """
    Builds the scan profiles data structure for the report template.
    It aggregates targets and findings by scan_job.
    """
    profiles = []
    
    for job_id in scan_job_ids:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            continue
            
        narrative = get_scan_profile_narrative(job.scan_type)
        
        # Get targets for this job
        results = db.query(ScanResult.device_id, Device.ip_address).\
            join(Device, Device.id == ScanResult.device_id).\
            filter(ScanResult.scan_job_id == job_id).\
            distinct().all()
            
        targets = []
        for device_id, ip in results:
            findings_count = db.query(Vulnerability).\
                join(ScanResult).\
                filter(ScanResult.scan_job_id == job_id, ScanResult.device_id == device_id).\
                count()
                
            targets.append({
                "ip": ip,
                "status": "Scanned",
                "findings_count": findings_count
            })
            
        profile_data = {
            "type": job.scan_type,
            "name": narrative["name"],
            "description": narrative["description"],
            "execution_summary": narrative["execution_summary"],
            "assessed": narrative["assessed"],
            "expected_output": narrative["expected_output"],
            "targets": targets
        }
        profiles.append(profile_data)
        
    return profiles

import logging
from celery import shared_task, chain, group
from .discovery import DiscoveryEngine
from .cloud_discovery import CloudDiscoveryEngine
from .fingerprint import FingerprintEngine
from .auth_scan import AuthScanEngine
from .correlation import CorrelationEngine
from .scoring import ScoringEngine
from .remediation import RemediationEngine
from .asset_discovery import AssetDiscoveryEngine
from utils.logger import log_scan_event

logger = logging.getLogger(__name__)

@shared_task(name="scanner.orchestrator.run_scan_pipeline")
def run_scan_pipeline(target: str, scan_type: str = "full", scan_job_id: str = None, cloud_integration: str = None, **kwargs):
    logger.info(f"Starting scan pipeline for {target} [Job: {scan_job_id}]")
    log_scan_event(scan_job_id, f"Initializing scan pipeline for target: {target} (Type: {scan_type})")

    # ---- Port Scan profile — dedicated port enumeration pipeline ----
    if scan_type == "port_scan":
        run_port_scan.delay(target, scan_job_id)
        return {"status": "started", "scan_job_id": scan_job_id}

    # ---- Service Detection profile ----
    if scan_type == "service_fingerprint":
        run_service_fingerprint.delay(target, scan_job_id)
        return {"status": "started", "scan_job_id": scan_job_id}

    # ---- Enumeration profile ----
    if scan_type == "enumeration":
        run_enumeration.delay(target, scan_job_id)
        return {"status": "started", "scan_job_id": scan_job_id}

    # ---- Vulnerability Scan profile ----
    if scan_type == "vulnerability_scan":
        run_vulnerability_scan.delay(target, scan_job_id)
        return {"status": "started", "scan_job_id": scan_job_id}
        
    # ---- Authenticated Deep Scan profile ----
    if scan_type == "authenticated":
        credential_id = kwargs.get("credential_id")
        if not credential_id:
            log_scan_event(scan_job_id, "ERROR: Authenticated scan requires a credential_id.")
            _mark_job_completed(scan_job_id, status="FAILED")
            return {"status": "failed", "reason": "Missing credential_id"}
            
        run_authenticated_scan.delay(target, scan_job_id, credential_id)
        return {"status": "started", "scan_job_id": scan_job_id}

    # ---- Risk Scoring / Severity Classification profile ----
    if scan_type == "risk_scoring":
        run_risk_scoring.delay(target, scan_job_id)
        return {"status": "started", "scan_job_id": scan_job_id}

    # ---- Full Scan (1 to 7) ----
    if scan_type in ("full", "full_scan"):
        credential_id = kwargs.get("credential_id")
        run_full_scan.delay(target, scan_job_id, credential_id)
        return {"status": "started", "scan_job_id": scan_job_id}

    # ---- Asset Discovery profile — dedicated lightweight pipeline ----
    if scan_type == "asset_discovery":
        run_asset_discovery.delay(target, scan_job_id, cloud_integration)
        return {"status": "started", "scan_job_id": scan_job_id}

    # ---- Fallback legacy pipeline ----
    credential_id = kwargs.get("credential_id")
    discovery_task = run_discovery.s(target, cloud_integration, scan_job_id)
    process_task = process_discovery.s(scan_job_id, credential_id)
    
    workflow = chain(discovery_task, process_task)
    workflow.apply_async()
    
    return {"status": "started", "scan_job_id": scan_job_id}

@shared_task(name="scanner.orchestrator.run_discovery")
def run_discovery(target: str, cloud_integration: str = None, scan_job_id: str = None):
    logger.info(f"Running discovery for target: {target}")
    log_scan_event(scan_job_id, f"Phase 1: Starting network discovery (Ping sweeps & ARP) on {target}")
    
    hosts = []
    if cloud_integration == "aws":
        log_scan_event(scan_job_id, "Querying AWS EC2 API for live instances...")
        engine = CloudDiscoveryEngine({})
        hosts = engine.discover_aws_ec2()
    elif cloud_integration == "gcp":
        log_scan_event(scan_job_id, "Querying GCP Compute Engine API for live instances...")
        engine = CloudDiscoveryEngine({})
        hosts = engine.discover_gcp_compute()
    else:
        log_scan_event(scan_job_id, f"Running local Nmap ping sweep for {target}...")
        engine = DiscoveryEngine()
        hosts = engine.scan_network(target)
        
    log_scan_event(scan_job_id, f"Discovery complete. Found {len(hosts)} live host(s).")
    return hosts

@shared_task(name="scanner.orchestrator.process_discovery")
def process_discovery(discovered_hosts: list, scan_job_id: str, credentials_id: int = None):
    logger.info(f"Processing {len(discovered_hosts)} discovered hosts for Job: {scan_job_id}")
    log_scan_event(scan_job_id, f"Phase 2: Initiating deep scans for {len(discovered_hosts)} host(s)...")
    
    from db.session import SessionLocal
    from models.assets import Device
    
    db = SessionLocal()
    try:
        tasks = []
        for host_data in discovered_hosts:
            ip = host_data.get('ip')
            
            device = db.query(Device).filter(Device.ip_address == ip).first()
            if not device:
                device = Device(ip_address=ip, os_name=host_data.get('os_family', 'Unknown'))
                db.add(device)
                db.commit()
                db.refresh(device)
            
            log_scan_event(scan_job_id, f"Queueing parallel fingerprint and correlation tasks for {ip} (Device ID: {device.id})")
            
            tasks.append(
                chain(
                    run_fingerprint.s(ip, scan_job_id),
                    run_auth_and_correlate.s(ip, device.id, credentials_id, scan_job_id)
                )
            )
            
        if tasks:
            job = group(tasks)
            job.apply_async()
        else:
            log_scan_event(scan_job_id, "No hosts to scan. Job finished.")
            # Mark job as completed
            from models.scans import ScanJob
            from datetime import datetime
            job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            if job:
                job.status = "COMPLETED"
                job.completed_at = datetime.now()
                db.commit()
    finally:
        db.close()
        
    return {"status": "processing_hosts", "count": len(discovered_hosts)}

@shared_task(name="scanner.orchestrator.run_fingerprint")
def run_fingerprint(target_ip: str, scan_job_id: str = None):
    logger.info(f"Fingerprinting {target_ip}")
    log_scan_event(scan_job_id, f"Starting Nmap port scan and OS fingerprinting on {target_ip}...")
    
    engine = FingerprintEngine()
    services = engine.scan_host(target_ip)
    
    log_scan_event(scan_job_id, f"Fingerprinting complete for {target_ip}. Discovered {len(services)} open port(s)/service(s).")
    return {"ip": target_ip, "services": services}

@shared_task(name="scanner.orchestrator.run_auth_and_correlate")
def run_auth_and_correlate(fingerprint_data: dict, target_ip: str, device_id: int, credentials_id: int, scan_job_id: str):
    logger.info(f"Running auth scan and correlation for {target_ip}")
    log_scan_event(scan_job_id, f"Phase 3: Correlating vulnerabilities for {target_ip}...")
    
    services = fingerprint_data.get("services", [])
    
    auth_engine = AuthScanEngine()
    inventory = {}
    if credentials_id:
        log_scan_event(scan_job_id, f"Executing authenticated deep scan via SSH/WinRM on {target_ip}...")
        dummy_creds = {"username": "admin", "password": "password"}
        inventory = auth_engine.scan_linux(target_ip, dummy_creds)
        log_scan_event(scan_job_id, f"Authenticated scan complete. Extracted {len(inventory.get('packages', []))} installed packages.")
        
    corr_engine = CorrelationEngine()
    score_engine = ScoringEngine()
    rem_engine = RemediationEngine()
    
    all_vulns = []
    
    for service in services:
        if service.get("cpe"):
            vulns = corr_engine.correlate_cpe(service["cpe"])
            all_vulns.extend(vulns)
            
    for pkg in inventory.get("packages", []):
        if pkg.get("cpe"):
            vulns = corr_engine.correlate_cpe(pkg["cpe"])
            all_vulns.extend(vulns)
            
    log_scan_event(scan_job_id, f"Discovered {len(all_vulns)} potential CVE matches for {target_ip}. Calculating risk scores...")
            
    findings = []
    for vuln in all_vulns:
        score_data = score_engine.calculate_risk(vuln.get("cvss_score", 5.0))
        rem_data = rem_engine.generate_remediation(vuln.get("cve_id"), "Product", "Version")
        
        vuln.update(score_data)
        vuln.update(rem_data)
        findings.append(vuln)
        
    log_scan_event(scan_job_id, f"Saving {len(findings)} correlated findings to the database for {target_ip}...")
        
    from db.session import SessionLocal
    from models.scans import ScanResult, ScanJob
    from models.vulnerabilities import Vulnerability
    from datetime import datetime
    
    db = SessionLocal()
    try:
        scan_result = ScanResult(
            scan_job_id=scan_job_id,
            device_id=device_id,
            protocol="tcp",
            service_name="various"
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        
        for vuln in findings:
            cve_id = vuln.get("cve_id")
            if not cve_id:
                continue
            # Ensure the CVE exists in cve_catalog (upsert stub record if missing)
            from models.vulnerabilities import CveCatalog
            cve_entry = db.query(CveCatalog).filter(CveCatalog.cve_id == cve_id).first()
            if not cve_entry:
                cve_entry = CveCatalog(
                    cve_id=cve_id,
                    description=vuln.get("description", ""),
                    severity=vuln.get("severity", "Medium"),
                    cvss_score=vuln.get("cvss_score", 0.0),
                )
                db.add(cve_entry)
                db.flush()
            v_record = Vulnerability(
                cve_id=cve_id,
                scan_result_id=scan_result.id,
                risk_score=vuln.get("risk_score", 50.0),
            )
            db.add(v_record)
            
        job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if job:
            job.status = "COMPLETED"
            job.completed_at = datetime.now()
            log_scan_event(scan_job_id, f"Job {scan_job_id} COMPLETED successfully.")
            
        db.commit()
    finally:
        db.close()
    
    return {"ip": target_ip, "findings_count": len(findings)}


# =====================================================================
# Asset Discovery — standalone pipeline
# =====================================================================
@shared_task(name="scanner.orchestrator.run_asset_discovery")
def run_asset_discovery(target: str, scan_job_id: str, cloud_integration: str = None, mark_completed: bool = True):
    """
    Full asset-discovery pipeline:
      1. Ping sweep   -> live hosts / IPs / MACs
      2. DNS reverse  -> hostnames
      3. OS + service fingerprint -> routers/firewalls, servers
      4. Web-app detection
      5. Container port detection
      6. Cloud instance enrichment (if cloud_integration set)
      7. Persist to asset_discovery_results + mark ScanJob COMPLETED
    """
    log_scan_event(scan_job_id, f"[Asset Discovery] Starting comprehensive asset enumeration for: {target}")

    engine = AssetDiscoveryEngine()

    # --- Step 1: Live hosts ---
    log_scan_event(scan_job_id, "Step 1/6 — Ping sweep: identifying live hosts...")
    hosts = engine.discover_live_hosts(target)
    log_scan_event(scan_job_id, f"  ✔ Found {len(hosts)} live host(s).")

    if not hosts:
        log_scan_event(scan_job_id, "No live hosts found. Completing job.")
        if mark_completed:
            _mark_job_completed(scan_job_id)
        return {"status": "completed", "assets": 0}

    # --- Step 2: Hostnames ---
    log_scan_event(scan_job_id, "Step 2/6 — Resolving hostnames via reverse DNS...")
    hosts = engine.resolve_hostnames(hosts)
    resolved = sum(1 for h in hosts if h.get("hostname"))
    log_scan_event(scan_job_id, f"  ✔ Resolved {resolved} hostname(s).")

    # --- Step 3: OS / device fingerprint ---
    log_scan_event(scan_job_id, "Step 3/6 — OS & service fingerprinting (routers / firewalls / servers)...")
    hosts = engine.fingerprint_hosts(hosts)
    roles = {}
    for h in hosts:
        roles[h.get("role", "unknown")] = roles.get(h.get("role", "unknown"), 0) + 1
    log_scan_event(scan_job_id, f"  ✔ Device roles found: {roles}")

    # --- Step 4: Web apps ---
    log_scan_event(scan_job_id, "Step 4/6 — Detecting web applications (HTTP/HTTPS services)...")
    hosts = engine.detect_web_apps(hosts)
    web_count = sum(len(h.get("web_apps", [])) for h in hosts)
    log_scan_event(scan_job_id, f"  ✔ Detected {web_count} web application(s).")

    # --- Step 5: Containers ---
    log_scan_event(scan_job_id, "Step 5/6 — Scanning for Docker / Kubernetes container endpoints...")
    hosts = engine.detect_containers(hosts)
    container_count = sum(len(h.get("containers", [])) for h in hosts)
    log_scan_event(scan_job_id, f"  ✔ Detected {container_count} container endpoint(s).")

    # --- Step 6: Cloud enrichment (stub) ---
    log_scan_event(scan_job_id, "Step 6/6 — Cloud instance enrichment...")
    if cloud_integration:
        cloud_engine = CloudDiscoveryEngine({})
        cloud_hosts = []
        if cloud_integration == "aws":
            cloud_hosts = cloud_engine.discover_aws_ec2()
        elif cloud_integration == "gcp":
            cloud_hosts = cloud_engine.discover_gcp_compute()
        elif cloud_integration == "azure":
            cloud_hosts = cloud_engine.discover_azure_vms()
        for ch in cloud_hosts:
            ch["cloud_instance"] = {"provider": cloud_integration}
            ch["role"] = "cloud_instance"
            ch.setdefault("open_ports", [])
            ch.setdefault("web_apps", [])
            ch.setdefault("containers", [])
            hosts.append(ch)
        log_scan_event(scan_job_id, f"  ✔ Added {len(cloud_hosts)} cloud instance(s) from {cloud_integration.upper()}.")
    else:
        log_scan_event(scan_job_id, "  ⓘ No cloud integration configured — skipping cloud discovery.")

    # --- Persist results ---
    log_scan_event(scan_job_id, f"Saving {len(hosts)} asset record(s) to database...")
    _persist_asset_results(scan_job_id, hosts)

    log_scan_event(scan_job_id, f"[Asset Discovery] COMPLETE — {len(hosts)} asset(s) enumerated.")
    if mark_completed:
        _mark_job_completed(scan_job_id)
    return {"status": "completed", "assets": len(hosts)}


def _persist_asset_results(scan_job_id: str, hosts: list):
    from db.session import SessionLocal
    from models.asset_discovery import AssetDiscoveryResult
    db = SessionLocal()
    try:
        for h in hosts:
            record = AssetDiscoveryResult(
                scan_job_id=scan_job_id,
                ip_address=h.get("ip", ""),
                hostname=h.get("hostname", ""),
                mac_address=h.get("mac_address", ""),
                vendor=h.get("vendor", ""),
                os_name=h.get("os_name", ""),
                os_family=h.get("os_family", ""),
                os_accuracy=str(h.get("os_accuracy", "")),
                device_type=h.get("device_type", ""),
                role=h.get("role", "host"),
                open_ports=h.get("open_ports", []),
                web_apps=h.get("web_apps", []),
                containers=h.get("containers", []),
                cloud_instance=h.get("cloud_instance"),
            )
            db.add(record)
        db.commit()
    finally:
        db.close()


def _mark_job_completed(scan_job_id: str):
    from db.session import SessionLocal
    from models.scans import ScanJob
    from datetime import datetime
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if job:
            job.status = "COMPLETED"
            job.completed_at = datetime.now()
            db.commit()
    finally:
        db.close()


# =====================================================================
# Port Scan — standalone pipeline
# =====================================================================
@shared_task(name="scanner.orchestrator.run_port_scan")
def run_port_scan(target: str, scan_job_id: str, mark_completed: bool = True):
    """
    Full port-scan pipeline:
      1. Discover live hosts (ping sweep)
      2. TCP SYN scan (all 65535 ports)
      3. UDP scan (top service ports)
      4. Service version + banner detection
      5. OS fingerprinting
      6. Persist results + compute risk summary per host
    """
    from .port_scan import PortScanEngine
    import ipaddress
    import socket as _socket

    log_scan_event(scan_job_id, f"[Port Scan] Starting comprehensive port scan for: {target}")
    engine = PortScanEngine()

    # ── Step 1: Identify target hosts ──
    log_scan_event(scan_job_id, "Step 1/6 — Identifying target host(s)...")
    target_ips = _resolve_port_scan_targets(target)
    log_scan_event(scan_job_id, f"  ✔ Resolved {len(target_ips)} target host(s): {', '.join(target_ips[:10])}{'...' if len(target_ips) > 10 else ''}")

    if not target_ips:
        log_scan_event(scan_job_id, "No target hosts resolved. Completing job.")
        if mark_completed:
            _mark_job_completed(scan_job_id)
        return {"status": "completed", "ports_found": 0}

    all_port_records = []
    host_os_info = {}

    for idx, ip in enumerate(target_ips):
        host_label = f"[{idx + 1}/{len(target_ips)}] {ip}"

        # ── Step 2: TCP SYN scan ──
        log_scan_event(scan_job_id, f"Step 2/6 — TCP SYN scan on {host_label} (all 65535 ports)...")
        tcp_results = engine.tcp_syn_scan(ip, ports="1-65535", timing="T4")
        log_scan_event(scan_job_id, f"  ✔ Found {len(tcp_results)} open TCP port(s) on {ip}.")

        # ── Step 3: UDP scan ──
        log_scan_event(scan_job_id, f"Step 3/6 — UDP scan on {host_label} (top service ports)...")
        udp_results = engine.udp_scan(ip, timing="T4")
        log_scan_event(scan_job_id, f"  ✔ Found {len(udp_results)} open/filtered UDP port(s) on {ip}.")

        # ── Step 4: Service version + banner grabbing ──
        open_tcp_ports = ",".join(str(r["port"]) for r in tcp_results)
        if open_tcp_ports:
            log_scan_event(scan_job_id, f"Step 4/6 — Service version detection on {host_label}...")
            version_results = engine.service_version_scan(ip, ports=open_tcp_ports, timing="T4")
            # Merge version data back into tcp_results
            version_map = {(r["port"], r["protocol"]): r for r in version_results}
            for rec in tcp_results:
                key = (rec["port"], rec["protocol"])
                if key in version_map:
                    vr = version_map[key]
                    rec["product"] = vr.get("product") or rec.get("product", "")
                    rec["version"] = vr.get("version") or rec.get("version", "")
                    rec["extrainfo"] = vr.get("extrainfo") or rec.get("extrainfo", "")
                    rec["cpe"] = vr.get("cpe") or rec.get("cpe", "")
                    rec["scripts"] = vr.get("scripts")
                    rec["scan_method"] = "SYN+Version"

            # Banner grabbing for ports where nmap version detection yielded nothing
            for rec in tcp_results:
                if not rec.get("product"):
                    banner = engine.grab_banner(ip, rec["port"])
                    if banner:
                        rec["banner"] = banner
            log_scan_event(scan_job_id, f"  ✔ Service detection complete for {ip}.")
        else:
            log_scan_event(scan_job_id, f"Step 4/6 — Skipped (no open TCP ports found on {ip}).")

        # ── Step 5: OS fingerprinting ──
        log_scan_event(scan_job_id, f"Step 5/6 — OS fingerprinting on {host_label}...")
        os_info = engine.os_fingerprint(ip)
        host_os_info[ip] = os_info
        os_display = os_info.get("os_name") or "Unknown"
        log_scan_event(scan_job_id, f"  ✔ OS detected: {os_display}")

        all_port_records.extend(tcp_results)
        all_port_records.extend(udp_results)

    # ── Step 6: Persist ──
    log_scan_event(scan_job_id, f"Step 6/6 — Saving {len(all_port_records)} port record(s) to database...")
    _persist_port_scan_results(scan_job_id, all_port_records, host_os_info, target_ips)

    log_scan_event(scan_job_id, f"[Port Scan] COMPLETE — {len(all_port_records)} port(s) discovered across {len(target_ips)} host(s).")
    if mark_completed:
        _mark_job_completed(scan_job_id)
    return {"status": "completed", "ports_found": len(all_port_records)}


def _resolve_port_scan_targets(target: str) -> list:
    """Resolve target string (IP, CIDR, hostname, CSV) to a list of IPs."""
    import ipaddress
    import socket as _socket

    ips = set()
    # Split on spaces and commas
    tokens = target.replace(",", " ").split()
    for t in tokens:
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses <= 256:
                for addr in net.hosts():
                    ips.add(str(addr))
            else:
                # For very large CIDRs, limit to first 256 for port scanning
                count = 0
                for addr in net.hosts():
                    ips.add(str(addr))
                    count += 1
                    if count >= 256:
                        break
        except ValueError:
            # Treat as hostname
            try:
                resolved = _socket.gethostbyname(t)
                ips.add(resolved)
            except _socket.gaierror:
                pass
    return sorted(ips)


def _persist_port_scan_results(scan_job_id: str, port_records: list, os_info: dict, target_ips: list):
    from db.session import SessionLocal
    from models.port_scan import PortScanResult, PortScanSummary
    import socket as _socket

    db = SessionLocal()
    try:
        # Persist individual port records
        for rec in port_records:
            record = PortScanResult(
                scan_job_id=scan_job_id,
                ip_address=rec.get("ip", ""),
                port=rec.get("port", 0),
                protocol=rec.get("protocol", "tcp"),
                state=rec.get("state", "open"),
                service=rec.get("service", ""),
                product=rec.get("product", ""),
                version=rec.get("version", ""),
                extrainfo=rec.get("extrainfo", ""),
                cpe=rec.get("cpe", ""),
                banner=rec.get("banner", ""),
                scan_method=rec.get("scan_method", ""),
                risk=rec.get("risk", "LOW"),
                reason=rec.get("reason", ""),
                scripts=rec.get("scripts"),
            )
            db.add(record)

        # Compute per-host summaries
        from collections import defaultdict
        host_ports = defaultdict(list)
        for rec in port_records:
            host_ports[rec["ip"]].append(rec)

        for ip in target_ips:
            records = host_ports.get(ip, [])
            tcp_count = sum(1 for r in records if r["protocol"] == "tcp")
            udp_count = sum(1 for r in records if r["protocol"] == "udp")
            critical_count = sum(1 for r in records if r.get("risk") == "CRITICAL")
            high_count = sum(1 for r in records if r.get("risk") == "HIGH")

            if critical_count > 0:
                overall = "CRITICAL"
            elif high_count > 0:
                overall = "HIGH"
            elif len(records) > 20:
                overall = "MEDIUM"
            else:
                overall = "LOW"

            host_info = os_info.get(ip, {})
            # Resolve hostname
            try:
                hostname = _socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""

            summary = PortScanSummary(
                scan_job_id=scan_job_id,
                ip_address=ip,
                hostname=hostname,
                os_name=host_info.get("os_name", ""),
                os_family=host_info.get("os_family", ""),
                os_accuracy=str(host_info.get("os_accuracy", "")),
                device_type=host_info.get("device_type", ""),
                total_open_ports=len(records),
                tcp_open=tcp_count,
                udp_open=udp_count,
                critical_ports=critical_count,
                high_risk_ports=high_count,
                overall_risk=overall,
            )
            db.add(summary)

        db.commit()
    finally:
        db.close()


# =====================================================================
# Service Fingerprinting — standalone pipeline
# =====================================================================
@shared_task(name="scanner.orchestrator.run_service_fingerprint")
def run_service_fingerprint(target: str, scan_job_id: str, mark_completed: bool = True):
    from .service_detection import ServiceDetectionEngine

    log_scan_event(scan_job_id, f"[Service Fingerprint] Starting service detection for: {target}")
    engine = ServiceDetectionEngine()

    target_ips = _resolve_port_scan_targets(target)
    if not target_ips:
        log_scan_event(scan_job_id, "No target hosts resolved. Completing job.")
        if mark_completed:
            _mark_job_completed(scan_job_id)
        return {"status": "completed"}

    all_results = []
    for idx, ip in enumerate(target_ips):
        host_label = f"[{idx + 1}/{len(target_ips)}] {ip}"
        log_scan_event(scan_job_id, f"Scanning {host_label} for open ports and services...")
        
        # We reuse the port scan logic conceptually, but rely entirely on ServiceDetectionEngine
        results = engine.detect_services(ip)
        if results:
            log_scan_event(scan_job_id, f"  ✔ Detected {len(results)} service(s) on {ip}.")
            all_results.extend(results)
        else:
            log_scan_event(scan_job_id, f"  ⓘ No services detected on {ip}.")

    # Persist
    log_scan_event(scan_job_id, f"Saving {len(all_results)} service record(s) to database...")
    from db.session import SessionLocal
    from models.service_fingerprint import ServiceFingerprintResult
    
    db = SessionLocal()
    try:
        for r in all_results:
            record = ServiceFingerprintResult(
                scan_job_id=scan_job_id,
                ip_address=r.get("ip", ""),
                port=r.get("port", 0),
                protocol=r.get("protocol", "tcp"),
                service=r.get("service", ""),
                product=r.get("product", ""),
                version=r.get("version", ""),
                extrainfo=r.get("extrainfo", ""),
                cpe=r.get("cpe", ""),
                banner=r.get("banner", ""),
                http_server=r.get("http_server", "")
            )
            db.add(record)
        db.commit()
    finally:
        db.close()

    log_scan_event(scan_job_id, f"[Service Fingerprint] COMPLETE.")
    if mark_completed:
        _mark_job_completed(scan_job_id)
    return {"status": "completed", "services_found": len(all_results)}


# =====================================================================
# Enumeration — standalone pipeline
# =====================================================================
@shared_task(name="scanner.orchestrator.run_enumeration")
def run_enumeration(target: str, scan_job_id: str, mark_completed: bool = True):
    from .enumeration import EnumerationEngine
    from db.session import SessionLocal
    from models.enumeration import EnumerationResult

    log_scan_event(scan_job_id, f"[Enumeration] Starting deep enumeration for: {target}")
    engine = EnumerationEngine()

    target_ips = _resolve_port_scan_targets(target)
    if not target_ips:
        log_scan_event(scan_job_id, "No target hosts resolved. Completing job.")
        if mark_completed:
            _mark_job_completed(scan_job_id)
        return {"status": "completed"}

    # Target format for Nmap
    target_string = " ".join(target_ips)
    log_scan_event(scan_job_id, f"Running NSE scripts (SMB, SNMP, DNS, SSL) on targets...")
    
    results = engine.run_enumeration(target_string)
    
    if not results:
        log_scan_event(scan_job_id, f"  ⓘ No enumeration data found.")
    else:
        log_scan_event(scan_job_id, f"  ✔ Extracted data for {len(results)} host(s).")

    # Persist
    log_scan_event(scan_job_id, f"Saving enumeration record(s) to database...")
    db = SessionLocal()
    try:
        for ip, data in results.items():
            record = EnumerationResult(
                scan_job_id=scan_job_id,
                ip_address=ip,
                smb_shares=data.get("smb_shares", []),
                smb_users=data.get("smb_users", []),
                snmp_sysdescr=data.get("snmp_sysdescr", ""),
                snmp_interfaces=data.get("snmp_interfaces", []),
                dns_records=data.get("dns_records", []),
                ssl_certs=data.get("ssl_certs", []),
                os_info=data.get("os_info", "")
            )
            db.add(record)
        db.commit()
    finally:
        db.close()

    log_scan_event(scan_job_id, f"[Enumeration] COMPLETE.")
    if mark_completed:
        _mark_job_completed(scan_job_id)
    return {"status": "completed", "hosts_enumerated": len(results)}


# =====================================================================
# Vulnerability Scan — standalone pipeline
# =====================================================================
@shared_task(name="scanner.orchestrator.run_vulnerability_scan")
def run_vulnerability_scan(target: str, scan_job_id: str, mark_completed: bool = True):
    from .vulnerability_scan import VulnerabilityScanEngine
    from db.session import SessionLocal
    from models.vulnerability_scan import VulnerabilityScanFinding

    log_scan_event(scan_job_id, f"[VulnScan] Starting Vulnerability Detection on: {target}")
    engine = VulnerabilityScanEngine()

    target_ips = _resolve_port_scan_targets(target)
    if not target_ips:
        log_scan_event(scan_job_id, "No target hosts resolved. Completing job.")
        if mark_completed:
            _mark_job_completed(scan_job_id)
        return {"status": "completed"}

    target_string = " ".join(target_ips)
    log_scan_event(scan_job_id, f"Running Nmap vulnerability scripts and CVE correlation...")
    
    results = engine.run_vulnerability_scan(target_string)
    
    total_findings = 0
    if not results:
        log_scan_event(scan_job_id, f"  ⓘ No vulnerabilities or misconfigurations found.")
    else:
        for r in results:
            total_findings += len(r.get("cves", [])) + len(r.get("misconfigurations", []))
        log_scan_event(scan_job_id, f"  🚨 Identified {total_findings} weaknesses across {len(results)} services.")

    # Persist
    log_scan_event(scan_job_id, f"Saving vulnerability record(s) to database...")
    db = SessionLocal()
    try:
        for data in results:
            record = VulnerabilityScanFinding(
                scan_job_id=scan_job_id,
                ip_address=data["ip"],
                port=data["port"],
                protocol=data["protocol"],
                service=data["service"],
                product=data["product"],
                cves=data.get("cves", []),
                misconfigurations=data.get("misconfigurations", [])
            )
            db.add(record)
        db.commit()
    finally:
        db.close()


    # Sync to global tracker
    sync_findings_to_global_tracker(scan_job_id)

    log_scan_event
    if mark_completed:
        _mark_job_completed(scan_job_id)
    return {"status": "completed", "weaknesses_found": total_findings}


# =====================================================================
# Authenticated Deep Scan
# =====================================================================
@shared_task(name="scanner.orchestrator.run_authenticated_scan")
def run_authenticated_scan(target: str, scan_job_id: str, credential_id: int, mark_completed: bool = True):
    from .auth_scan import AuthScanEngine
    from db.session import SessionLocal
    from models.assets import CredentialStore, Device, InstalledSoftware
    from models.auth_scan import AuthScanFinding
    
    log_scan_event(scan_job_id, f"[AuthScan] Starting Authenticated Deep Scan on: {target}")
    
    db = SessionLocal()
    try:
        cred = db.query(CredentialStore).filter(CredentialStore.id == credential_id).first()
        if not cred:
            log_scan_event(scan_job_id, f"ERROR: Credential ID {credential_id} not found.")
            if mark_completed:
                _mark_job_completed(scan_job_id)
            return {"status": "failed", "reason": "credential not found"}
            
        credentials = {
            "username": cred.username,
            "encrypted_password": cred.encrypted_password,
            "private_key": cred.private_key
        }
        
        target_ips = _resolve_port_scan_targets(target)
        if not target_ips:
            log_scan_event(scan_job_id, "No target hosts resolved.")
            if mark_completed:
                _mark_job_completed(scan_job_id)
            return {"status": "completed"}
            
        engine = AuthScanEngine()
        
        for ip in target_ips:
            log_scan_event(scan_job_id, f"Connecting to {ip} via {cred.auth_type.upper()}...")
            if cred.auth_type.lower() == 'ssh':
                results = engine.scan_linux(ip, credentials)
            elif cred.auth_type.lower() == 'winrm':
                results = engine.scan_windows(ip, credentials)
            else:
                log_scan_event(scan_job_id, f"Unsupported auth_type: {cred.auth_type}")
                continue
                
            if not results.get("packages") and not results.get("os_details"):
                log_scan_event(scan_job_id, f"Failed to retrieve data from {ip}. Check credentials or connectivity.")
                continue
                
            log_scan_event(scan_job_id, f"Successfully extracted {len(results.get('packages', []))} software packages and {len(results.get('local_users', []))} users from {ip}.")
            
            # Save to scan-specific history
            record = AuthScanFinding(
                scan_job_id=scan_job_id,
                ip_address=ip,
                os_details=results.get('os_details'),
                packages=results.get('packages', []),
                local_users=results.get('local_users', []),
                patch_levels=results.get('patch_levels', [])
            )
            db.add(record)
            
            # Also push to global Device Inventory
            device = db.query(Device).filter(Device.ip_address == ip).first()
            if not device:
                device = Device(ip_address=ip, os_name=results.get('os_details'))
                db.add(device)
                db.flush()
                
            for pkg in results.get('packages', []):
                # Simple deduplication
                existing = db.query(InstalledSoftware).filter(
                    InstalledSoftware.device_id == device.id,
                    InstalledSoftware.name == pkg.get("name")
                ).first()
                if not existing:
                    soft = InstalledSoftware(
                        device_id=device.id,
                        name=pkg.get("name"),
                        version=pkg.get("version"),
                        cpe=pkg.get("cpe")
                    )
                    db.add(soft)
            
        db.commit()
    except Exception as e:
        log_scan_event(scan_job_id, f"Fatal error during authenticated scan: {e}")
        db.rollback()
    finally:
        db.close()
        
    log_scan_event(scan_job_id, f"[AuthScan] COMPLETE.")
    if mark_completed:
        _mark_job_completed(scan_job_id)
    return {"status": "completed"}



# =====================================================================
# Validation & Verification Scan
# =====================================================================
@shared_task(name="scanner.orchestrator.run_validation")
def run_validation(target: str, scan_job_id: str, mark_completed: bool = True):
    from scanner.validation import ValidationEngine
    from db.session import SessionLocal
    from models.vulnerability_scan import VulnerabilityScanFinding
    from models.validation import ValidationResult
    
    log_scan_event(scan_job_id, f"[Validation] Starting Validation & Verification on: {target}")
    
    db = SessionLocal()
    engine = ValidationEngine()
    try:
        # Fetch findings to validate
        findings = db.query(VulnerabilityScanFinding).filter(VulnerabilityScanFinding.scan_job_id == scan_job_id).all()
        if not findings:
            log_scan_event(scan_job_id, "[Validation] No findings to validate. Completing job.")
            if mark_completed:
                _mark_job_completed(scan_job_id)
            return {"status": "completed"}
            
        total_validated = 0
        total_fps = 0
        
        for finding in findings:
            cves = []
            if finding.cves:
                c_list = finding.cves if isinstance(finding.cves, list) else []
                cves.extend(c_list)
                
            if finding.misconfigurations:
                m_list = finding.misconfigurations if isinstance(finding.misconfigurations, list) else []
                # Map misconfigs to dict format for engine
                for m in m_list:
                    import hashlib
                    m_str = str(m)
                    cves.append({
                        "id": f"MISC-{hashlib.md5(m_str.encode()).hexdigest()[:8].upper()}",
                        "description": m_str
                    })
                    
            if not cves:
                continue
                
            log_scan_event(scan_job_id, f"[Validation] Verifying {len(cves)} finding(s) on {finding.ip_address}:{finding.port}...")
            
            results = engine.validate_findings(
                ip_address=finding.ip_address,
                cves=cves,
                port=finding.port,
                protocol=finding.protocol
            )
            
            for res in results:
                v_record = ValidationResult(
                    scan_job_id=scan_job_id,
                    ip_address=finding.ip_address,
                    vulnerability_id=res["vulnerability_id"],
                    is_confirmed=res["is_confirmed"],
                    is_false_positive=res["is_false_positive"],
                    verification_method=res["verification_method"],
                    proof_of_concept=res["proof_of_concept"]
                )
                db.add(v_record)
                total_validated += 1
                if res["is_false_positive"]:
                    total_fps += 1
                    
        db.commit()
        log_scan_event(scan_job_id, f"[Validation] Validated {total_validated} findings. Flagged {total_fps} false positives.")
    except Exception as e:
        log_scan_event(scan_job_id, f"Fatal error during validation: {e}")
        db.rollback()
        return {"status": "error"}
    finally:
        db.close()
        
    if mark_completed:
        _mark_job_completed(scan_job_id)
    return {"status": "completed", "validated": total_validated, "false_positives": total_fps}


# =====================================================================
# Risk Scoring / Severity Classification
# =====================================================================
@shared_task(name="scanner.orchestrator.run_risk_scoring")
def run_risk_scoring(target: str, scan_job_id: str, mark_completed: bool = True):
    from db.session import SessionLocal
    from models.vulnerability_scan import VulnerabilityScanFinding
    from models.risk_scoring import RiskScoringResult
    from .scoring import ScoringEngine
    import ipaddress
    
    log_scan_event(scan_job_id, f"[RiskScoring] Starting Contextual Risk Scoring on: {target}")
    
    db = SessionLocal()
    engine = ScoringEngine()
    try:
        target_ips = _resolve_port_scan_targets(target)
        if not target_ips:
            log_scan_event(scan_job_id, "No target hosts resolved.")
            if mark_completed:
                _mark_job_completed(scan_job_id)
            return {"status": "completed"}
            
        total_scored = 0
        
        for ip in target_ips:
            # Simple heuristic for internet exposure
            is_public = False
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    is_public = True
            except:
                pass
                
            environmental_factors = {
                "is_publicly_exposed": is_public,
                "contains_sensitive_data": False, # Default
                "is_kev": False
            }
            
            # Fetch existing vulnerabilities for this IP from recent scans
            vulns = db.query(VulnerabilityScanFinding).filter(
                VulnerabilityScanFinding.ip_address == ip
            ).all()
            
            from models.validation import ValidationResult
            
            validations = db.query(ValidationResult).filter(
                ValidationResult.scan_job_id == scan_job_id,
                ValidationResult.ip_address == ip
            ).all()
            val_map = {v.vulnerability_id: v for v in validations}
            
            if not vulns:
                log_scan_event(scan_job_id, f"No existing vulnerabilities found for {ip}. Please run a Vulnerability Scan first.")
                continue
                
            for v_record in vulns:
                for cve in (v_record.cves or []):
                    # Default cvss if not present
                    cvss = cve.get("cvss")
                    if not cvss:
                        if cve.get("severity") == "Critical": cvss = 9.5
                        elif cve.get("severity") == "High": cvss = 7.5
                        elif cve.get("severity") == "Medium": cvss = 5.5
                        elif cve.get("severity") == "Low": cvss = 2.5
                        else: cvss = 0.0
                        
                    calc = engine.calculate_risk(cvss, environmental_factors)
                    
                    # Apply False Positive Override
                    vuln_id = cve.get("id", "Unknown")
                    if vuln_id in val_map and val_map[vuln_id].is_false_positive:
                        calc["risk_score"] = 0.0
                        calc["severity"] = "False Positive"
                    
                    risk_result = RiskScoringResult(
                        scan_job_id=scan_job_id,
                        ip_address=ip,
                        vulnerability_id=cve.get("id", "Unknown"),
                        description=cve.get("description", ""),
                        base_severity=cve.get("severity", "Info"),
                        base_score=cvss * 10, # Normalizing to 100 scale for comparison
                        environmental_factors=environmental_factors,
                        adjusted_score=calc["risk_score"],
                        final_severity=calc["severity"]
                    )
                    db.add(risk_result)
                    total_scored += 1
                    
                    # Update the Global Vulnerability Tracker
                    from models.vulnerabilities import Vulnerability
                    from models.scans import ScanResult
                    from models.assets import Device
                    
                    # Join through Device to get the right ScanResult
                    device = db.query(Device).filter(Device.ip_address == ip).first()
                    if device:
                        scan_res = db.query(ScanResult).filter(
                            ScanResult.device_id == device.id,
                            ScanResult.scan_job_id == scan_job_id
                        ).first()
                        if scan_res:
                            global_vuln = db.query(Vulnerability).filter(
                                Vulnerability.scan_result_id == scan_res.id,
                                Vulnerability.cve_id == cve.get("id")
                            ).first()
                            
                            if global_vuln:
                                global_vuln.risk_score = calc["risk_score"]
                    
        db.commit()
        log_scan_event(scan_job_id, f"[RiskScoring] Processed {total_scored} vulnerabilities.")
    except Exception as e:
        log_scan_event(scan_job_id, f"Fatal error during risk scoring: {e}")
        db.rollback()
    finally:
        db.close()
        
    log_scan_event(scan_job_id, f"[RiskScoring] COMPLETE.")
    if mark_completed:
        _mark_job_completed(scan_job_id)
    return {"status": "completed"}



# =====================================================================
# Full Scan Orchestrator
# =====================================================================
@shared_task(name="scanner.orchestrator.run_full_scan")
def run_full_scan(target: str, scan_job_id: str, credential_id: str = None):
    log_scan_event(scan_job_id, f"=== STARTING FULL SCAN FOR {target} ===")
    
    # Step 1: Asset Discovery
    log_scan_event(scan_job_id, "[Step 1/7] Asset Discovery...")
    run_asset_discovery(target, scan_job_id, cloud_integration=None, mark_completed=False)
    
    # Step 2: Port Scan
    log_scan_event(scan_job_id, "[Step 2/7] Port Scan...")
    run_port_scan(target, scan_job_id, mark_completed=False)
    
    # Step 3: Service Fingerprint
    log_scan_event(scan_job_id, "[Step 3/7] Service Fingerprint...")
    run_service_fingerprint(target, scan_job_id, mark_completed=False)
    
    # Step 4: Enumeration
    log_scan_event(scan_job_id, "[Step 4/7] System Enumeration...")
    run_enumeration(target, scan_job_id, mark_completed=False)
    
    # Step 5: Vulnerability Scan
    log_scan_event(scan_job_id, "[Step 5/7] Vulnerability Detection...")
    run_vulnerability_scan(target, scan_job_id, mark_completed=False)
    
    # Step 6: Authenticated Scan (if credentials provided)
    if credential_id:
        log_scan_event(scan_job_id, "[Step 6/7] Authenticated Deep Scan...")
        run_authenticated_scan(target, scan_job_id, int(credential_id), mark_completed=False)
    else:
        log_scan_event(scan_job_id, "[Step 6/7] Authenticated Deep Scan skipped (No credentials provided).")
        
    # Step 7: Risk Scoring
    log_scan_event(scan_job_id, "[Step 7/7] Risk Scoring & Severity Classification...")
    run_risk_scoring(target, scan_job_id, mark_completed=False)
    
    # Step 8: Sync to Global Tracker
    log_scan_event(scan_job_id, "[Step 8] Syncing modular findings to Global Tracker...")
    sync_findings_to_global_tracker(scan_job_id)
    
    # Finally, mark completed
    _mark_job_completed(scan_job_id)
    
    log_scan_event(scan_job_id, f"=== FULL SCAN COMPLETED FOR {target} ===")
    return {"status": "completed"}

# =====================================================================
# Synchronize Modular Findings to Global Tracker
# =====================================================================
def sync_findings_to_global_tracker(scan_job_id: str):
    from db.session import SessionLocal
    from models.scans import ScanResult, ScanJob
    from models.vulnerabilities import Vulnerability, CveCatalog, RemediationLibrary
    from models.assets import Device
    from models.vulnerability_scan import VulnerabilityScanFinding
    
    log_scan_event(scan_job_id, "[Sync] Synchronizing scan findings with Global Tracker...")
    
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return
            
        # Get all raw findings from this job
        findings = db.query(VulnerabilityScanFinding).filter(VulnerabilityScanFinding.scan_job_id == scan_job_id).all()
        
        sync_count = 0
        for finding in findings:
            # 1. Ensure Device exists
            device = db.query(Device).filter(Device.ip_address == finding.ip_address).first()
            if not device:
                device = Device(ip_address=finding.ip_address, os_name="Unknown")
                db.add(device)
                db.flush()
                
            # 2. Ensure ScanResult exists
            scan_result = db.query(ScanResult).filter(
                ScanResult.scan_job_id == scan_job_id,
                ScanResult.device_id == device.id
            ).first()
            if not scan_result:
                scan_result = ScanResult(
                    scan_job_id=scan_job_id,
                    device_id=device.id,
                    protocol=finding.protocol or "tcp",
                    service_name=finding.service or "unknown"
                )
                db.add(scan_result)
                db.flush()
                
            # 3. Add Vulnerabilities
            cves = finding.cves
            if isinstance(cves, str):
                import json
                cves = json.loads(cves)
                
            for cve_obj in cves:
                if isinstance(cve_obj, dict):
                    cve_id = cve_obj.get("id")
                    severity = cve_obj.get("severity", "High")
                    desc = cve_obj.get("description", "Automatically populated from scan.")
                    cvss = float(cve_obj.get("cvss", 7.0))
                else:
                    cve_id = str(cve_obj)
                    severity = "High"
                    desc = "Automatically populated from scan."
                    cvss = 7.0
                    
                if not cve_id:
                    continue
                    
                # Ensure CVE in catalog
                cve_entry = db.query(CveCatalog).filter(CveCatalog.cve_id == cve_id).first()
                if not cve_entry:
                    cve_entry = CveCatalog(
                        cve_id=cve_id,
                        description=desc,
                        severity=severity,
                        cvss_score=cvss
                    )
                    db.add(cve_entry)
                    db.flush()
                
                # Check if this vuln is already tracked for this scan_result
                existing_vuln = db.query(Vulnerability).filter(
                    Vulnerability.scan_result_id == scan_result.id,
                    Vulnerability.cve_id == cve_id
                ).first()
                
                if not existing_vuln:
                    v_record = Vulnerability(
                        cve_id=cve_id,
                        scan_result_id=scan_result.id,
                        risk_score=cvss * 10, # default risk score
                        status="Open"
                    )
                    db.add(v_record)
                    db.flush()
                    sync_count += 1
                    
                    # 4. Generate Remediation
                    existing_rem = db.query(RemediationLibrary).filter(RemediationLibrary.vulnerability_id == v_record.id).first()
                    if not existing_rem:
                        rem = RemediationLibrary(
                            vulnerability_id=v_record.id,
                            patch_version="Latest",
                            recommended_update=f"Apply latest vendor patches for {finding.product or 'the affected service'}.",
                            workaround="Isolate service if patch is unavailable.",
                            mitigation="Restrict network access to affected port."
                        )
                        db.add(rem)
                        
            # Also process misconfigurations as vulnerabilities
            misconfigs = finding.misconfigurations
            if isinstance(misconfigs, str):
                import json
                try:
                    misconfigs = json.loads(misconfigs)
                except:
                    misconfigs = []
            if not misconfigs:
                misconfigs = []
                
            import hashlib
            for idx, misc in enumerate(misconfigs):
                misc_text = str(misc)
                # Create a pseudo-CVE ID for the misconfiguration
                misc_hash = hashlib.md5(misc_text.encode()).hexdigest()[:8]
                misc_id = f"MISC-{misc_hash.upper()}"
                
                # Ensure pseudo-CVE in catalog
                cve_entry = db.query(CveCatalog).filter(CveCatalog.cve_id == misc_id).first()
                if not cve_entry:
                    cve_entry = CveCatalog(
                        cve_id=misc_id,
                        description=misc_text,
                        severity="Medium",
                        cvss_score=5.0
                    )
                    db.add(cve_entry)
                    db.flush()
                    
                existing_vuln = db.query(Vulnerability).filter(
                    Vulnerability.scan_result_id == scan_result.id,
                    Vulnerability.cve_id == misc_id
                ).first()
                
                if not existing_vuln:
                    v_record = Vulnerability(
                        cve_id=misc_id,
                        scan_result_id=scan_result.id,
                        risk_score=50.0,
                        status="Open"
                    )
                    db.add(v_record)
                    db.flush()
                    sync_count += 1
                    
                    rem = RemediationLibrary(
                        vulnerability_id=v_record.id,
                        patch_version="N/A",
                        recommended_update="Review configuration against security best practices.",
                        workaround="Apply secure configuration changes.",
                        mitigation="Disable insecure features or protocols."
                    )
                    db.add(rem)
        
        db.commit()
        log_scan_event(scan_job_id, f"[Sync] Successfully correlated {sync_count} vulnerabilities into the Global Tracker.")
    except Exception as e:
        logger.error(f"Sync error: {e}")
        db.rollback()
    finally:
        db.close()

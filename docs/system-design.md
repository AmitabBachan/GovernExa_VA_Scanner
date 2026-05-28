# VulnScope System Design

## Shared Interfaces

### Module Contracts
Each engine in the scanner is designed as a standalone Python class conforming to expected I/O types.
- `DiscoveryEngine.discover(target: str) -> List[AssetSchema]`
- `FingerprintEngine.scan(ip: str, ports: List[int]) -> List[ServiceSchema]`
- `AuthEngine.inventory(ip: str, credentials: dict) -> SoftwareInventorySchema`
- `CorrelationEngine.correlate(software: SoftwareInventorySchema) -> List[CVEResultSchema]`
- `ScoringEngine.score(cves: List[CVEResultSchema]) -> RiskScoreSchema`

## Shared Schemas
We use Pydantic models centrally defined in `backend/schemas/` to enforce data integrity across service boundaries.

- **AssetSchema**: IP, Hostname, MAC Address, Status.
- **ServiceSchema**: Port, Protocol, Service Name, Version, Product.
- **VulnerabilitySchema**: CVE ID, Severity, CVSS, Risk Score.

## High-level Design Flow
1. **Trigger**: User initiates a scan from Frontend -> API.
2. **Orchestration**: API writes Job to DB and drops message on Redis queue.
3. **Execution**: Celery worker picks up job.
   - Executes Discovery (Nmap/Scapy).
   - For each found IP, executes Fingerprinting.
   - Executes Auth Scan for deep software inventory.
   - Correlates inventory/services to local CVE DB.
   - Applies business logic Risk Scoring.
4. **Completion**: Updates DB and triggers Report Engine.

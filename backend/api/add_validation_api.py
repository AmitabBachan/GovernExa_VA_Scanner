import re

with open('backend/api/routers/scan.py', 'r', encoding='utf-8') as f:
    content = f.read()

validation_endpoint = """
@router.get("/{scan_job_id}/validation", tags=["Scanning"])
def get_validation_results(
    scan_job_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    \"\"\"Return validation & verification results for a specific scan job.\"\"\"
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
"""

content += validation_endpoint

with open('backend/api/routers/scan.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("scan.py updated")

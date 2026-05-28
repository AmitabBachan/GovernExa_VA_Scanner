import json
from typing import Dict, Any

ENRICHMENT_SYSTEM_PROMPT = """You are a senior cybersecurity analyst and vulnerability management expert. 
Your task is to analyze vulnerability findings and enrich them with clear, actionable insights.

You MUST return ONLY a valid JSON object matching the exact structure below. Do not include markdown formatting like ```json or any other text outside the JSON object.

Required JSON Structure:
{
    "plain_language_explanation": "A clear, non-jargon explanation of what the vulnerability is, why it matters, and the risk it introduces.",
    "business_impact": "An assessment of the likelihood of exploitation, potential operational impact, and data exposure risk.",
    "technical_remediation": "Specific technical steps to patch or resolve the issue, including fixed versions and references to vendor advisories if known.",
    "mitigation_plan": "Short-term containment steps, workarounds, compensating controls, or firewall restrictions if a patch cannot be applied immediately.",
    "verification": "Instructions on how the security team can verify that the remediation was successful and how to re-scan for the issue."
}
"""

def build_enrichment_prompt(finding: Dict[str, Any]) -> str:
    """
    Constructs the user prompt string based on the vulnerability finding data.
    """
    # Extract relevant data with fallbacks
    title = finding.get('title', 'Unknown Vulnerability')
    severity = finding.get('severity', 'Unknown Severity')
    description = finding.get('description', 'No description provided.')
    cves = finding.get('cves', [])
    affected_asset = finding.get('asset', 'Unknown Asset')
    
    # Format CVEs safely if it's a list
    if isinstance(cves, list):
        cves_str = ", ".join(cves) if cves else "None"
    else:
        cves_str = str(cves)

    prompt = f"""Please analyze and enrich the following vulnerability finding:

Title: {title}
Severity: {severity}
CVEs: {cves_str}
Affected Asset: {affected_asset}

Original Description / Details:
{description}

Using your expertise, provide the requested JSON payload with the five specific enrichment fields.
"""
    return prompt

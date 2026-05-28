import os
import json
from typing import Dict, Any

from .prompts import ENRICHMENT_SYSTEM_PROMPT, build_enrichment_prompt
from .llm_client import LLMClient

class AIEnrichmentEngine:
    """
    Engine to enrich vulnerability findings with AI-generated explanations and mitigation plans.
    """
    def __init__(self, config: Dict[str, str] = None):
        if config is None:
            config = {}
        
        # It relies on the environment variables already being loaded (e.g. via python-dotenv 
        # or pydantic-settings in the main application lifecycle) as a fallback.
        ai_mode = config.get("ai_report_mode", os.environ.get("AI_REPORT_MODE", "false")).lower()
        self.ai_report_mode = (ai_mode == "true")
        
        if self.ai_report_mode:
            self.client = LLMClient(config)
        else:
            self.client = None

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enriches a single vulnerability finding.
        If AI_REPORT_MODE=true, calls the configured LLM API.
        If false, passes through the data unmodified.
        """
        if not self.ai_report_mode:
            return finding

        system_prompt = ENRICHMENT_SYSTEM_PROMPT
        user_prompt = build_enrichment_prompt(finding)

        enrichment_data = self.client.generate_json(system_prompt, user_prompt)

        if enrichment_data:
            # Append generated sections to the finding
            finding["ai_enrichment"] = {
                "plain_language_explanation": enrichment_data.get("plain_language_explanation", "Not provided."),
                "business_impact": enrichment_data.get("business_impact", "Not provided."),
                "technical_remediation": enrichment_data.get("technical_remediation", "Not provided."),
                "mitigation_plan": enrichment_data.get("mitigation_plan", "Not provided."),
                "verification": enrichment_data.get("verification", "Not provided.")
            }
        else:
            finding["ai_enrichment_error"] = "Failed to generate AI enrichment or no valid credentials found."

        return finding

    def enrich_findings_batch(self, findings: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        """
        Enriches a batch of findings.
        """
        if not self.ai_report_mode:
            return findings
            
        return [self.enrich_finding(f) for f in findings]

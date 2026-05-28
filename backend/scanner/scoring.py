from typing import Dict, Any

class ScoringEngine:
    """
    Calculates context-aware risk scores for vulnerabilities.
    """
    def calculate_risk(self, cvss: float, environmental_factors: Dict[str, Any] = None) -> Dict[str, Any]:
        environmental_factors = environmental_factors or {}
        
        # Base score based on CVSS v3.1/v4.0
        score = cvss * 10
        
        # Cloud/Environment specific multipliers
        if environmental_factors.get("is_publicly_exposed", False):
            score += 15
            
        if environmental_factors.get("contains_sensitive_data", False):
            score += 20
            
        if environmental_factors.get("is_kev", False):
            score += 25 # Known Exploited Vulnerability

        final_score = min(max(score, 0), 100)
        
        severity = self._map_severity(final_score)
        
        return {
            "risk_score": round(final_score, 2),
            "severity": severity,
            "priority": self._map_priority(severity)
        }

    def _map_severity(self, score: float) -> str:
        if score >= 90: return "Critical"
        if score >= 70: return "High"
        if score >= 40: return "Medium"
        if score > 0: return "Low"
        return "Info"
        
    def _map_priority(self, severity: str) -> int:
        return {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5}.get(severity, 5)

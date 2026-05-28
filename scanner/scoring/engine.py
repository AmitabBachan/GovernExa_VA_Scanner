from typing import Dict, Any

class ScoringEngine:
    def __init__(self):
        pass

    def calculate_risk(self, cvss: float, epss: float = 0.0, is_kev: bool = False, 
                       internet_exposure: bool = False, business_criticality: str = "Medium",
                       exploit_available: bool = False) -> Dict[str, Any]:
        """
        Calculates a contextual risk score based on multiple factors.
        Base score is CVSS (0-10).
        """
        score = cvss * 10 # Scale to 0-100
        
        # Adjust for Exploitability
        if is_kev:
            score += 20
        elif exploit_available:
            score += 10
            
        # Adjust for EPSS (probability of exploitation in the next 30 days)
        if epss > 0.5:
            score += 10
            
        # Adjust for exposure
        if internet_exposure:
            score += 15
            
        # Adjust for business criticality
        criticality_weight = {
            "Low": -10,
            "Medium": 0,
            "High": 10,
            "Critical": 20
        }
        score += criticality_weight.get(business_criticality, 0)
        
        # Cap score at 100
        final_score = min(max(score, 0), 100)
        
        severity = self._determine_severity(final_score)
        priority = self._determine_priority(severity)
        
        return {
            "risk_score": round(final_score, 2),
            "severity": severity,
            "priority": priority
        }

    def _determine_severity(self, score: float) -> str:
        if score >= 90:
            return "Critical"
        elif score >= 70:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score > 0:
            return "Low"
        return "Info"
        
    def _determine_priority(self, severity: str) -> int:
        mapping = {
            "Critical": 1,
            "High": 2,
            "Medium": 3,
            "Low": 4,
            "Info": 5
        }
        return mapping.get(severity, 5)

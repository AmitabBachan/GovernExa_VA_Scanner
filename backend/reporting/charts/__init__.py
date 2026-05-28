"""
Chart generation package for reporting.
"""

from .colour_palette import get_profile_colour, get_severity_colour
from .chart_generator import (
    generate_severity_pie_chart,
    generate_vulnerabilities_by_profile_chart,
    generate_vulnerabilities_by_host_chart,
    generate_remediation_progress_chart,
    generate_risk_trend_chart
)

__all__ = [
    'get_profile_colour',
    'get_severity_colour',
    'generate_severity_pie_chart',
    'generate_vulnerabilities_by_profile_chart',
    'generate_vulnerabilities_by_host_chart',
    'generate_remediation_progress_chart',
    'generate_risk_trend_chart'
]

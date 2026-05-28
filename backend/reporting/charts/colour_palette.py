"""
Colour Palette definitions for reporting charts.
Defines central colour system logic for consistency across all chart components.
"""

# Profile colours mapping
PROFILE_COLOURS = {
    "Discovery": "#0000FF",     # Blue
    "Port": "#00FFFF",          # Cyan
    "Vulnerability": "#FF0000", # Red
    "Authenticated": "#800080", # Purple
    "Compliance": "#008000",    # Green
    "Config": "#FFA500"         # Orange
}

def get_profile_colour(profile_name: str, default: str = "#CCCCCC") -> str:
    """
    Retrieve the exact hex colour assigned to a specific profile name.
    
    Args:
        profile_name (str): The name of the profile.
        default (str): Fallback colour if the profile name isn't found.
        
    Returns:
        str: Hex colour code string.
    """
    return PROFILE_COLOURS.get(profile_name, default)

# Severity colours mapping for consistency (optional extension, but good for pie charts)
SEVERITY_COLOURS = {
    "Critical": "#8B0000",  # Dark Red
    "High": "#FF0000",      # Red
    "Medium": "#FFA500",    # Orange
    "Low": "#FFFF00",       # Yellow
    "Info": "#0000FF",      # Blue
    "None": "#A9A9A9"       # Dark Gray
}

def get_severity_colour(severity: str, default: str = "#CCCCCC") -> str:
    """
    Retrieve the hex colour assigned to a vulnerability severity level.
    """
    # Try title case matching for robustness
    return SEVERITY_COLOURS.get(severity.title(), default)

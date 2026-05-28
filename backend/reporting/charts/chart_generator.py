import io
import base64
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for generating image files
import matplotlib.pyplot as plt
from typing import Dict, List

from .colour_palette import get_profile_colour, get_severity_colour

def _fig_to_base64(fig) -> str:
    """Helper method to convert a matplotlib figure to base64 string."""
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)
    return img_base64

def generate_severity_pie_chart(severity_counts: Dict[str, int]) -> str:
    """
    Generate a Pie Chart showing distribution of vulnerabilities by severity.
    
    Args:
        severity_counts: Dictionary mapping severity level (e.g. 'High') to count.
    
    Returns:
        Base64 encoded PNG string.
    """
    labels = list(severity_counts.keys())
    sizes = list(severity_counts.values())
    colours = [get_severity_colour(sev) for sev in labels]
    
    fig, ax = plt.subplots(figsize=(6, 6))
    
    # Don't plot if empty
    if sum(sizes) == 0:
        ax.text(0.5, 0.5, 'No Data Available', ha='center', va='center')
        ax.axis('off')
        return _fig_to_base64(fig)
        
    ax.pie(sizes, labels=labels, colors=colours, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    ax.set_title('Vulnerabilities by Severity')
    
    return _fig_to_base64(fig)

def generate_vulnerabilities_by_profile_chart(profile_counts: Dict[str, int]) -> str:
    """
    Generate a Bar Chart showing vulnerabilities mapped to specific scan profiles.
    
    Args:
        profile_counts: Dictionary mapping profile name (e.g. 'Discovery') to count.
        
    Returns:
        Base64 encoded PNG string.
    """
    labels = list(profile_counts.keys())
    counts = list(profile_counts.values())
    colours = [get_profile_colour(prof) for prof in labels]
    
    fig, ax = plt.subplots(figsize=(8, 5))
    
    if not labels:
        ax.text(0.5, 0.5, 'No Data Available', ha='center', va='center')
        ax.axis('off')
        return _fig_to_base64(fig)
        
    bars = ax.bar(labels, counts, color=colours)
    
    ax.set_xlabel('Scan Profiles')
    ax.set_ylabel('Number of Vulnerabilities')
    ax.set_title('Vulnerabilities by Scan Profile')
    
    # Add value labels on top of bars
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')
                    
    plt.xticks(rotation=45, ha='right')
    fig.tight_layout()
    
    return _fig_to_base64(fig)

def generate_vulnerabilities_by_host_chart(host_counts: Dict[str, int], top_n: int = 10) -> str:
    """
    Generate a Bar Chart showing top N vulnerable hosts.
    
    Args:
        host_counts: Dictionary mapping host identifier (IP/Hostname) to count.
        top_n: Number of top hosts to display.
        
    Returns:
        Base64 encoded PNG string.
    """
    # Sort and take top N
    sorted_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    if not sorted_hosts:
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.text(0.5, 0.5, 'No Data Available', ha='center', va='center')
        ax.axis('off')
        return _fig_to_base64(fig)
        
    labels = [host for host, _ in sorted_hosts]
    counts = [count for _, count in sorted_hosts]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    bars = ax.bar(labels, counts, color='steelblue')
    
    ax.set_xlabel('Hosts')
    ax.set_ylabel('Number of Vulnerabilities')
    ax.set_title(f'Top {len(labels)} Most Vulnerable Hosts')
    
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')
                    
    plt.xticks(rotation=45, ha='right')
    fig.tight_layout()
    
    return _fig_to_base64(fig)

def generate_remediation_progress_chart(resolved: int, unresolved: int) -> str:
    """
    Generate a Chart (e.g. Donut or Pie) showing remediation progress.
    
    Args:
        resolved: Count of resolved vulnerabilities.
        unresolved: Count of unresolved vulnerabilities.
        
    Returns:
        Base64 encoded PNG string.
    """
    labels = ['Resolved', 'Unresolved']
    sizes = [resolved, unresolved]
    colors = ['#2ca02c', '#d62728'] # Green for resolved, Red for unresolved
    
    fig, ax = plt.subplots(figsize=(6, 6))
    
    if sum(sizes) == 0:
        ax.text(0.5, 0.5, 'No Data Available', ha='center', va='center')
        ax.axis('off')
        return _fig_to_base64(fig)
        
    # Create donut chart
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', 
                                      startangle=90, wedgeprops=dict(width=0.4))
    
    ax.set_title('Remediation Progress')
    
    return _fig_to_base64(fig)

def generate_risk_trend_chart(dates: List[str], risk_scores: List[float]) -> str:
    """
    Generate a Line Chart showing the trend of risk scores over time.
    
    Args:
        dates: List of date strings (e.g. YYYY-MM-DD).
        risk_scores: Corresponding list of overall risk scores.
        
    Returns:
        Base64 encoded PNG string.
    """
    fig, ax = plt.subplots(figsize=(10, 5))
    
    if not dates or not risk_scores or len(dates) != len(risk_scores):
        ax.text(0.5, 0.5, 'No Data Available or Invalid Data', ha='center', va='center')
        ax.axis('off')
        return _fig_to_base64(fig)
        
    ax.plot(dates, risk_scores, marker='o', linestyle='-', color='purple', linewidth=2)
    
    ax.set_xlabel('Date')
    ax.set_ylabel('Risk Score')
    ax.set_title('Risk Trend Over Time')
    
    ax.grid(True, linestyle='--', alpha=0.7)
    plt.xticks(rotation=45, ha='right')
    fig.tight_layout()
    
    return _fig_to_base64(fig)

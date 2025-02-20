import uuid
from datetime import datetime
import streamlit as st

def generate_incident_id():
    """Generate a unique incident ID"""
    return f"INC-{uuid.uuid4().hex[:8].upper()}"

def send_notification(message):
    """Send a notification (placeholder for real implementation)"""
    st.toast(message)
    return True

def format_datetime(dt):
    """Format datetime for display"""
    return dt.strftime("%Y-%m-%d %H:%M:%S")
import shutil
from datetime import datetime

def backup_data():
    """Create a backup of the data directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f'data_backup_{timestamp}'
    try:
        shutil.copytree('data', backup_dir)
        return True
    except Exception as e:
        print(f"Backup failed: {e}")
        return False

def get_threat_intel(indicator):
    """Get threat intelligence for an IP or domain using VirusTotal API"""
    import vt
    import re
    import os

    # Get API key from environment variable
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        return {"error": "VirusTotal API key not configured"}
    
    try:
        client = vt.Client(api_key)
        
        # Check if indicator is IP or domain
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, indicator):
            result = client.get_object(f"/ip_addresses/{indicator}")
        else:
            result = client.get_object(f"/domains/{indicator}")
            
        intel = {
            "malicious_count": result.last_analysis_stats.get('malicious', 0),
            "suspicious_count": result.last_analysis_stats.get('suspicious', 0),
            "reputation_score": result.reputation if hasattr(result, 'reputation') else 0,
            "last_analysis_date": result.last_analysis_date,
        }
        client.close()
        return intel
        
    except Exception as e:
        return {"error": str(e)}

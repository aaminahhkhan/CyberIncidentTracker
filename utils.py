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

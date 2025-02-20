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

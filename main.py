import streamlit as st
import pandas as pd
from datetime import datetime
import plotly.express as px
from auth import check_password, create_user, is_admin
from database import load_incidents, save_incident, update_incident, load_users
from utils import generate_incident_id, send_notification

# Page configuration
st.set_page_config(
    page_title="Cybersecurity Incident Management",
    page_icon="🛡️",
    layout="wide"
)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None

def login_page():
    st.title("🛡️ Cybersecurity Incident Management")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login"):
            if check_password(username, password):
                st.session_state.authenticated = True
                st.session_state.username = username
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid credentials")
    
    with tab2:
        new_username = st.text_input("Username", key="reg_username")
        new_password = st.text_input("Password", type="password", key="reg_password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        if st.button("Register"):
            if new_password != confirm_password:
                st.error("Passwords don't match")
            elif create_user(new_username, new_password):
                st.success("Registration successful! Please login.")
            else:
                st.error("Username already exists")

def main_page():
    st.sidebar.title(f"Welcome, {st.session_state.username}")
    
    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.username = None
        st.rerun()
    
    # Main navigation
    page = st.sidebar.radio(
        "Navigation",
        ["Dashboard", "Submit Incident", "My Incidents", "Reports"] if not is_admin(st.session_state.username)
        else ["Dashboard", "All Incidents", "User Management", "Reports"]
    )
    
    if page == "Dashboard":
        show_dashboard()
    elif page == "Submit Incident":
        submit_incident()
    elif page == "My Incidents" or page == "All Incidents":
        show_incidents(show_all=page=="All Incidents")
    elif page == "User Management":
        user_management()
    elif page == "Reports":
        show_reports()

def show_dashboard():
    st.title("Dashboard")
    incidents = load_incidents()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Incidents", len(incidents))
    with col2:
        open_incidents = len(incidents[incidents['status'] == 'Open'])
        st.metric("Open Incidents", open_incidents)
    with col3:
        closed_incidents = len(incidents[incidents['status'] == 'Closed'])
        st.metric("Closed Incidents", closed_incidents)
    
    # Status distribution chart
    fig = px.pie(incidents, names='status', title='Incident Status Distribution')
    st.plotly_chart(fig)

def submit_incident():
    st.title("Submit New Incident")
    
    incident_type = st.selectbox(
        "Incident Type",
        ["Malware", "Phishing", "Data Breach", "DDoS", "Other"]
    )
    
    severity = st.select_slider(
        "Severity",
        options=["Low", "Medium", "High", "Critical"]
    )
    
    description = st.text_area("Description")
    
    if st.button("Submit"):
        incident_id = generate_incident_id()
        new_incident = {
            'id': incident_id,
            'type': incident_type,
            'severity': severity,
            'description': description,
            'status': 'Open',
            'reported_by': st.session_state.username,
            'reported_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'assigned_to': '',
            'resolution': ''
        }
        
        save_incident(new_incident)
        st.success(f"Incident submitted successfully. Incident ID: {incident_id}")
        send_notification(f"New incident reported: {incident_id}")

def show_incidents(show_all=False):
    st.title("Incident Management")
    
    incidents = load_incidents()
    if not show_all:
        incidents = incidents[incidents['reported_by'] == st.session_state.username]
    
    if len(incidents) == 0:
        st.info("No incidents found")
        return
    
    for _, incident in incidents.iterrows():
        with st.expander(f"Incident {incident['id']} - {incident['type']} ({incident['status']})"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Severity:** {incident['severity']}")
                st.write(f"**Reported By:** {incident['reported_by']}")
                st.write(f"**Date:** {incident['reported_date']}")
            
            with col2:
                st.write(f"**Status:** {incident['status']}")
                st.write(f"**Assigned To:** {incident['assigned_to']}")
            
            st.write("**Description:**")
            st.write(incident['description'])
            
            if is_admin(st.session_state.username):
                new_status = st.selectbox(
                    "Update Status",
                    ["Open", "In Progress", "Closed"],
                    key=f"status_{incident['id']}"
                )
                
                new_assignment = st.selectbox(
                    "Assign To",
                    [""] + list(load_users()['username']),
                    key=f"assign_{incident['id']}"
                )
                
                if st.button("Update", key=f"update_{incident['id']}"):
                    incident['status'] = new_status
                    incident['assigned_to'] = new_assignment
                    update_incident(incident)
                    st.success("Incident updated successfully")
                    st.rerun()

def show_reports():
    st.title("Reports")
    
    incidents = load_incidents()
    
    # Time series of incidents
    daily_incidents = incidents.groupby('reported_date').size().reset_index(name='count')
    fig1 = px.line(daily_incidents, x='reported_date', y='count', title='Incidents Over Time')
    st.plotly_chart(fig1)
    
    # Severity distribution
    fig2 = px.bar(incidents, x='severity', title='Incidents by Severity')
    st.plotly_chart(fig2)
    
    # Type distribution
    fig3 = px.bar(incidents, x='type', title='Incidents by Type')
    st.plotly_chart(fig3)

def user_management():
    if not is_admin(st.session_state.username):
        st.error("Unauthorized access")
        return
    
    st.title("User Management")
    users = load_users()
    st.dataframe(users[['username', 'is_admin']])

# Main app logic
if not st.session_state.authenticated:
    login_page()
else:
    main_page()
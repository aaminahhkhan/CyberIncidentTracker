import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from auth import check_password, create_user, is_admin
from database import load_incidents, save_incident, update_incident, load_users
from utils import generate_incident_id, send_notification, format_datetime

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

def show_user_dashboard():
    st.title("My Dashboard")
    incidents = load_incidents()
    user_incidents = incidents[incidents['reported_by'] == st.session_state.username]

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Reports", len(user_incidents))
    with col2:
        open_incidents = len(user_incidents[user_incidents['status'] == 'Open'])
        st.metric("Open", open_incidents)
    with col3:
        in_progress = len(user_incidents[user_incidents['status'] == 'In Progress'])
        st.metric("In Progress", in_progress)
    with col4:
        closed = len(user_incidents[user_incidents['status'] == 'Closed'])
        st.metric("Closed", closed)

    # Recent activity
    st.subheader("Recent Activity")
    recent_incidents = user_incidents.sort_values('reported_date', ascending=False).head(5)
    if not recent_incidents.empty:
        for _, incident in recent_incidents.iterrows():
            with st.expander(f"{incident['type']} - {incident['reported_date']}"):
                st.write(f"**Status:** {incident['status']}")
                st.write(f"**Severity:** {incident['severity']}")
                st.write(f"**Description:** {incident['description']}")
    else:
        st.info("No recent activity")

    # Activity timeline
    st.subheader("Activity Timeline")
    if not user_incidents.empty:
        fig = go.Figure()
        for severity in ['Low', 'Medium', 'High', 'Critical']:
            severity_data = user_incidents[user_incidents['severity'] == severity]
            if not severity_data.empty:
                fig.add_trace(go.Scatter(
                    x=pd.to_datetime(severity_data['reported_date']),
                    y=[severity] * len(severity_data),
                    mode='markers',
                    name=severity,
                    marker=dict(
                        size=12,
                        symbol='circle'
                    )
                ))
        fig.update_layout(
            title="Incident Timeline by Severity",
            yaxis_title="Severity Level",
            xaxis_title="Date",
            showlegend=True
        )
        st.plotly_chart(fig)

def submit_report():
    st.title("Submit Detailed Report")

    with st.form("report_form"):
        # Basic Information
        st.subheader("Basic Information")
        incident_type = st.selectbox(
            "Incident Type",
            ["Malware", "Phishing", "Data Breach", "DDoS", "Unauthorized Access", 
             "Social Engineering", "System Vulnerability", "Other"]
        )

        severity = st.select_slider(
            "Severity",
            options=["Low", "Medium", "High", "Critical"],
            value="Medium"
        )

        # Detailed Information
        st.subheader("Incident Details")
        description = st.text_area(
            "Description",
            placeholder="Provide a detailed description of the incident..."
        )

        impact = st.text_area(
            "Business Impact",
            placeholder="Describe the impact on business operations..."
        )

        # Technical Details
        st.subheader("Technical Details")
        col1, col2 = st.columns(2)
        with col1:
            affected_systems = st.multiselect(
                "Affected Systems",
                ["Network", "Servers", "Workstations", "Mobile Devices", 
                 "Cloud Services", "Applications", "Data Storage"]
            )
        with col2:
            indicators = st.multiselect(
                "Indicators of Compromise",
                ["Suspicious Network Traffic", "Unusual Login Attempts",
                 "Modified Files", "Unknown Processes", "System Alerts"]
            )

        # Submit button
        submitted = st.form_submit_button("Submit Report")

        if submitted:
            incident_id = generate_incident_id()
            new_incident = {
                'id': incident_id,
                'type': incident_type,
                'severity': severity,
                'description': f"""
                Description: {description}

                Business Impact: {impact}

                Affected Systems: {', '.join(affected_systems)}
                Indicators: {', '.join(indicators)}
                """.strip(),
                'status': 'Open',
                'reported_by': st.session_state.username,
                'reported_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'assigned_to': '',
                'resolution': ''
            }

            save_incident(new_incident)
            st.success(f"Report submitted successfully. Incident ID: {incident_id}")
            send_notification(f"New detailed report submitted: {incident_id}")

def show_dashboard():
    st.markdown("<h1 style='text-align: center;'>Security Incident Dashboard</h1>", unsafe_allow_html=True)
    incidents = load_incidents()

    st.markdown("---")
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
    priority = st.select_slider(
        "Priority",
        options=["Low", "Medium", "High", "Critical"],
        value="Medium"
    )

    description = st.text_area("Description")

    if st.button("Submit"):
        incident_id = generate_incident_id()
        new_incident = {
            'id': incident_id,
            'type': incident_type,
            'severity': severity,
            'description': description,
            'status': 'Pending',
            'reported_by': st.session_state.username,
            'reported_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'assigned_to': '',
            'resolution': '',
            'priority': priority,
            'comments': []
        }

        save_incident(new_incident)
        st.success(f"Incident submitted successfully. Incident ID: {incident_id}")
        send_notification(f"New incident reported: {incident_id}")

def show_incidents(show_all=False):
    st.title("Incident Management")

    incidents = load_incidents()
    if not show_all:
        # Show incidents either reported by or assigned to the user
        incidents = incidents[
            (incidents['reported_by'] == st.session_state.username) |
            (incidents['assigned_to'] == st.session_state.username)
        ]

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
                    key=f"status_{incident['id']}",
                    index=["Open", "In Progress", "Closed"].index(incident['status'])
                )

                users = load_users()
                user_list = [""] + list(users['username'])
                current_assignment_index = user_list.index(incident['assigned_to']) if incident['assigned_to'] in user_list else 0

                new_assignment = st.selectbox(
                    "Assign To",
                    user_list,
                    key=f"assign_{incident['id']}",
                    index=current_assignment_index
                )

                # Comments section
                st.write("---")
                st.write("**Comments**")

                if 'comments' not in incident:
                    incident['comments'] = []

                for comment in incident['comments']:
                    st.text(f"{comment['user']} ({comment['timestamp']}): {comment['text']}")

                new_comment = st.text_area("Add comment", key=f"comment_{incident['id']}")

                if st.button("Update & Comment", key=f"update_{incident['id']}"):
                    updated_incident = incident.copy()
                    updated_incident['status'] = new_status
                    updated_incident['assigned_to'] = new_assignment

                    if new_comment:
                        if 'comments' not in updated_incident:
                            updated_incident['comments'] = []
                        updated_incident['comments'].append({
                            'user': st.session_state.username,
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'text': new_comment
                        })

                    update_incident(updated_incident)
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

def main_page():
    st.sidebar.title(f"Welcome, {st.session_state.username}")

    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.username = None
        st.rerun()

    # Updated navigation
    if not is_admin(st.session_state.username):
        page = st.sidebar.radio(
            "Navigation",
            ["My Dashboard", "Submit Report", "My Incidents", "Reports"]
        )
    else:
        page = st.sidebar.radio(
            "Navigation",
            ["Dashboard", "All Incidents", "User Management", "Reports"]
        )

    if page == "My Dashboard":
        show_user_dashboard()
    elif page == "Dashboard":
        show_dashboard()
    elif page == "Submit Report":
        submit_report()
    elif page == "My Incidents" or page == "All Incidents":
        show_incidents(show_all=page=="All Incidents")
    elif page == "User Management":
        user_management()
    elif page == "Reports":
        show_reports()


# Main app logic
if not st.session_state.authenticated:
    login_page()
else:
    main_page()
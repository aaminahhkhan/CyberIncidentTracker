import pandas as pd
import os

# Ensure data directory exists
os.makedirs('data', exist_ok=True)

def load_users():
    """Load users from CSV file"""
    if not os.path.exists('data/users.csv'):
        df = pd.DataFrame(columns=['username', 'password', 'is_admin'])
        df.to_csv('data/users.csv', index=False)
    return pd.read_csv('data/users.csv')

def save_user(user):
    """Save a new user to CSV"""
    users = load_users()
    users = users.append(user, ignore_index=True)
    users.to_csv('data/users.csv', index=False)

def load_incidents():
    """Load incidents from CSV file"""
    if not os.path.exists('data/incidents.csv'):
        df = pd.DataFrame(columns=[
            'id', 'type', 'severity', 'description', 'status',
            'reported_by', 'reported_date', 'assigned_to', 'resolution'
        ])
        df.to_csv('data/incidents.csv', index=False)
    return pd.read_csv('data/incidents.csv')

def save_incident(incident):
    """Save a new incident to CSV"""
    incidents = load_incidents()
    incidents = incidents.append(incident, ignore_index=True)
    incidents.to_csv('data/incidents.csv', index=False)

def update_incident(incident):
    """Update an existing incident"""
    incidents = load_incidents()
    incidents.loc[incidents['id'] == incident['id']] = incident
    incidents.to_csv('data/incidents.csv', index=False)

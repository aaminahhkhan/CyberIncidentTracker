import pandas as pd
import os

# Ensure data directory exists
os.makedirs('data', exist_ok=True)

def load_users():
    """Load users from CSV file"""
    if not os.path.exists('data/users.csv'):
        df = pd.DataFrame(columns=['username', 'password', 'email', 'department', 'phone', 'is_admin', 'created_at', 'last_login'])
        df.to_csv('data/users.csv', index=False)
        # Create default admin user
        from auth import hash_password
        admin_user = {
            'username': 'admin',
            'password': hash_password('admin'),
            'email': 'admin@company.com',
            'department': 'IT Security',
            'phone': '',
            'is_admin': True,
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'last_login': None
        }
        save_user(admin_user)
    return pd.read_csv('data/users.csv')

def save_user(user):
    """Save a new user to CSV"""
    users = load_users()
    new_user_df = pd.DataFrame([user])
    users = pd.concat([users, new_user_df], ignore_index=True)
    users.to_csv('data/users.csv', index=False)

def load_incidents():
    """Load incidents from CSV file"""
    if not os.path.exists('data/incidents.csv'):
        df = pd.DataFrame(columns=[
            'id', 'type', 'severity', 'description', 'status',
            'reported_by', 'reported_date', 'assigned_to', 'resolution',
            'priority', 'comments'
        ])
        df.to_csv('data/incidents.csv', index=False)
    return pd.read_csv('data/incidents.csv')

def save_incident(incident):
    """Save a new incident to CSV"""
    incidents = load_incidents()
    new_incident_df = pd.DataFrame([incident])
    incidents = pd.concat([incidents, new_incident_df], ignore_index=True)
    incidents.to_csv('data/incidents.csv', index=False)

def update_incident(incident):
    """Update an existing incident"""
    incidents = load_incidents()
    idx = incidents.index[incidents['id'] == incident['id']].tolist()[0]
    
    for column in incidents.columns:
        incidents.at[idx, column] = incident[column]
        
    incidents.to_csv('data/incidents.csv', index=False)
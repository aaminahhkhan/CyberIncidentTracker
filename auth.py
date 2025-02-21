import pandas as pd
import hashlib
import os
from database import load_users, save_user

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(username, password):
    """Verify user credentials"""
    users = load_users()
    if username in users['username'].values:
        user = users[users['username'] == username].iloc[0]
        return user['password'] == hash_password(password)
    return False

def create_user(username, password, email, department="", phone=""):
    """Create a new user"""
    users = load_users()
    if username in users['username'].values:
        return False
    
    new_user = {
        'username': username,
        'password': hash_password(password),
        'email': email,
        'department': department,
        'phone': phone,
        'is_admin': False,
        'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'last_login': None
    }
    save_user(new_user)
    return True

def is_admin(username):
    """Check if user is an admin"""
    users = load_users()
    if username in users['username'].values:
        return users[users['username'] == username].iloc[0]['is_admin']
    return False

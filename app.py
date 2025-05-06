import streamlit as st
import time
import random
import string
import sqlite3
import hashlib
import os
from datetime import datetime

# Set page configuration
st.set_page_config(
    page_title="Secure Access System",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Database setup
DB_FILE = "secure_access.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Create users table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Create access logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL,
            ip_address TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Hash password for security
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# User registration function
def register_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        password_hash = hash_password(password)
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                  (username, password_hash))
        conn.commit()
        log_access(username, "registration", "success")
        return True
    except sqlite3.IntegrityError:
        log_access(username, "registration", "failed")
        return False
    finally:
        conn.close()

# User verification function
def verify_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    password_hash = hash_password(password)
    c.execute("SELECT id FROM users WHERE username = ? AND password_hash = ?", 
              (username, password_hash))
    user = c.fetchone()
    
    if user:
        # Update last login time
        c.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user[0],))
        conn.commit()
        log_access(username, "login", "success")
        result = True
    else:
        log_access(username, "login", "failed")
        result = False
    
    conn.close()
    return result

# Check if username exists
def username_exists(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    result = c.fetchone() is not None
    conn.close()
    return result

# Log access attempts
def log_access(username, action, status, ip_address="127.0.0.1"):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO access_logs (username, action, status, ip_address) VALUES (?, ?, ?, ?)",
        (username, action, status, ip_address)
    )
    conn.commit()
    conn.close()

# Function to generate random secure data
def generate_secure_data():
    # Choose a random pattern for secure data
    pattern_type = random.randint(1, 3)
    
    if pattern_type == 1:
        return (f"{''.join(random.choices(string.ascii_uppercase + string.digits, k=3))}-"
                f"{''.join(random.choices(string.ascii_uppercase + string.digits, k=4))}-"
                f"{''.join(random.choices(string.ascii_uppercase + string.digits, k=3))}-"
                f"{''.join(random.choices(string.ascii_uppercase + string.digits, k=4))}")
    elif pattern_type == 2:
        return (f"SEC-{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}-"
                f"{''.join(random.choices(string.ascii_uppercase + string.digits, k=4))}")
    else:
        return (f"{''.join(random.choices(string.ascii_uppercase, k=2))}"
                f"{''.join(random.choices(string.digits, k=4))}-"
                f"{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}")

# Initialize session state variables
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
    
if 'username' not in st.session_state:
    st.session_state.username = ""
    
if 'attempts' not in st.session_state:
    st.session_state.attempts = 0
    
if 'locked_out' not in st.session_state:
    st.session_state.locked_out = False

if 'secure_data' not in st.session_state:
    st.session_state.secure_data = generate_secure_data()

if 'show_register' not in st.session_state:
    st.session_state.show_register = False

# Constants
MAX_ATTEMPTS = 3

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem !important;
        font-weight: 700 !important;
        color: #1E3A8A !important;
        text-align: center;
        margin-bottom: 2rem !important;
    }
    .sub-header {
        font-size: 1.5rem !important;
        font-weight: 600 !important;
        margin-top: 1rem !important;
        margin-bottom: 1rem !important; 
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
        font-weight: 500;
    }
    .login-container {
        background-color: #f8f9fa;
        padding: 2rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-bottom: 1rem;
    }
    .info-container {
        background-color: #e8f4f8;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 5px solid #4285f4;
        margin-top: 1rem;
    }
    .warning-text {
        color: #d62728;
        font-weight: 500;
    }
    .success-container {
        background-color: #edf7ed;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 5px solid #34a853;
        margin-top: 1rem;
    }
    .secure-data {
        font-family: 'Courier New', monospace;
        font-size: 1.2rem;
        font-weight: 700;
        background-color: #f0f0f0;
        padding: 0.5rem 1rem;
        border-radius: 5px;
        letter-spacing: 2px;
    }
    .footer {
        text-align: center;
        margin-top: 3rem;
        color: #6c757d;
        font-size: 0.8rem;
    }
</style>
""", unsafe_allow_html=True)

# App header
st.markdown("<h1 class='main-header'>🔒 Secure Access System</h1>", unsafe_allow_html=True)

# Main app container
main_container = st.container()

with main_container:
    # Authentication flow
    if st.session_state.authenticated:
        # User is logged in - show secure content
        st.markdown("<div class='success-container'>", unsafe_allow_html=True)
        st.markdown(f"### 🔓 Welcome, {st.session_state.username}!")
        st.markdown("You have successfully accessed the secure area.")
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Tabs for different secure sections
        tab1, tab2, tab3 = st.tabs(["Secure Data", "Account Info", "Access Log"])
        
        with tab1:
            st.markdown("<h3 class='sub-header'>Your Secure Information</h3>", unsafe_allow_html=True)
            
            # Simulating loading of secure content
            with st.spinner("Retrieving secure data..."):
                time.sleep(0.8)
            
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"<div class='secure-data'>{st.session_state.secure_data}</div>", unsafe_allow_html=True)
            with col2:
                if st.button("🔄 Refresh"):
                    st.session_state.secure_data = generate_secure_data()
                    st.rerun()
            
            st.markdown("<div class='info-container'>", unsafe_allow_html=True)
            st.markdown("**Note:** This is your unique secure access key. Do not share it with anyone.")
            st.markdown("</div>", unsafe_allow_html=True)
        
        with tab2:
            st.markdown("<h3 class='sub-header'>Account Information</h3>", unsafe_allow_html=True)
            
            # Get user information from database
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT created_at, last_login FROM users WHERE username = ?", (st.session_state.username,))
            user_info = c.fetchone()
            conn.close()
            
            if user_info:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Username:**")
                    st.markdown("**Account Created:**")
                    st.markdown("**Last Login:**")
                with col2:
                    st.markdown(f"*{st.session_state.username}*")
                    st.markdown(f"*{user_info[0]}*")
                    st.markdown(f"*{user_info[1]}*")
        
        with tab3:
            st.markdown("<h3 class='sub-header'>Recent Access Logs</h3>", unsafe_allow_html=True)
            
            # Get access logs for current user
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute(
                "SELECT action, timestamp, status, ip_address FROM access_logs WHERE username = ? ORDER BY timestamp DESC LIMIT 5", 
                (st.session_state.username,)
            )
            logs = c.fetchall()
            conn.close()
            
            if logs:
                for log in logs:
                    action, timestamp, status, ip = log
                    status_icon = "✅" if status == "success" else "❌"
                    st.markdown(f"**{action.capitalize()}** {status_icon} - {timestamp} from {ip}")
            else:
                st.markdown("No access logs found.")
        
        # Logout button at the bottom
        if st.button("🚪 Logout"):
            st.session_state.authenticated = False
            st.session_state.username = ""
            st.session_state.attempts = 0
            log_access(st.session_state.username, "logout", "success")
            st.rerun()
            
    elif st.session_state.locked_out:
        # System is locked due to too many failed attempts
        st.markdown("<div class='login-container'>", unsafe_allow_html=True)
        st.error("🚨 System Locked - Too many failed attempts!")
        st.markdown("<p class='warning-text'>The system has been locked due to multiple failed login attempts.</p>", unsafe_allow_html=True)
        
        # Add countdown or reset option
        if st.button("🔄 Reset Lock"):
            st.session_state.attempts = 0
            st.session_state.locked_out = False
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
        
    else:
        # User is not logged in - show login/register form
        auth_container = st.container()
        
        with auth_container:
            if st.session_state.show_register:
                # Registration form
                st.markdown("<div class='login-container'>", unsafe_allow_html=True)
                st.markdown("<h3 class='sub-header'>Create an Account</h3>", unsafe_allow_html=True)
                
                reg_username = st.text_input("Username", key="reg_username")
                reg_password = st.text_input("Password", type="password", key="reg_password")
                reg_confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    if st.button("Register"):
                        if not reg_username or not reg_password:
                            st.error("Username and password are required")
                        elif reg_password != reg_confirm_password:
                            st.error("Passwords do not match")
                        elif username_exists(reg_username):
                            st.error("Username already exists")
                        else:
                            if register_user(reg_username, reg_password):
                                st.success("Registration successful! You can now log in.")
                                st.session_state.show_register = False
                                st.rerun()
                            else:
                                st.error("Registration failed. Please try again.")
                
                with col2:
                    if st.button("Back to Login"):
                        st.session_state.show_register = False
                        st.rerun()
                        
                st.markdown("</div>", unsafe_allow_html=True)
                
            else:
                # Login form
                st.markdown("<div class='login-container'>", unsafe_allow_html=True)
                st.markdown("<h3 class='sub-header'>Login to Access</h3>", unsafe_allow_html=True)
                
                # Display attempt counter if there have been failed attempts
                if st.session_state.attempts > 0:
                    remaining = MAX_ATTEMPTS - st.session_state.attempts
                    st.warning(f"⚠️ Attempts remaining: {remaining}")
                    
                    # Progress bar showing attempts used
                    st.progress(st.session_state.attempts / MAX_ATTEMPTS)
                
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    if st.button("Login"):
                        if not username or not password:
                            st.error("Please enter both username and password")
                        else:
                            if verify_user(username, password):
                                st.session_state.authenticated = True
                                st.session_state.username = username
                                st.session_state.attempts = 0
                                st.rerun()
                            else:
                                st.session_state.attempts += 1
                                if st.session_state.attempts >= MAX_ATTEMPTS:
                                    st.session_state.locked_out = True
                                    st.rerun()
                                else:
                                    st.error(f"Invalid credentials. {MAX_ATTEMPTS - st.session_state.attempts} attempts remaining.")
                
                with col2:
                    if st.button("Register New Account"):
                        st.session_state.show_register = True
                        st.rerun()
                
                st.markdown("</div>", unsafe_allow_html=True)
        
        # Information about the system
        with st.expander("ℹ️ About Secure Access System"):
            st.markdown("""
            This secure access system provides:
            - User registration and authentication
            - Secure password storage with hashing
            - Access attempt tracking and lockout protection
            - Dynamically generated secure data
            - Access logging for security auditing
            
            For assistance, please contact system administrator.
            """)

# Footer
st.markdown("<div class='footer'>© 2025 Secure Access Systems | Powered by Streamlit</div>", unsafe_allow_html=True)

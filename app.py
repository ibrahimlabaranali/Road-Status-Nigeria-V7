import streamlit as st
import sqlite3
import bcrypt
import re
import os
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
import pandas as pd
from io import BytesIO
import base64

# Page configuration
st.set_page_config(
    page_title="Nigerian Road Risk Reporting - Authentication",
    page_icon="🚗",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .form-container {
        background: white;
        padding: 2rem;
        border-radius: 15px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-bottom: 2rem;
    }
    .success-message {
        background: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid #c3e6cb;
    }
    .error-message {
        background: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid #f5c6cb;
    }
    .info-message {
        background: #d1ecf1;
        color: #0c5460;
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid #bee5eb;
    }
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 0.5rem 2rem;
        font-weight: 600;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #5a6fd8 0%, #6a4190 100%);
    }
    .auth-container {
        max-width: 500px;
        margin: 0 auto;
        padding: 2rem;
    }
    .dashboard-container {
        padding: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Database setup
def init_database():
    """Initialize SQLite database with users, logs, and reset_tokens tables"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            phone_number TEXT UNIQUE NOT NULL,
            email TEXT,
            role TEXT NOT NULL,
            nin_or_passport TEXT UNIQUE NOT NULL,
            official_authority_name TEXT,
            id_file_data BLOB,
            id_file_name TEXT,
            password_hash TEXT NOT NULL,
            registration_status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            verified_at TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Create logs table for audit trail
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create reset_tokens table for password reset
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Validation functions
def validate_nigerian_phone(phone):
    """Validate Nigerian phone number format"""
    phone_pattern = r'^(\+234|0)[789][01]\d{8}$'
    return re.match(phone_pattern, phone) is not None

def validate_email(email):
    """Validate email format"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email) is not None

def validate_nin_or_passport(value):
    """Validate NIN (11 digits) or passport number"""
    # NIN: 11 digits, Passport: alphanumeric 6-9 characters
    nin_pattern = r'^\d{11}$'
    passport_pattern = r'^[A-Z0-9]{6,9}$'
    return re.match(nin_pattern, value) is not None or re.match(passport_pattern, value) is not None

def validate_password(password):
    """Validate password strength"""
    return len(password) >= 8

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Authentication functions
def log_action(user_id, action, details, ip_address="127.0.0.1"):
    """Log user actions for audit trail"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (user_id, action, details, ip_address)
        VALUES (?, ?, ?, ?)
    ''', (user_id, action, details, ip_address))
    conn.commit()
    conn.close()

def authenticate_user(identifier, password):
    """Authenticate user by email/phone and password"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Check if identifier is email or phone
    if '@' in identifier:
        cursor.execute('SELECT * FROM users WHERE email = ?', (identifier,))
    else:
        cursor.execute('SELECT * FROM users WHERE phone_number = ?', (identifier,))
    
    user = cursor.fetchone()
    conn.close()
    
    if user and verify_password(password, user[9]):  # password_hash is at index 9
        # Update last login
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user[0]))
        conn.commit()
        conn.close()
        
        # Log successful login
        log_action(user[0], 'LOGIN_SUCCESS', f'User logged in via {identifier}')
        
        return {
            'id': user[0],
            'full_name': user[1],
            'phone_number': user[2],
            'email': user[3],
            'role': user[4],
            'registration_status': user[10]
        }
    
    # Log failed login attempt
    if user:
        log_action(user[0], 'LOGIN_FAILED', f'Failed login attempt via {identifier}')
    else:
        log_action(None, 'LOGIN_FAILED', f'Failed login attempt with unknown identifier: {identifier}')
    
    return None

def generate_reset_token(user_id):
    """Generate a secure reset token"""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=1)  # Token expires in 1 hour
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO reset_tokens (user_id, token, expires_at)
        VALUES (?, ?, ?)
    ''', (user_id, token, expires_at))
    conn.commit()
    conn.close()
    
    return token

def validate_reset_token(token):
    """Validate reset token and return user_id if valid"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT user_id FROM reset_tokens 
        WHERE token = ? AND expires_at > ? AND used = FALSE
    ''', (token, datetime.now()))
    
    result = cursor.fetchone()
    conn.close()
    
    return result[0] if result else None

def use_reset_token(token):
    """Mark reset token as used"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE reset_tokens SET used = TRUE WHERE token = ?', (token,))
    conn.commit()
    conn.close()

def reset_password(user_id, new_password):
    """Reset user password"""
    hashed_password = hash_password(new_password)
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_password, user_id))
    conn.commit()
    conn.close()
    
    log_action(user_id, 'PASSWORD_RESET', 'Password successfully reset')

def find_user_by_identifier(identifier):
    """Find user by email or phone number"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    if '@' in identifier:
        cursor.execute('SELECT id, full_name, email FROM users WHERE email = ?', (identifier,))
    else:
        cursor.execute('SELECT id, full_name, phone_number FROM users WHERE phone_number = ?', (identifier,))
    
    user = cursor.fetchone()
    conn.close()
    
    return user

# Existing functions (keeping for compatibility)
def check_unique_constraints(phone_number, nin_or_passport, email=None):
    """Check if phone number, NIN/passport, and email are unique"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Check phone number
    cursor.execute('SELECT id FROM users WHERE phone_number = ?', (phone_number,))
    if cursor.fetchone():
        conn.close()
        return False, "Phone number already registered"
    
    # Check NIN/passport
    cursor.execute('SELECT id FROM users WHERE nin_or_passport = ?', (nin_or_passport,))
    if cursor.fetchone():
        conn.close()
        return False, "NIN/Passport number already registered"
    
    # Check email if provided
    if email:
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            conn.close()
            return False, "Email already registered"
    
    conn.close()
    return True, "All constraints satisfied"

def save_user(user_data, id_file_data=None, id_file_name=None):
    """Save new user to database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO users (
            full_name, phone_number, email, role, nin_or_passport,
            official_authority_name, id_file_data, id_file_name, password_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_data['full_name'], user_data['phone_number'], user_data['email'],
        user_data['role'], user_data['nin_or_passport'], user_data.get('official_authority_name'),
        id_file_data, id_file_name, user_data['password_hash']
    ))
    
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    log_action(user_id, 'USER_REGISTERED', f'New user registered: {user_data["full_name"]}')
    return user_id

def get_all_users():
    """Get all users for admin dashboard"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, full_name, phone_number, email, role, registration_status, 
               created_at, last_login
        FROM users ORDER BY created_at DESC
    ''')
    users = cursor.fetchall()
    conn.close()
    return users

def verify_user(user_id):
    """Verify a pending user"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users SET registration_status = 'verified', verified_at = ?
        WHERE id = ?
    ''', (datetime.now(), user_id))
    conn.commit()
    conn.close()
    
    log_action(user_id, 'USER_VERIFIED', 'User account verified by admin')

# UI Functions
def show_login_form():
    """Display login form"""
    st.markdown("""
    <div class="main-header">
        <h1>🔐 Login to Nigerian Road Risk Reporter</h1>
        <p>Enter your credentials to access your account</p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.container():
        st.markdown('<div class="auth-container">', unsafe_allow_html=True)
        
        with st.form("login_form"):
            st.subheader("📝 Login")
            
            identifier = st.text_input("Email or Phone Number", placeholder="Enter your email or phone number")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            col1, col2 = st.columns(2)
            with col1:
                login_submitted = st.form_submit_button("🔑 Login", use_container_width=True)
            with col2:
                forgot_submitted = st.form_submit_button("🔓 Forgot Password?", use_container_width=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        if login_submitted:
            if not identifier or not password:
                st.error("Please fill in all fields")
                return
            
            user = authenticate_user(identifier, password)
            if user:
                if user['registration_status'] == 'pending':
                    st.warning("⚠️ Your account is pending verification. Please contact an administrator.")
                else:
                    st.success(f"✅ Welcome back, {user['full_name']}!")
                    st.session_state['authenticated'] = True
                    st.session_state['user'] = user
                    st.rerun()
            else:
                st.error("❌ Invalid credentials. Please check your email/phone and password.")
        
        if forgot_submitted:
            st.session_state['show_forgot_password'] = True
            st.rerun()

def show_forgot_password_form():
    """Display forgot password form"""
    st.markdown("""
    <div class="main-header">
        <h1>🔓 Forgot Password</h1>
        <p>Enter your email or phone number to reset your password</p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.container():
        st.markdown('<div class="auth-container">', unsafe_allow_html=True)
        
        if 'reset_step' not in st.session_state:
            st.session_state['reset_step'] = 'request'
        
        if st.session_state['reset_step'] == 'request':
            with st.form("forgot_password_form"):
                st.subheader("📧 Request Password Reset")
                
                identifier = st.text_input("Email or Phone Number", placeholder="Enter your email or phone number")
                
                col1, col2 = st.columns(2)
                with col1:
                    submit_request = st.form_submit_button("📤 Send Reset Link", use_container_width=True)
                with col2:
                    back_to_login = st.form_submit_button("🔙 Back to Login", use_container_width=True)
                
                if submit_request:
                    if not identifier:
                        st.error("Please enter your email or phone number")
                    else:
                        user = find_user_by_identifier(identifier)
                        if user:
                            token = generate_reset_token(user[0])
                            st.session_state['reset_user_id'] = user[0]
                            st.session_state['reset_step'] = 'token'
                            
                            # Simulate sending email (in real app, send actual email)
                            st.success(f"✅ Reset link sent to {identifier}")
                            st.info(f"🔑 Reset Token: {token} (This would be sent via email in production)")
                            st.rerun()
                        else:
                            st.error("❌ No account found with that email or phone number")
                
                if back_to_login:
                    st.session_state['show_forgot_password'] = False
                    st.session_state['reset_step'] = 'request'
                    st.rerun()
        
        elif st.session_state['reset_step'] == 'token':
            with st.form("reset_token_form"):
                st.subheader("🔑 Enter Reset Token")
                
                token = st.text_input("Reset Token", placeholder="Enter the token from your email")
                
                col1, col2 = st.columns(2)
                with col1:
                    verify_token = st.form_submit_button("✅ Verify Token", use_container_width=True)
                with col2:
                    back_to_request = st.form_submit_button("🔙 Back", use_container_width=True)
                
                if verify_token:
                    if not token:
                        st.error("Please enter the reset token")
                    else:
                        user_id = validate_reset_token(token)
                        if user_id:
                            st.session_state['reset_step'] = 'new_password'
                            st.rerun()
                        else:
                            st.error("❌ Invalid or expired token")
                
                if back_to_request:
                    st.session_state['reset_step'] = 'request'
                    st.rerun()
        
        elif st.session_state['reset_step'] == 'new_password':
            with st.form("new_password_form"):
                st.subheader("🔒 Set New Password")
                
                new_password = st.text_input("New Password", type="password", placeholder="Enter new password")
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm new password")
                
                col1, col2 = st.columns(2)
                with col1:
                    reset_password_btn = st.form_submit_button("🔒 Reset Password", use_container_width=True)
                with col2:
                    back_to_token = st.form_submit_button("🔙 Back", use_container_width=True)
                
                if reset_password_btn:
                    if not new_password or not confirm_password:
                        st.error("Please fill in all fields")
                    elif new_password != confirm_password:
                        st.error("Passwords do not match")
                    elif not validate_password(new_password):
                        st.error("Password must be at least 8 characters long")
                    else:
                        reset_password(st.session_state['reset_user_id'], new_password)
                        use_reset_token(token)
                        st.success("✅ Password successfully reset!")
                        st.info("You can now login with your new password")
                        
                        # Clear session state
                        st.session_state['show_forgot_password'] = False
                        st.session_state['reset_step'] = 'request'
                        st.session_state.pop('reset_user_id', None)
                        st.rerun()
                
                if back_to_token:
                    st.session_state['reset_step'] = 'token'
                    st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)

def show_dashboard():
    """Display user dashboard based on role"""
    user = st.session_state.get('user')
    
    if not user:
        st.error("User session not found")
        return
    
    st.markdown(f"""
    <div class="main-header">
        <h1>🚗 Welcome, {user['full_name']}!</h1>
        <p>Role: {user['role'].title()} | Status: {user['registration_status'].title()}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    
    if user['role'] == 'Admin':
        page = st.sidebar.selectbox("Choose a page", ["Dashboard", "User Management", "Registration", "Audit Logs"])
    else:
        page = st.sidebar.selectbox("Choose a page", ["Dashboard", "Registration"])
    
    # Logout button
    if st.sidebar.button("🚪 Logout"):
        log_action(user['id'], 'LOGOUT', 'User logged out')
        st.session_state.clear()
        st.rerun()
    
    if page == "Dashboard":
        show_user_dashboard(user)
    elif page == "User Management" and user['role'] == 'Admin':
        show_admin_dashboard()
    elif page == "Registration":
        show_registration_form()
    elif page == "Audit Logs" and user['role'] == 'Admin':
        show_audit_logs()

def show_user_dashboard(user):
    """Display user dashboard"""
    st.subheader("📊 Your Dashboard")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Role", user['role'].title())
    
    with col2:
        st.metric("Status", user['registration_status'].title())
    
    with col3:
        st.metric("Account Type", "Verified" if user['registration_status'] == 'verified' else "Pending")
    
    st.markdown("---")
    
    if user['registration_status'] == 'pending':
        st.warning("⚠️ Your account is pending verification. You can still register new users.")
    else:
        st.success("✅ Your account is verified and active!")

def show_audit_logs():
    """Display audit logs for admin"""
    st.subheader("📋 Audit Logs")
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT l.timestamp, u.full_name, l.action, l.details, l.ip_address
        FROM logs l
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY l.timestamp DESC
        LIMIT 100
    ''')
    logs = cursor.fetchall()
    conn.close()
    
    if logs:
        df = pd.DataFrame(logs, columns=['Timestamp', 'User', 'Action', 'Details', 'IP Address'])
        st.dataframe(df, use_container_width=True)
        
        # Download logs
        csv = df.to_csv(index=False)
        st.download_button(
            label="📥 Download Logs (CSV)",
            data=csv,
            file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No logs found")

def show_registration_form():
    """Display registration form (existing functionality)"""
    st.subheader("📝 User Registration")
    
    with st.form("registration_form"):
        st.write("Please fill in all required fields:")
        
        full_name = st.text_input("Full Name *", placeholder="Enter your full name")
        
        col1, col2 = st.columns(2)
        with col1:
            phone_number = st.text_input("Phone Number *", placeholder="+2348012345678")
        with col2:
            email = st.text_input("Email (Optional)", placeholder="your.email@example.com")
        
        col1, col2 = st.columns(2)
        with col1:
            role = st.selectbox("Role *", ["Driver", "Public", "Admin"])
        with col2:
            nin_or_passport = st.text_input("NIN or Passport Number *", placeholder="11 digits or passport")
        
        if role == "Admin":
            official_authority_name = st.text_input("Official Authority Name *", placeholder="Enter authority name")
        else:
            official_authority_name = ""
        
        password = st.text_input("Password *", type="password", placeholder="Minimum 8 characters")
        confirm_password = st.text_input("Confirm Password *", type="password", placeholder="Confirm your password")
        
        uploaded_file = st.file_uploader("Upload ID Document (PDF/JPEG/PNG, max 5MB)", 
                                       type=['pdf', 'jpeg', 'jpg', 'png'])
        
        col1, col2 = st.columns(2)
        with col1:
            verify_identity = st.form_submit_button("🔍 Verify Identity", use_container_width=True)
        with col2:
            register_submitted = st.form_submit_button("📝 Register", use_container_width=True)
        
        if verify_identity:
            st.info("🔍 Identity verification simulation: This would typically involve CAPTCHA or OTP verification.")
        
        if register_submitted:
            # Validation
            errors = []
            
            if not full_name:
                errors.append("Full name is required")
            
            if not phone_number:
                errors.append("Phone number is required")
            elif not validate_nigerian_phone(phone_number):
                errors.append("Invalid Nigerian phone number format")
            
            if email and not validate_email(email):
                errors.append("Invalid email format")
            
            if not nin_or_passport:
                errors.append("NIN or Passport number is required")
            elif not validate_nin_or_passport(nin_or_passport):
                errors.append("Invalid NIN or Passport format")
            
            if role == "Admin" and not official_authority_name:
                errors.append("Official Authority Name is required for Admin role")
            
            if not password:
                errors.append("Password is required")
            elif not validate_password(password):
                errors.append("Password must be at least 8 characters long")
            
            if password != confirm_password:
                errors.append("Passwords do not match")
            
            if uploaded_file and uploaded_file.size > 5 * 1024 * 1024:  # 5MB
                errors.append("File size must be less than 5MB")
            
            if errors:
                for error in errors:
                    st.error(error)
            else:
                # Check unique constraints
                is_unique, message = check_unique_constraints(phone_number, nin_or_passport, email)
                
                if not is_unique:
                    st.error(message)
                else:
                    # Process file upload
                    id_file_data = None
                    id_file_name = None
                    
                    if uploaded_file:
                        id_file_data = uploaded_file.read()
                        id_file_name = uploaded_file.name
                    
                    # Save user
                    user_data = {
                        'full_name': full_name,
                        'phone_number': phone_number,
                        'email': email,
                        'role': role,
                        'nin_or_passport': nin_or_passport,
                        'official_authority_name': official_authority_name,
                        'password_hash': hash_password(password)
                    }
                    
                    try:
                        user_id = save_user(user_data, id_file_data, id_file_name)
                        st.success(f"✅ Registration successful! User ID: {user_id}")
                        st.info("Your account is pending verification by an administrator.")
                    except Exception as e:
                        st.error(f"❌ Registration failed: {str(e)}")

def show_admin_dashboard():
    """Display admin dashboard (existing functionality)"""
    st.subheader("👨‍💼 Admin Dashboard")
    
    # Get all users
    users = get_all_users()
    
    if users:
        # Convert to DataFrame for better display
        df = pd.DataFrame(users, columns=[
            'ID', 'Full Name', 'Phone Number', 'Email', 'Role', 
            'Status', 'Created At', 'Last Login'
        ])
        
        # Display statistics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Users", len(users))
        
        with col2:
            verified_users = len([u for u in users if u[5] == 'verified'])
            st.metric("Verified Users", verified_users)
        
        with col3:
            pending_users = len([u for u in users if u[5] == 'pending'])
            st.metric("Pending Users", pending_users)
        
        with col4:
            admin_users = len([u for u in users if u[4] == 'Admin'])
            st.metric("Admin Users", admin_users)
        
        st.markdown("---")
        
        # Display users table
        st.subheader("📋 User Management")
        
        # Add color coding for status
        def color_status(val):
            if val == 'verified':
                return 'background-color: #d4edda'
            elif val == 'pending':
                return 'background-color: #fff3cd'
            return ''
        
        styled_df = df.style.applymap(color_status, subset=['Status'])
        st.dataframe(styled_df, use_container_width=True)
        
        # Download functionality
        csv = df.to_csv(index=False)
        st.download_button(
            label="📥 Download Users (CSV)",
            data=csv,
            file_name=f"users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        
        # User verification section
        st.markdown("---")
        st.subheader("✅ User Verification")
        
        pending_users = [u for u in users if u[5] == 'pending']
        if pending_users:
            selected_user = st.selectbox(
                "Select user to verify:",
                options=pending_users,
                format_func=lambda x: f"{x[1]} ({x[2]}) - {x[4]}"
            )
            
            if st.button("✅ Verify User"):
                verify_user(selected_user[0])
                st.success(f"✅ User {selected_user[1]} has been verified!")
                st.rerun()
        else:
            st.info("No pending users to verify")
    else:
        st.info("No users found in the database")

def main():
    """Main application function"""
    # Initialize database
    init_database()
    
    # Check if user is authenticated
    if 'authenticated' not in st.session_state:
        st.session_state['authenticated'] = False
    
    # Show appropriate page based on authentication status
    if st.session_state['authenticated']:
        show_dashboard()
    else:
        if st.session_state.get('show_forgot_password', False):
            show_forgot_password_form()
        else:
            show_login_form()

if __name__ == "__main__":
    main() 
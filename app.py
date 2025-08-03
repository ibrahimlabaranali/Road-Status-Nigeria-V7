import streamlit as st
import sqlite3
import bcrypt
import re
import os
import uuid
from datetime import datetime
import pandas as pd
from io import BytesIO
import base64

# Page configuration
st.set_page_config(
    page_title="Nigerian Road Risk Reporting - Registration",
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
</style>
""", unsafe_allow_html=True)

# Database setup
def init_database():
    """Initialize SQLite database"""
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
            verified_at TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Validation functions
def validate_nigerian_phone(phone):
    """Validate Nigerian phone number format"""
    pattern = r'^(\+234|0)[789][01]\d{8}$'
    return re.match(pattern, phone) is not None

def validate_email(email):
    """Validate email format"""
    if not email:
        return True  # Email is optional
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_nin_or_passport(value):
    """Validate NIN or passport number"""
    # NIN: 11 digits, Passport: 6-9 characters
    if len(value) == 11 and value.isdigit():
        return True  # NIN format
    elif 6 <= len(value) <= 9:
        return True  # Passport format
    return False

def validate_password(password):
    """Validate password strength"""
    return len(password) >= 8

def hash_password(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, hashed):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Database operations
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
    """Save user to database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO users (
                full_name, phone_number, email, role, nin_or_passport,
                official_authority_name, id_file_data, id_file_name, password_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_data['full_name'],
            user_data['phone_number'],
            user_data['email'],
            user_data['role'],
            user_data['nin_or_passport'],
            user_data.get('official_authority_name'),
            id_file_data,
            id_file_name,
            user_data['password_hash']
        ))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return True, user_id
    except Exception as e:
        conn.rollback()
        conn.close()
        return False, str(e)

def get_all_users():
    """Get all users for admin view"""
    conn = sqlite3.connect('users.db')
    df = pd.read_sql_query('''
        SELECT id, full_name, phone_number, email, role, 
               registration_status, created_at
        FROM users
        ORDER BY created_at DESC
    ''', conn)
    conn.close()
    return df

def verify_user(user_id):
    """Verify a user account"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE users 
            SET registration_status = 'verified', verified_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (user_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.rollback()
        conn.close()
        return False

# Main application
def main():
    # Initialize database
    init_database()
    
    # Header
    st.markdown("""
        <div class="main-header">
            <h1>🚗 Nigerian Road Risk Reporting</h1>
            <p>Secure Registration Portal</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page",
        ["Registration", "Admin Dashboard", "User Verification"]
    )
    
    if page == "Registration":
        show_registration_form()
    elif page == "Admin Dashboard":
        show_admin_dashboard()
    elif page == "User Verification":
        show_user_verification()

def show_registration_form():
    """Display the registration form"""
    st.markdown('<div class="form-container">', unsafe_allow_html=True)
    st.header("📝 User Registration")
    
    # Initialize session state
    if 'verification_complete' not in st.session_state:
        st.session_state.verification_complete = False
    
    # Form sections
    with st.form("registration_form"):
        st.subheader("👤 Personal Information")
        
        col1, col2 = st.columns(2)
        with col1:
            full_name = st.text_input("Full Name *", placeholder="Enter your full name")
            phone_number = st.text_input("Phone Number *", placeholder="+2348012345678 or 08012345678")
        
        with col2:
            email = st.text_input("Email Address (Optional)", placeholder="your.email@example.com")
            role = st.selectbox("Role *", ["", "Public", "Driver", "Admin"], help="Select your role in the system")
        
        st.subheader("🆔 Identity Information")
        
        col1, col2 = st.columns(2)
        with col1:
            nin_or_passport = st.text_input("NIN or Passport Number *", 
                                          placeholder="11-digit NIN or Passport number")
        
        with col2:
            if role == "Admin":
                official_authority_name = st.text_input("Official Authority Name *", 
                                                      placeholder="Your official authority name")
            else:
                official_authority_name = ""
        
        st.subheader("📄 Identity Document Upload")
        uploaded_file = st.file_uploader(
            "Upload ID Document (PDF, JPEG, PNG - Max 5MB)",
            type=['pdf', 'jpeg', 'jpg', 'png'],
            help="Upload a scanned copy of your ID document"
        )
        
        if uploaded_file is not None:
            # Check file size (5MB limit)
            if uploaded_file.size > 5 * 1024 * 1024:
                st.error("File size too large. Maximum size is 5MB.")
                uploaded_file = None
            else:
                st.success(f"File uploaded: {uploaded_file.name} ({(uploaded_file.size / 1024 / 1024):.2f} MB)")
        
        st.subheader("🔒 Security")
        
        col1, col2 = st.columns(2)
        with col1:
            password = st.text_input("Password *", type="password", 
                                   help="Minimum 8 characters")
        with col2:
            confirm_password = st.text_input("Confirm Password *", type="password")
        
        # Identity verification
        st.subheader("✅ Identity Verification")
        if st.button("Verify Identity", help="Click to verify your identity (simulated CAPTCHA/OTP)"):
            st.session_state.verification_complete = True
            st.success("Identity verification successful!")
        
        # Submit button
        submitted = st.form_submit_button("Complete Registration")
        
        if submitted:
            # Validation
            errors = []
            
            if not full_name or len(full_name.strip()) < 2:
                errors.append("Full name must be at least 2 characters long")
            
            if not validate_nigerian_phone(phone_number):
                errors.append("Invalid Nigerian phone number format")
            
            if email and not validate_email(email):
                errors.append("Invalid email format")
            
            if not role:
                errors.append("Please select a role")
            
            if not validate_nin_or_passport(nin_or_passport):
                errors.append("Invalid NIN (11 digits) or passport number")
            
            if role == "Admin" and not official_authority_name:
                errors.append("Official authority name is required for Admin role")
            
            if not validate_password(password):
                errors.append("Password must be at least 8 characters long")
            
            if password != confirm_password:
                errors.append("Passwords do not match")
            
            if not st.session_state.verification_complete:
                errors.append("Please complete identity verification")
            
            # Display errors or process registration
            if errors:
                for error in errors:
                    st.error(error)
            else:
                # Check unique constraints
                is_unique, message = check_unique_constraints(phone_number, nin_or_passport, email)
                
                if not is_unique:
                    st.error(message)
                else:
                    # Prepare user data
                    user_data = {
                        'full_name': full_name.strip(),
                        'phone_number': phone_number,
                        'email': email if email else None,
                        'role': role,
                        'nin_or_passport': nin_or_passport,
                        'official_authority_name': official_authority_name if role == "Admin" else None,
                        'password_hash': hash_password(password)
                    }
                    
                    # Handle file upload
                    id_file_data = None
                    id_file_name = None
                    if uploaded_file:
                        id_file_data = uploaded_file.read()
                        id_file_name = uploaded_file.name
                    
                    # Save user
                    success, result = save_user(user_data, id_file_data, id_file_name)
                    
                    if success:
                        st.success(f"""
                        🎉 Registration successful!
                        
                        **User ID:** {result}
                        **Status:** Pending verification
                        
                        Your account has been created and is awaiting verification by an administrator.
                        """)
                        
                        # Reset form
                        st.session_state.verification_complete = False
                        st.rerun()
                    else:
                        st.error(f"Registration failed: {result}")
    
    st.markdown('</div>', unsafe_allow_html=True)

def show_admin_dashboard():
    """Display admin dashboard"""
    st.markdown('<div class="form-container">', unsafe_allow_html=True)
    st.header("👨‍💼 Admin Dashboard")
    
    # Get all users
    users_df = get_all_users()
    
    if users_df.empty:
        st.info("No users registered yet.")
    else:
        # Display statistics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Users", len(users_df))
        
        with col2:
            pending_count = len(users_df[users_df['registration_status'] == 'pending'])
            st.metric("Pending Verification", pending_count)
        
        with col3:
            verified_count = len(users_df[users_df['registration_status'] == 'verified'])
            st.metric("Verified Users", verified_count)
        
        with col4:
            admin_count = len(users_df[users_df['role'] == 'Admin'])
            st.metric("Admin Users", admin_count)
        
        # Display users table
        st.subheader("📊 Registered Users")
        
        # Format the dataframe for display
        display_df = users_df.copy()
        display_df['created_at'] = pd.to_datetime(display_df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
        
        # Add status color coding
        def color_status(val):
            if val == 'verified':
                return 'background-color: #d4edda'
            elif val == 'pending':
                return 'background-color: #fff3cd'
            return ''
        
        styled_df = display_df.style.applymap(color_status, subset=['registration_status'])
        st.dataframe(styled_df, use_container_width=True)
        
        # Download functionality
        csv = users_df.to_csv(index=False)
        st.download_button(
            label="Download Users Data (CSV)",
            data=csv,
            file_name=f"users_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    
    st.markdown('</div>', unsafe_allow_html=True)

def show_user_verification():
    """Display user verification interface"""
    st.markdown('<div class="form-container">', unsafe_allow_html=True)
    st.header("✅ User Verification")
    
    # Get pending users
    conn = sqlite3.connect('users.db')
    pending_users = pd.read_sql_query('''
        SELECT id, full_name, phone_number, email, role, created_at
        FROM users
        WHERE registration_status = 'pending'
        ORDER BY created_at DESC
    ''', conn)
    conn.close()
    
    if pending_users.empty:
        st.info("No users pending verification.")
    else:
        st.subheader("⏳ Pending Verifications")
        
        for _, user in pending_users.iterrows():
            with st.expander(f"User: {user['full_name']} (ID: {user['id']})"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Name:** {user['full_name']}")
                    st.write(f"**Phone:** {user['phone_number']}")
                    st.write(f"**Email:** {user['email'] if user['email'] else 'Not provided'}")
                    st.write(f"**Role:** {user['role']}")
                    st.write(f"**Registered:** {user['created_at']}")
                
                with col2:
                    if st.button(f"Verify User {user['id']}", key=f"verify_{user['id']}"):
                        if verify_user(user['id']):
                            st.success("User verified successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to verify user")
    
    st.markdown('</div>', unsafe_allow_html=True)

if __name__ == "__main__":
    main() 
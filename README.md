# 🚗 Nigerian Road Risk Reporting App

A comprehensive web application for reporting and managing road risks in Nigeria, featuring secure user authentication, registration, and administrative controls.

## 🌟 Features

### 🔐 Authentication System
- **Secure Login**: Email/phone + password authentication
- **Forgot Password**: Complete password reset flow with secure tokens
- **Session Management**: Persistent user sessions with role-based access
- **Audit Logging**: Comprehensive logging of all user actions
- **Password Security**: bcrypt hashing for secure password storage

### 📝 User Registration
- **Multi-role Support**: Admin, Driver, Public user types
- **Identity Verification**: NIN (11 digits) or International Passport validation
- **Document Upload**: Secure ID document storage (PDF/JPEG/PNG, max 5MB)
- **Validation**: Comprehensive input validation and error handling
- **Status Tracking**: Pending/verified account status management

### 👨‍💼 Admin Dashboard
- **User Management**: View, verify, and manage all registered users
- **Statistics**: Real-time user statistics and metrics
- **Audit Logs**: Complete audit trail of system activities
- **Data Export**: Download user data and logs in CSV format
- **Role-based Access**: Admin-only features and controls

### 🔒 Security Features
- **Password Hashing**: bcrypt for secure password storage
- **Input Validation**: Comprehensive validation for all user inputs
- **Session Security**: Secure session management
- **Audit Trail**: Complete logging of user actions and system events
- **Token-based Reset**: Secure password reset with time-limited tokens

## 🛠 Tech Stack

- **Frontend**: Streamlit (Python web framework)
- **Backend**: Python with SQLite database
- **Database**: SQLite with SQLAlchemy-style operations
- **Authentication**: bcrypt for password hashing
- **Security**: Built-in Python security modules (secrets, hashlib)
- **Deployment**: Streamlit Cloud ready

## 📋 Database Schema

### Users Table
- `id`: Primary key
- `full_name`: User's full name
- `phone_number`: Nigerian phone number (unique)
- `email`: Email address (optional)
- `role`: User role (Admin/Driver/Public)
- `nin_or_passport`: NIN or Passport number (unique)
- `official_authority_name`: Required for Admin role
- `id_file_data`: Uploaded ID document (BLOB)
- `id_file_name`: Original filename
- `password_hash`: Hashed password
- `registration_status`: Pending/Verified
- `created_at`: Registration timestamp
- `verified_at`: Verification timestamp
- `last_login`: Last login timestamp

### Logs Table (Audit Trail)
- `id`: Primary key
- `user_id`: Foreign key to users
- `action`: Action performed (LOGIN_SUCCESS, LOGIN_FAILED, etc.)
- `details`: Action details
- `ip_address`: User's IP address
- `timestamp`: Action timestamp

### Reset Tokens Table
- `id`: Primary key
- `user_id`: Foreign key to users
- `token`: Secure reset token
- `expires_at`: Token expiration time
- `used`: Token usage status
- `created_at`: Token creation time

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Local Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/ibrahimlabaranali/Road-Status-Nigeria-V7.git
   cd Road-Status-Nigeria-V7
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   streamlit run app.py
   ```

4. **Access the application**
   - Open your browser and go to `http://localhost:8501`
   - The app will automatically create the database and tables

## 🌐 Streamlit Cloud Deployment

### Prerequisites
- GitHub account
- Streamlit Cloud account (free at [share.streamlit.io](https://share.streamlit.io))

### Deployment Steps

1. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Add authentication system"
   git push origin main
   ```

2. **Deploy to Streamlit Cloud**
   - Visit [share.streamlit.io](https://share.streamlit.io)
   - Sign in with GitHub
   - Click "New app"
   - Select repository: `ibrahimlabaranali/Road-Status-Nigeria-V7`
   - Set main file: `app.py`
   - Click "Deploy"

3. **Access Your App**
   - Your app will be available at: `https://road-status-nigeria-v7-ibrahimlabaranali.streamlit.app`

## 🔐 Authentication Flow

### Login Process
1. User enters email/phone and password
2. System validates credentials against database
3. If valid, user is logged in and redirected to dashboard
4. If invalid, error message is shown and login attempt is logged
5. Session is maintained for authenticated users

### Password Reset Process
1. User clicks "Forgot Password" on login page
2. User enters email or phone number
3. System generates secure reset token (valid for 1 hour)
4. Token is displayed (in production, would be sent via email)
5. User enters token and new password
6. Password is updated and token is marked as used

### Registration Process
1. User fills out registration form with all required fields
2. System validates all inputs (phone, email, NIN/passport, etc.)
3. Password is hashed using bcrypt
4. User account is created with "pending" status
5. Admin can verify user account from admin dashboard

## 👨‍💼 Admin Features

### User Management
- View all registered users
- See user statistics (total, verified, pending, admin users)
- Verify pending user accounts
- Download user data as CSV

### Audit Logs
- View complete audit trail of system activities
- See login attempts, registrations, password resets, etc.
- Download logs as CSV for analysis
- Track user actions with timestamps and IP addresses

### Security Monitoring
- Monitor failed login attempts
- Track password reset requests
- View user verification activities
- Monitor system usage patterns

## 🔒 Security Considerations

### Password Security
- All passwords are hashed using bcrypt
- Password validation requires minimum 8 characters
- Secure token generation for password reset
- Time-limited reset tokens (1 hour expiration)

### Input Validation
- Nigerian phone number format validation
- Email format validation
- NIN (11 digits) or Passport number validation
- File upload size and type restrictions

### Session Management
- Secure session state management
- Automatic logout functionality
- Role-based access control
- Audit logging of all actions

### Data Protection
- SQLite database with proper indexing
- Secure file upload handling
- Input sanitization and validation
- Comprehensive error handling

## 📊 Usage Statistics

The application tracks various metrics:
- Total registered users
- Verified vs pending users
- Admin user count
- Login success/failure rates
- User activity patterns

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Ensure the app has write permissions in the directory
   - Check if `users.db` file is not locked by another process

2. **Import Errors**
   - Verify all dependencies are installed: `pip install -r requirements.txt`
   - Check Python version compatibility (3.8+)

3. **Streamlit Cloud Deployment Issues**
   - Ensure `requirements.txt` is in the root directory
   - Check that `app.py` is the main file
   - Verify all imports are compatible with Streamlit Cloud

### Local Testing
```bash
# Test the application locally
streamlit run app.py

# Check for any import errors
python -c "import streamlit, pandas, bcrypt, sqlite3"
```

## 🔄 Updates and Maintenance

### Adding New Features
1. Update the main `app.py` file
2. Test locally with `streamlit run app.py`
3. Update `requirements.txt` if new dependencies are added
4. Commit and push to GitHub
5. Streamlit Cloud will automatically redeploy

### Database Migrations
- The app automatically creates/updates database schema
- New tables are added automatically when the app starts
- Existing data is preserved during updates

## 📞 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the audit logs for error details
3. Ensure all dependencies are properly installed
4. Verify database permissions and connectivity

## 🎯 Future Enhancements

- Email integration for password reset
- Two-factor authentication (2FA)
- Advanced user roles and permissions
- API endpoints for external integrations
- Mobile app compatibility
- Real-time notifications
- Advanced reporting and analytics

---

**Built with ❤️ for Nigerian Road Safety** 
# Nigerian Road Risk Reporting App - Registration Module

A secure, modern registration system for the Nigerian Road Risk Reporting application. Built with Streamlit, SQLite, and optimized for Streamlit Cloud deployment.

## 🚀 Features

### Core Registration Features
- **Multi-role Registration**: Support for Admin, Driver, and Public users
- **Identity Verification**: NIN (11 digits) or International Passport validation
- **File Upload**: Secure document upload (PDF/JPEG/PNG) with 5MB limit
- **Phone Validation**: Nigerian phone number format validation
- **Email Validation**: Optional email with format validation
- **Password Security**: bcrypt hashing with minimum 8-character requirement

### Security Features
- **Password Hashing**: Secure bcrypt implementation
- **Input Validation**: Comprehensive client and server-side validation
- **File Type Validation**: Restricted to secure document formats
- **Unique Constraints**: Phone number, NIN/Passport, and email uniqueness
- **Identity Verification**: Simulated CAPTCHA/OTP system

### User Experience
- **Modern UI**: Beautiful Streamlit interface with custom styling
- **Real-time Validation**: Instant feedback on form inputs
- **Progress Indicators**: Visual feedback during operations
- **Error Handling**: Comprehensive error messages
- **Mobile Responsive**: Optimized for all device sizes
- **Admin Dashboard**: Complete user management interface

## 🛠 Tech Stack

- **Frontend & Backend**: Streamlit (Python)
- **Database**: SQLite with native Python sqlite3
- **Security**: bcrypt for password hashing
- **Data Processing**: Pandas for data manipulation
- **File Handling**: Secure file upload with validation
- **Validation**: Custom validation functions

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## 🚀 Installation & Setup

### Local Development

#### 1. Clone or Download the Project
```bash
# If using git
git clone <repository-url>
cd "Road Status Nigeria V7"

# Or simply download and extract the files
```

#### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 3. Run the Application
```bash
streamlit run streamlit_app.py
```

#### 4. Access the Application
Open your browser and navigate to:
```
http://localhost:8501
```

### Streamlit Cloud Deployment

#### 1. Prepare Your Repository
Ensure your repository contains:
- `streamlit_app.py` (main application file)
- `requirements.txt` (dependencies)
- `.streamlit/config.toml` (configuration)

#### 2. Deploy to Streamlit Cloud
1. Go to [share.streamlit.io](https://share.streamlit.io)
2. Sign in with your GitHub account
3. Click "New app"
4. Select your repository
5. Set the main file path to: `streamlit_app.py`
6. Click "Deploy"

#### 3. Access Your Deployed App
Your app will be available at:
```
https://your-app-name-your-username.streamlit.app
```

## 📁 Project Structure

```
Road Status Nigeria V7/
├── streamlit_app.py        # Main Streamlit application
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── .streamlit/
│   └── config.toml        # Streamlit configuration
├── app.py                 # FastAPI version (alternative)
├── templates/             # HTML templates (for FastAPI version)
├── static/               # CSS files (for FastAPI version)
├── test_app.py           # Test script
├── start_app.bat         # Windows startup script
├── .gitignore           # Git ignore file
└── users.db             # SQLite database (auto-created)
```

## 🎯 Usage Guide

### Registration Process

1. **Fill Personal Information**
   - Full Name (required)
   - Phone Number (Nigerian format: +2348012345678 or 08012345678)
   - Email Address (optional)
   - Role selection (Admin, Driver, or Public)

2. **Provide Identity Information**
   - NIN (11 digits) or Passport Number
   - Official Authority Name (required for Admin role)

3. **Upload Identity Document**
   - Supported formats: PDF, JPEG, PNG
   - Maximum size: 5MB
   - Drag and drop or click to upload

4. **Set Security Credentials**
   - Password (minimum 8 characters)
   - Confirm password

5. **Verify Identity**
   - Click "Verify Identity" button (simulated CAPTCHA/OTP)
   - Complete the verification process

6. **Submit Registration**
   - Review all information
   - Click "Complete Registration"

### Admin Features

#### Admin Dashboard
- View all registered users
- Download user data as CSV
- View registration statistics
- Monitor pending verifications

#### User Verification
- Review pending user registrations
- Verify user accounts
- View user details

### Validation Rules

#### Phone Number
- Must be Nigerian format: `+2348012345678` or `08012345678`
- Must start with +234 or 0, followed by 7, 8, or 9, then 0 or 1, then 8 digits

#### NIN/Passport
- **NIN**: Exactly 11 digits
- **Passport**: 6-9 characters

#### Email (Optional)
- Must be valid email format if provided
- Must be unique if provided

#### Password
- Minimum 8 characters
- Confirmed password must match

#### File Upload
- **Types**: PDF, JPEG, PNG only
- **Size**: Maximum 5MB
- **Required**: Yes

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
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
);
```

## 🔒 Security Features

### Password Security
- bcrypt hashing with salt
- Minimum 8-character requirement
- Secure password verification

### Input Validation
- Server-side validation with custom functions
- Client-side validation with Streamlit
- SQL injection prevention with parameterized queries

### File Security
- File type validation
- File size limits
- Secure file storage in database

### Data Protection
- Unique constraints on sensitive fields
- Input sanitization
- Error handling without data exposure

## 🚨 Error Handling

The application provides comprehensive error handling:

- **Validation Errors**: Clear messages for invalid inputs
- **File Upload Errors**: Size and type validation feedback
- **Database Errors**: Unique constraint violations
- **Network Errors**: Connection and timeout handling

## 🔧 Configuration

### Streamlit Configuration (.streamlit/config.toml)
```toml
[theme]
primaryColor = "#667eea"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"
font = "sans serif"
```

### Environment Variables (Optional)
Create a `.env` file for custom configuration:
```env
DATABASE_PATH=users.db
MAX_FILE_SIZE=5242880
```

## 🧪 Testing

### Manual Testing
1. Test all form validations
2. Test file upload with different file types
3. Test role-specific requirements
4. Test identity verification flow
5. Test error scenarios
6. Test admin dashboard functionality

### Automated Testing
Run the test script:
```bash
python test_app.py
```

## 🚀 Deployment

### Local Development
```bash
streamlit run streamlit_app.py --server.port 8501
```

### Streamlit Cloud Deployment
1. Push your code to GitHub
2. Connect your repository to Streamlit Cloud
3. Deploy with one click
4. Your app is live and accessible worldwide

### Production Considerations
- Database backups
- SSL certificates (handled by Streamlit Cloud)
- Rate limiting (consider implementing)
- Monitoring and logging

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions:
- Check the documentation above
- Review error messages in the application
- Test with different inputs
- Verify all dependencies are installed

## 🔄 Future Enhancements

- [ ] Email verification system
- [ ] SMS OTP verification
- [ ] Advanced admin dashboard
- [ ] User profile management
- [ ] Password reset functionality
- [ ] Audit logging
- [ ] Rate limiting
- [ ] Multi-language support
- [ ] Dark mode theme
- [ ] Advanced analytics

## 🌟 Streamlit Cloud Benefits

- **Zero Infrastructure**: No server setup required
- **Automatic Scaling**: Handles traffic spikes automatically
- **Global CDN**: Fast loading worldwide
- **SSL Certificates**: Secure HTTPS by default
- **Version Control**: Automatic deployments from Git
- **Free Tier**: Generous free hosting
- **Custom Domains**: Use your own domain name

---

**Note**: This is a registration module for the Nigerian Road Risk Reporting app. The system is designed to be secure, scalable, and ready for integration with additional modules like login, dashboard, and reporting features. The Streamlit version is optimized for easy deployment and maintenance. 
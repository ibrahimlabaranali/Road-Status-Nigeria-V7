# Deployment Guide for Nigerian Road Risk Reporting App

## 🚀 Streamlit Cloud Deployment

### Prerequisites
- GitHub account
- Streamlit Cloud account (free at [share.streamlit.io](https://share.streamlit.io))

### Step 1: Push to GitHub

1. **Initialize Git Repository** (if not already done):
```bash
git init
git add .
git commit -m "Initial commit: Nigerian Road Risk Reporting App"
```

2. **Add GitHub Remote**:
```bash
git remote add origin https://github.com/ibrahimlabaranali/Road-Status-Nigeria-V7.git
```

3. **Push to GitHub**:
```bash
git push -u origin main
```

### Step 2: Deploy to Streamlit Cloud

1. **Go to Streamlit Cloud**: Visit [share.streamlit.io](https://share.streamlit.io)

2. **Sign in with GitHub**: Use your GitHub account to sign in

3. **Create New App**:
   - Click "New app"
   - Select your repository: `ibrahimlabaranali/Road-Status-Nigeria-V7`
   - Set the main file path to: `app.py`
   - Click "Deploy"

4. **Wait for Deployment**: Streamlit Cloud will automatically:
   - Install dependencies from `requirements.txt`
   - Build your app
   - Deploy it to a public URL

### Step 3: Access Your App

Your app will be available at:
```
https://road-status-nigeria-v7-ibrahimlabaranali.streamlit.app
```

## 📁 Required Files for Deployment

Ensure these files are in your repository:

```
Road-Status-Nigeria-V7/
├── app.py                 # Main Streamlit application
├── requirements.txt       # Python dependencies
├── .streamlit/
│   └── config.toml       # Streamlit configuration
├── README.md             # Project documentation
├── .gitignore           # Git ignore file
└── LICENSE              # MIT License
```

## 🔧 Configuration Files

### requirements.txt
```
streamlit==1.28.1
pandas==2.1.3
bcrypt==4.1.2
python-dotenv==1.0.0
```

### .streamlit/config.toml
```toml
[global]
developmentMode = false

[server]
headless = true
port = 8501
enableCORS = false
enableXsrfProtection = false

[browser]
gatherUsageStats = false

[theme]
primaryColor = "#667eea"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"
font = "sans serif"

[client]
showErrorDetails = false
```

## 🐛 Troubleshooting

### Common Issues:

1. **Import Errors**: Ensure all dependencies are in `requirements.txt`
2. **Database Issues**: SQLite works fine on Streamlit Cloud
3. **File Upload**: Supported up to 5MB
4. **Port Issues**: Streamlit Cloud handles ports automatically

### Local Testing:
```bash
streamlit run app.py
```

## 🔄 Updates

To update your deployed app:

1. Make changes to your code
2. Commit and push to GitHub:
```bash
git add .
git commit -m "Update: [describe changes]"
git push
```
3. Streamlit Cloud will automatically redeploy

## 📊 Monitoring

- Check deployment status in Streamlit Cloud dashboard
- View logs for any errors
- Monitor app performance

## 🔒 Security Notes

- Database is stored locally in Streamlit Cloud
- File uploads are stored in the database
- Passwords are hashed with bcrypt
- No sensitive data is exposed

## 🌟 Features Available

- ✅ User Registration with validation
- ✅ File upload (PDF, JPEG, PNG)
- ✅ Admin Dashboard
- ✅ User Verification
- ✅ Data export (CSV)
- ✅ Responsive design
- ✅ Nigerian phone number validation
- ✅ NIN/Passport validation

## 📞 Support

If you encounter issues:
1. Check the Streamlit Cloud logs
2. Verify all files are committed to GitHub
3. Ensure `app.py` is the main file
4. Check that `requirements.txt` is in the root directory 
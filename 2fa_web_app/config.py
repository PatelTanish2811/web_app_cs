import os

class Config:
    # Secret key for session and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev_secret_key'
    # SQLite database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Flask-Mail (Gmail SMTP)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    # Use environment variables for security. Set these in your terminal:
    # $env:MAIL_USERNAME="your@email.com"
    # $env:MAIL_PASSWORD="your_app_password" (Gmail App Password, not your normal password)
    # For local testing, you can hardcode your Gmail and app password here (not recommended for production)
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'menattanishtm@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'wmpiafycahsvnlsg'

import secrets
import string
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_real_email_otp(receiver_email, otp_code):
    sender_email = "zappohackoo@gmail.com"  # Put your Gmail here
    app_password = "fkqpwddtscndasgf"   # Put your App Password here (no spaces)

    # Create the email message
    msg = MIMEMultipart()
    msg['Subject'] = "PRIVACY_OS: Security Clearance Request"
    msg['From'] = sender_email
    msg['To'] = receiver_email

    # The creepy hacker-style email body
    body = f"""
    [ SYSTEM ALERT ]
    
    An authentication request was made for this email address.
    
    YOUR AUTHORIZATION CIPHER: {otp_code}
    
    If you did not request this clearance, someone is attempting to breach your account.
    """
    msg.attach(MIMEText(body, 'plain'))

    # Send the email through Google's SMTP server
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls() # Secure the connection
        server.login(sender_email, app_password)
        server.send_message(msg)
        server.quit()
        print(f"SUCCESS: Email sent to {receiver_email}")
    except Exception as e:
        print(f"CRITICAL ERROR sending email: {e}")
# --- PASSWORD HASHING ---
# CRITICAL FIX: Changed back to pbkdf2_sha256 to match your PostgreSQL database!
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def generate_otp(length=6):
    """Generates a random 6-digit OTP."""
    digits = string.digits
    return ''.join(secrets.choice(digits) for i in range(length))

# --- JWT TOKEN GENERATION ---
SECRET_KEY = "privacy-os-super-secret-key-change-this-later" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 # Token expires in 1 hour

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    
    # Cryptographically sign the token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
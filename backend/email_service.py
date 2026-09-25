import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Replace with your actual Postman SMTP credentials
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "privacy.os.dispatch@gmail.com"
SENDER_PASSWORD = "your_app_password_here"  # Keep your active app password

def send_dispatch_email(sender_email: str, recipient_email: str, file_id: str, lock_type: str):
    """
    Dispatches a secure drop notification to the recipient via Postman SMTP.
    NOTE: As per Zero-Trust Protocol, the encryption key/password is NEVER sent 
    via email. The sender must communicate it directly (out-of-band).
    """
    subject = "🛡️ PrivacyOS // Secure Payload Dispatched"
    
    body = f"""
    CLASSIFIED INTELLIGENCE DISPATCH
    ---------------------------------
    Sender Agent: {sender_email}
    Transfer Protocol: Zero-Trust End-to-End Encrypted Drop
    
    A secure payload has been deposited into your PrivacyOS Inbound Terminal.
    
    VAULT FILE ID (UUID):
    {file_id}
    
    SECURITY NOTICE:
    As per zero-trust policy, the decryption key or cipher has NOT been 
    transmitted through this email channel. Contact Agent {sender_email} directly 
    via secure comms or out-of-band channels to acquire your decryption key.
    
    ---------------------------------
    PrivacyOS Ghost Engine v1.0 // DEFCON 1
    """

    message = MIMEMultipart()
    message["From"] = SENDER_EMAIL
    message["To"] = recipient_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, message.as_string())
        server.quit()
        print(f"Secure dispatch notification sent to {recipient_email}")
    except Exception as e:
        print(f"SMTP Dispatch Error: {str(e)}")
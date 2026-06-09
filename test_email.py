import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv

# Load .env
load_dotenv()

def test_smtp_connection():
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", 587))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASS")
    sender = os.getenv("SMTP_FROM")
    recipient = os.getenv("SMTP_TO")

    print(f"--- Project Sentinel SMTP Test ---")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"User: {user}")
    print(f"Sender: {sender}")
    print(f"Recipient: {recipient}")
    print(f"----------------------------------")

    msg = MIMEMultipart()
    msg['Subject'] = "Sentinel DEBUG: SMTP Test Run"
    msg['From'] = sender
    msg['To'] = recipient
    
    body = "This is a diagnostic email from Project Sentinel to verify SMTP delivery settings."
    msg.attach(MIMEText(body, 'plain'))

    try:
        print("\n[Step 1] Connecting to server...")
        server = smtplib.SMTP(host, port, timeout=30)
        server.set_debuglevel(1)  # Enable verbose output
        
        print("\n[Step 2] Sending HELO/EHLO...")
        server.ehlo()
        
        if server.has_extn('STARTTLS'):
            print("\n[Step 3] Starting STARTTLS...")
            server.starttls()
            server.ehlo()  # EHLO again after STARTTLS
        
        print(f"\n[Step 4] Logging in as {user}...")
        server.login(user, password)
        
        print(f"\n[Step 5] Sending message to {recipient}...")
        server.send_message(msg)
        
        server.quit()
        print("\n>>> SUCCESS: SMTP transaction completed successfully.")
        print(f">>> Check your inbox (and SPAM) at: {recipient}")
    except Exception as e:
        print(f"\n>>> FAILURE: {e}")

if __name__ == "__main__":
    test_smtp_connection()

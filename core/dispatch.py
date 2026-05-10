import smtplib
import json
import requests
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from typing import List, Optional, Dict, Any
from config import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, SMTP_TO,
    WEBHOOK_URL, logger
)

class Dispatcher:
    def __init__(self):
        self.smtp_host = SMTP_HOST
        self.smtp_port = SMTP_PORT
        self.smtp_user = SMTP_USER
        self.smtp_pass = SMTP_PASS
        self.smtp_from = SMTP_FROM
        self.smtp_to = SMTP_TO
        self.webhook_url = WEBHOOK_URL

    def send_email(self, subject: str, html_content: str, attachments: List[Dict[str, Any]] = None):
        """Sends an HTML email with optional attachments."""
        if not all([self.smtp_host, self.smtp_user, self.smtp_pass, self.smtp_to]):
            logger.warning("SMTP configuration incomplete. Skipping email dispatch.")
            return

        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = self.smtp_from or self.smtp_user
        msg['To'] = self.smtp_to

        msg.attach(MIMEText(html_content, 'html'))

        if attachments:
            for att in attachments:
                try:
                    part = MIMEApplication(att['content'], Name=att['filename'])
                    part['Content-Disposition'] = f'attachment; filename="{att["filename"]}"'
                    msg.attach(part)
                except Exception as e:
                    logger.error(f"Failed to attach file {att.get('filename')}: {e}")

        try:
            logger.info(f"Sending email to {self.smtp_to}: {subject}")
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
            logger.info("Email sent successfully.")
        except Exception as e:
            logger.error(f"Error sending email: {e}")

    def send_webhook(self, briefing: str):
        """Sends a briefing to a webhook via POST."""
        if not self.webhook_url:
            logger.warning("Webhook URL not set. Skipping webhook dispatch.")
            return

        payload = {
            "text": briefing,
            "source": "Project Sentinel",
            "type": "executive_briefing"
        }

        try:
            logger.info(f"Sending briefing to webhook: {self.webhook_url}")
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("Webhook sent successfully.")
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")

if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    dispatcher = Dispatcher()
    # dispatcher.send_webhook("Test briefing")

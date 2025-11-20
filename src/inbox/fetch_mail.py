import imaplib
import email
from email import policy
import os
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class EmailFetcher:
    def __init__(self, imap_server, username, password, mailbox='INBOX'):
        self.imap_server = imap_server
        self.username = username
        self.password = password
        self.mailbox = mailbox
        self.connection = None
        
    def connect(self):
        """Establish connection to IMAP server"""
        try:
            self.connection = imaplib.IMAP4_SSL(self.imap_server)
            self.connection.login(self.username, self.password)
            self.connection.select(self.mailbox)
            logger.info("Successfully connected to IMAP server")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to IMAP server: {e}")
            return False
            
    def fetch_unread_emails(self):
        """Fetch all unread emails from mailbox"""
        if not self.connection:
            logger.error("No connection established")
            return []
            
        try:
            # Search for unread messages
            status, messages = self.connection.search(None, 'UNSEEN')
            if status != 'OK':
                logger.error("Failed to search emails")
                return []
                
            email_ids = messages[0].split()
            emails = []
            
            for email_id in email_ids:
                try:
                    status, msg_data = self.connection.fetch(email_id, '(RFC822)')
                    if status == 'OK':
                        raw_email = msg_data[0][1]
                        email_message = email.message_from_bytes(raw_email, policy=policy.default)
                        emails.append({
                            'id': email_id.decode(),
                            'subject': email_message.get('Subject', 'No Subject'),
                            'from': email_message.get('From', 'Unknown'),
                            'date': email_message.get('Date', ''),
                            'raw': raw_email,
                            'message': email_message
                        })
                        logger.info(f"Fetched email: {email_message.get('Subject')}")
                except Exception as e:
                    logger.error(f"Error processing email {email_id}: {e}")
                    
            return emails
        except Exception as e:
            logger.error(f"Error fetching unread emails: {e}")
            return []
            
    def save_eml_file(self, raw_email, filename_prefix=""):
        """Save raw email as .eml file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{filename_prefix}email_{timestamp}.eml"
            os.makedirs('samples', exist_ok=True)
            
            with open(f'samples/{filename}', 'wb') as f:
                f.write(raw_email)
                
            logger.info(f"Email saved as: samples/{filename}")
            return filename
        except Exception as e:
            logger.error(f"Error saving email file: {e}")
            return None
            
    def disconnect(self):
        """Close IMAP connection"""
        if self.connection:
            try:
                self.connection.close()
                self.connection.logout()
                logger.info("Disconnected from IMAP server")
            except Exception as e:
                logger.error(f"Error disconnecting: {e}")
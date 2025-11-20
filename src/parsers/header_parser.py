import email
from email import policy
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class HeaderParser:
    def __init__(self, raw_email):
        self.raw_email = raw_email
        self.email_message = email.message_from_bytes(raw_email, policy=policy.default)
        self.parsed_headers = {}
        
    def parse_all_headers(self):
        """Parse all relevant email headers for phishing analysis"""
        try:
            self.parsed_headers = {
                'basic_info': self._parse_basic_info(),
                'authentication': self._parse_authentication_headers(),
                'routing': self._parse_routing_headers(),
                'security': self._parse_security_headers(),
                'suspicious_indicators': self._check_suspicious_indicators()
            }
            return self.parsed_headers
        except Exception as e:
            logger.error(f"Error parsing headers: {e}")
            return {}
            
    def _parse_basic_info(self):
        """Extract basic email information"""
        return {
            'subject': self.email_message.get('Subject', ''),
            'from': self.email_message.get('From', ''),
            'to': self.email_message.get('To', ''),
            'date': self.email_message.get('Date', ''),
            'message_id': self.email_message.get('Message-ID', ''),
            'reply_to': self.email_message.get('Reply-To', '')
        }
        
    def _parse_authentication_headers(self):
        """Parse authentication-related headers"""
        auth_headers = {}
        
        # SPF Check
        received_spf = self.email_message.get('Received-SPF', '')
        auth_headers['spf'] = {
            'value': received_spf,
            'result': self._extract_spf_result(received_spf)
        }
        
        # DKIM Signature
        dkim_signature = self.email_message.get('DKIM-Signature', '')
        auth_headers['dkim'] = {
            'present': bool(dkim_signature),
            'value': dkim_signature[:100] + "..." if len(dkim_signature) > 100 else dkim_signature
        }
        
        # DMARC
        authentication_results = self.email_message.get('Authentication-Results', '')
        auth_headers['dmarc'] = {
            'value': authentication_results,
            'result': self._extract_dmarc_result(authentication_results)
        }
        
        return auth_headers
        
    def _parse_routing_headers(self):
        """Parse email routing headers"""
        routing = {}
        
        # Received headers
        received_headers = self.email_message.get_all('Received', [])
        routing['received'] = []
        
        for received in received_headers:
            routing['received'].append({
                'from': self._extract_received_from(received),
                'by': self._extract_received_by(received),
                'with': self._extract_received_with(received),
                'timestamp': self._extract_received_date(received)
            })
            
        # Return-Path
        routing['return_path'] = self.email_message.get('Return-Path', '')
        
        return routing
        
    def _parse_security_headers(self):
        """Parse security-related headers"""
        security = {}
        
        security_headers = [
            'X-Mailer', 'User-Agent', 'X-Originating-IP',
            'X-Priority', 'MIME-Version', 'Content-Type'
        ]
        
        for header in security_headers:
            value = self.email_message.get(header, '')
            if value:
                security[header.lower()] = value
                
        return security
        
    def _check_suspicious_indicators(self):
        """Check for suspicious indicators in headers"""
        indicators = []
        basic_info = self._parse_basic_info()
        
        # Check for suspicious subject patterns
        subject = basic_info['subject'].lower()
        suspicious_subject_terms = ['urgent', 'security alert', 'password reset', 'verify account']
        if any(term in subject for term in suspicious_subject_terms):
            indicators.append('Suspicious subject containing urgency terms')
            
        # Check for mismatched From and Reply-To
        from_addr = basic_info['from']
        reply_to = basic_info['reply_to']
        if reply_to and from_addr != reply_to:
            indicators.append(f'From ({from_addr}) and Reply-To ({reply_to}) mismatch')
            
        # Check for missing authentication headers
        auth = self._parse_authentication_headers()
        if not auth['dkim']['present']:
            indicators.append('Missing DKIM signature')
            
        if 'fail' in auth['spf']['result'].lower():
            indicators.append(f"SPF check failed: {auth['spf']['result']}")
            
        return indicators
        
    def _extract_spf_result(self, received_spf):
        """Extract SPF result from header"""
        match = re.search(r'(\w+)\s*\(', received_spf)
        return match.group(1) if match else 'none'
        
    def _extract_dmarc_result(self, auth_results):
        """Extract DMARC result from header"""
        match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        return match.group(1) if match else 'none'
        
    def _extract_received_from(self, received_header):
        """Extract from information from Received header"""
        match = re.search(r'from\s+([^\s]+)', received_header, re.IGNORECASE)
        return match.group(1) if match else ''
        
    def _extract_received_by(self, received_header):
        """Extract by information from Received header"""
        match = re.search(r'by\s+([^\s]+)', received_header, re.IGNORECASE)
        return match.group(1) if match else ''
        
    def _extract_received_with(self, received_header):
        """Extract with information from Received header"""
        match = re.search(r'with\s+([^\s;]+)', received_header, re.IGNORECASE)
        return match.group(1) if match else ''
        
    def _extract_received_date(self, received_header):
        """Extract date from Received header"""
        match = re.search(r';\s*([^;]+)$', received_header)
        return match.group(1).strip() if match else ''
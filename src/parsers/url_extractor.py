import re
import email
from urllib.parse import urlparse, unquote
import logging
from html.parser import HTMLParser
import base64

logger = logging.getLogger(__name__)

class URLHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
        
    def handle_starttag(self, tag, attrs):
        if tag in ['a', 'img', 'script', 'link', 'form']:
            for attr, value in attrs:
                if attr in ['href', 'src', 'action'] and value:
                    self.urls.append(value)

class URLExtractor:
    def __init__(self, email_message):
        self.email_message = email_message
        self.found_urls = []
        
    def extract_all_urls(self):
        """Extract URLs from all parts of the email"""
        try:
            self.found_urls = []
            
            # Extract from text parts
            self._extract_from_text_parts()
            
            # Extract from HTML parts
            self._extract_from_html_parts()
            
            # Extract from headers
            self._extract_from_headers()
            
            # Clean and deduplicate URLs
            self._clean_urls()
            
            logger.info(f"Extracted {len(self.found_urls)} unique URLs")
            return self.found_urls
            
        except Exception as e:
            logger.error(f"Error extracting URLs: {e}")
            return []
            
    def _extract_from_text_parts(self):
        """Extract URLs from plain text parts"""
        for part in self.email_message.walk():
            if part.get_content_type() == 'text/plain':
                text_content = part.get_content()
                if text_content:
                    self._extract_urls_from_text(text_content)
                    
    def _extract_from_html_parts(self):
        """Extract URLs from HTML parts"""
        for part in self.email_message.walk():
            if part.get_content_type() == 'text/html':
                html_content = part.get_content()
                if html_content:
                    self._extract_urls_from_html(html_content)
                    
    def _extract_from_headers(self):
        """Extract URLs from email headers"""
        headers_to_check = ['List-Unsubscribe', 'X-Link', 'X-URL']
        
        for header in headers_to_check:
            value = self.email_message.get(header, '')
            if value:
                self._extract_urls_from_text(value)
                
    def _extract_urls_from_text(self, text):
        """Extract URLs from plain text using regex"""
        # Common URL patterns
        url_patterns = [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            r'www\.[^\s<>"{}|\\^`\[\]]+',
            r'[a-z0-9.-]+\.[a-z]{2,}/[^\s<>"{}|\\^`\[\]]+'
        ]
        
        for pattern in url_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                url = match.group(0)
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                self.found_urls.append(url)
                
    def _extract_urls_from_html(self, html_content):
        """Extract URLs from HTML content"""
        try:
            parser = URLHTMLParser()
            parser.feed(html_content)
            
            for url in parser.urls:
                if not url.startswith(('http://', 'https://', 'mailto:')):
                    url = 'http://' + url
                self.found_urls.append(url)
                
        except Exception as e:
            logger.error(f"Error parsing HTML for URLs: {e}")
            
    def _clean_urls(self):
        """Clean and deduplicate extracted URLs"""
        cleaned_urls = []
        seen_urls = set()
        
        for url in self.found_urls:
            try:
                # Decode URL-encoded characters
                cleaned_url = unquote(url)
                
                # Remove common tracking parameters
                parsed = urlparse(cleaned_url)
                if parsed.netloc:  # Only keep URLs with valid netloc
                    # Basic normalization
                    normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    if normalized_url not in seen_urls:
                        seen_urls.add(normalized_url)
                        cleaned_urls.append({
                            'original': url,
                            'cleaned': cleaned_url,
                            'domain': parsed.netloc,
                            'path': parsed.path,
                            'full_url': normalized_url,
                            'suspicious': self._check_suspicious_url(cleaned_url)
                        })
            except Exception as e:
                logger.warning(f"Error cleaning URL {url}: {e}")
                
        self.found_urls = cleaned_urls
        
    def _check_suspicious_url(self, url):
        """Check if URL has suspicious characteristics"""
        suspicious_indicators = []
        
        # Check for IP address instead of domain
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        if re.search(ip_pattern, url):
            suspicious_indicators.append('Uses IP address instead of domain')
            
        # Check for URL shortening services
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        if any(shortener in url for shortener in shorteners):
            suspicious_indicators.append('Uses URL shortening service')
            
        # Check for mismatched domains in display vs actual URL
        if '@' in url:
            suspicious_indicators.append('Contains @ symbol (possible deception)')
            
        # Check for excessive subdomains
        domain = urlparse(url).netloc
        if domain.count('.') > 3:
            suspicious_indicators.append('Excessive subdomains')
            
        return suspicious_indicators
import re
from html.parser import HTMLParser
import logging
from urllib.parse import urlparse, unquote
import base64

logger = logging.getLogger(__name__)

class HTMLPhishingAnalyzer(HTMLParser):
    def __init__(self):
        super().__init__()
        self.suspicious_elements = []
        self.form_data = []
        self.hidden_inputs = []
        self.script_content = []
        self.external_resources = []
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        # Check for suspicious form attributes
        if tag == 'form':
            self._analyze_form(attrs_dict)
            
        # Check for hidden inputs
        if tag == 'input' and attrs_dict.get('type') == 'hidden':
            self._analyze_hidden_input(attrs_dict)
            
        # Check for suspicious meta tags
        if tag == 'meta':
            self._analyze_meta_tag(attrs_dict)
            
        # Check for external resources
        if tag in ['img', 'script', 'link']:
            self._analyze_external_resource(tag, attrs_dict)
            
    def handle_data(self, data):
        # Analyze script content
        if self.script_content is not None:
            script_text = data.strip()
            if script_text and len(script_text) > 10:
                self._analyze_script_content(script_text)
                
    def _analyze_form(self, attrs):
        """Analyze HTML form for phishing indicators"""
        form_info = {'action': attrs.get('action', ''), 'indicators': []}
        
        # Check for suspicious form actions
        action = attrs.get('action', '').lower()
        if not action.startswith(('http://', 'https://')):
            form_info['indicators'].append('Form action uses relative URL')
        elif 'http://' in action and not action.startswith('https://'):
            form_info['indicators'].append('Form uses HTTP instead of HTTPS')
            
        # Check for suspicious form attributes
        if attrs.get('method', 'get').lower() == 'get':
            form_info['indicators'].append('Form uses GET method (credentials in URL)')
            
        if form_info['indicators']:
            self.form_data.append(form_info)
            
    def _analyze_hidden_input(self, attrs):
        """Analyze hidden input fields"""
        hidden_input = {
            'name': attrs.get('name', ''),
            'value': attrs.get('value', ''),
            'suspicious': False
        }
        
        # Check for common phishing hidden fields
        suspicious_names = ['return_url', 'redirect', 'token', 'session']
        if any(name in hidden_input['name'].lower() for name in suspicious_names):
            hidden_input['suspicious'] = True
            
        self.hidden_inputs.append(hidden_input)
        
    def _analyze_meta_tag(self, attrs):
        """Analyze meta tags for redirection"""
        http_equiv = attrs.get('http-equiv', '').lower()
        content = attrs.get('content', '')
        
        if http_equiv == 'refresh':
            self.suspicious_elements.append({
                'type': 'meta_redirect',
                'details': f"Meta refresh redirect: {content}",
                'risk': 'high'
            })
            
    def _analyze_external_resource(self, tag, attrs):
        """Analyze external resources"""
        src = attrs.get('src', '') or attrs.get('href', '')
        
        if src and src.startswith(('http://', 'https://')):
            resource_info = {
                'tag': tag,
                'src': src,
                'domain': urlparse(src).netloc,
                'suspicious': self._check_external_domain(src)
            }
            self.external_resources.append(resource_info)
            
    def _analyze_script_content(self, script_text):
        """Analyze JavaScript content for suspicious patterns"""
        suspicious_patterns = [
            (r'document\.location\s*=', 'Document location manipulation'),
            (r'window\.location\s*=', 'Window location manipulation'),
            (r'eval\s*\(', 'Use of eval() function'),
            (r'atob\s*\(', 'Base64 decoding'),
            (r'String\.fromCharCode', 'Character code obfuscation'),
            (r'\.submit\s*\(', 'Form submission'),
            (r'password', 'Password field access'),
            (r'alert\s*\(', 'Alert box')
        ]
        
        for pattern, description in suspicious_patterns:
            if re.search(pattern, script_text, re.IGNORECASE):
                self.script_content.append({
                    'pattern': description,
                    'snippet': script_text[:100] + '...'
                })
                break
                
    def _check_external_domain(self, url):
        """Check if external domain is suspicious"""
        domain = urlparse(url).netloc.lower()
        
        # Check for CDNs and common legitimate domains
        legitimate_domains = [
            'googleapis.com', 'cloudflare.com', 'jquery.com',
            'bootstrapcdn.com', 'fonts.googleapis.com'
        ]
        
        if any(legit in domain for legit in legitimate_domains):
            return False
            
        # Check for IP addresses
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            return True
            
        return False

class PhishingHTMLAnalyzer:
    def __init__(self, html_content):
        self.html_content = html_content
        self.analysis_results = {}
        
    def analyze(self):
        """Perform comprehensive HTML phishing analysis"""
        try:
            parser = HTMLPhishingAnalyzer()
            parser.feed(self.html_content)
            
            self.analysis_results = {
                'suspicious_elements': parser.suspicious_elements,
                'forms': parser.form_data,
                'hidden_inputs': parser.hidden_inputs,
                'external_resources': parser.external_resources,
                'suspicious_scripts': parser.script_content,
                'obfuscation_checks': self._check_obfuscation(),
                'credential_harvesting_checks': self._check_credential_harvesting(),
                'overall_risk_score': self._calculate_risk_score(parser)
            }
            
            return self.analysis_results
            
        except Exception as e:
            logger.error(f"Error analyzing HTML: {e}")
            return {}
            
    def _check_obfuscation(self):
        """Check for common obfuscation techniques"""
        obfuscation_indicators = []
        
        # Check for base64 encoded content
        base64_patterns = [
            r'[A-Za-z0-9+/]{20,}={0,2}',
            r'data:text/html;base64,[A-Za-z0-9+/]+={0,2}'
        ]
        
        for pattern in base64_patterns:
            if re.search(pattern, self.html_content):
                obfuscation_indicators.append('Base64 encoded content detected')
                break
                
        # Check for excessive encoding
        if '&#x' in self.html_content or '&#' in self.html_content:
            obfuscation_indicators.append('HTML character encoding detected')
            
        # Check for JavaScript obfuscation patterns
        js_obfuscation_patterns = [
            r'\\x[0-9a-fA-F]{2}',
            r'String\.fromCharCode\([^)]+\)',
            r'eval\([^)]+\)'
        ]
        
        for pattern in js_obfuscation_patterns:
            if re.search(pattern, self.html_content):
                obfuscation_indicators.append('JavaScript obfuscation detected')
                break
                
        return obfuscation_indicators
        
    def _check_credential_harvesting(self):
        """Check for credential harvesting indicators"""
        credential_indicators = []
        
        # Check for password fields
        password_patterns = [
            r'type=["\']password["\']',
            r'name=["\'][^"\']*pass[^"\']*["\']',
            r'id=["\'][^"\']*pass[^"\']*["\']'
        ]
        
        for pattern in password_patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                credential_indicators.append('Password input field detected')
                break
                
        # Check for login-related text
        login_text_patterns = [
            r'sign\s*in', r'log\s*in', r'username', r'password',
            r'credentials', r'authenticate', r'account'
        ]
        
        for pattern in login_text_patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                credential_indicators.append('Login-related text detected')
                break
                
        return credential_indicators
        
    def _calculate_risk_score(self, parser):
        """Calculate overall phishing risk score"""
        risk_score = 0
        
        # Weight different risk factors
        risk_factors = {
            'suspicious_elements': len(parser.suspicious_elements) * 2,
            'forms': len(parser.form_data) * 3,
            'suspicious_hidden_inputs': len([i for i in parser.hidden_inputs if i['suspicious']]) * 2,
            'external_resources': len([r for r in parser.external_resources if r['suspicious']]) * 1,
            'suspicious_scripts': len(parser.script_content) * 2,
            'obfuscation': len(self._check_obfuscation()) * 3,
            'credential_harvesting': len(self._check_credential_harvesting()) * 4
        }
        
        total_risk = sum(risk_factors.values())
        
        # Normalize to 0-100 scale
        normalized_risk = min(total_risk * 5, 100)
        
        return round(normalized_risk, 2)
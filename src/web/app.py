from flask import Flask, render_template, request, jsonify, send_file
import json
import os
import sys
from datetime import datetime
import logging

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from inbox.fetch_mail import EmailFetcher
from parsers.header_parser import HeaderParser
from parsers.url_extractor import URLExtractor
from analysis.vt_lookup import VirusTotalAnalyzer
from analysis.file_analyzer import FileAnalyzer
from analysis.html_analyzer import PhishingHTMLAnalyzer
from reporting.report_generator import PDFReportGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingAnalyzer:
    def __init__(self, config):
        self.config = config
        self.vt_analyzer = VirusTotalAnalyzer(config.get('virustotal_api_key', ''))
        self.file_analyzer = FileAnalyzer()
        
    def analyze_email(self, raw_email):
        """Main analysis function for email"""
        try:
            analysis_results = {
                'timestamp': datetime.now().isoformat(),
                'overall_risk_score': 0
            }
            
            # Parse headers
            header_parser = HeaderParser(raw_email)
            analysis_results['headers'] = header_parser.parse_all_headers()
            
            # Extract URLs
            email_message = header_parser.email_message
            url_extractor = URLExtractor(email_message)
            analysis_results['urls'] = url_extractor.extract_all_urls()
            
            # Analyze attachments
            analysis_results['attachments'] = self.file_analyzer.analyze_attachments(email_message)
            
            # Analyze HTML content
            html_analysis = self._analyze_html_content(email_message)
            analysis_results['html_analysis'] = html_analysis
            
            # Run VirusTotal checks
            analysis_results['vt_results'] = self._run_virustotal_checks(analysis_results)
            
            # Calculate overall risk score
            analysis_results['overall_risk_score'] = self._calculate_overall_risk(analysis_results)
            analysis_results['malicious_detections'] = self._count_malicious_detections(analysis_results)
            
            # Add basic email info
            analysis_results['subject'] = analysis_results['headers']['basic_info']['subject']
            analysis_results['from'] = analysis_results['headers']['basic_info']['from']
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error analyzing email: {e}")
            return {'error': str(e)}
            
    def _analyze_html_content(self, email_message):
        """Analyze HTML content of email"""
        html_content = ""
        for part in email_message.walk():
            if part.get_content_type() == 'text/html':
                html_content = part.get_content()
                break
                
        if html_content:
            html_analyzer = PhishingHTMLAnalyzer(html_content)
            return html_analyzer.analyze()
        return {}
        
    def _run_virustotal_checks(self, analysis_results):
        """Run VirusTotal checks on URLs and files"""
        vt_results = {}
        
        try:
            # Check URLs
            for url_info in analysis_results.get('urls', []):
                url = url_info.get('cleaned')
                if url:
                    result = self.vt_analyzer.check_url_reputation(url)
                    if result:
                        vt_results[url] = result
                        url_info['vt_analysis'] = result
                        
            # Check file attachments (by hash)
            for attachment in analysis_results.get('attachments', []):
                file_hash = attachment.get('hashes', {}).get('sha256')
                if file_hash:
                    # For demo purposes, we'll simulate file check
                    # In real implementation, you'd use VT file API
                    vt_results[file_hash] = {
                        'simulated': True,
                        'message': 'File analysis requires actual file submission to VT'
                    }
                    
        except Exception as e:
            logger.error(f"Error in VirusTotal checks: {e}")
            
        return vt_results
        
    def _calculate_overall_risk(self, analysis_results):
        """Calculate overall phishing risk score"""
        risk_factors = []
        
        # Header analysis risk
        suspicious_headers = len(analysis_results.get('headers', {}).get('suspicious_indicators', []))
        risk_factors.append(min(suspicious_headers * 10, 30))
        
        # URL risk
        suspicious_urls = len([u for u in analysis_results.get('urls', []) if u.get('suspicious')])
        risk_factors.append(min(suspicious_urls * 15, 30))
        
        # Attachment risk
        suspicious_attachments = len([a for a in analysis_results.get('attachments', []) if a.get('suspicious_indicators')])
        risk_factors.append(min(suspicious_attachments * 20, 30))
        
        # HTML risk
        html_risk = analysis_results.get('html_analysis', {}).get('overall_risk_score', 0) * 0.3
        risk_factors.append(html_risk)
        
        # VT risk
        vt_risk = 0
        for vt_result in analysis_results.get('vt_results', {}).values():
            if 'malicious' in vt_result and vt_result['malicious'] > 0:
                vt_risk += min(vt_result['malicious'] * 5, 20)
                
        risk_factors.append(vt_risk)
        
        total_risk = min(sum(risk_factors), 100)
        return round(total_risk, 2)
        
    def _count_malicious_detections(self, analysis_results):
        """Count total malicious detections across all analysis"""
        count = 0
        
        for vt_result in analysis_results.get('vt_results', {}).values():
            if 'malicious' in vt_result:
                count += vt_result['malicious']
                
        return count

# Load configuration
def load_config():
    """Load configuration from YAML file"""
    try:
        import yaml
        config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'settings.yaml')
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return {}

config = load_config()
analyzer = PhishingAnalyzer(config)

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_email():
    """Analyze uploaded email file"""
    try:
        if 'email_file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['email_file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        if file and file.filename.endswith('.eml'):
            raw_email = file.read()
            analysis_results = analyzer.analyze_email(raw_email)
            
            # Generate PDF report
            report_filename = f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            report_path = os.path.join('/tmp', report_filename)
            
            report_generator = PDFReportGenerator(report_path)
            report_generator.generate_report(analysis_results)
            
            analysis_results['report_filename'] = report_filename
            
            return jsonify(analysis_results)
        else:
            return jsonify({'error': 'Invalid file type. Please upload .eml file'}), 400
            
    except Exception as e:
        logger.error(f"Error in analyze_email: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/fetch_emails', methods=['POST'])
def fetch_emails():
    """Fetch emails from IMAP server"""
    try:
        imap_config = config.get('imap', {})
        fetcher = EmailFetcher(
            imap_config.get('server', ''),
            imap_config.get('username', ''),
            imap_config.get('password', '')
        )
        
        if fetcher.connect():
            emails = fetcher.fetch_unread_emails()
            fetcher.disconnect()
            
            # Return basic email info for selection
            email_list = []
            for email_data in emails:
                email_list.append({
                    'id': email_data['id'],
                    'subject': email_data['subject'],
                    'from': email_data['from'],
                    'date': email_data['date']
                })
                
            return jsonify({'emails': email_list})
        else:
            return jsonify({'error': 'Failed to connect to IMAP server'}), 500
            
    except Exception as e:
        logger.error(f"Error fetching emails: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/analyze_imap_email', methods=['POST'])
def analyze_imap_email():
    """Analyze specific email from IMAP server"""
    try:
        email_id = request.json.get('email_id')
        if not email_id:
            return jsonify({'error': 'No email ID provided'}), 400
            
        imap_config = config.get('imap', {})
        fetcher = EmailFetcher(
            imap_config.get('server', ''),
            imap_config.get('username', ''),
            imap_config.get('password', '')
        )
        
        if fetcher.connect():
            # Fetch specific email
            status, msg_data = fetcher.connection.fetch(email_id.encode(), '(RFC822)')
            if status == 'OK':
                raw_email = msg_data[0][1]
                analysis_results = analyzer.analyze_email(raw_email)
                fetcher.disconnect()
                
                # Generate PDF report
                report_filename = f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                report_path = os.path.join('/tmp', report_filename)
                
                report_generator = PDFReportGenerator(report_path)
                report_generator.generate_report(analysis_results)
                
                analysis_results['report_filename'] = report_filename
                
                return jsonify(analysis_results)
            else:
                fetcher.disconnect()
                return jsonify({'error': 'Failed to fetch email'}), 500
        else:
            return jsonify({'error': 'Failed to connect to IMAP server'}), 500
            
    except Exception as e:
        logger.error(f"Error analyzing IMAP email: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/download_report/<filename>')
def download_report(filename):
    """Download generated PDF report"""
    try:
        report_path = os.path.join('/tmp', filename)
        if os.path.exists(report_path):
            return send_file(report_path, as_attachment=True)
        else:
            return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
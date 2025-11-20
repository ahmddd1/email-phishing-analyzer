import unittest
import email
from email import policy
from src.parsers.header_parser import HeaderParser
from src.parsers.url_extractor import URLExtractor

class TestHeaderParser(unittest.TestCase):
    def setUp(self):
        self.sample_email = b"""From: "Test Sender" <test@sender.com>
To: "Test Receiver" <test@receiver.com>
Subject: Test Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <test123>
Received-SPF: pass (google.com: domain of test@sender.com designates 192.168.1.1 as permitted sender)
Authentication-Results: mx.google.com; dkim=pass header.d=sender.com; dmarc=pass
Reply-To: "Different Sender" <different@sender.com>
"""

    def test_basic_info_parsing(self):
        parser = HeaderParser(self.sample_email)
        headers = parser.parse_all_headers()
        
        basic_info = headers['basic_info']
        self.assertEqual(basic_info['subject'], 'Test Email')
        self.assertEqual(basic_info['from'], '"Test Sender" <test@sender.com>')
        self.assertEqual(basic_info['to'], '"Test Receiver" <test@receiver.com>')

    def test_authentication_parsing(self):
        parser = HeaderParser(self.sample_email)
        headers = parser.parse_all_headers()
        
        auth = headers['authentication']
        self.assertEqual(auth['spf']['result'], 'pass')
        self.assertTrue(auth['dkim']['present'])
        self.assertEqual(auth['dmarc']['result'], 'pass')

    def test_suspicious_indicators(self):
        parser = HeaderParser(self.sample_email)
        headers = parser.parse_all_headers()
        
        # Should detect From/Reply-To mismatch
        indicators = headers['suspicious_indicators']
        self.assertTrue(any('mismatch' in indicator for indicator in indicators))

class TestURLExtractor(unittest.TestCase):
    def setUp(self):
        self.sample_html = """
        <html>
        <body>
            <a href="https://example.com">Legit Link</a>
            <a href="http://phishing-site.com/login">Phishing Link</a>
            <img src="https://tracker.com/pixel.png">
            <form action="http://collector.com/submit">
            <script src="http://malicious.com/script.js"></script>
        </body>
        </html>
        """
        
        email_content = f"""Content-Type: text/html

        {self.sample_html}
        """
        self.email_message = email.message_from_string(email_content, policy=policy.default)

    def test_url_extraction(self):
        extractor = URLExtractor(self.email_message)
        urls = extractor.extract_all_urls()
        
        # Should find all URLs
        self.assertGreaterEqual(len(urls), 4)
        
        # Check domain extraction
        domains = [url['domain'] for url in urls]
        self.assertIn('example.com', domains)
        self.assertIn('phishing-site.com', domains)

    def test_suspicious_url_detection(self):
        extractor = URLExtractor(self.email_message)
        urls = extractor.extract_all_urls()
        
        # Find the phishing site URL
        phishing_urls = [url for url in urls if 'phishing-site.com' in url['domain']]
        self.assertGreater(len(phishing_urls), 0)

if __name__ == '__main__':
    unittest.main()
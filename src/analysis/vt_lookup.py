import requests
import time
import hashlib
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class VirusTotalAnalyzer:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "User-Agent": "EmailPhishingAnalyzer/1.0"
        }
        
    def check_url_reputation(self, url: str) -> Optional[Dict]:
        """Check URL reputation with VirusTotal"""
        try:
            # First, submit URL for analysis if not already in VT
            url_id = hashlib.sha256(url.encode()).hexdigest()
            analysis_url = f"{self.base_url}/urls/{url_id}"
            
            response = requests.get(analysis_url, headers=self.headers)
            
            if response.status_code == 200:
                return self._parse_url_analysis(response.json())
            else:
                # Submit URL for analysis
                submit_response = self._submit_url(url)
                if submit_response:
                    time.sleep(15)  # Wait for analysis
                    return self.check_url_reputation(url)
                    
        except Exception as e:
            logger.error(f"Error checking URL {url}: {e}")
            return None
            
    def check_file_reputation(self, file_path: str) -> Optional[Dict]:
        """Check file reputation with VirusTotal using SHA256 hash"""
        try:
            file_hash = self._calculate_file_hash(file_path)
            analysis_url = f"{self.base_url}/files/{file_hash}"
            
            response = requests.get(analysis_url, headers=self.headers)
            
            if response.status_code == 200:
                return self._parse_file_analysis(response.json())
            else:
                logger.warning(f"File {file_path} not found in VirusTotal")
                return None
                
        except Exception as e:
            logger.error(f"Error checking file {file_path}: {e}")
            return None
            
    def _submit_url(self, url: str) -> bool:
        """Submit URL to VirusTotal for analysis"""
        try:
            submit_url = f"{self.base_url}/urls"
            data = {"url": url}
            response = requests.post(submit_url, headers=self.headers, data=data)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error submitting URL {url}: {e}")
            return False
            
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
        
    def _parse_url_analysis(self, vt_data: Dict) -> Dict:
        """Parse VirusTotal URL analysis results"""
        if 'data' not in vt_data:
            return {'error': 'No data in response'}
            
        data = vt_data['data']
        attributes = data.get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        return {
            'url': attributes.get('url', ''),
            'harmless': last_analysis_stats.get('harmless', 0),
            'malicious': last_analysis_stats.get('malicious', 0),
            'suspicious': last_analysis_stats.get('suspicious', 0),
            'undetected': last_analysis_stats.get('undetected', 0),
            'reputation': attributes.get('reputation', 0),
            'categories': attributes.get('categories', {}),
            'last_analysis_date': attributes.get('last_analysis_date', ''),
            'total_engines': sum(last_analysis_stats.values()),
            'confidence_score': self._calculate_confidence_score(last_analysis_stats)
        }
        
    def _parse_file_analysis(self, vt_data: Dict) -> Dict:
        """Parse VirusTotal file analysis results"""
        if 'data' not in vt_data:
            return {'error': 'No data in response'}
            
        data = vt_data['data']
        attributes = data.get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        return {
            'sha256': attributes.get('sha256', ''),
            'meaningful_name': attributes.get('meaningful_name', ''),
            'type_description': attributes.get('type_description', ''),
            'size': attributes.get('size', 0),
            'harmless': last_analysis_stats.get('harmless', 0),
            'malicious': last_analysis_stats.get('malicious', 0),
            'suspicious': last_analysis_stats.get('suspicious', 0),
            'undetected': last_analysis_stats.get('undetected', 0),
            'type_tags': attributes.get('type_tags', []),
            'popular_threat_classification': attributes.get('popular_threat_classification', {}),
            'total_engines': sum(last_analysis_stats.values()),
            'confidence_score': self._calculate_confidence_score(last_analysis_stats)
        }
        
    def _calculate_confidence_score(self, stats: Dict) -> float:
        """Calculate confidence score based on analysis stats"""
        total = sum(stats.values())
        if total == 0:
            return 0.0
            
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        
        # Weight malicious and suspicious findings more heavily
        risk_score = (malicious * 1.0 + suspicious * 0.5) / total
        return round(risk_score * 100, 2)
        
    def batch_check_urls(self, urls: List[str]) -> Dict[str, Dict]:
        """Check multiple URLs in batch"""
        results = {}
        
        for url in urls:
            try:
                result = self.check_url_reputation(url)
                if result:
                    results[url] = result
                time.sleep(1)  # Rate limiting
            except Exception as e:
                logger.error(f"Error in batch check for {url}: {e}")
                results[url] = {'error': str(e)}
                
        return results
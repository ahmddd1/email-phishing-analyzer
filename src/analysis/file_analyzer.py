import os
import hashlib
import magic
import logging
from typing import Dict, List, Optional
import json

logger = logging.getLogger(__name__)

class FileAnalyzer:
    def __init__(self):
        self.suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', 
            '.js', '.jar', '.zip', '.rar', '.iso', '.msi'
        ]
        
    def analyze_attachments(self, email_message) -> List[Dict]:
        """Analyze all attachments in email"""
        attachments = []
        
        try:
            for part in email_message.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        attachment_data = self._analyze_attachment(part, filename)
                        if attachment_data:
                            attachments.append(attachment_data)
                            
        except Exception as e:
            logger.error(f"Error analyzing attachments: {e}")
            
        return attachments
        
    def _analyze_attachment(self, part, filename: str) -> Optional[Dict]:
        """Analyze individual attachment"""
        try:
            # Extract attachment content
            file_content = part.get_payload(decode=True)
            if not file_content:
                return None
                
            # Create temporary file for analysis
            temp_filename = f"/tmp/{filename}"
            with open(temp_filename, 'wb') as f:
                f.write(file_content)
                
            # Perform analysis
            analysis_result = {
                'filename': filename,
                'size': len(file_content),
                'file_type': self._get_file_type(temp_filename),
                'hashes': self._calculate_hashes(file_content),
                'suspicious_indicators': self._check_suspicious_indicators(filename, file_content),
                'content_preview': self._get_content_preview(file_content, filename)
            }
            
            # Clean up temp file
            os.unlink(temp_filename)
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing attachment {filename}: {e}")
            return None
            
    def _get_file_type(self, file_path: str) -> str:
        """Determine file type using python-magic"""
        try:
            return magic.from_file(file_path, mime=True)
        except Exception as e:
            logger.warning(f"Could not determine file type: {e}")
            return "unknown"
            
    def _calculate_hashes(self, file_content: bytes) -> Dict[str, str]:
        """Calculate various hash digests for the file"""
        return {
            'md5': hashlib.md5(file_content).hexdigest(),
            'sha1': hashlib.sha1(file_content).hexdigest(),
            'sha256': hashlib.sha256(file_content).hexdigest()
        }
        
    def _check_suspicious_indicators(self, filename: str, content: bytes) -> List[str]:
        """Check for suspicious indicators in file"""
        indicators = []
        
        # Check file extension
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext in self.suspicious_extensions:
            indicators.append(f"Suspicious file extension: {file_ext}")
            
        # Check for double extensions
        if filename.count('.') > 1:
            base_name = os.path.splitext(filename)[0]
            if os.path.splitext(base_name)[1].lower() in self.suspicious_extensions:
                indicators.append("Double file extension detected")
                
        # Check file size (too small or too large)
        if len(content) < 100:  # Less than 100 bytes
            indicators.append("Suspiciously small file size")
        elif len(content) > 50 * 1024 * 1024:  # Larger than 50MB
            indicators.append("Unusually large attachment")
            
        # Check for executable markers (crude check)
        if content[:2] == b'MZ':  # DOS header
            indicators.append("Executable file detected")
            
        # Check for script content
        try:
            text_content = content.decode('utf-8', errors='ignore')
            suspicious_script_patterns = [
                'powershell', 'cmd.exe', 'wscript', 'cscript', 
                'regsvr32', 'mshta', 'rundll32'
            ]
            if any(pattern in text_content.lower() for pattern in suspicious_script_patterns):
                indicators.append("Contains suspicious script commands")
        except:
            pass
            
        return indicators
        
    def _get_content_preview(self, content: bytes, filename: str) -> str:
        """Get preview of file content"""
        try:
            file_ext = os.path.splitext(filename)[1].lower()
            
            if file_ext in ['.txt', '.log', '.csv']:
                # Text file preview
                text_content = content.decode('utf-8', errors='ignore')[:500]
                return text_content + "..." if len(text_content) == 500 else text_content
                
            elif file_ext in ['.html', '.htm']:
                # HTML file preview
                html_content = content.decode('utf-8', errors='ignore')[:500]
                return html_content + "..." if len(html_content) == 500 else html_content
                
            else:
                # Binary file - show hex preview
                hex_preview = content.hex()[:200]
                return f"Hex: {hex_preview}..."
                
        except Exception as e:
            logger.warning(f"Could not generate content preview: {e}")
            return "Preview not available"
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import logging
import os

logger = logging.getLogger(__name__)

class PDFReportGenerator:
    def __init__(self, output_path):
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
        
    def _create_custom_styles(self):
        """Create custom styles for the report"""
        self.styles.add(ParagraphStyle(
            name='Heading1',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='Heading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=6,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.red,
            backColor=colors.mistyrose,
            spaceAfter=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            spaceAfter=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            textColor=colors.green,
            spaceAfter=6
        ))
        
    def generate_report(self, analysis_data):
        """Generate comprehensive PDF report"""
        try:
            doc = SimpleDocTemplate(
                self.output_path,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            story = []
            
            # Title page
            story.extend(self._create_title_page(analysis_data))
            
            # Executive Summary
            story.extend(self._create_executive_summary(analysis_data))
            
            # Email Headers Analysis
            story.extend(self._create_headers_section(analysis_data.get('headers', {})))
            
            # URL Analysis
            story.extend(self._create_urls_section(analysis_data.get('urls', [])))
            
            # Attachment Analysis
            story.extend(self._create_attachments_section(analysis_data.get('attachments', [])))
            
            # HTML Analysis
            story.extend(self._create_html_section(analysis_data.get('html_analysis', {})))
            
            # VirusTotal Results
            story.extend(self._create_virustotal_section(analysis_data.get('vt_results', {})))
            
            # Build PDF
            doc.build(story)
            logger.info(f"PDF report generated: {self.output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            return False
            
    def _create_title_page(self, analysis_data):
        """Create title page for the report"""
        elements = []
        
        # Title
        title_style = ParagraphStyle(
            name='Title',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.darkblue,
            alignment=TA_CENTER,
            spaceAfter=24
        )
        
        elements.append(Paragraph("Phishing Analysis Report", title_style))
        elements.append(Spacer(1, 0.5*inch))
        
        # Analysis metadata
        meta_style = self.styles["Normal"]
        
        elements.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", meta_style))
        elements.append(Paragraph(f"Email Subject: {analysis_data.get('subject', 'N/A')}", meta_style))
        elements.append(Paragraph(f"From: {analysis_data.get('from', 'N/A')}", meta_style))
        elements.append(Spacer(1, 0.3*inch))
        
        # Overall risk assessment
        risk_score = analysis_data.get('overall_risk_score', 0)
        risk_level = self._get_risk_level(risk_score)
        
        risk_style = self.styles[f'Risk{risk_level}']
        elements.append(Paragraph(f"Overall Risk Score: {risk_score}/100", risk_style))
        elements.append(Paragraph(f"Risk Level: {risk_level}", risk_style))
        
        elements.append(Spacer(1, inch))
        
        return elements
        
    def _create_executive_summary(self, analysis_data):
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['Heading1']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Summary statistics
        stats = [
            f"• Suspicious URLs Found: {len([u for u in analysis_data.get('urls', []) if u.get('suspicious')])}",
            f"• Attachments Analyzed: {len(analysis_data.get('attachments', []))}",
            f"• Malicious VT Detections: {analysis_data.get('malicious_detections', 0)}",
            f"• HTML Phishing Score: {analysis_data.get('html_analysis', {}).get('overall_risk_score', 0)}/100"
        ]
        
        for stat in stats:
            elements.append(Paragraph(stat, self.styles["Normal"]))
            
        elements.append(Spacer(1, 0.2*inch))
        
        # Recommendations based on risk level
        risk_score = analysis_data.get('overall_risk_score', 0)
        recommendations = self._get_recommendations(risk_score)
        
        elements.append(Paragraph("Recommendations:", self.styles['Heading2']))
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", self.styles["Normal"]))
            
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
        
    def _create_headers_section(self, headers_data):
        """Create email headers analysis section"""
        elements = []
        
        elements.append(Paragraph("Email Headers Analysis", self.styles['Heading1']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Basic info table
        basic_info = headers_data.get('basic_info', {})
        basic_data = [
            ["Field", "Value"],
            ["Subject", basic_info.get('subject', 'N/A')],
            ["From", basic_info.get('from', 'N/A')],
            ["To", basic_info.get('to', 'N/A')],
            ["Date", basic_info.get('date', 'N/A')]
        ]
        
        basic_table = Table(basic_data, colWidths=[1.5*inch, 4*inch])
        basic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(basic_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Authentication results
        auth_info = headers_data.get('authentication', {})
        auth_data = [
            ["Authentication", "Result"],
            ["SPF", auth_info.get('spf', {}).get('result', 'N/A')],
            ["DKIM", "Present" if auth_info.get('dkim', {}).get('present') else "Missing"],
            ["DMARC", auth_info.get('dmarc', {}).get('result', 'N/A')]
        ]
        
        auth_table = Table(auth_data, colWidths=[1.5*inch, 4*inch])
        auth_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(auth_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Suspicious indicators
        suspicious = headers_data.get('suspicious_indicators', [])
        if suspicious:
            elements.append(Paragraph("Suspicious Indicators:", self.styles['Heading2']))
            for indicator in suspicious:
                elements.append(Paragraph(f"• {indicator}", self.styles['RiskHigh']))
                
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
        
    def _create_urls_section(self, urls_data):
        """Create URL analysis section"""
        elements = []
        
        elements.append(Paragraph("URL Analysis", self.styles['Heading1']))
        elements.append(Spacer(1, 0.2*inch))
        
        if not urls_data:
            elements.append(Paragraph("No URLs found in email.", self.styles["Normal"]))
            return elements
            
        for url_info in urls_data:
            url_elements = self._create_url_entry(url_info)
            elements.extend(url_elements)
            
        elements.append(Spacer(1, 0.3*inch))
        return elements
        
    def _create_url_entry(self, url_info):
        """Create individual URL analysis entry"""
        elements = []
        
        # URL display
        elements.append(Paragraph(f"URL: {url_info.get('cleaned', 'N/A')}", self.styles['Normal']))
        
        # Suspicious indicators
        suspicious = url_info.get('suspicious', [])
        if suspicious:
            for indicator in suspicious:
                elements.append(Paragraph(f"⚠️ {indicator}", self.styles['RiskHigh']))
                
        # VirusTotal results if available
        vt_data = url_info.get('vt_analysis', {})
        if vt_data and 'error' not in vt_data:
            vt_text = f"VirusTotal: {vt_data.get('malicious', 0)}/{vt_data.get('total_engines', 0)} engines detected as malicious"
            risk_style = self.styles['RiskHigh'] if vt_data.get('malicious', 0) > 0 else self.styles['Normal']
            elements.append(Paragraph(vt_text, risk_style))
            
        elements.append(Spacer(1, 0.1*inch))
        
        return elements
        
    def _create_attachments_section(self, attachments_data):
        """Create attachments analysis section"""
        elements = []
        
        elements.append(Paragraph("Attachment Analysis", self.styles['Heading1']))
        elements.append(Spacer(1, 0.2*inch))
        
        if not attachments_data:
            elements.append(Paragraph("No attachments found in email.", self.styles["Normal"]))
            return elements
            
        for attachment in attachments_data:
            attachment_elements = self._create_attachment_entry(attachment)
            elements.extend(attachment_elements)
            
        elements.append(Spacer(1, 0.3*inch))
        return elements
        
    def _create_attachment_entry(self, attachment):
        """Create individual attachment analysis entry"""
        elements = []
        
        elements.append(Paragraph(f"File: {attachment.get('filename', 'N/A')}", self.styles['Normal']))
        elements.append(Paragraph(f"Type: {attachment.get('file_type', 'N/A')}", self.styles['Normal']))
        elements.append(Paragraph(f"Size: {attachment.get('size', 0)} bytes", self.styles['Normal']))
        elements.append(Paragraph(f"SHA256: {attachment.get('hashes', {}).get('sha256', 'N/A')}", self.styles['Normal']))
        
        # Suspicious indicators
        suspicious = attachment.get('suspicious_indicators', [])
        if suspicious:
            for indicator in suspicious:
                elements.append(Paragraph(f"⚠️ {indicator}", self.styles['RiskHigh']))
                
        elements.append(Spacer(1, 0.1*inch))
        
        return elements
        
    def _create_html_section(self, html_data):
        """Create HTML analysis section"""
        elements = []
        
        elements.append(Paragraph("HTML Content Analysis", self.styles['Heading1']))
        elements.append(Spacer(1, 0.2*inch))
        
        if not html_data:
            elements.append(Paragraph("No HTML content to analyze.", self.styles["Normal"]))
            return elements
            
        risk_score = html_data.get('overall_risk_score', 0)
        elements.append(Paragraph(f"Phishing Risk Score: {risk_score}/100", 
                                self.styles[f'Risk{self._get_risk_level(risk_score)}']))
        
        # Suspicious elements
        suspicious = html_data.get('suspicious_elements', [])
        if suspicious:
            elements.append(Paragraph("Suspicious Elements:", self.styles['Heading2']))
            for element in suspicious:
                elements.append(Paragraph(f"• {element.get('details', 'N/A')}", self.styles['RiskHigh']))
                
        # Forms
        forms = html_data.get('forms', [])
        if forms:
            elements.append(Paragraph(f"Suspicious Forms: {len(forms)}", self.styles['Heading2']))
            for form in forms:
                elements.append(Paragraph(f"• Action: {form.get('action', 'N/A')}", self.styles['Normal']))
                
        elements.append(Spacer(1, 0.3*inch))
        return elements
        
    def _create_virustotal_section(self, vt_data):
        """Create VirusTotal results section"""
        elements = []
        
        elements.append(Paragraph("VirusTotal Analysis", self.styles['Heading1']))
        elements.append(Spacer(1, 0.2*inch))
        
        if not vt_data:
            elements.append(Paragraph("No VirusTotal results available.", self.styles["Normal"]))
            return elements
            
        for item, results in vt_data.items():
            if 'error' not in results:
                elements.append(Paragraph(f"Item: {item}", self.styles['Heading2']))
                elements.append(Paragraph(f"Malicious: {results.get('malicious', 0)}", 
                                        self.styles['RiskHigh'] if results.get('malicious', 0) > 0 else self.styles['Normal']))
                elements.append(Paragraph(f"Suspicious: {results.get('suspicious', 0)}", self.styles['Normal']))
                elements.append(Paragraph(f"Confidence: {results.get('confidence_score', 0)}%", self.styles['Normal']))
                elements.append(Spacer(1, 0.1*inch))
                
        elements.append(Spacer(1, 0.3*inch))
        return elements
        
    def _get_risk_level(self, score):
        """Determine risk level based on score"""
        if score >= 70:
            return "High"
        elif score >= 40:
            return "Medium"
        else:
            return "Low"
            
    def _get_recommendations(self, risk_score):
        """Get recommendations based on risk score"""
        if risk_score >= 70:
            return [
                "Immediately delete this email",
                "Do not click any links or download attachments",
                "Report to your security team",
                "Scan your system for malware",
                "Consider resetting credentials if interacted with"
            ]
        elif risk_score >= 40:
            return [
                "Exercise caution with this email",
                "Verify sender identity through other means",
                "Do not provide sensitive information",
                "Monitor for suspicious activity"
            ]
        else:
            return [
                "Email appears safe but remain vigilant",
                "Verify unexpected attachments before opening",
                "Report any suspicious behavior"
            ]
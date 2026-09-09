"""
PDF Report Generator for Vulnerability Assessment
"""
from typing import List, Dict, Any
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

class PDFReportGenerator:
    """Generate PDF reports from scan results"""
    
    def __init__(self, target_url: str, findings: List[Dict[str, Any]]):
        self.target_url = target_url
        self.findings = findings
        self.styles = getSampleStyleSheet()
        
    def generate(self, output_file: str = "report.pdf"):
        """Generate PDF report"""
        doc = SimpleDocTemplate(
            output_file,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        story = []
        
        # Add title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a5276'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        story.append(Paragraph("Vulnerability Assessment Report", title_style))
        
        # Add target information
        info_style = ParagraphStyle(
            'InfoStyle',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=6
        )
        
        story.append(Paragraph(f"<b>Target URL:</b> {self.target_url}", info_style))
        story.append(Paragraph(f"<b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", info_style))
        story.append(Paragraph(f"<b>Total Findings:</b> {len(self.findings)}", info_style))
        story.append(Spacer(1, 20))
        
        # Add executive summary
        story.append(Paragraph("Executive Summary", self.styles['Heading1']))
        
        # Count by severity
        severity_counts = {}
        for finding in self.findings:
            severity = finding.get('severity', 'Info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary_text = f"""
        This report presents the results of an automated vulnerability assessment 
        conducted on {self.target_url}. The assessment covers application security, 
        authentication logic, and human negligence factors.
        <br/><br/>
        <b>Summary of Findings:</b><br/>
        """
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            if severity in severity_counts:
                summary_text += f"&nbsp;&nbsp;• {severity}: {severity_counts[severity]} issues<br/>"
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Add findings table
        story.append(Paragraph("Detailed Findings", self.styles['Heading1']))
        story.append(Spacer(1, 10))
        
        # Create table data
        table_data = [
            ['Severity', 'Title', 'Category', 'CVSS Score']
        ]
        
        # Sort findings by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x.get('severity', 'Info'), 5))
        
        for finding in sorted_findings:
            table_data.append([
                finding.get('severity', 'Info'),
                finding.get('title', 'Unknown')[:50],
                finding.get('category', 'General'),
                str(finding.get('cvss_score', '0.0'))
            ])
        
        # Create table
        table = Table(table_data, colWidths=[1.2*inch, 3*inch, 1.5*inch, 1*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a5276')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Add detailed findings
        story.append(Paragraph("Finding Details", self.styles['Heading1']))
        story.append(Spacer(1, 10))
        
        for i, finding in enumerate(sorted_findings, 1):
            # Severity color
            severity_colors = {
                'Critical': '#ff0000',
                'High': '#ff6600',
                'Medium': '#ffcc00',
                'Low': '#66cc00',
                'Info': '#0066cc'
            }
            
            color = severity_colors.get(finding.get('severity', 'Info'), '#000000')
            
            finding_style = ParagraphStyle(
                f'Finding{i}',
                parent=self.styles['Normal'],
                fontSize=10,
                spaceAfter=10,
                leftIndent=20
            )
            
            finding_text = f"""
            <b>Finding {i}: {finding.get('title', 'Unknown')}</b><br/>
            <b>Severity:</b> <font color="{color}">{finding.get('severity', 'Info')}</font><br/>
            <b>Category:</b> {finding.get('category', 'General')}<br/>
            <b>CVSS Score:</b> {finding.get('cvss_score', '0.0')}<br/>
            <b>Description:</b> {finding.get('description', 'No description')}<br/>
            """
            
            if finding.get('evidence'):
                finding_text += f"<b>Evidence:</b> {finding['evidence']}<br/>"
            
            if finding.get('remediation'):
                finding_text += f"<b>Remediation:</b> {finding['remediation']}<br/>"
            
            finding_text += "<br/>" + "-" * 50
            
            story.append(Paragraph(finding_text, finding_style))
        
        # Add footer
        story.append(Spacer(1, 30))
        footer_style = ParagraphStyle(
            'FooterStyle',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        )
        story.append(Paragraph(
            "Generated by Integrated Automated Vulnerability Assessment Framework<br/>"
            "For Educational and Authorized Testing Purposes Only",
            footer_style
        ))
        
        # Build PDF
        doc.build(story)
        return output_file

# backend/report_generator.py
# PDF Report Generator for Attack Path Predictor

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.colors import HexColor
from datetime import datetime
from typing import List, Dict
import io

class PentestReportGenerator:
    """Generate professional PDF reports for penetration testing results"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=HexColor('#DC2626'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Heading style
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=HexColor('#1F2937'),
            spaceBefore=12,
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))
        
        # Subheading style
        self.styles.add(ParagraphStyle(
            name='CustomSubheading',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=HexColor('#374151'),
            spaceBefore=8,
            spaceAfter=4,
            fontName='Helvetica-Bold'
        ))
    
    def generate_report(self, data: Dict) -> io.BytesIO:
        """
        Generate PDF report from attack path data
        
        Args:
            data: Dictionary containing:
                - paths: List of attack paths
                - hosts: List of network hosts
                - metadata: Report metadata (title, date, etc.)
        
        Returns:
            BytesIO object containing PDF data
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch)
        
        # Container for PDF elements
        story = []
        
        # Add cover page
        story.extend(self._create_cover_page(data))
        story.append(PageBreak())
        
        # Add executive summary
        story.extend(self._create_executive_summary(data))
        story.append(Spacer(1, 0.3*inch))
        
        # Add network overview
        story.extend(self._create_network_overview(data))
        story.append(PageBreak())
        
        # Add attack paths analysis
        story.extend(self._create_attack_paths_section(data))
        story.append(PageBreak())
        
        # Add recommendations
        story.extend(self._create_recommendations(data))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        return buffer
    
    def _create_cover_page(self, data: Dict) -> List:
        """Create report cover page"""
        elements = []
        
        # Title
        title = Paragraph(
            "PENETRATION TEST REPORT",
            self.styles['CustomTitle']
        )
        elements.append(Spacer(1, 2*inch))
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))
        
        # Subtitle
        subtitle = Paragraph(
            "Attack Path Analysis",
            self.styles['Heading2']
        )
        elements.append(subtitle)
        elements.append(Spacer(1, 1*inch))
        
        # Metadata
        metadata_text = f"""
        <para align=center>
        <b>Report Generated:</b> {datetime.now().strftime('%B %d, %Y at %H:%M')}<br/>
        <b>Tool:</b> Attack Path Predictor v1.0<br/>
        <b>Hosts Analyzed:</b> {len(data.get('hosts', []))}<br/>
        <b>Attack Paths Found:</b> {len(data.get('paths', []))}
        </para>
        """
        metadata = Paragraph(metadata_text, self.styles['Normal'])
        elements.append(metadata)
        
        return elements
    
    def _create_executive_summary(self, data: Dict) -> List:
        """Create executive summary section"""
        elements = []
        
        # Section header
        elements.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        paths = data.get('paths', [])
        hosts = data.get('hosts', [])
        
        # Calculate statistics
        critical_hosts = sum(1 for h in hosts if h.get('criticality') == 'critical')
        high_hosts = sum(1 for h in hosts if h.get('criticality') == 'high')
        total_vulns = sum(h.get('vulns', 0) for h in hosts)
        highest_prob = max([p.get('probability', 0) for p in paths]) if paths else 0
        
        summary_text = f"""
        This report presents the results of an automated attack path analysis conducted on 
        {len(hosts)} network hosts. The analysis identified {len(paths)} potential attack paths 
        to critical assets, with the highest probability path showing a {highest_prob*100:.0f}% 
        likelihood of success.
        <br/><br/>
        <b>Key Findings:</b><br/>
        • Total hosts analyzed: {len(hosts)}<br/>
        • Critical assets identified: {critical_hosts}<br/>
        • High-risk hosts: {high_hosts}<br/>
        • Total vulnerabilities detected: {total_vulns}<br/>
        • Highest attack path probability: {highest_prob*100:.0f}%<br/>
        <br/>
        The most viable attack path requires {paths[0].get('path', []).count(',')+1 if paths else 0} hops 
        and is estimated to take {paths[0].get('estimated_time', 'N/A') if paths else 'N/A'}.
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        
        return elements
    
    def _create_network_overview(self, data: Dict) -> List:
        """Create network overview table"""
        elements = []
        
        elements.append(Paragraph("Network Overview", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        hosts = data.get('hosts', [])
        
        # Create table data
        table_data = [
            ['Hostname', 'IP Address', 'OS', 'Services', 'Criticality', 'Vulns']
        ]
        
        for host in hosts:
            services_str = ', '.join(host.get('services', [])[:3])
            if len(host.get('services', [])) > 3:
                services_str += '...'
            
            table_data.append([
                host.get('name', 'Unknown')[:25],
                host.get('ip', 'N/A'),
                host.get('os', 'Unknown')[:20],
                services_str[:30],
                host.get('criticality', 'N/A').upper(),
                str(host.get('vulns', 0))
            ])
        
        # Create table
        table = Table(table_data, colWidths=[1.5*inch, 1*inch, 1.2*inch, 1.5*inch, 0.8*inch, 0.5*inch])
        
        # Style table
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1F2937')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F9FAFB')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#E5E7EB')),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, HexColor('#F9FAFB')])
        ]))
        
        elements.append(table)
        
        return elements
    
    def _create_attack_paths_section(self, data: Dict) -> List:
        """Create attack paths analysis section"""
        elements = []
        
        elements.append(Paragraph("Attack Path Analysis", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        paths = data.get('paths', [])
        
        for i, path in enumerate(paths, 1):
            # Path header
            path_title = f"Attack Path #{i} - {path.get('probability', 0)*100:.0f}% Success Probability"
            elements.append(Paragraph(path_title, self.styles['CustomSubheading']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Path details
            path_nodes = path.get('path', [])
            path_visual = " → ".join(path_nodes)
            
            path_info = f"""
            <b>Path:</b> {path_visual}<br/>
            <b>Hops:</b> {len(path_nodes) - 1}<br/>
            <b>Difficulty:</b> {path.get('difficulty', 'N/A')}<br/>
            <b>Stealth Level:</b> {path.get('stealth', 'N/A')}<br/>
            <b>Estimated Time:</b> {path.get('estimated_time', 'N/A')}<br/>
            """
            
            elements.append(Paragraph(path_info, self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Techniques table
            techniques = path.get('techniques', [])
            if techniques:
                elements.append(Paragraph("<b>Attack Techniques:</b>", self.styles['Normal']))
                elements.append(Spacer(1, 0.05*inch))
                
                tech_data = [['Step', 'Technique', 'MITRE ID']]
                for idx, tech in enumerate(techniques, 1):
                    # Extract MITRE ID if present
                    mitre_id = tech.split(' - ')[0] if 'T' in tech else 'N/A'
                    tech_name = tech.split(' - ')[1] if ' - ' in tech else tech
                    tech_data.append([str(idx), tech_name, mitre_id])
                
                tech_table = Table(tech_data, colWidths=[0.5*inch, 3.5*inch, 1*inch])
                tech_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#374151')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#E5E7EB')),
                    ('FONTSIZE', (0, 1), (-1, -1), 8)
                ]))
                
                elements.append(tech_table)
            
            elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_recommendations(self, data: Dict) -> List:
        """Create recommendations section"""
        elements = []
        
        elements.append(Paragraph("Security Recommendations", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        paths = data.get('paths', [])
        hosts = data.get('hosts', [])
        
        recommendations = []
        
        # Priority 1: Block highest probability path
        if paths:
            highest_path = paths[0]
            path_nodes = highest_path.get('path', [])
            if len(path_nodes) >= 2:
                recommendations.append(
                    f"<b>CRITICAL:</b> Implement network segmentation between {path_nodes[0]} and {path_nodes[1]} "
                    f"to block the highest probability attack path ({highest_path.get('probability', 0)*100:.0f}% success rate)."
                )
        
        # Priority 2: Patch critical vulnerabilities
        critical_hosts = [h for h in hosts if h.get('criticality') == 'critical']
        if critical_hosts:
            recommendations.append(
                f"<b>HIGH:</b> Immediately patch vulnerabilities on {len(critical_hosts)} critical asset(s): "
                f"{', '.join([h.get('name', 'Unknown') for h in critical_hosts[:3]])}."
            )
        
        # Priority 3: Harden common attack vectors
        recommendations.extend([
            "<b>MEDIUM:</b> Implement multi-factor authentication (MFA) on all Remote Desktop Protocol (RDP) services.",
            "<b>MEDIUM:</b> Deploy Endpoint Detection and Response (EDR) on high-value targets.",
            "<b>MEDIUM:</b> Enable advanced logging and SIEM monitoring for lateral movement detection.",
            "<b>LOW:</b> Conduct regular vulnerability assessments and maintain patch management schedules.",
            "<b>LOW:</b> Implement least privilege access controls and regular access reviews."
        ])
        
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def generate_simple_report(self, paths: List[Dict], hosts: List[Dict]) -> io.BytesIO:
        """Quick report generation"""
        data = {
            'paths': paths,
            'hosts': hosts,
            'metadata': {
                'title': 'Attack Path Analysis Report',
                'date': datetime.now().strftime('%Y-%m-%d')
            }
        }
        
        return self.generate_report(data)
"""
PDF Report Generation Service for SecureScan Pro
Generates professional security assessment reports
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import io
import os
import logging
import base64

from reportlab.lib import colors  # type: ignore
from reportlab.lib.pagesizes import letter, A4  # type: ignore
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # type: ignore
from reportlab.lib.units import inch  # type: ignore
from reportlab.platypus import (  # type: ignore
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, ListFlowable, ListItem
)
from reportlab.graphics.shapes import Drawing, Rect  # type: ignore
from reportlab.graphics.charts.piecharts import Pie  # type: ignore
from reportlab.graphics.charts.barcharts import VerticalBarChart  # type: ignore

from app.core.supabase_client import get_supabase

logger = logging.getLogger(__name__)


class PDFReportService:
    """Generate professional PDF security reports"""
    
    # Severity colors
    SEVERITY_COLORS = {
        "critical": colors.Color(0.75, 0.1, 0.1),
        "high": colors.Color(0.9, 0.4, 0.1),
        "medium": colors.Color(0.9, 0.7, 0.1),
        "low": colors.Color(0.2, 0.6, 0.3),
        "info": colors.Color(0.3, 0.5, 0.7)
    }
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1a365d')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#2d3748')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=10,
            spaceBefore=15,
            textColor=colors.HexColor('#4a5568')
        ))
        
        self.styles.add(ParagraphStyle(
            name='Finding',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            leftIndent=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.white,
            backColor=self.SEVERITY_COLORS['critical']
        ))
        
        self.styles.add(ParagraphStyle(
            name='FooterStyle',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.gray
        ))
    
    async def generate_scan_report(
        self,
        scan_id: str,
        include_remediation: bool = True,
        include_evidence: bool = True,
        include_executive_summary: bool = True,
        output_path: Optional[str] = None
    ) -> bytes:
        """
        Generate a comprehensive PDF report for a scan
        
        Args:
            scan_id: The scan ID to generate report for
            include_remediation: Include remediation steps
            include_evidence: Include technical evidence
            include_executive_summary: Include executive summary
            output_path: Optional file path to save the PDF
            
        Returns:
            PDF content as bytes
        """
        sb = get_supabase()
        
        # Fetch scan data
        scan_result = sb.table("scans").select("*").eq("id", scan_id).execute()
        if not scan_result.data:
            raise ValueError(f"Scan {scan_id} not found")
        
        scan = scan_result.data[0]
        
        # Fetch vulnerabilities
        vulns_result = sb.table("vulnerabilities").select("*").eq(
            "scan_id", scan_id
        ).order("severity_score", desc=True).execute()
        
        vulnerabilities = vulns_result.data or []
        
        # Fetch organization info if available
        org_name = "Security Assessment"
        if scan.get("organization_id"):
            org_result = sb.table("organizations").select("name").eq(
                "id", scan["organization_id"]
            ).execute()
            if org_result.data:
                org_name = org_result.data[0]["name"]
        
        # Generate PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch
        )
        
        # Build document content
        story = []
        
        # Cover page
        story.extend(self._build_cover_page(scan, org_name))
        story.append(PageBreak())
        
        # Table of contents
        story.extend(self._build_toc(vulnerabilities))
        story.append(PageBreak())
        
        # Executive summary
        if include_executive_summary:
            story.extend(self._build_executive_summary(scan, vulnerabilities))
            story.append(PageBreak())
        
        # Findings overview with charts
        story.extend(self._build_findings_overview(vulnerabilities))
        story.append(PageBreak())
        
        # Detailed findings
        story.extend(self._build_detailed_findings(
            vulnerabilities,
            include_remediation=include_remediation,
            include_evidence=include_evidence
        ))
        
        # Appendix
        story.extend(self._build_appendix(scan))
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
        
        pdf_content = buffer.getvalue()
        buffer.close()
        
        # Save to file if path provided
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_content)
        
        # Store report reference in database
        await self._save_report_record(scan_id, scan, vulnerabilities, pdf_content)
        
        return pdf_content
    
    def _build_cover_page(self, scan: Dict, org_name: str) -> List:
        """Build the cover page"""
        elements = []
        
        elements.append(Spacer(1, 2*inch))
        
        # Title
        elements.append(Paragraph(
            "Security Assessment Report",
            self.styles['CustomTitle']
        ))
        
        elements.append(Spacer(1, 0.5*inch))
        
        # Target info
        elements.append(Paragraph(
            f"<b>Target:</b> {scan.get('target', 'N/A')}",
            self.styles['Normal']
        ))
        
        elements.append(Spacer(1, 0.25*inch))
        
        # Organization
        elements.append(Paragraph(
            f"<b>Organization:</b> {org_name}",
            self.styles['Normal']
        ))
        
        elements.append(Spacer(1, 0.25*inch))
        
        # Date
        scan_date = scan.get('created_at', datetime.now(timezone.utc).isoformat())
        if isinstance(scan_date, str):
            try:
                scan_date = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
            except Exception:
                scan_date = datetime.now(timezone.utc)
        
        elements.append(Paragraph(
            f"<b>Assessment Date:</b> {scan_date.strftime('%B %d, %Y')}",
            self.styles['Normal']
        ))
        
        elements.append(Spacer(1, 0.25*inch))
        
        # Scan type
        scan_types = scan.get('scan_type', ['full'])
        if isinstance(scan_types, list):
            scan_type_str = ', '.join(scan_types)
        else:
            scan_type_str = str(scan_types)
        
        elements.append(Paragraph(
            f"<b>Scan Type:</b> {scan_type_str}",
            self.styles['Normal']
        ))
        
        elements.append(Spacer(1, 2*inch))
        
        # Confidentiality notice
        elements.append(Paragraph(
            "<b>CONFIDENTIAL</b>",
            ParagraphStyle(
                name='Confidential',
                parent=self.styles['Normal'],
                fontSize=12,
                textColor=colors.red,
                alignment=1  # Center
            )
        ))
        
        elements.append(Paragraph(
            "This report contains sensitive security information and should be handled accordingly.",
            ParagraphStyle(
                name='ConfidentialNote',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.gray,
                alignment=1
            )
        ))
        
        return elements
    
    def _build_toc(self, vulnerabilities: List) -> List:
        """Build table of contents"""
        elements = []
        
        elements.append(Paragraph("Table of Contents", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.25*inch))
        
        toc_items = [
            "1. Executive Summary",
            "2. Findings Overview",
            "3. Detailed Findings",
        ]
        
        # Add vulnerability categories
        categories = set()
        for v in vulnerabilities:
            cat = v.get('category', 'General')
            categories.add(cat)
        
        for i, cat in enumerate(sorted(categories), start=4):
            toc_items.append(f"   3.{i-3}. {cat}")
        
        toc_items.append(f"{len(categories)+4}. Appendix")
        
        for item in toc_items:
            elements.append(Paragraph(item, self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _build_executive_summary(self, scan: Dict, vulnerabilities: List) -> List:
        """Build executive summary section"""
        elements = []
        
        elements.append(Paragraph("1. Executive Summary", self.styles['SectionHeader']))
        
        # Overview paragraph
        critical = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
        high = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
        medium = sum(1 for v in vulnerabilities if v.get('severity') == 'medium')
        low = sum(1 for v in vulnerabilities if v.get('severity') == 'low')
        info = sum(1 for v in vulnerabilities if v.get('severity') == 'info')
        total = len(vulnerabilities)
        
        target = scan.get('target', 'the target')
        
        if critical > 0:
            risk_level = "CRITICAL"
            risk_color = "red"
            recommendation = "Immediate remediation is strongly recommended."
        elif high > 0:
            risk_level = "HIGH"
            risk_color = "orange"
            recommendation = "Prompt remediation is recommended."
        elif medium > 0:
            risk_level = "MEDIUM"
            risk_color = "#CC9900"
            recommendation = "Remediation should be planned and executed."
        else:
            risk_level = "LOW"
            risk_color = "green"
            recommendation = "Continue monitoring and maintaining security posture."
        
        summary_text = f"""
        A security assessment was conducted on <b>{target}</b>. The assessment identified 
        <b>{total}</b> security findings, including <font color="red"><b>{critical}</b> critical</font>, 
        <font color="orange"><b>{high}</b> high</font>, <font color="#CC9900"><b>{medium}</b> medium</font>, 
        <font color="green"><b>{low}</b> low</font>, and <font color="blue"><b>{info}</b> informational</font> issues.
        <br/><br/>
        <b>Overall Risk Level: <font color="{risk_color}">{risk_level}</font></b>
        <br/><br/>
        {recommendation}
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.25*inch))
        
        # Key findings table
        elements.append(Paragraph("<b>Key Findings Summary</b>", self.styles['SubHeader']))
        
        summary_data = [
            ["Severity", "Count", "Percentage"],
            ["Critical", str(critical), f"{(critical/total*100) if total else 0:.1f}%"],
            ["High", str(high), f"{(high/total*100) if total else 0:.1f}%"],
            ["Medium", str(medium), f"{(medium/total*100) if total else 0:.1f}%"],
            ["Low", str(low), f"{(low/total*100) if total else 0:.1f}%"],
            ["Informational", str(info), f"{(info/total*100) if total else 0:.1f}%"],
            ["Total", str(total), "100%"]
        ]
        
        table = Table(summary_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#fed7d7')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#feebc8')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#fefcbf')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#c6f6d5')),
            ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#bee3f8')),
            ('BACKGROUND', (0, 6), (-1, 6), colors.HexColor('#e2e8f0')),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.gray)
        ]))
        
        elements.append(table)
        
        return elements
    
    def _build_findings_overview(self, vulnerabilities: List) -> List:
        """Build findings overview with charts"""
        elements = []
        
        elements.append(Paragraph("2. Findings Overview", self.styles['SectionHeader']))
        
        # Severity distribution pie chart
        critical = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
        high = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
        medium = sum(1 for v in vulnerabilities if v.get('severity') == 'medium')
        low = sum(1 for v in vulnerabilities if v.get('severity') == 'low')
        info = sum(1 for v in vulnerabilities if v.get('severity') == 'info')
        
        if vulnerabilities:
            elements.append(Paragraph("<b>Severity Distribution</b>", self.styles['SubHeader']))
            
            # Create pie chart
            drawing = Drawing(400, 200)
            pie = Pie()
            pie.x = 100
            pie.y = 25
            pie.width = 150
            pie.height = 150
            pie.data = [critical, high, medium, low, info]
            pie.labels = ['Critical', 'High', 'Medium', 'Low', 'Info']
            pie.slices[0].fillColor = self.SEVERITY_COLORS['critical']
            pie.slices[1].fillColor = self.SEVERITY_COLORS['high']
            pie.slices[2].fillColor = self.SEVERITY_COLORS['medium']
            pie.slices[3].fillColor = self.SEVERITY_COLORS['low']
            pie.slices[4].fillColor = self.SEVERITY_COLORS['info']
            drawing.add(pie)
            
            elements.append(drawing)
            elements.append(Spacer(1, 0.25*inch))
        
        # Category breakdown
        categories = {}
        for v in vulnerabilities:
            cat = v.get('category', 'General')
            if cat not in categories:
                categories[cat] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            sev = v.get('severity', 'info')
            categories[cat][sev] = categories[cat].get(sev, 0) + 1
        
        if categories:
            elements.append(Paragraph("<b>Findings by Category</b>", self.styles['SubHeader']))
            
            cat_data = [["Category", "Critical", "High", "Medium", "Low", "Info", "Total"]]
            for cat, counts in sorted(categories.items()):
                total = sum(counts.values())
                cat_data.append([
                    cat,
                    str(counts['critical']),
                    str(counts['high']),
                    str(counts['medium']),
                    str(counts['low']),
                    str(counts['info']),
                    str(total)
                ])
            
            table = Table(cat_data, colWidths=[1.8*inch, 0.7*inch, 0.7*inch, 0.7*inch, 0.7*inch, 0.7*inch, 0.7*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.gray)
            ]))
            
            elements.append(table)
        
        return elements
    
    def _build_detailed_findings(
        self,
        vulnerabilities: List,
        include_remediation: bool = True,
        include_evidence: bool = True
    ) -> List:
        """Build detailed findings section"""
        elements = []
        
        elements.append(Paragraph("3. Detailed Findings", self.styles['SectionHeader']))
        
        # Group by category
        categories = {}
        for v in vulnerabilities:
            cat = v.get('category', 'General')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(v)
        
        finding_num = 1
        for cat_idx, (cat_name, cat_vulns) in enumerate(sorted(categories.items()), start=1):
            elements.append(Paragraph(f"3.{cat_idx}. {cat_name}", self.styles['SubHeader']))
            
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            cat_vulns.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 5))
            
            for vuln in cat_vulns:
                elements.extend(self._build_finding(
                    vuln,
                    finding_num,
                    include_remediation,
                    include_evidence
                ))
                finding_num += 1
                elements.append(Spacer(1, 0.15*inch))
        
        return elements
    
    def _build_finding(
        self,
        vuln: Dict,
        finding_num: int,
        include_remediation: bool,
        include_evidence: bool
    ) -> List:
        """Build a single finding entry"""
        elements = []
        
        severity = vuln.get('severity', 'info').upper()
        severity_color = self.SEVERITY_COLORS.get(vuln.get('severity', 'info'), colors.gray)
        
        # Finding header with severity badge
        header_data = [[
            f"Finding #{finding_num}",
            vuln.get('name', 'Unknown Finding'),
            severity
        ]]
        
        header_table = Table(header_data, colWidths=[1*inch, 4.5*inch, 1*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (2, 0), (2, 0), severity_color),
            ('TEXTCOLOR', (2, 0), (2, 0), colors.white),
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#e2e8f0')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (2, 0), (2, 0), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('BOX', (0, 0), (-1, 0), 1, colors.gray)
        ]))
        
        elements.append(header_table)
        
        # Description
        elements.append(Paragraph(
            f"<b>Description:</b> {vuln.get('description', 'No description available.')}",
            self.styles['Finding']
        ))
        
        # Location/URL
        if vuln.get('url') or vuln.get('location'):
            elements.append(Paragraph(
                f"<b>Location:</b> {vuln.get('url') or vuln.get('location', 'N/A')}",
                self.styles['Finding']
            ))
        
        # CVSS Score
        if vuln.get('cvss_score'):
            elements.append(Paragraph(
                f"<b>CVSS Score:</b> {vuln.get('cvss_score')}",
                self.styles['Finding']
            ))
        
        # CVE
        if vuln.get('cve_id'):
            elements.append(Paragraph(
                f"<b>CVE:</b> {vuln.get('cve_id')}",
                self.styles['Finding']
            ))
        
        # Evidence
        if include_evidence and vuln.get('evidence'):
            elements.append(Paragraph("<b>Evidence:</b>", self.styles['Finding']))
            evidence_text = vuln.get('evidence', '')
            if len(evidence_text) > 500:
                evidence_text = evidence_text[:500] + "..."
            
            evidence_style = ParagraphStyle(
                name='Evidence',
                parent=self.styles['Normal'],
                fontSize=8,
                fontName='Courier',
                backColor=colors.HexColor('#f7fafc'),
                leftIndent=30,
                rightIndent=10,
                spaceBefore=5,
                spaceAfter=5
            )
            elements.append(Paragraph(evidence_text, evidence_style))
        
        # Remediation
        if include_remediation and vuln.get('remediation'):
            elements.append(Paragraph(
                f"<b>Remediation:</b> {vuln.get('remediation')}",
                self.styles['Finding']
            ))
        
        # References
        if vuln.get('references'):
            refs = vuln.get('references', [])
            if isinstance(refs, list) and refs:
                elements.append(Paragraph("<b>References:</b>", self.styles['Finding']))
                for ref in refs[:5]:  # Limit to 5 references
                    elements.append(Paragraph(
                        f"• {ref}",
                        ParagraphStyle(
                            name='RefLink',
                            parent=self.styles['Normal'],
                            fontSize=8,
                            leftIndent=40,
                            textColor=colors.blue
                        )
                    ))
        
        return elements
    
    def _build_appendix(self, scan: Dict) -> List:
        """Build appendix section"""
        elements = []
        
        elements.append(PageBreak())
        elements.append(Paragraph("Appendix", self.styles['SectionHeader']))
        
        # Scan details
        elements.append(Paragraph("<b>Scan Details</b>", self.styles['SubHeader']))
        
        details = [
            ["Property", "Value"],
            ["Scan ID", scan.get('id', 'N/A')],
            ["Target", scan.get('target', 'N/A')],
            ["Status", scan.get('status', 'N/A')],
            ["Started At", str(scan.get('started_at', 'N/A'))],
            ["Completed At", str(scan.get('completed_at', 'N/A'))],
            ["Duration", self._format_duration(scan.get('started_at'), scan.get('completed_at'))]
        ]
        
        table = Table(details, colWidths=[2*inch, 4.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.gray),
            ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#f7fafc'))
        ]))
        
        elements.append(table)
        
        # Methodology
        elements.append(Spacer(1, 0.25*inch))
        elements.append(Paragraph("<b>Testing Methodology</b>", self.styles['SubHeader']))
        
        methodology_text = """
        This security assessment was conducted using a combination of automated scanning tools
        and manual verification techniques. The assessment covered the following areas:
        
        • Network and Port Scanning
        • SSL/TLS Certificate Analysis
        • HTTP Security Header Assessment
        • Web Application Vulnerability Testing
        • Authentication and Authorization Testing
        • Information Disclosure Analysis
        
        All testing was performed from an external perspective, simulating the viewpoint
        of a remote attacker without prior knowledge of the system architecture.
        """
        
        elements.append(Paragraph(methodology_text, self.styles['Normal']))
        
        # Disclaimer
        elements.append(Spacer(1, 0.25*inch))
        elements.append(Paragraph("<b>Disclaimer</b>", self.styles['SubHeader']))
        
        disclaimer_text = """
        This report represents a point-in-time assessment and may not reflect current
        security conditions. The findings are based on information available at the time
        of testing. Organizations should conduct regular security assessments to maintain
        an accurate understanding of their security posture.
        
        The information in this report is provided "as is" without warranty of any kind.
        """
        
        elements.append(Paragraph(
            disclaimer_text,
            ParagraphStyle(
                name='Disclaimer',
                parent=self.styles['Normal'],
                fontSize=9,
                textColor=colors.gray
            )
        ))
        
        return elements
    
    def _add_header_footer(self, canvas, doc):
        """Add header and footer to each page"""
        canvas.saveState()
        
        # Header
        canvas.setFont('Helvetica-Bold', 10)
        canvas.setFillColor(colors.HexColor('#2d3748'))
        canvas.drawString(0.75*inch, letter[1] - 0.5*inch, "SecureScan Pro - Security Assessment Report")
        
        # Header line
        canvas.setStrokeColor(colors.HexColor('#e2e8f0'))
        canvas.line(0.75*inch, letter[1] - 0.6*inch, letter[0] - 0.75*inch, letter[1] - 0.6*inch)
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.gray)
        
        # Page number
        canvas.drawCentredString(letter[0]/2, 0.5*inch, f"Page {doc.page}")
        
        # Confidential notice
        canvas.drawString(0.75*inch, 0.5*inch, "CONFIDENTIAL")
        
        # Generated date
        canvas.drawRightString(
            letter[0] - 0.75*inch,
            0.5*inch,
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        )
        
        canvas.restoreState()
    
    def _format_duration(self, start, end) -> str:
        """Format scan duration"""
        if not start or not end:
            return "N/A"
        
        try:
            if isinstance(start, str):
                start = datetime.fromisoformat(start.replace('Z', '+00:00'))
            if isinstance(end, str):
                end = datetime.fromisoformat(end.replace('Z', '+00:00'))
            
            duration = end - start
            total_seconds = int(duration.total_seconds())
            
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60
            
            if hours > 0:
                return f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                return f"{minutes}m {seconds}s"
            else:
                return f"{seconds}s"
        except Exception:
            return "N/A"
    
    async def _save_report_record(
        self,
        scan_id: str,
        scan: Dict,
        vulnerabilities: List,
        pdf_content: bytes
    ):
        """Save report record to database"""
        sb = get_supabase()
        
        # Calculate summary
        critical = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
        high = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
        medium = sum(1 for v in vulnerabilities if v.get('severity') == 'medium')
        low = sum(1 for v in vulnerabilities if v.get('severity') == 'low')
        
        report_data = {
            "scan_id": scan_id,
            "organization_id": scan.get("organization_id"),
            "report_type": "pdf",
            "format": "pdf",
            "file_size": len(pdf_content),
            "summary": {
                "total_findings": len(vulnerabilities),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low
            },
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        try:
            sb.table("reports").insert(report_data).execute()
        except Exception as e:
            logger.error(f"Failed to save report record: {e}")


# API function for generating reports
async def generate_pdf_report(
    scan_id: str,
    include_remediation: bool = True,
    include_evidence: bool = True,
    include_executive_summary: bool = True
) -> bytes:
    """
    Generate a PDF report for a scan
    
    Args:
        scan_id: The scan ID
        include_remediation: Include remediation steps
        include_evidence: Include technical evidence
        include_executive_summary: Include executive summary
        
    Returns:
        PDF content as bytes
    """
    service = PDFReportService()
    return await service.generate_scan_report(
        scan_id,
        include_remediation=include_remediation,
        include_evidence=include_evidence,
        include_executive_summary=include_executive_summary
    )

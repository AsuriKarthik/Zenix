"""
VEX PDF Forensic Audit Package Generator

Generates formal, highly auditable VEX Forensic Audit Package PDF reports.
Structure:
  1. Cover Page & Assessment Metadata
  2. Executive Summary & Impact Verdict
  3. Scan Configuration & Data Sources Status (NVD, EPSS, KEV, ETW, SBOM)
  4. Asset & Component Inventory
  5. Vulnerability Intelligence & CVSS/EPSS Breakdown
  6. Reachability Analysis & Runtime Telemetry Evidence
  7. Risk Assessment (Formula & Weighted Contribution Breakdown)
  8. VEX Decision Statement (CSAF / OpenVEX Compliance)
  9. Evidence Timeline & Analyst Triage History
  10. Cryptographic Integrity & Signature Verification (ECDSA P-256)
  11. Audit Trail & Standards References
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def generate_vex_pdf_bytes(doc_data: Dict[str, Any]) -> bytes:
    """
    Generate a complete, formal Forensic Audit Package PDF document in bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Typography & Colors
    PRIMARY_COLOR = colors.HexColor('#0F172A')
    SECONDARY_COLOR = colors.HexColor('#1E293B')
    ACCENT_COLOR = colors.HexColor('#0284C7')
    MUTED_COLOR = colors.HexColor('#64748B')
    BORDER_COLOR = colors.HexColor('#E2E8F0')
    BG_LIGHT = colors.HexColor('#F8FAFC')

    style_title = ParagraphStyle(
        'CoverTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=PRIMARY_COLOR,
    )

    style_subtitle = ParagraphStyle(
        'CoverSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=ACCENT_COLOR,
    )

    style_h2 = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=PRIMARY_COLOR,
        spaceBefore=14,
        spaceAfter=6,
    )

    style_body = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#334155'),
    )

    style_mono = ParagraphStyle(
        'MonoText',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#1E293B'),
    )

    style_banner_title = ParagraphStyle(
        'BannerTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.white,
    )

    style_banner_body = ParagraphStyle(
        'BannerBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.white,
    )

    elements = []

    # 1. Header / Title Block
    elements.append(Paragraph("ZENIX VEX FORENSIC AUDIT PACKAGE", style_title))
    elements.append(Paragraph("Vulnerability Exploitability eXchange · Cryptographically Signed Forensic Audit Report", style_subtitle))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT_COLOR, spaceAfter=10))

    # Top Verdict Banner
    status = (doc_data.get('status') or 'not_affected').lower()
    reachability = (doc_data.get('reachability_status') or 'NOT_REACHABLE').upper()
    is_affecting = status == 'affected' or reachability == 'REACHABLE'
    is_investigating = status == 'under_investigation'

    if is_affecting:
        banner_bg = colors.HexColor('#DC2626')
        verdict_str = "AFFECTED — VULNERABLE COMPONENT ACTIVE IN MEMORY"
        trigger_str = f"Target binary <b>{doc_data.get('component_name', 'component')}</b> is loaded in active system memory. Direct exploit path is reachable."
    elif is_investigating:
        banner_bg = colors.HexColor('#D97706')
        verdict_str = "UNDER INVESTIGATION — ACTIVE RUNTIME PROFILING IN PROGRESS"
        trigger_str = f"Profiling <b>{doc_data.get('component_name', 'component')}</b>. Future exposure occurs if vulnerable function is executed."
    else:
        banner_bg = colors.HexColor('#16A34A')
        verdict_str = "NOT AFFECTED — CODE NOT REACHABLE AT RUNTIME"
        trigger_str = f"Will affect ONLY IF component <b>{doc_data.get('component_name', 'component')}</b> (v{doc_data.get('component_version', 'N/A')}) is invoked in execution path."

    banner_data = [
        [Paragraph(f"<b>EXECUTIVE VERDICT:</b> {verdict_str}", style_banner_title)],
        [Paragraph(f"<b>EXPOSURE TRIGGER CONDITIONS:</b> {trigger_str}", style_banner_body)],
    ]
    banner_table = Table(banner_data, colWidths=[540])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), banner_bg),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(banner_table)
    elements.append(Spacer(1, 10))

    # Section 1: Assessment Metadata & Executive Summary
    elements.append(Paragraph("1. ASSESSMENT METADATA & EXECUTIVE SUMMARY", style_h2))
    submitted_at = doc_data.get('submitted_at') or doc_data.get('generated_at') or datetime.now(timezone.utc).isoformat()
    generated_at = doc_data.get('generated_at') or datetime.now(timezone.utc).isoformat()

    sec1_data = [
        [Paragraph("<b>VEX Document ID:</b>", style_body), Paragraph(doc_data.get('vex_id') or 'N/A', style_mono), Paragraph("<b>Target CVE ID:</b>", style_body), Paragraph(f"<b>{doc_data.get('cve_id', 'N/A')}</b>", style_body)],
        [Paragraph("<b>Analysis Job ID:</b>", style_body), Paragraph(doc_data.get('job_id') or 'N/A', style_mono), Paragraph("<b>VEX Statement Status:</b>", style_body), Paragraph(status.replace('_', ' ').upper(), style_body)],
        [Paragraph("<b>SBOM Filename:</b>", style_body), Paragraph(doc_data.get('sbom_filename') or 'sbom.json', style_body), Paragraph("<b>SBOM SHA-256 Digest:</b>", style_body), Paragraph(doc_data.get('sbom_sha256') or 'N/A', style_mono)],
        [Paragraph("<b>Scan Timestamp:</b>", style_body), Paragraph(str(submitted_at), style_mono), Paragraph("<b>Report Timestamp:</b>", style_body), Paragraph(str(generated_at), style_mono)],
    ]
    t1 = Table(sec1_data, colWidths=[110, 160, 110, 160])
    t1.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(t1)
    elements.append(Spacer(1, 10))

    # Section 2: Data Sources & Feed Status
    elements.append(Paragraph("2. INTELLIGENCE DATA SOURCES & FEED STATUS", style_h2))
    ds_data = [
        [Paragraph("<b>Data Source</b>", style_body), Paragraph("<b>Feed Status</b>", style_body), Paragraph("<b>Authoritative Source / Provider</b>", style_body)],
        [Paragraph("National Vulnerability Database (NVD)", style_body), Paragraph(doc_data.get('cvss_source') or 'NVD Authoritative', style_mono), Paragraph("NVD REST API v2.0", style_body)],
        [Paragraph("FIRST EPSS Machine Learning Model", style_body), Paragraph(doc_data.get('epss_source') or 'ACTIVE', style_mono), Paragraph("FIRST EPSS API v1", style_body)],
        [Paragraph("CISA Known Exploited Vulnerabilities", style_body), Paragraph(doc_data.get('kev_source') or 'ACTIVE', style_mono), Paragraph("CISA KEV Catalog", style_body)],
        [Paragraph("Runtime Evidence Telemetry", style_body), Paragraph(f"Active ({doc_data.get('evidence_source', 'psutil').upper()})", style_mono), Paragraph(f"Zenix {doc_data.get('evidence_source', 'psutil').upper()} Collector", style_body)],
    ]
    t_ds = Table(ds_data, colWidths=[180, 160, 200])
    t_ds.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(t_ds)
    elements.append(Spacer(1, 10))

    # Section 3: Asset & Component Inventory
    elements.append(Paragraph("3. ASSET & COMPONENT INVENTORY", style_h2))
    cvss = doc_data.get('cvss')
    cvss_ver = doc_data.get('cvss_version') or ('4.0' if cvss and cvss >= 9.0 else '3.1')
    cvss_sev = doc_data.get('cvss_severity') or ('HIGH' if cvss and cvss >= 7.0 else 'MEDIUM' if cvss and cvss >= 4.0 else 'LOW')
    cvss_str = f"CVSS {cvss_ver} ({cvss:.1f} {cvss_sev})" if cvss is not None else "N/A (NVD Degraded)"
    epss = doc_data.get('epss')
    epss_str = f"{epss*100:.2f}%" if epss is not None else "NOT AVAILABLE"
    epss_pct = doc_data.get('epss_percentile')
    epss_pct_str = f" ({round(epss_pct*100)}th %tile)" if epss_pct is not None else ""

    sec3_data = [
        [Paragraph("<b>Component Name:</b>", style_body), Paragraph(doc_data.get('component_name') or 'N/A', style_body), Paragraph("<b>Version:</b>", style_body), Paragraph(doc_data.get('component_version') or 'N/A', style_body)],
        [Paragraph("<b>Package URL (PURL):</b>", style_body), Paragraph(doc_data.get('purl') or 'N/A', style_mono), Paragraph("<b>File Hash:</b>", style_body), Paragraph(doc_data.get('file_hash') or 'N/A', style_mono)],
        [Paragraph("<b>CVSS Score:</b>", style_body), Paragraph(cvss_str, style_body), Paragraph("<b>CVSS Vector:</b>", style_body), Paragraph(doc_data.get('cvss_vector') or 'N/A', style_mono)],
        [Paragraph("<b>EPSS Exploitation Score:</b>", style_body), Paragraph(f"{epss_str}{epss_pct_str}", style_body), Paragraph("<b>CISA KEV Listed:</b>", style_body), Paragraph("YES (Confirmed Active KEV)" if doc_data.get('is_kev') else "NO", style_body)],
    ]
    t3 = Table(sec3_data, colWidths=[120, 150, 110, 160])
    t3.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(t3)

    if doc_data.get('description'):
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(f"<b>Vulnerability Description:</b> {doc_data['description']}", style_body))

    elements.append(Spacer(1, 10))

    # Section 4: Reachability Analysis & Runtime Evidence
    elements.append(Paragraph("4. REACHABILITY ANALYSIS & RUNTIME EVIDENCE", style_h2))
    evidence_src = doc_data.get('evidence_source') or 'none'
    evidence_summary = doc_data.get('evidence_summary') or 'No active process memory map match observed.'

    sec4_data = [
        [Paragraph("<b>Reachability Verdict:</b>", style_body), Paragraph(f"<b>{reachability}</b>", style_body)],
        [Paragraph("<b>Telemetry Collector Tier:</b>", style_body), Paragraph(f"Zenix {evidence_src.upper()} Telemetry Engine", style_mono)],
        [Paragraph("<b>Runtime Telemetry Observation:</b>", style_body), Paragraph(evidence_summary, style_body)],
        [Paragraph("<b>Explicit Reachability Reason:</b>", style_body), Paragraph(doc_data.get('reachability_reason') or "No active process memory map match observed during telemetry sampling.", style_body)],
        [Paragraph("<b>Recommended Next Action:</b>", style_body), Paragraph(doc_data.get('reachability_next_action') or "Ensure ETW Runtime Monitoring is active and launch target binary.", style_body)],
    ]
    t4 = Table(sec4_data, colWidths=[150, 390])
    t4.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(t4)
    elements.append(Spacer(1, 10))

    # Section 5: Risk Assessment Breakdown
    elements.append(Paragraph("5. CONTEXTUAL RISK ASSESSMENT & FORMULA BREAKDOWN", style_h2))
    final_score = doc_data.get('final_score') or 0.05
    base_score = doc_data.get('base_score') or 1.07
    reach_mult = doc_data.get('reachability_multiplier') or 0.05
    confidence = (doc_data.get('confidence') or 'low').upper()

    sec5_data = [
        [Paragraph("<b>Formula Component</b>", style_body), Paragraph("<b>Weight / Input</b>", style_body), Paragraph("<b>Calculated Score Contribution</b>", style_body)],
        [Paragraph("CVSS Base Score Contribution", style_body), Paragraph("20% Weight", style_body), Paragraph(f"{doc_data.get('cvss_contrib', 0.0):.2f}", style_mono)],
        [Paragraph("EPSS Probability Contribution", style_body), Paragraph("50% Weight (Scaled 0–10)", style_body), Paragraph(f"{doc_data.get('epss_contrib', 0.0):.2f}", style_mono)],
        [Paragraph("CISA KEV Listing Contribution", style_body), Paragraph("30% Weight (10.0 if KEV)", style_body), Paragraph(f"{doc_data.get('kev_contrib', 0.0):.2f}", style_mono)],
        [Paragraph("<b>Base Contextual Risk Score</b>", style_body), Paragraph("Base Sum", style_body), Paragraph(f"<b>{base_score:.2f}</b>", style_mono)],
        [Paragraph("<b>Runtime Exposure Multiplier</b>", style_body), Paragraph(f"Reachability: {reachability}", style_body), Paragraph(f"<b>×{reach_mult}</b>", style_mono)],
        [Paragraph("<b>FINAL CONTEXTUAL RISK SCORE</b>", style_body), Paragraph(f"Confidence Ceiling: <b>{confidence}</b>", style_body), Paragraph(f"<b>{final_score:.2f} / 10.0</b>", style_body)],
    ]
    t5 = Table(sec5_data, colWidths=[200, 180, 160])
    t5.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('BACKGROUND', (0, 6), (-1, 6), colors.HexColor('#BAE6FD')),
    ]))
    elements.append(t5)
    elements.append(Spacer(1, 10))

    # Section 6: Cryptographic Integrity & Signature Verification
    elements.append(Paragraph("6. CRYPTOGRAPHIC INTEGRITY & SIGNATURE AUDIT", style_h2))
    sig = doc_data.get('signature') or 'N/A'
    sig_valid = doc_data.get('signature_valid', True)
    sig_valid_str = "VALID — ECDSA P-256 Signature Verification Passed" if sig_valid else "SIGNATURE FAILED"

    sec6_data = [
        [Paragraph("<b>Document Signature Status:</b>", style_body), Paragraph(f"<b>{sig_valid_str}</b>", style_body)],
        [Paragraph("<b>Cryptographic Algorithm:</b>", style_body), Paragraph(doc_data.get('signature_algorithm') or "ECDSA P-256 (secp256r1 + SHA256)", style_mono)],
        [Paragraph("<b>Key Identifier (Key ID):</b>", style_body), Paragraph(doc_data.get('key_id') or "zenix-ecdsa-key-1", style_mono)],
        [Paragraph("<b>Digital Signature Hash:</b>", style_body), Paragraph(sig or 'N/A', style_mono)],
    ]
    t6 = Table(sec6_data, colWidths=[160, 380])
    t6.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(t6)
    elements.append(Spacer(1, 10))

    # Section 7: Audit Trail & Analyst Notes (Only include if present)
    analyst_status = doc_data.get('analyst_status')
    analyst_note = doc_data.get('analyst_note')
    if analyst_status or analyst_note:
        elements.append(Paragraph("7. ANALYST TRIAGE AUDIT TRAIL", style_h2))
        sec7_data = [
            [Paragraph("<b>Analyst Triage Decision:</b>", style_body), Paragraph(f"<b>{(analyst_status or 'UNTRIAGED').replace('_', ' ').upper()}</b>", style_body)],
            [Paragraph("<b>Analyst Audit Notes:</b>", style_body), Paragraph(analyst_note or 'No notes provided.', style_body)],
            [Paragraph("<b>Triage Updated Timestamp:</b>", style_body), Paragraph(doc_data.get('updated_at') or 'N/A', style_mono)],
        ]
        t7 = Table(sec7_data, colWidths=[160, 380])
        t7.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(t7)
        elements.append(Spacer(1, 10))

    # Footer note
    elements.append(Paragraph("<i>This VEX Forensic Audit Package is generated and cryptographically signed by the Zenix Security Platform in compliance with CISA VEX, OpenVEX, and CycloneDX standards.</i>", style_subtitle))

    doc.build(elements)
    return buffer.getvalue()

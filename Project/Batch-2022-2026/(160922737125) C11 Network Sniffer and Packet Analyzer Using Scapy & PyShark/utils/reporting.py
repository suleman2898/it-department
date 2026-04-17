import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

from utils.helpers import get_app_root


def generate_pdf_report(
    report_id: int,
    input_name: str,
    source_type: str,
    summary: str,
    risk_level: str,
    risk_score: int,
    packets_analyzed: int,
    findings: list,
    ledger_hash: str,
    created_at
) -> str:
    reports_dir = os.path.join(get_app_root(), "uploads")
    os.makedirs(reports_dir, exist_ok=True)

    output_path = os.path.join(reports_dir, f"report_{report_id}.pdf")
    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4

    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Network Sniffer and Packet Analyzer Report")
    y -= 30

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Report ID: {report_id}")
    y -= 18
    c.drawString(50, y, f"Input Name: {input_name}")
    y -= 18
    c.drawString(50, y, f"Source Type: {source_type}")
    y -= 18
    c.drawString(50, y, f"Created At: {created_at}")
    y -= 18
    c.drawString(50, y, f"Packets Analyzed: {packets_analyzed}")
    y -= 18
    c.drawString(50, y, f"Risk Score: {risk_score}")
    y -= 18
    c.drawString(50, y, f"Risk Level: {risk_level}")
    y -= 25

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Summary")
    y -= 18

    c.setFont("Helvetica", 10)
    for line in split_text(summary, 90):
        c.drawString(50, y, line)
        y -= 14
        if y < 100:
            c.showPage()
            y = height - 50

    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Findings")
    y -= 18

    c.setFont("Helvetica", 10)
    if not findings:
        c.drawString(50, y, "No major findings.")
        y -= 14
    else:
        for idx, finding in enumerate(findings, start=1):
            line = f"{idx}. [{finding.get('severity', 'Info')}] {finding.get('type', 'Finding')}: {finding.get('details', '')}"
            for wrapped in split_text(line, 90):
                c.drawString(50, y, wrapped)
                y -= 14
                if y < 100:
                    c.showPage()
                    y = height - 50

    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Evidence Integrity")
    y -= 18

    c.setFont("Helvetica", 10)
    for line in split_text(f"SHA256 Ledger Hash: {ledger_hash}", 90):
        c.drawString(50, y, line)
        y -= 14
        if y < 100:
            c.showPage()
            y = height - 50

    y -= 20
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(
        50, y,
        "Alert Simulation: No external email or cloud alerting used. All notifications remain local."
    )

    c.save()
    return output_path


def split_text(text: str, max_chars: int) -> list[str]:
    words = text.split()
    lines = []
    current = ""

    for word in words:
        test_line = word if not current else f"{current} {word}"
        if len(test_line) <= max_chars:
            current = test_line
        else:
            lines.append(current)
            current = word

    if current:
        lines.append(current)

    return lines
"""PDF and CSV threat report exporters using fpdf2 and Python stdlib csv."""

import csv
import io
from datetime import datetime
from fpdf import FPDF


def _safe_text(value: str, max_len: int = 160) -> str:
    """Normalize text to latin-1 safe characters for standard PDF core fonts."""
    text = (value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text.encode("latin-1", "replace").decode("latin-1")


def generate_pdf_report(analysis: dict, filename: str = "capture.csv") -> bytes:
    """Build a clean ThreatLens forensic PDF report and return bytes."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Header
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "ThreatLens - Forensic Threat Analysis Report", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90, 98, 112)
    pdf.cell(
        0,
        6,
        _safe_text(
            f"Source: {filename}  |  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
            f"Mode: {analysis.get('ai', {}).get('mode', 'offline').upper()}"
        ),
        ln=True,
    )
    pdf.ln(4)

    # Summary Box
    summary = analysis.get("summary", {})
    pdf.set_text_color(20, 24, 31)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Scan Summary", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(
        0,
        6,
        f"Events Scanned: {analysis.get('total_events', 0)}   |   "
        f"Threats Flagged: {analysis.get('total_threats', 0)}   |   "
        f"Critical: {summary.get('Critical', 0)}   "
        f"High: {summary.get('High', 0)}   "
        f"Medium: {summary.get('Medium', 0)}   "
        f"Low: {summary.get('Low', 0)}",
        ln=True,
    )
    pdf.ln(4)

    # AI Context if present
    narrative = (analysis.get("ai") or {}).get("narrative")
    if narrative:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(pdf.epw, 8, "Gemini AI Attack-Chain Context", ln=True)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.multi_cell(pdf.epw, 5, _safe_text(narrative, max_len=2000))
        pdf.ln(4)

    # Threat Timeline
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(pdf.epw, 8, "Chronological Threat Timeline", ln=True)
    threats = analysis.get("threats", [])
    if not threats:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(pdf.epw, 7, "No threat indicators detected.", ln=True)
    else:
        for t in threats[:100]:
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 9.5)
            header = f"[{t['timestamp']}] {t['severity'].upper()} - {t['title']} ({t['ring']})"
            pdf.multi_cell(pdf.epw, 5.5, _safe_text(header, 140))
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "", 9)
            meta = f"Process: {t['process']} (PID {t['pid']}) | Op: {t['operation']} | Result: {t['result']}"
            pdf.multi_cell(pdf.epw, 5, _safe_text(meta, 150))
            if t.get("path") and t["path"] != "(none)":
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(pdf.epw, 5, _safe_text(f"Path: {t['path']}", 150))
            pdf.set_x(pdf.l_margin)
            pdf.set_text_color(70, 78, 90)
            pdf.multi_cell(pdf.epw, 4.8, _safe_text(f"Why: {t['why']}", 240))
            pdf.set_text_color(20, 24, 31)
            pdf.ln(2)

    raw = pdf.output()
    return bytes(raw) if isinstance(raw, (bytes, bytearray)) else raw.encode("latin-1")


def generate_csv_report(analysis: dict) -> bytes:
    """Export flagged threats as a downloadable CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "ID",
            "Timestamp",
            "Severity",
            "Ring Level",
            "Threat Type",
            "Process Name",
            "PID",
            "Operation",
            "Path",
            "Result",
            "Explanation",
            "Recommended Action",
        ]
    )
    for t in analysis.get("threats", []):
        writer.writerow(
            [
                t["id"],
                t["timestamp"],
                t["severity"],
                t["ring"],
                t["threat_type"],
                t["process"],
                t["pid"],
                t["operation"],
                t["path"],
                t["result"],
                t["why"],
                t["action"],
            ]
        )
    return buf.getvalue().encode("utf-8-sig")

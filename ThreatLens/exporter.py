"""
ThreatLens — Export Module
===========================
Generates PDF and CSV reports from analysis results.
"""

import csv
import io
from datetime import datetime

from threat_db import SEVERITY_EMOJI


def export_csv(analysis_result: dict) -> str:
    """
    Generate a CSV string of all detected threats.
    Returns CSV content as a string (ready to serve as download).
    """
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        "Severity", "Timestamp", "Process Name", "PID", "Operation",
        "Path", "Result", "Threat Type", "Category", "MITRE ATT&CK",
        "Description"
    ])
    
    for threat in analysis_result.get("timeline", []):
        writer.writerow([
            threat["severity"].upper(),
            threat["timestamp"],
            threat["process_name"],
            threat["pid"],
            threat["operation"],
            threat["path"][:200],
            threat["result"],
            threat["threat_type"],
            threat["category"],
            threat.get("mitre_id", "N/A"),
            threat["description"][:300],
        ])
    
    return output.getvalue()


def export_pdf(analysis_result: dict, ai_result: dict = None) -> bytes:
    """
    Generate a PDF report of the threat analysis.
    Returns PDF content as bytes.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        raise ImportError("fpdf2 is required for PDF export. Run: pip install fpdf2")
    
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    
    # --- Page 1: Title & Summary ---
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 15, "ThreatLens - Threat Analysis Report", align="C", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Total Log Entries Analyzed: {analysis_result['total_entries']}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Scan Duration: {analysis_result['scan_time']}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    # Summary Box
    summary = analysis_result["summary"]
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "SCAN SUMMARY", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    
    pdf.set_fill_color(220, 38, 38)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(45, 10, f"  CRITICAL: {summary['critical']}", fill=True)
    
    pdf.set_fill_color(234, 88, 12)
    pdf.cell(45, 10, f"  HIGH: {summary['high']}", fill=True)
    
    pdf.set_fill_color(202, 138, 4)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(45, 10, f"  MEDIUM: {summary['medium']}", fill=True)
    
    pdf.set_fill_color(22, 163, 74)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(45, 10, f"  LOW: {summary['low']}", fill=True, new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)
    
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, f"Total Threats Detected: {summary['total_threats']}", new_x="LMARGIN", new_y="NEXT")
    
    if summary.get("top_processes"):
        procs = ", ".join(f"{name} ({count})" for name, count in summary["top_processes"])
        pdf.cell(0, 7, f"Top Suspicious Processes: {procs}", new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(5)
    
    # --- AI Analysis (if available) ---
    if ai_result:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "AI THREAT ANALYSIS", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        
        if ai_result.get("risk_score") is not None:
            pdf.cell(0, 7, f"Risk Score: {ai_result['risk_score']}/100 - {ai_result.get('risk_label', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        
        if ai_result.get("ai_analysis"):
            pdf.ln(3)
            pdf.multi_cell(0, 5, ai_result["ai_analysis"][:2000])
        
        if ai_result.get("attack_chain"):
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 7, "Attack Chain:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 5, ai_result["attack_chain"][:1500])
        
        if ai_result.get("recommendations"):
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 7, "Recommendations:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            for i, rec in enumerate(ai_result["recommendations"][:5], 1):
                pdf.multi_cell(0, 5, f"{i}. {rec}")
                pdf.ln(2)
        
        pdf.ln(5)
    
    # --- Threat Details ---
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "THREAT TIMELINE (Chronological)", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    
    for i, threat in enumerate(analysis_result.get("timeline", [])[:50], 1):
        # Check if we need a new page
        if pdf.get_y() > 250:
            pdf.add_page()
        
        sev = threat["severity"].upper()
        emoji = SEVERITY_EMOJI.get(threat["severity"], "⚪")
        
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, f"{emoji} [{sev}] {threat['threat_type']}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"Time: {threat['timestamp']}  |  Process: {threat['process_name']} (PID: {threat['pid']})", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, f"Operation: {threat['operation']}  |  Result: {threat['result']}", new_x="LMARGIN", new_y="NEXT")
        
        if threat["path"]:
            path_display = threat["path"][:120]
            pdf.cell(0, 5, f"Path: {path_display}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font("Helvetica", "I", 8)
        desc = threat["description"][:250]
        pdf.multi_cell(0, 4, desc)
        
        if threat.get("mitre_id") and threat["mitre_id"] != "N/A":
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(0, 4, f"MITRE ATT&CK: {threat['mitre_id']}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.ln(4)
    
    # --- Footer ---
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "ABOUT THIS REPORT", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, (
        "This report was generated by ThreatLens - Endpoint Behavioral Analysis & "
        "Runtime Threat Detection Engine. ThreatLens analyzes ProcMon (Process Monitor) "
        "system logs using a combination of offline rule-based heuristic detection and "
        "AI-powered contextual analysis to identify Ring 0 (Kernel) and Ring 3 (User-Mode) "
        "security threats.\n\n"
        "Developed for SFIC 2026 - Seva First Innovation Challenge.\n"
        "CHARUSAT, Anand, Gujarat."
    ))
    
    return bytes(pdf.output())

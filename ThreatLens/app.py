"""
ThreatLens — Flask Application (Main Entry Point)
===================================================
Smart offline-first ProcMon log analyzer with AI-enhanced threat detection.

Run:
    cd threatlens
    pip install -r requirements.txt
    set GEMINI_API_KEY=your_key_here    (optional — for AI mode)
    python app.py

Then open: http://localhost:5000
"""

import os
import json
from datetime import datetime

from flask import Flask, request, render_template, jsonify, send_file, session
import io

from engine import parse_procmon_csv, analyze_logs, get_entries_for_ai, build_local_reasoning
from gemini_engine import is_online, analyze_with_gemini, get_api_key
from exporter import export_csv, export_pdf

app = Flask(__name__)
app.secret_key = os.urandom(24)

# In-memory store for the last analysis (simple — no DB needed)
_last_analysis = {}
_last_ai_result = {}
_last_entries = []


@app.route("/")
def index():
    """Serve the main single-page application."""
    online = is_online()
    return render_template("index.html", is_online=online)


@app.route("/api/status")
def api_status():
    """Check online/offline status and API key availability."""
    from gemini_engine import get_api_key
    return jsonify({
        "online": is_online(),
        "has_api_key": bool(get_api_key()),
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """
    Upload and analyze a ProcMon CSV file.
    
    Accepts:
      - multipart/form-data with file field 'logfile'
      - JSON body with 'content' field (raw CSV text)
    
    Returns JSON analysis results.
    """
    global _last_analysis, _last_ai_result, _last_entries
    
    # --- Get CSV content ---
    csv_content = None
    filename = "uploaded_log.csv"
    
    if "logfile" in request.files:
        file = request.files["logfile"]
        if file.filename:
            filename = file.filename
            csv_content = file.read().decode("utf-8-sig", errors="replace")
    elif request.is_json and request.json.get("content"):
        csv_content = request.json["content"]
        filename = request.json.get("filename", "pasted_log.csv")
    
    if not csv_content or len(csv_content.strip()) < 10:
        return jsonify({"error": "No valid CSV content received. Please upload a ProcMon CSV export."}), 400
    
    # --- Parse CSV ---
    try:
        entries = parse_procmon_csv(csv_content)
    except Exception as e:
        return jsonify({"error": f"Failed to parse CSV: {str(e)}. Ensure this is a ProcMon CSV export."}), 400
    
    if not entries:
        return jsonify({"error": "No valid log entries found in the CSV. Check that it's a ProcMon export with standard columns (Time of Day, Process Name, PID, Operation, Path, Result, Detail)."}), 400
    
    # --- Run offline rule-based analysis ---
    analysis = analyze_logs(entries)
    analysis["filename"] = filename
    
    # --- Run AI analysis ONLY when online + API key + ?ai=true; otherwise Data Privacy Mode ---
    ai_result = None
    use_ai = request.args.get("ai", "true").lower() != "false"
    online_now = is_online()
    has_key = bool(get_api_key())
    llm_used = False

    if use_ai and online_now and has_key and analysis["summary"]["total_threats"] > 0:
        suspicious_text = get_entries_for_ai(entries, analysis["threats"])
        ai_result = analyze_with_gemini(suspicious_text, analysis["summary"])
        if ai_result:
            ai_result["engine_source"] = "gemini_llm"
            llm_used = True

    if not llm_used:
        # Data Privacy Mode: 100% local Python pattern finding & solution reasoning
        ai_result = build_local_reasoning(analysis)
    
    # Store for export
    _last_analysis = analysis
    _last_ai_result = ai_result or {}
    _last_entries = entries
    
    # --- Build response ---
    response = {
        "success": True,
        "filename": filename,
        "total_entries": analysis["total_entries"],
        "scan_time": analysis["scan_time"],
        "summary": analysis["summary"],
        "threats": analysis["threats"][:200],  # Cap for JSON response
        "timeline": analysis["timeline"][:200],
        "ai_result": ai_result,
        "mode": "ai_enhanced" if llm_used else "privacy_offline",
        "privacy_mode": not llm_used,
    }
    
    return jsonify(response)


@app.route("/api/export/csv")
def api_export_csv():
    """Download the last analysis as a CSV file."""
    global _last_analysis
    if not _last_analysis:
        return jsonify({"error": "No analysis available. Upload and analyze a log first."}), 400
    
    csv_content = export_csv(_last_analysis)
    
    buf = io.BytesIO(csv_content.encode("utf-8-sig"))
    buf.seek(0)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        buf,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"threatlens_report_{timestamp}.csv"
    )


@app.route("/api/export/pdf")
def api_export_pdf():
    """Download the last analysis as a PDF report."""
    global _last_analysis, _last_ai_result
    if not _last_analysis:
        return jsonify({"error": "No analysis available. Upload and analyze a log first."}), 400
    
    try:
        pdf_bytes = export_pdf(_last_analysis, _last_ai_result)
    except ImportError as e:
        return jsonify({"error": str(e)}), 500
    
    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"threatlens_report_{timestamp}.pdf"
    )


@app.route("/api/threat/<int:index>")
def api_threat_detail(index):
    """Get detailed info for a specific threat by its index in the timeline."""
    global _last_analysis
    if not _last_analysis:
        return jsonify({"error": "No analysis available."}), 400
    
    timeline = _last_analysis.get("timeline", [])
    if index < 0 or index >= len(timeline):
        return jsonify({"error": f"Threat index {index} out of range (0-{len(timeline)-1})."}), 404
    
    return jsonify({"success": True, "threat": timeline[index]})


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  ThreatLens — Endpoint Behavioral Analysis Engine")
    print("  SFIC 2026 | CHARUSAT, Anand, Gujarat")
    print("=" * 60)
    
    if is_online():
        from gemini_engine import get_api_key
        if get_api_key():
            print("  Mode: 🟢 AI-Enhanced (Gemini API connected)")
        else:
            print("  Mode: 🟡 Online but no API key set")
            print("  Set: set GEMINI_API_KEY=your_key")
    else:
        print("  Mode: 🔴 Offline (Rule engine only)")
    
    print(f"  Server: http://localhost:5000")
    print("=" * 60 + "\n")
    
    app.run(host="0.0.0.0", port=5000, debug=True)

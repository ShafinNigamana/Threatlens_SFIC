"""ThreatLens Flask backend — offline-first ProcMon log analyzer with optional Gemini AI."""

import os
from pathlib import Path
from flask import Flask, jsonify, render_template, request, send_file
import io

from engine import analyze_events, parse_procmon_csv
from exporter import generate_csv_report, generate_pdf_report
from gemini_engine import get_ai_context, is_online

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB max CSV upload

BASE_DIR = Path(__file__).resolve().parent
PROCMON_SAMPLES_DIR = (
    BASE_DIR.parent / "Repo_sfic_project" / "Test-Results-Repeat" / "Procmon_system_logs"
)

SAMPLE_FILES = {
    "dryrun1": PROCMON_SAMPLES_DIR / "Logfile_1_success_dryrun.CSV",
    "dryrun2": PROCMON_SAMPLES_DIR / "Logfile_2_success_dryrun.CSV",
}

# In-memory store for single-PC local session (per build plan)
LAST_SESSION = {
    "filename": "capture.csv",
    "analysis": None,
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    online = is_online()
    has_key = bool(os.getenv("GEMINI_API_KEY", "").strip())
    return jsonify(
        {
            "online": online and has_key,
            "internet": online,
            "api_key_configured": has_key,
            "samples_available": {k: p.exists() for k, p in SAMPLE_FILES.items()},
        }
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    file_bytes = None
    filename = "capture.csv"

    if "file" in request.files and request.files["file"].filename:
        uploaded = request.files["file"]
        filename = uploaded.filename
        file_bytes = uploaded.read()
    elif request.is_json:
        sample_key = (request.get_json(silent=True) or {}).get("sample")
        sample_path = SAMPLE_FILES.get(sample_key)
        if sample_path and sample_path.exists():
            filename = sample_path.name
            file_bytes = sample_path.read_bytes()

    if not file_bytes:
        return jsonify({"error": "No ProcMon CSV file provided."}), 400

    events = parse_procmon_csv(file_bytes)
    if not events:
        return (
            jsonify(
                {
                    "error": (
                        "Could not parse any ProcMon events. Ensure the file is a valid "
                        "ProcMon CSV export with Time of Day, Process Name, and Operation columns."
                    )
                }
            ),
            400,
        )

    analysis = analyze_events(events)
    ai_result = get_ai_context(analysis)
    analysis["ai"] = ai_result
    analysis["filename"] = filename

    LAST_SESSION["filename"] = filename
    LAST_SESSION["analysis"] = analysis
    return jsonify(analysis)


@app.route("/export/pdf")
def export_pdf():
    analysis = LAST_SESSION.get("analysis")
    if not analysis:
        return jsonify({"error": "No analysis available to export."}), 400
    pdf_bytes = generate_pdf_report(analysis, LAST_SESSION.get("filename", "capture.csv"))
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="ThreatLens_Report.pdf",
    )


@app.route("/export/csv")
def export_csv():
    analysis = LAST_SESSION.get("analysis")
    if not analysis:
        return jsonify({"error": "No analysis available to export."}), 400
    csv_bytes = generate_csv_report(analysis)
    return send_file(
        io.BytesIO(csv_bytes),
        mimetype="text/csv",
        as_attachment=True,
        download_name="ThreatLens_Threats.csv",
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

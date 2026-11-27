# 🛡️ ThreatLens

**Endpoint Behavioral Analysis & Runtime Threat Detection Engine**

Smart offline-first ProcMon log analyzer with AI-enhanced threat detection. Upload your ProcMon CSV exports → get Ring 0 (Kernel) and Ring 3 (User-Mode) threat analysis with severity scoring, timeline reconstruction, and AI-powered contextual explanations.

Built for **SFIC 2026 — Seva First Innovation Challenge** | CHARUSAT, Anand, Gujarat

---

## 🚀 Quick Start (2 Minutes)

### Prerequisites
- **Python 3.10+** installed (`python --version`)
- **pip** package manager

### Setup & Run
```bash
cd threatlens
pip install -r requirements.txt

# Optional: Set Gemini API key for AI-enhanced mode
# Windows CMD:
set GEMINI_API_KEY=your_api_key_here
# Windows PowerShell:
$env:GEMINI_API_KEY="your_api_key_here"
# Linux/Mac:
export GEMINI_API_KEY=your_api_key_here

# Run the app
python app.py
```

Then open: **http://localhost:5000**

### Usage
1. Open [ProcMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
2. Capture activity (30-60 seconds)
3. File → Save → CSV format
4. Upload the CSV to ThreatLens
5. View threat analysis → Export PDF/CSV

---

## 📁 Project Structure

```
threatlens/
├── app.py                 # Flask backend — routes & API endpoints
├── engine.py              # Core detection engine — CSV parser + rule matching
├── gemini_engine.py       # Gemini AI integration — online enhanced analysis
├── exporter.py            # PDF + CSV report generation
├── threat_db.py           # Offline threat pattern database (Ring 0 + Ring 3)
├── requirements.txt       # Python dependencies
├── README.md              # This file
└── templates/
    └── index.html         # Single-page frontend (HTML + Tailwind + JS)
```

---

## 🔄 Modes

| Mode | Badge | When | Capability |
|------|-------|------|------------|
| **AI-Enhanced** | 🟢 | Internet + API key | Rule engine + Gemini AI contextual analysis |
| **Online (No Key)** | 🟡 | Internet, no API key | Rule engine only |
| **Offline** | 🔴 | No internet | Rule engine only (fully functional) |

---

## 🛡️ What It Detects

### Ring 0 (Kernel) Threats
- Rootkit driver installation & loading
- Direct physical memory access
- Boot-level persistence (bootkits)
- Suspicious driver IOCTL communication
- EFI/boot partition modification

### Ring 3 (User-Mode) Threats
- Process injection (WriteProcessMemory, CreateRemoteThread)
- DLL injection & shellcode staging
- LSASS credential dumping
- Registry autorun persistence
- Security product tampering
- Known malware process detection (Mimikatz, PsExec, Cobalt Strike, etc.)
- Keylogger hook installation
- LOLBin abuse (certutil, mshta, regsvr32, etc.)

---

## 📊 Exports

- **PDF Report** — Full threat analysis with severity summary, AI insights, and timeline
- **CSV Export** — Filtered threat data for further analysis

---

## 🏗️ Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Backend | Python + Flask | Minimal boilerplate, built-in CSV parsing |
| Frontend | Vanilla HTML/JS + Tailwind CSS (CDN) | Zero build step, instant styling |
| AI Engine | Google Gemini API | Natural language threat explanations |
| Offline Engine | Python rule-based heuristics | 50+ threat patterns, zero dependencies |
| PDF Export | fpdf2 | Lightweight, 10-line PDF generation |

---

## 👥 Team

| Role | Contribution |
|------|-------------|
| **Team Lead** | Architecture, detection engine, Gemini integration |
| **Frontend** | UI/UX, dashboard, export functionality |
| **Backend** | Flask API, CSV parsing, PDF generation |

---

*SFIC 2026 | PS Code: PS0001 | CHARUSAT, Anand, Gujarat*

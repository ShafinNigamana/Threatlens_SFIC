"""Connectivity check and optional Gemini AI contextual threat analysis."""

import os
import socket
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")


def is_online(timeout: float = 1.5) -> bool:
    """Quick TCP check to see if internet is reachable for Gemini API."""
    try:
        with socket.create_connection(("8.8.8.8", 53), timeout=timeout):
            return True
    except OSError:
        return False


def get_ai_context(analysis: dict) -> dict:
    """
    Enhance offline rule-engine findings with Gemini AI attack-chain narrative.
    Always returns gracefully; never breaks offline execution.
    """
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return {
            "mode": "offline",
            "reason": "GEMINI_API_KEY not configured",
            "narrative": None,
        }

    if not is_online():
        return {
            "mode": "offline",
            "reason": "No internet connection detected",
            "narrative": None,
        }

    threats = analysis.get("threats", [])
    if not threats:
        return {
            "mode": "online",
            "reason": "Connected",
            "narrative": "No suspicious Ring 0 or Ring 3 indicators were flagged in this ProcMon capture.",
        }

    # Summarize top 25 threats to keep prompt fast and within token limits
    sample_lines = []
    for t in threats[:25]:
        sample_lines.append(
            f"[{t['timestamp']}] {t['severity']} | {t['ring']} | {t['process']} (PID {t['pid']}) "
            f"| {t['operation']} | Path: {t['path']} | Result: {t['result']} | {t['threat_type']}"
        )

    prompt = (
        "You are a senior cybersecurity threat analyst. Analyze these flagged ProcMon log entries "
        "from an endpoint forensic capture and provide a concise, structured executive assessment:\n"
        "1. Attack Chain Summary (2-3 sentences explaining what happened chronologically)\n"
        "2. Key Risk & Ring 0 / Ring 3 Impact\n"
        "3. Recommended Immediate Containment Steps (2-3 bullet points)\n\n"
        f"Total Events Scanned: {analysis.get('total_events', 0)}\n"
        f"Severity Breakdown: {analysis.get('summary', {})}\n"
        "Flagged Entries:\n" + "\n".join(sample_lines)
    )

    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        text = (response.text or "").strip()
        if text:
            return {"mode": "online", "reason": "Gemini AI-Enhanced", "narrative": text}
    except Exception as exc:
        return {
            "mode": "offline",
            "reason": f"Gemini fallback ({type(exc).__name__})",
            "narrative": None,
        }

    return {"mode": "offline", "reason": "Empty AI response", "narrative": None}

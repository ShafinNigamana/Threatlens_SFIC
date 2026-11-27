"""
ThreatLens — Gemini AI Engine (Online Enhancement)
====================================================
When internet is available and a Gemini API key is set,
this module sends suspicious log entries to Gemini for
deeper contextual analysis and natural-language explanations.

Falls back gracefully to offline-only mode if unavailable.
"""

import os
import socket
import json


def is_online() -> bool:
    """Quick internet connectivity check (DNS to Google, 2s timeout)."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False


def get_api_key() -> str | None:
    """Get Gemini API key from environment variable or config."""
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")


def analyze_with_gemini(suspicious_logs: str, summary: dict) -> dict | None:
    """
    Send suspicious log entries to Gemini API for AI-powered analysis.
    
    Args:
        suspicious_logs: Formatted string of suspicious ProcMon log entries
        summary: Detection engine summary (threat counts, top processes)
    
    Returns:
        dict with 'ai_analysis' (str), 'attack_chain' (str), 'recommendations' (list)
        or None if offline / API unavailable
    """
    api_key = get_api_key()
    if not api_key:
        return None
    
    if not is_online():
        return None
    
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        
        model = genai.GenerativeModel("gemini-2.0-flash")
        
        prompt = f"""You are ThreatLens, a cybersecurity threat analyst AI. Analyze these ProcMon (Process Monitor) log entries that have been flagged as suspicious by our rule-based detection engine.

DETECTION SUMMARY:
- Critical threats found: {summary.get('critical', 0)}
- High threats found: {summary.get('high', 0)}  
- Medium threats found: {summary.get('medium', 0)}
- Low threats found: {summary.get('low', 0)}
- Top suspicious processes: {summary.get('top_processes', [])}

FLAGGED LOG ENTRIES:
{suspicious_logs}

Provide your analysis in this EXACT JSON format (no markdown, no code blocks, just raw JSON):
{{
    "ai_analysis": "2-3 paragraph overall threat assessment in plain English. Explain what the attacker appears to be doing, the attack methodology observed, and the potential impact. Write as if explaining to a college IT administrator who understands basic security but isn't a specialist.",
    "attack_chain": "Describe the sequence of events as a step-by-step attack chain (like a story). Number each step. Explain the logical progression from initial action to final impact.",
    "recommendations": [
        "First actionable recommendation for the user",
        "Second actionable recommendation",
        "Third actionable recommendation"
    ],
    "risk_score": 85,
    "risk_label": "High Risk"
}}

RULES:
- risk_score is 0-100 (0=safe, 100=actively compromised)
- Be factual based on the logs — don't invent threats not visible in the data
- If the logs show our project's own demo (hack.exe, app.exe, watchdog.exe), acknowledge it as a controlled security demonstration
- Keep language accessible and educational
"""
        
        response = model.generate_content(prompt)
        text = response.text.strip()
        
        # Strip markdown code fences if Gemini wraps in ```json ... ```
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
        
        result = json.loads(text)
        return result
    
    except ImportError:
        print("[ThreatLens] google-generativeai not installed — running offline only")
        return None
    except json.JSONDecodeError as e:
        print(f"[ThreatLens] Gemini returned non-JSON response: {e}")
        # Return raw text as fallback
        try:
            return {
                "ai_analysis": response.text[:1500],
                "attack_chain": "Could not parse structured attack chain from AI response.",
                "recommendations": ["Review the AI analysis text above for guidance."],
                "risk_score": summary.get("critical", 0) * 25 + summary.get("high", 0) * 15,
                "risk_label": "Analysis Available"
            }
        except Exception:
            return None
    except Exception as e:
        print(f"[ThreatLens] Gemini API error: {e}")
        return None

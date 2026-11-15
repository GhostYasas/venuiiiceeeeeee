# modules/ai_summary.py

import requests
import json

def generate_threat_summary(scan_data, api_key):
    """Generate AI threat summary using Groq (free)"""
    try:
        # Build simple context
        context = f"""
Domain: {scan_data.get('domain', 'N/A')}
Registrar: {scan_data.get('registrar', 'N/A')}
Country: {scan_data.get('country', 'N/A')}
IP Address: {scan_data.get('ip', 'N/A')}
ISP: {scan_data.get('isp', 'N/A')}
VirusTotal Score: {scan_data.get('vt_score', 'N/A')}
AbuseIPDB Score: {scan_data.get('abuse_score', 'N/A')}/100
Open Ports: {scan_data.get('open_ports', [])}
Vulnerabilities: {scan_data.get('vulns', [])}
Admin Panels Found: {scan_data.get('panels_found', 0)}
Email Breaches: {scan_data.get('email_breaches', 'None')}
"""

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        payload = {
           "model": "llama-3.1-8b-instant",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst. Give brief, professional threat assessments."
                },
                {
                    "role": "user",
                    "content": f"Analyze this OSINT scan data and give a threat assessment with: 1) Overall Risk Level 2) Key Findings 3) Recommendations\n\n{context}"
                }
            ],
            "max_tokens": 500,
            "temperature": 0.3
        }

        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()
            summary = data["choices"][0]["message"]["content"]
            return {
                "success": True,
                "summary": summary
            }
        else:
            # Show detailed error for debugging
            try:
                error_detail = response.json()
                return {"success": False, "error": f"Groq error {response.status_code}: {error_detail}"}
            except:
                return {"success": False, "error": f"Groq API error: {response.status_code}"}

    except Exception as e:
        return {"success": False, "error": str(e)}
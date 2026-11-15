# modules/virustotal.py

import requests
import time

def check_domain_virustotal(domain, api_key):
    """Check domain reputation on VirusTotal"""
    try:
        headers = {"x-apikey": api_key}
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            harmless    = stats.get("harmless", 0)
            undetected  = stats.get("undetected", 0)
            total       = malicious + suspicious + harmless + undetected

            # Determine risk level
            if malicious >= 5:
                risk = "CRITICAL"
            elif malicious >= 1:
                risk = "HIGH"
            elif suspicious >= 1:
                risk = "MEDIUM"
            else:
                risk = "CLEAN"

            # Get categories if available
            categories = data["data"]["attributes"].get("categories", {})
            category_list = list(categories.values())[:3]

            return {
                "domain": domain,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total,
                "risk": risk,
                "categories": category_list
            }

        elif response.status_code == 401:
            return {"error": "Invalid API key"}
        elif response.status_code == 429:
            return {"error": "API rate limit reached (4 requests/minute on free tier)"}
        else:
            return {"error": f"API returned status {response.status_code}"}

    except Exception as e:
        return {"error": str(e)}


def check_ip_virustotal(ip, api_key):
    """Check IP reputation on VirusTotal"""
    try:
        headers = {"x-apikey": api_key}
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total      = malicious + suspicious + harmless + undetected

            if malicious >= 5:
                risk = "CRITICAL"
            elif malicious >= 1:
                risk = "HIGH"
            elif suspicious >= 1:
                risk = "MEDIUM"
            else:
                risk = "CLEAN"

            return {
                "ip": ip,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total,
                "risk": risk
            }

        elif response.status_code == 401:
            return {"error": "Invalid API key"}
        elif response.status_code == 429:
            return {"error": "API rate limit reached"}
        else:
            return {"error": f"API returned status {response.status_code}"}

    except Exception as e:
        return {"error": str(e)}
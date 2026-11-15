# modules/abuseipdb.py

import requests

def check_ip_abuse(ip, api_key):
    """Check IP reputation on AbuseIPDB with full details"""
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }

        response = requests.get(url, headers=headers, params=params, timeout=15)

        if response.status_code == 200:
            data = response.json()["data"]

            score          = data.get("abuseConfidenceScore", 0)
            total_reports  = data.get("totalReports", 0)
            last_reported  = data.get("lastReportedAt", "Never")
            country        = data.get("countryCode", "N/A")
            isp            = data.get("isp", "N/A")
            domain         = data.get("domain", "N/A")
            is_tor         = data.get("isTor", False)
            usage_type     = data.get("usageType", "N/A")
            num_distinct   = data.get("numDistinctUsers", 0)

            # Network block info
            # Build network from IP
            ip_parts = ip.split(".")
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24" if len(ip_parts) == 4 else "N/A"

            # Determine risk level
            if score >= 80:
                risk = "CRITICAL"
            elif score >= 50:
                risk = "HIGH"
            elif score >= 20:
                risk = "MEDIUM"
            elif score > 0:
                risk = "LOW"
            else:
                risk = "CLEAN"

            # Attack categories map
            categories_map = {
                1:  "DNS Compromise",
                2:  "DNS Poisoning",
                3:  "Fraud Orders",
                4:  "DDoS Attack",
                5:  "FTP Brute-Force",
                6:  "Ping of Death",
                7:  "Phishing",
                8:  "Fraud VoIP",
                9:  "Open Proxy",
                10: "Web Spam",
                11: "Email Spam",
                12: "Blog Spam",
                13: "VPN IP",
                14: "Port Scan",
                15: "Hacking",
                16: "SQL Injection",
                17: "Spoofing",
                18: "Brute Force",
                19: "Bad Web Bot",
                20: "Exploited Host",
                21: "Web App Attack",
                22: "SSH Abuse",
                23: "IoT Targeted"
            }

            # Get recent reports
            reports = data.get("reports", [])
            attack_types = set()
            recent_reports = []

            for report in reports[:5]:
                for cat in report.get("categories", []):
                    if cat in categories_map:
                        attack_types.add(categories_map[cat])
                recent_reports.append({
                    "date": str(report.get("reportedAt", ""))[:10],
                    "categories": [categories_map.get(c, "Unknown") for c in report.get("categories", [])],
                    "country": report.get("reporterCountryCode", "N/A")
                })

            # Timeline counts
            reports_7d  = sum(1 for r in reports if r.get("reportedAt", "")[:10] >= "2026-04-20")
            reports_30d = sum(1 for r in reports if r.get("reportedAt", "")[:10] >= "2026-03-27")
            reports_90d = len(reports)

            return {
                "ip": ip,
                "score": score,
                "risk": risk,
                "total_reports": total_reports,
                "num_distinct_users": num_distinct,
                "last_reported": str(last_reported)[:10] if last_reported else "Never",
                "country": country,
                "isp": isp,
                "domain": domain,
                "network": network,
                "usage_type": usage_type,
                "is_tor": is_tor,
                "attack_types": list(attack_types)[:5],
                "recent_reports": recent_reports,
                "reports_7d": reports_7d,
                "reports_30d": reports_30d,
                "reports_90d": reports_90d
            }

        elif response.status_code == 401:
            return {"error": "Invalid API key"}
        elif response.status_code == 429:
            return {"error": "Rate limit reached (1000/day on free tier)"}
        else:
            return {"error": f"API returned status {response.status_code}"}

    except Exception as e:
        return {"error": str(e)}


def check_bulk_ips(ip_list, api_key):
    """Check multiple IPs at once"""
    results = {}
    for ip in ip_list:
        try:
            result = check_ip_abuse(ip, api_key)
            results[ip] = result
        except Exception as e:
            results[ip] = {"error": str(e)}
    return results
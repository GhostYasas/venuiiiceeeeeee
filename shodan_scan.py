# modules/shodan_scan.py

import requests

def shodan_host_lookup(ip, api_key):
    """Look up host information on Shodan"""
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        response = requests.get(url, timeout=15)

        if response.status_code == 200:
            data = response.json()

            # Extract open ports
            ports = data.get("ports", [])

            # Extract services/banners
            services = []
            for item in data.get("data", []):
                service = {
                    "port": item.get("port"),
                    "protocol": item.get("transport", "tcp"),
                    "service": item.get("_shodan", {}).get("module", "unknown"),
                    "banner": item.get("data", "")[:100],
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "cpe": item.get("cpe", [])
                }
                services.append(service)

            # Extract vulnerabilities
            vulns = data.get("vulns", {})
            vuln_list = []
            for cve_id, vuln_data in vulns.items():
                vuln_list.append({
                    "cve": cve_id,
                    "cvss": vuln_data.get("cvss", 0),
                    "summary": vuln_data.get("summary", "")[:100]
                })

            # Sort vulns by CVSS score
            vuln_list.sort(key=lambda x: x.get("cvss", 0), reverse=True)

            # Extract tags
            tags = data.get("tags", [])

            return {
                "ip": ip,
                "org": data.get("org", "N/A"),
                "isp": data.get("isp", "N/A"),
                "country": data.get("country_name", "N/A"),
                "city": data.get("city", "N/A"),
                "os": data.get("os", "Unknown"),
                "ports": ports,
                "services": services[:5],
                "vulns": vuln_list[:5],
                "vuln_count": len(vuln_list),
                "tags": tags,
                "last_update": data.get("last_update", "N/A")[:10]
            }

        elif response.status_code == 404:
            return {"error": "No Shodan data for this IP"}
        elif response.status_code == 401:
            return {"error": "Invalid Shodan API key"}
        else:
            return {"error": f"Shodan returned status {response.status_code}"}

    except Exception as e:
        return {"error": str(e)}


def get_exploit_search(query, api_key):
    """Search Shodan exploit database"""
    try:
        url = f"https://exploits.shodan.io/api/search?query={query}&key={api_key}"
        response = requests.get(url, timeout=15)

        if response.status_code == 200:
            data = response.json()
            exploits = []

            for item in data.get("matches", [])[:5]:
                exploits.append({
                    "title": item.get("description", "N/A")[:80],
                    "type": item.get("type", "N/A"),
                    "platform": item.get("platform", "N/A"),
                    "date": str(item.get("date", "N/A"))[:10],
                    "cve": item.get("cve", [])
                })

            return exploits
        else:
            return []

    except Exception:
        return []
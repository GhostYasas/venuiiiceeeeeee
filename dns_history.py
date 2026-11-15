# modules/dns_history.py

import requests

def get_dns_history(domain):
    """Get DNS history using free APIs"""
    results = {
        "domain": domain,
        "history": [],
        "passive_dns": [],
        "first_seen": "N/A",
        "last_seen": "N/A"
    }

    # Method 1: SecurityTrails free API
    try:
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        headers = {"apikey": "free"}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            records = data.get("records", [])

            for record in records[:10]:
                for value in record.get("values", []):
                    results["history"].append({
                        "ip": value.get("ip", "N/A"),
                        "first_seen": record.get("first_seen", "N/A"),
                        "last_seen": record.get("last_seen", "N/A")
                    })
    except Exception:
        pass

    # Method 2: HackerTarget passive DNS (free)
    try:
        url2 = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response2 = requests.get(url2, timeout=10)

        if response2.status_code == 200 and "error" not in response2.text.lower():
            lines = response2.text.strip().split("\n")
            for line in lines[:10]:
                parts = line.split(",")
                if len(parts) >= 2:
                    results["passive_dns"].append({
                        "hostname": parts[0].strip(),
                        "ip": parts[1].strip()
                    })
    except Exception:
        pass

    # Method 3: Get IP history from ViewDNS (free)
    try:
        url3 = f"https://api.viewdns.info/iphistory/?domain={domain}&apikey=free&output=json"
        response3 = requests.get(url3, timeout=10)

        if response3.status_code == 200:
            data3 = response3.json()
            records3 = data3.get("response", {}).get("records", [])

            for record in records3[:10]:
                results["history"].append({
                    "ip": record.get("ip", "N/A"),
                    "location": record.get("location", "N/A"),
                    "owner": record.get("owner", "N/A"),
                    "last_seen": record.get("lastseen", "N/A")
                })

            if results["history"]:
                results["first_seen"] = results["history"][-1].get("last_seen", "N/A")
                results["last_seen"] = results["history"][0].get("last_seen", "N/A")

    except Exception:
        pass

    return results
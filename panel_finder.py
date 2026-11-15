# modules/panel_finder.py

import requests
import concurrent.futures

ADMIN_PATHS = [
    "/admin", "/admin/login", "/admin.php", "/administrator",
    "/wp-admin", "/wp-login.php", "/wp-admin/login",
    "/login", "/login.php", "/signin", "/sign-in",
    "/dashboard", "/dashboard/login", "/control",
    "/controlpanel", "/control-panel", "/cpanel",
    "/phpmyadmin", "/pma", "/myadmin", "/mysql",
    "/manager", "/management", "/manage",
    "/portal", "/user/login", "/account/login",
    "/auth", "/auth/login", "/authentication",
    "/backend", "/back-end", "/backoffice",
    "/webadmin", "/web-admin", "/siteadmin",
    "/moderator", "/mod", "/staff",
    "/secure", "/security", "/protected",
    "/config", "/configuration", "/setup",
    "/install", "/installer", "/installation",
    "/api", "/api/admin", "/api/v1/admin",
    "/.env", "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info",
    "/.git", "/.git/config",
]

def check_path(base_url, path, timeout=5):
    """Check if a path exists on the target"""
    try:
        url = f"{base_url}{path}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)

        if response.status_code == 200:
            risk = "HIGH"
            if path in ["/robots.txt", "/sitemap.xml"]:
                risk = "LOW"
            elif path in ["/.env", "/.git", "/.git/config"]:
                risk = "CRITICAL"
            elif "login" in path or "admin" in path:
                risk = "HIGH"
            else:
                risk = "MEDIUM"

            return {
                "path": path,
                "url": url,
                "status": response.status_code,
                "found": True,
                "risk": risk,
                "size": len(response.content)
            }
        elif response.status_code == 403:
            return {
                "path": path,
                "url": url,
                "status": 403,
                "found": True,
                "risk": "MEDIUM",
                "size": 0,
                "note": "Forbidden - exists but restricted"
            }
        else:
            return {"path": path, "found": False}

    except Exception:
        return {"path": path, "found": False}

def find_admin_panels(domain, use_https=True):
    """Scan for hidden admin panels and sensitive paths"""
    protocol = "https" if use_https else "http"
    base_url = f"{protocol}://{domain}"
    found_panels = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_path = {
            executor.submit(check_path, base_url, path): path
            for path in ADMIN_PATHS
        }

        for future in concurrent.futures.as_completed(future_to_path):
            try:
                result = future.result()
                if result.get("found"):
                    found_panels.append(result)
            except Exception:
                pass

    found_panels.sort(key=lambda x: (
        0 if x.get("risk") == "CRITICAL" else
        1 if x.get("risk") == "HIGH" else
        2 if x.get("risk") == "MEDIUM" else 3
    ))

    return {
        "domain": domain,
        "base_url": base_url,
        "total_scanned": len(ADMIN_PATHS),
        "found_count": len(found_panels),
        "panels": found_panels
    }
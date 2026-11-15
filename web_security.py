# modules/web_security.py

import requests
import urllib3
import socket
import re
import concurrent.futures
from colorama import Fore, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# ═══════════════════════════════
# PHASE 1
# ═══════════════════════════════

def check_cors(domain):
    """Check for CORS misconfiguration"""
    results = {"vulnerable": False, "issues": []}
    try:
        url = f"https://{domain}"
        
        # Test 1: Wildcard origin
        headers = {**HEADERS, "Origin": "https://evil.com"}
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        
        if acao == "*":
            results["vulnerable"] = True
            results["issues"].append({
                "severity": "HIGH",
                "detail": "Wildcard CORS: Any origin can read responses"
            })
        
        if acao == "https://evil.com":
            results["vulnerable"] = True
            severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
            results["issues"].append({
                "severity": severity,
                "detail": f"Reflects arbitrary origin! Credentials: {acac or 'false'}"
            })

        # Test 2: Null origin
        headers2 = {**HEADERS, "Origin": "null"}
        r2 = requests.get(url, headers=headers2, timeout=10, verify=False)
        acao2 = r2.headers.get("Access-Control-Allow-Origin", "")
        if acao2 == "null":
            results["vulnerable"] = True
            results["issues"].append({
                "severity": "HIGH",
                "detail": "Null origin accepted! Sandbox bypass possible"
            })

        if not results["issues"]:
            results["issues"].append({
                "severity": "INFO",
                "detail": "No CORS misconfiguration found"
            })

    except Exception as e:
        results["issues"].append({"severity": "ERROR", "detail": str(e)})
    
    return results


def check_cookies(domain):
    """Analyze cookie security flags"""
    results = {"cookies": [], "issues": []}
    try:
        url = f"https://{domain}"
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        
        for cookie in r.cookies:
            cookie_info = {
                "name":     cookie.name,
                "httponly": cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly") is not None,
                "secure":   cookie.secure,
                "samesite": cookie._rest.get("SameSite", "Not Set"),
                "issues":   []
            }

            if not cookie_info["httponly"]:
                cookie_info["issues"].append("❌ HttpOnly MISSING → XSS can steal this cookie!")
                results["issues"].append({
                    "severity": "HIGH",
                    "detail": f"{cookie.name}: Missing HttpOnly flag"
                })

            if not cookie_info["secure"]:
                cookie_info["issues"].append("❌ Secure MISSING → Sent over HTTP!")
                results["issues"].append({
                    "severity": "MEDIUM",
                    "detail": f"{cookie.name}: Missing Secure flag"
                })

            if cookie_info["samesite"] == "Not Set":
                cookie_info["issues"].append("❌ SameSite MISSING → CSRF possible!")
                results["issues"].append({
                    "severity": "MEDIUM",
                    "detail": f"{cookie.name}: Missing SameSite flag"
                })

            results["cookies"].append(cookie_info)

        if not results["cookies"]:
            results["issues"].append({
                "severity": "INFO",
                "detail": "No cookies found"
            })

    except Exception as e:
        results["issues"].append({"severity": "ERROR", "detail": str(e)})

    return results


def check_clickjacking(domain):
    """Test for clickjacking vulnerability"""
    results = {"vulnerable": False, "details": []}
    try:
        url = f"https://{domain}"
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)

        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")

        has_xfo = bool(xfo)
        has_csp_frame = "frame-ancestors" in csp.lower()

        if not has_xfo and not has_csp_frame:
            results["vulnerable"] = True
            results["details"].append({
                "severity": "HIGH",
                "detail": "No clickjacking protection! Site can be embedded in iframe"
            })
        elif has_xfo:
            results["details"].append({
                "severity": "INFO",
                "detail": f"X-Frame-Options: {xfo} ✅"
            })
        elif has_csp_frame:
            results["details"].append({
                "severity": "INFO",
                "detail": "CSP frame-ancestors present ✅"
            })

    except Exception as e:
        results["details"].append({"severity": "ERROR", "detail": str(e)})

    return results


def check_http_methods(domain):
    """Check allowed HTTP methods"""
    results = {"methods": {}, "issues": []}
    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

    try:
        url = f"https://{domain}"

        # OPTIONS request reveals allowed methods
        r = requests.options(url, headers=HEADERS, timeout=10, verify=False)
        allow_header = r.headers.get("Allow", "") or r.headers.get("Access-Control-Allow-Methods", "")

        methods_to_check = ["GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "PATCH", "HEAD"]

        for method in methods_to_check:
            try:
                resp = requests.request(method, url, headers=HEADERS, timeout=5, verify=False)
                allowed = resp.status_code not in [405, 501]
                results["methods"][method] = {
                    "allowed": allowed,
                    "status": resp.status_code,
                    "dangerous": method in dangerous_methods
                }
                if allowed and method in dangerous_methods:
                    results["issues"].append({
                        "severity": "HIGH" if method in ["PUT", "DELETE", "TRACE"] else "MEDIUM",
                        "detail": f"{method} method allowed! {_method_risk(method)}"
                    })
            except Exception:
                results["methods"][method] = {"allowed": False, "status": 0, "dangerous": False}

    except Exception as e:
        results["issues"].append({"severity": "ERROR", "detail": str(e)})

    return results


def _method_risk(method):
    risks = {
        "PUT":     "Can upload/overwrite files!",
        "DELETE":  "Can delete files!",
        "TRACE":   "XST attack possible!",
        "CONNECT": "Proxy abuse possible!",
        "PATCH":   "Can modify resources!"
    }
    return risks.get(method, "Potentially dangerous")


# ═══════════════════════════════
# PHASE 2
# ═══════════════════════════════

TAKEOVER_SIGNATURES = {
    "AWS S3":           ["NoSuchBucket", "The specified bucket does not exist"],
    "GitHub Pages":     ["There isn't a GitHub Pages site here"],
    "Heroku":           ["No such app", "herokucdn.com/error-pages"],
    "Netlify":          ["Not Found - Request ID"],
    "Shopify":          ["Sorry, this shop is currently unavailable"],
    "Fastly":           ["Fastly error: unknown domain"],
    "Ghost":            ["The thing you were looking for is no longer here"],
    "Tumblr":           ["Whatever you were looking for doesn't live here"],
    "WordPress":        ["Do you want to register"],
    "Surge.sh":         ["project not found"],
    "Azure":            ["404 Web Site not found"],
    "Zendesk":          ["Help Center Closed"],
}

def check_subdomain_takeover(subdomains):
    """Check subdomains for takeover vulnerability"""
    results = {"vulnerable": [], "checked": 0}

    def check_single(subdomain):
        try:
            r = requests.get(
                f"https://{subdomain}",
                headers=HEADERS,
                timeout=5,
                verify=False,
                allow_redirects=True
            )
            for service, signatures in TAKEOVER_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in r.text.lower():
                        return {
                            "subdomain": subdomain,
                            "service": service,
                            "vulnerable": True
                        }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_single, sub): sub for sub in subdomains[:50]}
        for future in concurrent.futures.as_completed(futures):
            results["checked"] += 1
            result = future.result()
            if result:
                results["vulnerable"].append(result)

    return results


SENSITIVE_FILES = [
    {"path": "/.env",                "severity": "CRITICAL", "detail": "Environment file with passwords!"},
    {"path": "/.env.backup",         "severity": "CRITICAL", "detail": "Environment backup!"},
    {"path": "/.env.local",          "severity": "CRITICAL", "detail": "Local environment file!"},
    {"path": "/backup.zip",          "severity": "CRITICAL", "detail": "Full site backup!"},
    {"path": "/backup.tar.gz",       "severity": "CRITICAL", "detail": "Full site backup!"},
    {"path": "/db.sql",              "severity": "CRITICAL", "detail": "Database dump!"},
    {"path": "/database.sql",        "severity": "CRITICAL", "detail": "Database dump!"},
    {"path": "/.git/config",         "severity": "CRITICAL", "detail": "Git config exposed!"},
    {"path": "/.git/HEAD",           "severity": "CRITICAL", "detail": "Git HEAD exposed!"},
    {"path": "/config.php.bak",      "severity": "HIGH",     "detail": "PHP config backup!"},
    {"path": "/wp-config.php.bak",   "severity": "HIGH",     "detail": "WordPress config backup!"},
    {"path": "/.DS_Store",           "severity": "MEDIUM",   "detail": "Mac file structure exposed!"},
    {"path": "/robots.txt",          "severity": "LOW",      "detail": "Robots.txt found"},
    {"path": "/sitemap.xml",         "severity": "LOW",      "detail": "Sitemap found"},
    {"path": "/crossdomain.xml",     "severity": "MEDIUM",   "detail": "Flash crossdomain policy!"},
    {"path": "/phpinfo.php",         "severity": "CRITICAL", "detail": "PHP info page exposed!"},
    {"path": "/info.php",            "severity": "CRITICAL", "detail": "PHP info page exposed!"},
    {"path": "/test.php",            "severity": "HIGH",     "detail": "Test PHP file exposed!"},
    {"path": "/adminer.php",         "severity": "CRITICAL", "detail": "Adminer DB tool exposed!"},
    {"path": "/error.log",           "severity": "HIGH",     "detail": "Error log exposed!"},
    {"path": "/access.log",          "severity": "HIGH",     "detail": "Access log exposed!"},
    {"path": "/debug.log",           "severity": "HIGH",     "detail": "Debug log exposed!"},
    {"path": "/.htpasswd",           "severity": "CRITICAL", "detail": "Password file exposed!"},
    {"path": "/.htaccess",           "severity": "MEDIUM",   "detail": "Apache config exposed!"},
    {"path": "/package.json",        "severity": "MEDIUM",   "detail": "Node.js config exposed!"},
    {"path": "/composer.json",       "severity": "LOW",      "detail": "PHP composer config!"},
    {"path": "/Dockerfile",          "severity": "MEDIUM",   "detail": "Docker config exposed!"},
    {"path": "/docker-compose.yml",  "severity": "HIGH",     "detail": "Docker compose exposed!"},
    {"path": "/id_rsa",              "severity": "CRITICAL", "detail": "Private SSH key exposed!"},
    {"path": "/private.key",         "severity": "CRITICAL", "detail": "Private key exposed!"},
]

def find_sensitive_files(domain):
    """Search for sensitive exposed files"""
    results = {"found": [], "checked": 0}

    def check_file(file_info):
        try:
            url = f"https://{domain}{file_info['path']}"
            r = requests.get(
                url,
                headers=HEADERS,
                timeout=5,
                verify=False,
                allow_redirects=False
            )
            if r.status_code == 200:
                return {
                    "path":     file_info["path"],
                    "url":      url,
                    "severity": file_info["severity"],
                    "detail":   file_info["detail"],
                    "size":     len(r.content)
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_file, f): f for f in SENSITIVE_FILES}
        for future in concurrent.futures.as_completed(futures):
            results["checked"] += 1
            result = future.result()
            if result:
                results["found"].append(result)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results["found"].sort(key=lambda x: severity_order.get(x["severity"], 4))
    return results


def find_real_ip(domain):
    """Try to find real IP behind CDN"""
    results = {"cdn_detected": False, "cdn_name": None, "potential_ips": [], "methods": []}

    cdn_headers = {
        "cloudflare": ["cf-ray", "cf-cache-status"],
        "akamai":     ["x-akamai-transformed", "akamai-origin-hop"],
        "fastly":     ["x-fastly-request-id", "fastly-restarts"],
        "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
        "incapsula":  ["x-iinfo", "x-cdn"],
    }

    try:
        r = requests.get(f"https://{domain}", headers=HEADERS, timeout=10, verify=False)
        resp_headers_lower = {k.lower(): v for k, v in r.headers.items()}

        for cdn, indicators in cdn_headers.items():
            for indicator in indicators:
                if indicator in resp_headers_lower:
                    results["cdn_detected"] = True
                    results["cdn_name"] = cdn.title()
                    break

    except Exception:
        pass

    # Method 1: DNS History
    try:
        import subprocess
        result = subprocess.run(
            ["nslookup", domain],
            capture_output=True, text=True, timeout=10
        )
        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', result.stdout)
        for ip in ips:
            if ip not in results["potential_ips"] and not ip.startswith("127."):
                results["potential_ips"].append(ip)
        if ips:
            results["methods"].append(f"DNS lookup: {', '.join(ips[:3])}")
    except Exception:
        pass

    # Method 2: MX Record IP
    try:
        import dns.resolver
        mx_records = dns.resolver.resolve(domain, "MX")
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip(".")
            mx_ip = socket.gethostbyname(mx_host)
            if mx_ip not in results["potential_ips"]:
                results["potential_ips"].append(mx_ip)
                results["methods"].append(f"MX record: {mx_host} → {mx_ip}")
    except Exception:
        pass

    # Method 3: Check SecurityTrails history
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200 and "error" not in r.text.lower():
            ips = re.findall(r'\d+\.\d+\.\d+\.\d+', r.text)
            for ip in ips[:5]:
                if ip not in results["potential_ips"]:
                    results["potential_ips"].append(ip)
            if ips:
                results["methods"].append(f"HackerTarget history: {len(ips)} IPs found")
    except Exception:
        pass

    return results


def check_api_security(domain):
    """Test common API security issues"""
    results = {"endpoints": [], "issues": []}

    api_paths = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/api/users", "/api/user", "/api/admin",
        "/api/v1/users", "/api/v1/user/1", "/api/v1/admin",
        "/v1", "/v2", "/graphql", "/swagger.json",
        "/api-docs", "/openapi.json", "/api/swagger",
    ]

    def check_endpoint(path):
        try:
            url = f"https://{domain}{path}"
            r = requests.get(url, headers=HEADERS, timeout=5, verify=False)
            if r.status_code in [200, 201, 301, 302]:
                content_type = r.headers.get("Content-Type", "")
                is_api = "json" in content_type or "xml" in content_type
                return {
                    "path":         path,
                    "url":          url,
                    "status":       r.status_code,
                    "is_api":       is_api,
                    "content_type": content_type[:50]
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_endpoint, p): p for p in api_paths}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results["endpoints"].append(result)
                if result["is_api"]:
                    results["issues"].append({
                        "severity": "MEDIUM",
                        "detail": f"API endpoint exposed: {result['path']}"
                    })

    # Check IDOR on user endpoints
    try:
        for i in [1, 2, 3]:
            url = f"https://{domain}/api/v1/users/{i}"
            r = requests.get(url, headers=HEADERS, timeout=5, verify=False)
            if r.status_code == 200 and len(r.text) > 10:
                results["issues"].append({
                    "severity": "HIGH",
                    "detail": f"Possible IDOR: /api/v1/users/{i} returned data without auth!"
                })
                break
    except Exception:
        pass

    return results


# ═══════════════════════════════
# PHASE 3
# ═══════════════════════════════

def calculate_cvss(findings):
    """Calculate overall CVSS-like risk score"""
    score = 0
    breakdown = {
        "domain_security":  0,
        "network_security": 0,
        "web_security":     0,
        "threat_intel":     0
    }

    severity_scores = {
        "CRITICAL": 10,
        "HIGH":      7,
        "MEDIUM":    4,
        "LOW":       1
    }

    category_map = {
        "vulnerability":    "threat_intel",
        "domain_security":  "domain_security",
        "network_security": "network_security",
        "web_security":     "web_security",
        "threat_intel":     "threat_intel",
    }

    for finding in findings:
        severity = finding.get("severity", "LOW")
        points   = severity_scores.get(severity, 0)
        raw_cat  = finding.get("category", "web_security")
        category = category_map.get(raw_cat, "web_security")
        breakdown[category] += points * 10
        score += points

    # Normalize to 100
    max_score   = len(findings) * 10 if findings else 1
    final_score = min(100, int((score / max_score) * 100)) if findings else 0

    for key in breakdown:
        breakdown[key] = min(100, breakdown[key])

    if final_score >= 80:
        level = "CRITICAL"
    elif final_score >= 60:
        level = "HIGH"
    elif final_score >= 40:
        level = "MEDIUM"
    elif final_score > 0:
        level = "LOW"
    else:
        level = "CLEAN"

    return {
        "score":     final_score,
        "level":     level,
        "breakdown": breakdown
    }


MITRE_MAPPING = {
    "CORS":               {"id": "T1557", "name": "Adversary-in-the-Middle",    "tactic": "Collection"},
    "Cookie":             {"id": "T1539", "name": "Steal Web Session Cookie",   "tactic": "Credential Access"},
    "Clickjacking":       {"id": "T1185", "name": "Browser Session Hijacking",  "tactic": "Collection"},
    "SQL Injection":      {"id": "T1190", "name": "Exploit Public Application", "tactic": "Initial Access"},
    "XSS":                {"id": "T1059", "name": "Command & Scripting",        "tactic": "Execution"},
    "Sensitive Files":    {"id": "T1083",  "name": "File & Directory Discovery", "tactic": "Discovery"},
    "Subdomain Takeover": {"id": "T1584",  "name": "Compromise Infrastructure", "tactic": "Resource Development"},
    "Open Ports":         {"id": "T1046",  "name": "Network Service Discovery", "tactic": "Discovery"},
    "SSL/TLS":            {"id": "T1573",  "name": "Encrypted Channel",         "tactic": "C2"},
    "API Exposure":       {"id": "T1190",  "name": "Exploit Public Application", "tactic": "Initial Access"},
    "HTTP Methods":       {"id": "T1190",  "name": "Exploit Public Application", "tactic": "Initial Access"},
    "Admin Panel":        {"id": "T1078",  "name": "Valid Accounts",            "tactic": "Initial Access"},
}

def map_mitre_attack(findings):
    """Map findings to MITRE ATT&CK framework"""
    mapped = []
    seen   = set()

    for finding in findings:
        finding_type = finding.get("type", "")
        for key, technique in MITRE_MAPPING.items():
            if key.lower() in finding_type.lower() or key.lower() in finding.get("detail", "").lower():
                tid = technique["id"]
                if tid not in seen:
                    seen.add(tid)
                    mapped.append({
                        "id":      tid,
                        "name":    technique["name"],
                        "tactic":  technique["tactic"],
                        "finding": finding.get("detail", "")[:60]
                    })

    return mapped


def print_web_security_results(
    cors, cookies, clickjacking, http_methods,
    subdomain_takeover, sensitive_files, real_ip,
    api_security, cvss_score, mitre_map
):
    """Print all web security results"""

    # ── PHASE 1 ──
    print(Fore.CYAN + "\n  ═══ PHASE 1: QUICK WINS ═══" + Style.RESET_ALL)

    # CORS
    print(Fore.YELLOW + "\n  🌐 CORS MISCONFIGURATION:" + Style.RESET_ALL)
    for issue in cors["issues"]:
        sev = issue["severity"]
        if sev == "CRITICAL":
            color, icon = Fore.RED, "🔴"
        elif sev == "HIGH":
            color, icon = Fore.RED, "🟠"
        elif sev == "INFO":
            color, icon = Fore.GREEN, "✅"
        else:
            color, icon = Fore.YELLOW, "🟡"
        print(color + f"  {icon} [{sev:8}] {issue['detail']}" + Style.RESET_ALL)

    # Cookies
    print(Fore.YELLOW + "\n  🍪 COOKIE SECURITY:" + Style.RESET_ALL)
    if cookies["cookies"]:
        for cookie in cookies["cookies"]:
            print(f"\n  Cookie: {cookie['name']}")
            print(f"  HttpOnly : {'✅' if cookie['httponly'] else '❌ MISSING'}")
            print(f"  Secure   : {'✅' if cookie['secure']   else '❌ MISSING'}")
            print(f"  SameSite : {cookie['samesite']}")
            for issue in cookie["issues"]:
                print(Fore.YELLOW + f"    → {issue}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "  ✅ No cookies found" + Style.RESET_ALL)

    # Clickjacking
    print(Fore.YELLOW + "\n  🖱️  CLICKJACKING TEST:" + Style.RESET_ALL)
    for detail in clickjacking["details"]:
        sev = detail["severity"]
        color = Fore.RED if sev == "HIGH" else Fore.GREEN
        icon  = "🔴" if sev == "HIGH" else "✅"
        print(color + f"  {icon} {detail['detail']}" + Style.RESET_ALL)

    # HTTP Methods
    print(Fore.YELLOW + "\n  📡 HTTP METHODS:" + Style.RESET_ALL)
    for method, info in http_methods["methods"].items():
        if info["allowed"]:
            color = Fore.RED if info["dangerous"] else Fore.GREEN
            icon  = "🔴" if info["dangerous"] else "✅"
            print(color + f"  {icon} {method:8} → Allowed (Status: {info['status']})" + Style.RESET_ALL)
        else:
            print(Fore.WHITE + f"  ⬜ {method:8} → Not Allowed" + Style.RESET_ALL)

    if http_methods["issues"]:
        print(Fore.RED + "\n  ⚠️  DANGEROUS METHODS FOUND:" + Style.RESET_ALL)
        for issue in http_methods["issues"]:
            print(Fore.RED + f"  🔴 {issue['detail']}" + Style.RESET_ALL)

    # ── PHASE 2 ──
    print(Fore.CYAN + "\n  ═══ PHASE 2: ADVANCED CHECKS ═══" + Style.RESET_ALL)

    # Subdomain Takeover
    print(Fore.YELLOW + f"\n  🏴 SUBDOMAIN TAKEOVER (checked {subdomain_takeover['checked']}):" + Style.RESET_ALL)
    if subdomain_takeover["vulnerable"]:
        for vuln in subdomain_takeover["vulnerable"]:
            print(Fore.RED + f"  🔴 VULNERABLE: {vuln['subdomain']} → Unclaimed {vuln['service']}!" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "  ✅ No subdomain takeover vulnerabilities found" + Style.RESET_ALL)

    # Sensitive Files
    print(Fore.YELLOW + f"\n  📁 SENSITIVE FILES (checked {sensitive_files['checked']}):" + Style.RESET_ALL)
    if sensitive_files["found"]:
        for f in sensitive_files["found"]:
            sev = f["severity"]
            color = Fore.RED if sev in ["CRITICAL", "HIGH"] else Fore.YELLOW
            icon  = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
            print(color + f"  {icon} [{sev:8}] {f['path']:25} → {f['detail']} ({f['size']} bytes)" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "  ✅ No sensitive files found" + Style.RESET_ALL)

    # CDN Real IP
    print(Fore.YELLOW + "\n  🔍 CDN BYPASS / REAL IP FINDER:" + Style.RESET_ALL)
    if real_ip["cdn_detected"]:
        print(Fore.YELLOW + f"  ⚠️  CDN Detected: {real_ip['cdn_name']}" + Style.RESET_ALL)
        if real_ip["potential_ips"]:
            print(f"  Potential real IPs:")
            for ip in real_ip["potential_ips"][:5]:
                print(Fore.RED + f"    → {ip}" + Style.RESET_ALL)
        for method in real_ip["methods"]:
            print(f"  Method: {method}")
    else:
        print(Fore.GREEN + "  ✅ No CDN detected or CDN bypass not needed" + Style.RESET_ALL)

    # API Security
    print(Fore.YELLOW + "\n  🔌 API SECURITY TESTER:" + Style.RESET_ALL)
    if api_security["endpoints"]:
        print(f"  Found {len(api_security['endpoints'])} API endpoints:")
        for ep in api_security["endpoints"][:5]:
            color = Fore.YELLOW if ep["is_api"] else Fore.WHITE
            print(color + f"  → [{ep['status']}] {ep['path']}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "  ✅ No exposed API endpoints found" + Style.RESET_ALL)

    if api_security["issues"]:
        for issue in api_security["issues"]:
            color = Fore.RED if issue["severity"] == "HIGH" else Fore.YELLOW
            print(color + f"  ⚠️  {issue['detail']}" + Style.RESET_ALL)

    # ── PHASE 3 ──
    print(Fore.CYAN + "\n  ═══ PHASE 3: PROFESSIONAL REPORTING ═══" + Style.RESET_ALL)

    # CVSS Score
    print(Fore.YELLOW + "\n  📊 OVERALL RISK SCORE:" + Style.RESET_ALL)
    score = cvss_score["score"]
    level = cvss_score["level"]
    color = Fore.RED if level in ["CRITICAL", "HIGH"] else Fore.YELLOW if level == "MEDIUM" else Fore.GREEN

    print(color + f"""
  ┌─────────────────────────────┐
  │  RISK SCORE : {score:3}/100         │
  │  LEVEL      : {level:8}        │
  ├─────────────────────────────┤
  │  Domain Security  : {cvss_score['breakdown']['domain_security']:3}%     │
  │  Network Security : {cvss_score['breakdown']['network_security']:3}%     │
  │  Web Security     : {cvss_score['breakdown']['web_security']:3}%     │
  │  Threat Intel     : {cvss_score['breakdown']['threat_intel']:3}%     │
  └─────────────────────────────┘""" + Style.RESET_ALL)

    # MITRE ATT&CK
    print(Fore.YELLOW + "\n  🎯 MITRE ATT&CK MAPPING:" + Style.RESET_ALL)
    if mitre_map:
        for technique in mitre_map:
            print(Fore.CYAN + f"  [{technique['id']}] {technique['name']:30} | Tactic: {technique['tactic']}" + Style.RESET_ALL)
            print(f"         Finding: {technique['finding']}")
    else:
        print(Fore.GREEN + "  ✅ No techniques mapped (no findings)" + Style.RESET_ALL)
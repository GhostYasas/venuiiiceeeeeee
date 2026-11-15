# modules/advanced_scanner.py

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import nmap
import requests
import ssl
import socket
from datetime import datetime
from colorama import Fore, Style


def run_nmap_scan(target, ip):
    """Run all professional Nmap scans automatically"""

    results = {
        "target": target,
        "ip": ip,
        "scans": {}
    }

    nm = nmap.PortScanner()

    # ── SCAN 1: Service Version Detection ──
    try:
        print(Fore.YELLOW + "    [1/8] Running service version detection..." + Style.RESET_ALL)
        nm.scan(ip, arguments="-sV --version-intensity 5 -T4")

        services = []
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto].keys():
                    service = nm[ip][proto][port]
                    services.append({
                        "port": port,
                        "protocol": proto,
                        "state": service.get("state", "unknown"),
                        "service": service.get("name", "unknown"),
                        "product": service.get("product", ""),
                        "version": service.get("version", ""),
                        "extrainfo": service.get("extrainfo", "")
                    })
        results["scans"]["services"] = services
    except Exception as e:
        results["scans"]["services"] = []
        print(Fore.RED + f"    [!] Service scan error: {e}" + Style.RESET_ALL)

    # ── SCAN 2: OS Detection ──
    try:
        print(Fore.YELLOW + "    [2/8] Running OS detection..." + Style.RESET_ALL)
        nm.scan(ip, arguments="-O -T4 --osscan-guess")

        os_info = {"name": "Unknown", "accuracy": 0, "family": "Unknown"}
        if ip in nm.all_hosts():
            os_matches = nm[ip].get("osmatch", [])
            if os_matches:
                best = os_matches[0]
                os_info = {
                    "name": best.get("name", "Unknown"),
                    "accuracy": best.get("accuracy", 0),
                    "family": best.get("osclass", [{}])[0].get("osfamily", "Unknown") if best.get("osclass") else "Unknown"
                }
        results["scans"]["os"] = os_info
    except Exception as e:
        results["scans"]["os"] = {"name": "Unknown", "accuracy": 0, "family": "Unknown"}

    # ── SCAN 3: Vulnerability Scripts ──
    try:
        print(Fore.YELLOW + "    [3/8] Running vulnerability scripts..." + Style.RESET_ALL)
        nm.scan(ip, arguments="--script vuln -T4 --script-timeout 30s")

        vulns = []
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto].keys():
                    script_results = nm[ip][proto][port].get("script", {})
                    for script_name, output in script_results.items():
                        if output and "ERROR" not in output:
                            if "VULNERABLE" in output.upper():
                                severity = "CRITICAL"
                            elif "WARNING" in output.upper():
                                severity = "MEDIUM"
                            else:
                                severity = "HIGH"
                            vulns.append({
                                "port": port,
                                "script": script_name,
                                "output": output[:200],
                                "severity": severity
                            })
        results["scans"]["vulns"] = vulns
    except Exception as e:
        results["scans"]["vulns"] = []

    # ── SCAN 4: SSL/TLS Analysis ──
    try:
        print(Fore.YELLOW + "    [4/8] Running SSL/TLS analysis..." + Style.RESET_ALL)
        nm.scan(ip, arguments="--script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-cert -p 443 -T4")

        ssl_info = {
            "heartbleed": False,
            "poodle": False,
            "ciphers": [],
            "cert": {}
        }

        if ip in nm.all_hosts():
            tcp = nm[ip].get("tcp", {})
            port_443 = tcp.get(443, {})
            scripts = port_443.get("script", {})

            heartbleed = scripts.get("ssl-heartbleed", "")
            ssl_info["heartbleed"] = "VULNERABLE" in heartbleed.upper()

            poodle = scripts.get("ssl-poodle", "")
            ssl_info["poodle"] = "VULNERABLE" in poodle.upper()

            ciphers_raw = scripts.get("ssl-enum-ciphers", "")
            if ciphers_raw:
                ssl_info["ciphers"] = ciphers_raw[:300]

            cert_raw = scripts.get("ssl-cert", "")
            if cert_raw:
                ssl_info["cert"] = cert_raw[:300]

        results["scans"]["ssl"] = ssl_info
    except Exception as e:
        results["scans"]["ssl"] = {}

    # ── SCAN 5: HTTP Security Headers ──
    try:
        print(Fore.YELLOW + "    [5/8] Checking HTTP security headers..." + Style.RESET_ALL)
        nm.scan(ip, arguments="--script http-security-headers -p 80,443 -T4")

        headers_info = {}
        if ip in nm.all_hosts():
            tcp = nm[ip].get("tcp", {})
            for port in [80, 443]:
                port_data = tcp.get(port, {})
                scripts = port_data.get("script", {})
                header_output = scripts.get("http-security-headers", "")
                if header_output:
                    headers_info[port] = header_output

        results["scans"]["headers"] = headers_info
    except Exception as e:
        results["scans"]["headers"] = {}

    # ── SCAN 6: SQL Injection Check ──
    try:
        print(Fore.YELLOW + "    [6/8] Checking for SQL injection..." + Style.RESET_ALL)
        nm.scan(ip, arguments="--script http-sql-injection -p 80,443 -T4")

        sqli_results = []
        if ip in nm.all_hosts():
            tcp = nm[ip].get("tcp", {})
            for port in [80, 443]:
                port_data = tcp.get(port, {})
                scripts = port_data.get("script", {})
                sqli = scripts.get("http-sql-injection", "")
                if sqli and "Possible sqli" in sqli:
                    sqli_results.append({
                        "port": port,
                        "details": sqli[:200]
                    })

        results["scans"]["sqli"] = sqli_results
    except Exception as e:
        results["scans"]["sqli"] = []

    # ── SCAN 7: Default Credentials ──
    try:
        print(Fore.YELLOW + "    [7/8] Checking default credentials..." + Style.RESET_ALL)
        nm.scan(ip, arguments="--script auth -T4")

        auth_results = []
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto].keys():
                    scripts = nm[ip][proto][port].get("script", {})
                    for script_name, output in scripts.items():
                        if "auth" in script_name.lower() and output:
                            auth_results.append({
                                "port": port,
                                "script": script_name,
                                "output": output[:200]
                            })

        results["scans"]["auth"] = auth_results
    except Exception as e:
        results["scans"]["auth"] = []

    # ── SCAN 8: Firewall/WAF Detection ──
    try:
        print(Fore.YELLOW + "    [8/8] Detecting firewall/WAF..." + Style.RESET_ALL)
        nm.scan(ip, arguments="--script http-waf-detect,http-waf-fingerprint -p 80,443 -T4")

        waf_info = {"detected": False, "name": "None"}
        if ip in nm.all_hosts():
            tcp = nm[ip].get("tcp", {})
            for port in [80, 443]:
                port_data = tcp.get(port, {})
                scripts = port_data.get("script", {})
                waf = scripts.get("http-waf-fingerprint", "") or scripts.get("http-waf-detect", "")
                if waf and "DETECTED" in waf.upper():
                    waf_info = {"detected": True, "name": waf[:100]}

        results["scans"]["waf"] = waf_info
    except Exception as e:
        results["scans"]["waf"] = {"detected": False, "name": "None"}

    return results


def run_web_vulnerability_scan(domain):
    """Nikto-like web vulnerability scanner"""

    results = {
        "domain": domain,
        "vulnerabilities": [],
        "security_headers": {},
        "ssl_info": {},
        "server_info": {}
    }

    base_url = f"https://{domain}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    # ── CHECK 1: Security Headers ──
    try:
        response = requests.get(base_url, headers=headers, timeout=10, verify=False)
        resp_headers = response.headers
        resp_header_keys = [h.lower() for h in resp_headers.keys()]

        security_headers = {
            "Strict-Transport-Security": {
                "present": "strict-transport-security" in resp_header_keys,
                "severity": "HIGH",
                "description": "Protects against MITM attacks"
            },
            "X-Frame-Options": {
                "present": "x-frame-options" in resp_header_keys,
                "severity": "MEDIUM",
                "description": "Prevents clickjacking attacks"
            },
            "X-Content-Type-Options": {
                "present": "x-content-type-options" in resp_header_keys,
                "severity": "MEDIUM",
                "description": "Prevents MIME sniffing"
            },
            "Content-Security-Policy": {
                "present": "content-security-policy" in resp_header_keys,
                "severity": "HIGH",
                "description": "Prevents XSS attacks"
            },
            "X-XSS-Protection": {
                "present": "x-xss-protection" in resp_header_keys,
                "severity": "MEDIUM",
                "description": "Browser XSS filter"
            },
            "Referrer-Policy": {
                "present": "referrer-policy" in resp_header_keys,
                "severity": "LOW",
                "description": "Controls referrer information"
            },
            "Permissions-Policy": {
                "present": "permissions-policy" in resp_header_keys,
                "severity": "LOW",
                "description": "Controls browser features"
            }
        }

        results["security_headers"] = security_headers

        server = resp_headers.get("Server", "Hidden")
        powered_by = resp_headers.get("X-Powered-By", "Hidden")
        results["server_info"] = {
            "server": server,
            "powered_by": powered_by,
            "status_code": response.status_code
        }

        if server != "Hidden" and any(char.isdigit() for char in server):
            results["vulnerabilities"].append({
                "severity": "MEDIUM",
                "type": "Information Disclosure",
                "detail": f"Server version exposed: {server}"
            })

        if powered_by != "Hidden":
            results["vulnerabilities"].append({
                "severity": "LOW",
                "type": "Information Disclosure",
                "detail": f"Technology exposed: X-Powered-By: {powered_by}"
            })

    except Exception:
        pass

    # ── CHECK 2: SSL Certificate Analysis ──
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(10)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        days_left  = (not_after - datetime.now()).days

        issuer  = dict(x[0] for x in cert["issuer"])
        subject = dict(x[0] for x in cert["subject"])

        ssl_info = {
            "subject":       subject.get("commonName", "N/A"),
            "issuer":        issuer.get("organizationName", "N/A"),
            "valid_from":    str(not_before)[:10],
            "valid_until":   str(not_after)[:10],
            "days_left":     days_left,
            "is_expired":    days_left < 0,
            "expiring_soon": 0 < days_left < 30
        }
        results["ssl_info"] = ssl_info

        if days_left < 0:
            results["vulnerabilities"].append({
                "severity": "CRITICAL",
                "type": "SSL Certificate",
                "detail": "SSL certificate has EXPIRED!"
            })
        elif days_left < 30:
            results["vulnerabilities"].append({
                "severity": "HIGH",
                "type": "SSL Certificate",
                "detail": f"SSL certificate expires in {days_left} days!"
            })

    except Exception:
        pass

    # ── CHECK 3: Common Vulnerability Paths ──
    vuln_paths = [
        {"path": "/.env",            "severity": "CRITICAL", "type": "Config Exposure",    "detail": ".env file exposed (contains passwords!)"},
        {"path": "/.git/config",     "severity": "CRITICAL", "type": "Git Exposure",       "detail": "Git repository exposed!"},
        {"path": "/wp-login.php",    "severity": "HIGH",     "type": "CMS Detection",      "detail": "WordPress login page found"},
        {"path": "/phpmyadmin",      "severity": "CRITICAL", "type": "DB Admin Exposed",   "detail": "phpMyAdmin exposed!"},
        {"path": "/server-status",   "severity": "HIGH",     "type": "Info Disclosure",    "detail": "Apache server-status exposed"},
        {"path": "/api/v1",          "severity": "MEDIUM",   "type": "API Exposure",       "detail": "API endpoint found"},
        {"path": "/swagger-ui.html", "severity": "MEDIUM",   "type": "API Docs Exposure",  "detail": "Swagger API docs exposed"},
        {"path": "/actuator",        "severity": "HIGH",     "type": "Spring Exposure",    "detail": "Spring Boot actuator exposed"},
        {"path": "/elmah.axd",       "severity": "HIGH",     "type": "Error Log Exposure", "detail": "ELMAH error log exposed"},
        {"path": "/trace.axd",       "severity": "HIGH",     "type": "Trace Exposure",     "detail": "ASP.NET trace exposed"},
    ]

    for vuln in vuln_paths:
        try:
            url = f"https://{domain}{vuln['path']}"
            r = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200:
                results["vulnerabilities"].append({
                    "severity": vuln["severity"],
                    "type":     vuln["type"],
                    "detail":   vuln["detail"],
                    "url":      url
                })
        except Exception:
            pass

    # ── CHECK 4: XSS Detection ──
    try:
        xss_payload = "<script>alert(1)</script>"
        xss_url = f"https://{domain}/search?q={xss_payload}"
        r = requests.get(xss_url, headers=headers, timeout=5, verify=False)
        if xss_payload in r.text:
            results["vulnerabilities"].append({
                "severity": "CRITICAL",
                "type":     "XSS Vulnerability",
                "detail":   "Reflected XSS found at /search?q=",
                "url":      xss_url
            })
    except Exception:
        pass

    # ── CHECK 5: Directory Listing ──
    dir_paths = ["/images/", "/uploads/", "/files/", "/backup/", "/logs/"]
    for path in dir_paths:
        try:
            url = f"https://{domain}{path}"
            r = requests.get(url, headers=headers, timeout=5, verify=False)
            if r.status_code == 200 and "Index of" in r.text:
                results["vulnerabilities"].append({
                    "severity": "HIGH",
                    "type":     "Directory Listing",
                    "detail":   f"Directory listing enabled at {path}",
                    "url":      url
                })
        except Exception:
            pass

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results["vulnerabilities"].sort(key=lambda x: severity_order.get(x["severity"], 4))

    return results


def print_advanced_scan_results(nmap_results, web_results):
    """Print all results in beautiful format"""

    # ── NMAP RESULTS ──
    print(Fore.CYAN + "\n  ═══ NMAP PROFESSIONAL SCAN ═══" + Style.RESET_ALL)

    # Service Detection
    services = nmap_results["scans"].get("services", [])
    if services:
        print(Fore.YELLOW + "\n  📡 SERVICE VERSION DETECTION:" + Style.RESET_ALL)
        print(f"  {'PORT':<8} {'PROTO':<6} {'STATE':<8} {'SERVICE':<12} {'VERSION'}")
        print(f"  {'─'*60}")
        for svc in services:
            state_color = Fore.GREEN if svc["state"] == "open" else Fore.RED
            product = f"{svc['product']} {svc['version']}".strip() or "N/A"
            print(state_color + f"  {svc['port']:<8} {svc['protocol']:<6} {svc['state']:<8} {svc['service']:<12} {product}" + Style.RESET_ALL)

    # OS Detection
    os_info = nmap_results["scans"].get("os", {})
    if os_info and os_info.get("name") != "Unknown":
        print(Fore.YELLOW + "\n  🖥️  OS DETECTION:" + Style.RESET_ALL)
        print(f"  OS      : {os_info['name']}")
        print(f"  Family  : {os_info['family']}")
        print(f"  Accuracy: {os_info['accuracy']}%")

    # Vulnerability Scripts
    vulns = nmap_results["scans"].get("vulns", [])
    real_vulns = [
        v for v in vulns
        if "couldn't find" not in v["output"].lower()
        and "unable to" not in v["output"].lower()
        and "not vulnerable" not in v["output"].lower()
    ]
    if real_vulns:
        print(Fore.RED + f"\n  💀 NMAP VULNERABILITY SCRIPTS ({len(real_vulns)} found):" + Style.RESET_ALL)
        for vuln in real_vulns:
            color = Fore.RED if vuln["severity"] == "CRITICAL" else Fore.YELLOW
            print(color + f"  🔴 Port {vuln['port']} | {vuln['script']}" + Style.RESET_ALL)
            print(f"     {vuln['output'][:150]}")
    else:
        print(Fore.GREEN + "\n  ✅ No vulnerabilities found by Nmap scripts" + Style.RESET_ALL)

    # SSL Analysis
    ssl_info = nmap_results["scans"].get("ssl", {})
    if ssl_info:
        print(Fore.YELLOW + "\n  🔒 SSL/TLS ANALYSIS:" + Style.RESET_ALL)
        heartbleed = ssl_info.get("heartbleed", False)
        poodle     = ssl_info.get("poodle", False)
        print(Fore.RED   + "  ⚠️  Heartbleed : VULNERABLE!" + Style.RESET_ALL if heartbleed else Fore.GREEN + "  ✅ Heartbleed : Safe" + Style.RESET_ALL)
        print(Fore.RED   + "  ⚠️  POODLE     : VULNERABLE!" + Style.RESET_ALL if poodle     else Fore.GREEN + "  ✅ POODLE     : Safe" + Style.RESET_ALL)
        if ssl_info.get("ciphers"):
            print(f"\n  Cipher Suites:\n  {ssl_info['ciphers'][:200]}")

    # WAF Detection
    waf = nmap_results["scans"].get("waf", {})
    if waf.get("detected"):
        print(Fore.YELLOW + f"\n  🛡️  WAF DETECTED: {waf['name']}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "\n  🛡️  WAF: Not detected" + Style.RESET_ALL)

    # SQL Injection
    sqli = nmap_results["scans"].get("sqli", [])
    if sqli:
        print(Fore.RED + f"\n  💉 SQL INJECTION FOUND!" + Style.RESET_ALL)
        for s in sqli:
            print(f"  → Port {s['port']}: {s['details'][:150]}")

    # Auth Results
    auth = nmap_results["scans"].get("auth", [])
    if auth:
        print(Fore.YELLOW + f"\n  🔑 DEFAULT CREDENTIALS CHECK:" + Style.RESET_ALL)
        for a in auth:
            print(f"  → Port {a['port']} | {a['script']}: {a['output'][:100]}")

    # ── WEB VULNERABILITY RESULTS ──
    print(Fore.CYAN + "\n  ═══ WEB VULNERABILITY SCAN (Nikto-like) ═══" + Style.RESET_ALL)

    # Server Info
    server_info = web_results.get("server_info", {})
    if server_info:
        print(Fore.YELLOW + "\n  🖥️  SERVER INFORMATION:" + Style.RESET_ALL)
        print(f"  Server      : {server_info.get('server', 'N/A')}")
        print(f"  Powered By  : {server_info.get('powered_by', 'N/A')}")
        print(f"  Status Code : {server_info.get('status_code', 'N/A')}")

    # SSL Certificate
    ssl_cert = web_results.get("ssl_info", {})
    if ssl_cert:
        print(Fore.YELLOW + "\n  🔐 SSL CERTIFICATE:" + Style.RESET_ALL)
        days  = ssl_cert.get("days_left", 0)
        color = Fore.RED if days < 0 else Fore.YELLOW if days < 30 else Fore.GREEN
        print(f"  Subject     : {ssl_cert.get('subject', 'N/A')}")
        print(f"  Issuer      : {ssl_cert.get('issuer', 'N/A')}")
        print(f"  Valid From  : {ssl_cert.get('valid_from', 'N/A')}")
        print(f"  Expires     : {ssl_cert.get('valid_until', 'N/A')}")
        print(color + f"  Days Left   : {days} days" + Style.RESET_ALL)

    # Security Headers
    sec_headers = web_results.get("security_headers", {})
    if sec_headers:
        print(Fore.YELLOW + "\n  🛡️  SECURITY HEADERS:" + Style.RESET_ALL)
        score = sum(1 for h in sec_headers.values() if h["present"])
        total = len(sec_headers)
        grade_color = Fore.GREEN if score >= 6 else Fore.YELLOW if score >= 4 else Fore.RED
        print(grade_color + f"  Security Score: {score}/{total}" + Style.RESET_ALL)
        for header_name, info in sec_headers.items():
            if info["present"]:
                print(Fore.GREEN + f"  ✅ {header_name}" + Style.RESET_ALL)
            else:
                color = Fore.RED if info["severity"] == "HIGH" else Fore.YELLOW
                print(color + f"  ❌ MISSING: {header_name} ({info['severity']}) - {info['description']}" + Style.RESET_ALL)

    # Vulnerabilities
    web_vulns = web_results.get("vulnerabilities", [])
    if web_vulns:
        print(Fore.RED + f"\n  ⚠️  VULNERABILITIES FOUND: {len(web_vulns)}" + Style.RESET_ALL)
        for vuln in web_vulns:
            severity = vuln["severity"]
            if severity == "CRITICAL":
                color, icon = Fore.RED, "🔴"
            elif severity == "HIGH":
                color, icon = Fore.RED, "🟠"
            elif severity == "MEDIUM":
                color, icon = Fore.YELLOW, "🟡"
            else:
                color, icon = Fore.WHITE, "🟢"
            url = f" → {vuln.get('url', '')}" if vuln.get("url") else ""
            print(color + f"  {icon} [{severity:8}] {vuln['type']:20} | {vuln['detail']}{url}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "\n  ✅ No web vulnerabilities found" + Style.RESET_ALL)
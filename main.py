# main.py
from datetime import datetime
from modules.web_security import (
    check_cors, check_cookies, check_clickjacking, check_http_methods,
    check_subdomain_takeover, find_sensitive_files, find_real_ip,
    check_api_security, calculate_cvss, map_mitre_attack,
    print_web_security_results
)
from modules.pentest_report import generate_pentest_report
from modules.web_app_scanner import (
    detect_technology_stack, analyze_jwt_tokens,
    test_graphql_security, check_websocket_security,
    print_web_app_results
)
from modules.cve_checker import check_cves_for_tech, print_cve_results
from modules.domain_recon import get_whois, get_dns_records, get_subdomains
from modules.ip_recon import get_ip_from_domain, get_ip_geolocation, check_ip_reputation
from modules.email_check import check_email_breach, check_email_format
from modules.social_scan import check_username
from modules.port_scanner import scan_ports, get_risk_summary
from modules.virustotal import check_domain_virustotal, check_ip_virustotal
from modules.abuseipdb import check_ip_abuse, check_bulk_ips
from modules.screenshot import take_screenshot
from modules.panel_finder import find_admin_panels
from modules.shodan_scan import shodan_host_lookup
from modules.dns_history import get_dns_history
from modules.ai_summary import generate_threat_summary
from modules.report import generate_report
from modules.advanced_scanner import run_nmap_scan, run_web_vulnerability_scan, print_advanced_scan_results
from colorama import Fore, Style, init

init()

# ── API KEYS ──
VT_API_KEY    = "ee74ef32e8917b66c192796dc8f364cfab609248f1ad067a0816837a911650fc"
ABUSE_API_KEY = "7a91cd740b7b4ba2ce11a6eb96db24548b7040e5e9aee3aa6802fff29e59b981cb26f51e602e9d3c"
SHODAN_API_KEY = "Dn4Lti40GOOrRoCHmHaP37ob01QSo9wW"
GROQ_API_KEY  = "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"



def print_banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════╗
    ║     OSINT RECON TOOL v2.0         ║
    ║     Built for Investigation       ║
    ╚═══════════════════════════════════╝
    """ + Style.RESET_ALL)

def print_section(title):
    print(Fore.CYAN + f"\n{'='*45}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"  {title}" + Style.RESET_ALL)
    print(Fore.CYAN + f"{'='*45}" + Style.RESET_ALL)

def print_vt_result(result, target_type="domain"):
    if "error" in result:
        print(Fore.RED + f"  [!] {result['error']}" + Style.RESET_ALL)
        return
    risk = result["risk"]
    if risk == "CRITICAL":
        color, icon = Fore.RED, "🔴"
    elif risk == "HIGH":
        color, icon = Fore.RED, "🟠"
    elif risk == "MEDIUM":
        color, icon = Fore.YELLOW, "🟡"
    else:
        color, icon = Fore.GREEN, "🟢"
    print(color + f"  {icon} Risk Level    : {risk}" + Style.RESET_ALL)
    print(f"  🦠 Malicious   : {result['malicious']}/{result['total_engines']} engines")
    print(f"  ⚠️  Suspicious  : {result['suspicious']}/{result['total_engines']} engines")
    print(f"  ✅ Harmless    : {result['harmless']}/{result['total_engines']} engines")
    if target_type == "domain" and result.get("categories"):
        print(f"  🏷️  Categories  : {', '.join(result['categories'])}")

def print_abuse_result(result):
    if "error" in result:
        print(Fore.RED + f"  [!] {result['error']}" + Style.RESET_ALL)
        return
    risk = result["risk"]
    if risk == "CRITICAL":
        color, icon = Fore.RED, "🔴"
    elif risk == "HIGH":
        color, icon = Fore.RED, "🟠"
    elif risk == "MEDIUM":
        color, icon = Fore.YELLOW, "🟡"
    elif risk == "LOW":
        color, icon = Fore.YELLOW, "🟡"
    else:
        color, icon = Fore.GREEN, "🟢"
    print(color + f"  {icon} Abuse Score     : {result['score']}/100 ({risk})" + Style.RESET_ALL)
    print(f"  📊 Total Reports  : {result['total_reports']}")
    print(f"  👥 Distinct Users : {result['num_distinct_users']}")
    print(f"  🕒 Last Reported  : {result['last_reported']}")
    print(f"  🌍 Country        : {result['country']}")
    print(f"  🏢 ISP            : {result['isp']}")
    print(f"  🌐 Domain         : {result['domain']}")
    print(f"  🧅 Is Tor Node    : {'⚠️  YES' if result['is_tor'] else '✅ NO'}")
    print(f"  💼 Usage Type     : {result['usage_type']}")
    print(Fore.CYAN + f"\n  📡 NETWORK BLOCK INFO" + Style.RESET_ALL)
    print(f"  Network Range   : {result['network']}")
    if result["attack_types"]:
        print(Fore.CYAN + f"\n  ⚔️  ATTACK TYPES DETECTED" + Style.RESET_ALL)
        for attack in result["attack_types"]:
            print(Fore.YELLOW + f"    → {attack}" + Style.RESET_ALL)
    print(Fore.CYAN + f"\n  📅 ATTACK TIMELINE" + Style.RESET_ALL)
    r7  = result['reports_7d']
    r30 = result['reports_30d']
    r90 = result['reports_90d']
    print((Fore.RED if r7>10 else Fore.YELLOW if r7>0 else Fore.GREEN) + f"  Last 7 days   : {r7} reports" + Style.RESET_ALL)
    print((Fore.RED if r30>30 else Fore.YELLOW if r30>0 else Fore.GREEN) + f"  Last 30 days  : {r30} reports" + Style.RESET_ALL)
    print((Fore.RED if r90>50 else Fore.YELLOW if r90>0 else Fore.GREEN) + f"  Last 90 days  : {r90} reports" + Style.RESET_ALL)
    if result["recent_reports"]:
        print(Fore.CYAN + f"\n  📋 RECENT REPORTS" + Style.RESET_ALL)
        for r in result["recent_reports"][:5]:
            cats = ", ".join(r["categories"]) if r["categories"] else "Unknown"
            print(f"  → {r['date']} | {cats:25} | Reported from: {r['country']}")

def main():
    print_banner()

    target = input(Fore.YELLOW + "[?] Enter target domain: " + Style.RESET_ALL)

    scan_summary = {"domain": target}

    # ── WHOIS ──
    print_section("WHOIS INFORMATION")
    whois_data = get_whois(target)
    if "error" not in whois_data:
        print(f"  Registrar     : {whois_data.get('registrar', 'N/A')}")
        print(f"  Country       : {whois_data.get('country', 'N/A')}")
        print(f"  Created       : {whois_data.get('creation_date', 'N/A')}")
        print(f"  Expires       : {whois_data.get('expiration_date', 'N/A')}")
        ns_list = whois_data.get('name_servers', [])
        if ns_list:
            ns_str = []
            for ns in ns_list[:2]:
                if isinstance(ns, dict):
                    ns_str.append(ns.get('ldhName', str(ns)))
                else:
                    ns_str.append(str(ns))
            print(f"  Name Servers  : {', '.join(ns_str)}")
        else:
            print(f"  Name Servers  : N/A")
        scan_summary["registrar"] = whois_data.get("registrar")
        scan_summary["country"]   = whois_data.get("country")
    else:
        print(f"  [!] {whois_data['error']}")

    # ── DNS ──
    print_section("DNS RECORDS")
    dns_data = get_dns_records(target)
    for record_type, values in dns_data.items():
        if values:
            print(f"  {record_type:6} : {', '.join(values[:3])}")

    # ── SUBDOMAINS ──
    print_section("SUBDOMAINS")
    subdomains = get_subdomains(target)
    if subdomains:
        print(f"  Found {len(subdomains)} subdomains:")
        for sub in subdomains[:10]:
            print(f"    → {sub}")
    else:
        print("  [!] No subdomains found (crt.sh may be slow)")

    # ── DNS HISTORY ──
    print_section("DNS HISTORY")
    print(f"  Fetching DNS history for {target}...")
    dns_hist = get_dns_history(target)
    if dns_hist["history"]:
        print(f"\n  📜 IP HISTORY ({len(dns_hist['history'])} records found):")
        for record in dns_hist["history"][:5]:
            ip_h  = record.get("ip", "N/A")
            owner = record.get("owner", record.get("location", "N/A"))
            seen  = record.get("last_seen", "N/A")
            print(f"    → {ip_h:20} | Owner: {owner:20} | Last seen: {seen}")
    else:
        print(f"  [!] No IP history found")
    if dns_hist["passive_dns"]:
        print(f"\n  🔍 PASSIVE DNS ({len(dns_hist['passive_dns'])} hostnames):")
        for entry in dns_hist["passive_dns"][:5]:
            print(f"    → {entry['hostname']:35} → {entry['ip']}")
    else:
        print(f"  [!] No passive DNS data found")

    # ── IP RECON ──
    print_section("IP GEOLOCATION")
    ip = get_ip_from_domain(target)
    geo = {}
    rep = {}
    if ip:
        scan_summary["ip"] = ip
        print(f"  Resolved IP   : {ip}")
        geo = get_ip_geolocation(ip)
        if "error" not in geo:
            print(f"  Country       : {geo['country']}")
            print(f"  City          : {geo['city']}, {geo['region']}")
            print(f"  ISP           : {geo['isp']}")
            print(f"  Organization  : {geo['org']}")
            print(f"  Coordinates   : {geo['lat']}, {geo['lon']}")
            print(f"  Timezone      : {geo['timezone']}")
            scan_summary["isp"] = geo.get("isp")
        print_section("IP REPUTATION CHECK")
        rep = check_ip_reputation(ip)
        if "error" not in rep:
            print(f"  Is Proxy/VPN  : {'⚠️  YES' if rep['is_proxy'] else '✅ NO'}")
            print(f"  Is Hosting    : {'⚠️  YES' if rep['is_hosting'] else '✅ NO'}")
            print(f"  Is Mobile     : {'📱 YES' if rep['is_mobile'] else '✅ NO'}")
    else:
        print(f"  [!] Could not resolve IP for {target}")

    # ── VIRUSTOTAL ──
    print_section("VIRUSTOTAL THREAT INTELLIGENCE")
    if not VT_API_KEY or VT_API_KEY == "your_virustotal_key_here":
        print(f"  [!] Please add your VirusTotal API key in main.py")
        vt_domain_result = None
        vt_ip_result     = None
    else:
        print(f"  Checking domain: {target}...")
        vt_domain_result = check_domain_virustotal(target, VT_API_KEY)
        print_vt_result(vt_domain_result, "domain")
        scan_summary["vt_score"] = f"{vt_domain_result.get('malicious', 0)}/{vt_domain_result.get('total_engines', 0)}"
        if ip:
            print(f"\n  Checking IP: {ip}...")
            vt_ip_result = check_ip_virustotal(ip, VT_API_KEY)
            print_vt_result(vt_ip_result, "ip")

    # ── ABUSEIPDB ──
    print_section("ABUSEIPDB REPUTATION CHECK")
    if not ABUSE_API_KEY or ABUSE_API_KEY == "your_abuseipdb_key_here":
        print(f"  [!] Please add your AbuseIPDB API key in main.py")
    else:
        if ip:
            print(f"  Checking {ip} on AbuseIPDB...\n")
            abuse_result = check_ip_abuse(ip, ABUSE_API_KEY)
            print_abuse_result(abuse_result)
            scan_summary["abuse_score"] = abuse_result.get("score", 0)
            print(Fore.CYAN + f"\n  🔍 BULK IP CHECK (from DNS records)" + Style.RESET_ALL)
            dns_ips = dns_data.get("A", [])[:3]
            if dns_ips:
                print(f"  Checking {len(dns_ips)} IPs from DNS...\n")
                bulk_results = check_bulk_ips(dns_ips, ABUSE_API_KEY)
                for checked_ip, result in bulk_results.items():
                    if "error" not in result:
                        score = result["score"]
                        risk  = result["risk"]
                        if risk in ["CRITICAL", "HIGH"]:
                            color, icon = Fore.RED, "🔴"
                        elif risk == "MEDIUM":
                            color, icon = Fore.YELLOW, "🟡"
                        else:
                            color, icon = Fore.GREEN, "🟢"
                        print(color + f"  {icon} {checked_ip:20} Score: {score}/100 ({risk})" + Style.RESET_ALL)

    # ── SHODAN ──
    print_section("SHODAN EXPLOIT SEARCH")
    if not SHODAN_API_KEY or SHODAN_API_KEY == "your_shodan_key_here":
        print(f"  [!] Please add your Shodan API key in main.py")
    else:
        if ip:
            print(f"  Looking up {ip} on Shodan...\n")
            shodan_result = shodan_host_lookup(ip, SHODAN_API_KEY)
            if "error" in shodan_result:
                print(Fore.RED + f"  [!] {shodan_result['error']}" + Style.RESET_ALL)
            else:
                print(f"  🖥️  OS            : {shodan_result['os']}")
                print(f"  🏢 Organization  : {shodan_result['org']}")
                print(f"  🔄 Last Updated  : {shodan_result['last_update']}")
                if shodan_result["ports"]:
                    print(f"\n  🔓 OPEN PORTS    : {', '.join(map(str, shodan_result['ports'][:10]))}")
                if shodan_result["services"]:
                    print(f"\n  ⚙️  SERVICES DETECTED:")
                    for svc in shodan_result["services"]:
                        product = svc.get("product", "")
                        version = svc.get("version", "")
                        info    = f"{product} {version}".strip() or svc.get("service", "unknown")
                        print(f"    → Port {svc['port']:5} | {info}")
                if shodan_result["tags"]:
                    print(f"\n  🏷️  TAGS          : {', '.join(shodan_result['tags'])}")
                if shodan_result["vulns"]:
                    print(Fore.RED + f"\n  💀 VULNERABILITIES FOUND: {shodan_result['vuln_count']}" + Style.RESET_ALL)
                    for vuln in shodan_result["vulns"]:
                        cvss  = vuln.get("cvss", 0)
                        color = Fore.RED if cvss >= 7 else Fore.YELLOW if cvss >= 4 else Fore.GREEN
                        print(color + f"    🔴 {vuln['cve']:20} | CVSS: {cvss} | {vuln['summary'][:60]}" + Style.RESET_ALL)
                    scan_summary["vulns"] = [v["cve"] for v in shodan_result["vulns"]]
                else:
                    print(Fore.GREEN + f"\n  ✅ No vulnerabilities found" + Style.RESET_ALL)

    # ── PORT SCANNER ──
    print_section("PORT SCANNER")
    if ip:
        print(f"  Scanning 23 common ports on {ip}...")
        print(f"  Please wait...\n")
        scan_results = scan_ports(ip)
        risk         = get_risk_summary(scan_results)
        if risk["overall"] == "HIGH":
            print(Fore.RED    + f"  ⚠️  OVERALL RISK: HIGH"   + Style.RESET_ALL)
        elif risk["overall"] == "MEDIUM":
            print(Fore.YELLOW + f"  ⚡ OVERALL RISK: MEDIUM" + Style.RESET_ALL)
        else:
            print(Fore.GREEN  + f"  ✅ OVERALL RISK: LOW"    + Style.RESET_ALL)
        print(f"\n  Scanned  : {scan_results['total_scanned']} ports")
        print(f"  Open     : {scan_results['open_count']} ports")
        print(f"  Scan Time: {scan_results['scan_time']}s\n")
        if scan_results["open_ports"]:
            for p in scan_results["open_ports"]:
                if p["risk"] == "HIGH":
                    color, icon = Fore.RED, "🔴"
                elif p["risk"] == "MEDIUM":
                    color, icon = Fore.YELLOW, "🟡"
                else:
                    color, icon = Fore.GREEN, "🟢"
                print(color + f"  {icon} Port {p['port']:5} | {p['service']:15} | {p['risk']:6} | {p['reason']}" + Style.RESET_ALL)
            scan_summary["open_ports"] = [p["port"] for p in scan_results["open_ports"]]
        else:
            print(Fore.GREEN + "  ✅ No open ports found" + Style.RESET_ALL)
    else:
        print("  [!] Skipped - could not resolve IP")

    # ── ADVANCED SCANNER ──
    print_section("ADVANCED SECURITY SCANNER")
    if ip:
        print(Fore.YELLOW + "\n  🔍 Running professional Nmap scans (8 scan types)..." + Style.RESET_ALL)
        print(Fore.YELLOW + "  ⏳ This may take 2-5 minutes...\n" + Style.RESET_ALL)
        nmap_results = run_nmap_scan(target, ip)
        print(Fore.YELLOW + "\n  🌐 Running web vulnerability scan..." + Style.RESET_ALL)
        web_results  = run_web_vulnerability_scan(target)
        print_advanced_scan_results(nmap_results, web_results)
    else:
        print("  [!] Skipped - could not resolve IP")

    # ── WEB SECURITY PHASES 1-2-3 ──
    print_section("WEB SECURITY ASSESSMENT (Phase 1-2-3)")
    print(Fore.YELLOW + "\n  Running all security checks...\n" + Style.RESET_ALL)

    print(Fore.YELLOW + "  Phase 1: Quick Wins..." + Style.RESET_ALL)
    cors_result        = check_cors(target)
    cookie_result      = check_cookies(target)
    clickjack_result   = check_clickjacking(target)
    http_method_result = check_http_methods(target)

    print(Fore.YELLOW + "  Phase 2: Advanced Checks..." + Style.RESET_ALL)
    takeover_result  = check_subdomain_takeover(subdomains if subdomains else [])
    sensitive_result = find_sensitive_files(target)
    real_ip_result   = find_real_ip(target)
    api_result       = check_api_security(target)

    print(Fore.YELLOW + "  Phase 3: Calculating risk score..." + Style.RESET_ALL)
    all_findings = []
    for issue in cors_result["issues"]:
        if issue["severity"] not in ["INFO", "ERROR"]:
            all_findings.append({**issue, "type": "CORS", "category": "web_security"})
    for issue in cookie_result["issues"]:
        all_findings.append({**issue, "type": "Cookie", "category": "web_security"})
    for detail in clickjack_result["details"]:
        if detail["severity"] == "HIGH":
            all_findings.append({**detail, "type": "Clickjacking", "category": "web_security"})
    for issue in http_method_result["issues"]:
        all_findings.append({**issue, "type": "HTTP Methods", "category": "network_security"})
    for f in sensitive_result["found"]:
        all_findings.append({"severity": f["severity"], "detail": f["detail"], "type": "Sensitive Files", "category": "web_security"})
    for issue in api_result["issues"]:
        all_findings.append({**issue, "type": "API Exposure", "category": "web_security"})

    cvss_result  = calculate_cvss(all_findings)
    mitre_result = map_mitre_attack(all_findings)

    print_web_security_results(
        cors_result, cookie_result, clickjack_result, http_method_result,
        takeover_result, sensitive_result, real_ip_result,
        api_result, cvss_result, mitre_result
    )

    # ── WEB APPLICATION SCANNER ──
    print_section("WEB APPLICATION SECURITY")
    print(Fore.YELLOW + "\n  Running web app security checks...\n" + Style.RESET_ALL)
    print(Fore.YELLOW + "  [1/4] Detecting technology stack..." + Style.RESET_ALL)
    tech_stack = detect_technology_stack(target)
    print(Fore.YELLOW + "  [2/4] Analyzing JWT tokens..." + Style.RESET_ALL)
    jwt_results = analyze_jwt_tokens(target)
    print(Fore.YELLOW + "  [3/4] Testing GraphQL security..." + Style.RESET_ALL)
    graphql_results = test_graphql_security(target)
    print(Fore.YELLOW + "  [4/4] Checking WebSocket security..." + Style.RESET_ALL)
    ws_results = check_websocket_security(target)
    print_web_app_results(tech_stack, jwt_results, graphql_results, ws_results)

    # ── CVE CHECKER ──
    print_section("CVE VULNERABILITY CHECKER")
    print(Fore.YELLOW + "\n  Checking detected technologies for CVEs...\n" + Style.RESET_ALL)
    cve_results = check_cves_for_tech(tech_stack)
    print_cve_results(cve_results)

    # ── SCREENSHOT ──
    print_section("WEBSITE SCREENSHOT")
    print(f"  Capturing screenshot of {target}...")
    screenshot = take_screenshot(target)
    if screenshot["success"]:
        print(Fore.GREEN + f"  ✅ Screenshot saved: {screenshot['filename']}" + Style.RESET_ALL)
        print(f"  📄 Page Title    : {screenshot['title']}")
        print(f"  🔗 Final URL     : {screenshot['final_url']}")
        if screenshot.get("redirected"):
            print(Fore.YELLOW + f"  ⚠️  Redirect detected!" + Style.RESET_ALL)
    else:
        print(Fore.RED + f"  [!] Screenshot failed: {screenshot.get('error', 'Unknown error')}" + Style.RESET_ALL)

    # ── HIDDEN PANEL FINDER ──
    print_section("HIDDEN PANEL FINDER")
    print(f"  Scanning paths on {target}...")
    print(f"  Please wait...\n")
    panel_results = find_admin_panels(target)
    scan_summary["panels_found"] = panel_results["found_count"]
    print(f"  Scanned  : {panel_results['total_scanned']} paths")
    print(f"  Found    : {panel_results['found_count']} accessible paths\n")
    if panel_results["panels"]:
        for panel in panel_results["panels"]:
            risk = panel.get("risk", "MEDIUM")
            if risk == "CRITICAL":
                color, icon = Fore.RED, "🔴"
            elif risk == "HIGH":
                color, icon = Fore.RED, "🟠"
            else:
                color, icon = Fore.YELLOW, "🟡"
            note = f" ({panel.get('note', '')})" if panel.get("note") else ""
            print(color + f"  {icon} [{risk:8}] {panel['path']:25} → {panel['url']}{note}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "  ✅ No exposed panels found" + Style.RESET_ALL)

    # ── EMAIL BREACH CHECK ──
    print_section("EMAIL BREACH CHECK")
    email_result = None
    email = input(Fore.YELLOW + "  [?] Enter email to check (or press Enter to skip): " + Style.RESET_ALL)
    if email.strip():
        if check_email_format(email):
            print(f"  Checking {email}...")
            email_result = check_email_breach(email)
            if "error" in email_result:
                print(Fore.RED + f"  [!] {email_result['error']}" + Style.RESET_ALL)
            elif email_result["breached"]:
                print(Fore.RED + f"  ⚠️  BREACHED! Found in {email_result['breach_count']} breaches:" + Style.RESET_ALL)
                for breach in email_result["breaches"][:5]:
                    print(f"    → {breach}")
                scan_summary["email_breaches"] = email_result["breach_count"]
            else:
                print(Fore.GREEN + f"  ✅ No breaches found for {email}" + Style.RESET_ALL)
        else:
            print(f"  [!] Invalid email format")
    else:
        print(f"  [i] Skipped")

    # ── SOCIAL MEDIA SCAN ──
    print_section("SOCIAL MEDIA USERNAME SCAN")
    social_results = None
    username = input(Fore.YELLOW + "  [?] Enter username to search (or press Enter to skip): " + Style.RESET_ALL)
    if username.strip():
        print(f"\n  Searching for '{username}' across platforms...\n")
        social_results = check_username(username)
        found_count = 0
        not_found   = []
        for platform, data in social_results.items():
            if data["found"]:
                found_count += 1
                print(Fore.GREEN + f"  ✅ FOUND    {platform:15} → {data['url']}" + Style.RESET_ALL)
            else:
                not_found.append(platform)
        if not_found:
            print(Fore.RED + f"\n  ❌ NOT FOUND: {', '.join(not_found)}" + Style.RESET_ALL)
        print(f"\n  📊 Found on {found_count}/{len(social_results)} platforms")
    else:
        print(f"  [i] Skipped")

    # ── AI THREAT SUMMARY ──
    print_section("🧠 AI THREAT SUMMARY")
    if not GROQ_API_KEY or GROQ_API_KEY == "your_groq_key_here":
        print(f"  [!] Please add your Groq API key in main.py")
        print(f"  [i] Get free key at: console.groq.com")
    else:
        print(f"  Analyzing all scan results with AI...\n")
        ai_result = generate_threat_summary(scan_summary, GROQ_API_KEY)
        if ai_result["success"]:
            print(Fore.CYAN + "─" * 45 + Style.RESET_ALL)
            print(ai_result["summary"])
            print(Fore.CYAN + "─" * 45 + Style.RESET_ALL)
        else:
            print(Fore.RED + f"  [!] AI Summary failed: {ai_result['error']}" + Style.RESET_ALL)

    # ── GENERATING REPORTS ──
    print_section("GENERATING REPORTS")

    # Basic recon report
    try:
        filename = generate_report(
            target, whois_data, dns_data,
            ip, geo, rep, subdomains,
            email_result, social_results
        )
        print(Fore.GREEN + f"  ✅ Recon report saved : {filename}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"  [!] Recon report error: {e}" + Style.RESET_ALL)

    # Professional pentest report
    try:
        print(Fore.YELLOW + "\n  Generating professional pentest report..." + Style.RESET_ALL)
        pentest_scan_data = {
            "domain":          target,
            "date":            datetime.now().strftime("%Y-%m-%d"),
            "ip":              ip or "N/A",
            "registrar":       whois_data.get("registrar", "N/A"),
            "country":         whois_data.get("country",   "N/A"),
            "isp":             geo.get("isp",      "N/A") if geo else "N/A",
            "org":             geo.get("org",      "N/A") if geo else "N/A",
            "city":            geo.get("city",     "N/A") if geo else "N/A",
            "timezone":        geo.get("timezone", "N/A") if geo else "N/A",
            "vt_score":        scan_summary.get("vt_score", "N/A"),
            "abuse_score":     scan_summary.get("abuse_score", 0),
            "open_ports":      scan_summary.get("open_ports", []),
            "subdomain_count": len(subdomains) if subdomains else 0,
        }
        pentest_filename = generate_pentest_report(
            target,
            pentest_scan_data,
            all_findings,
            mitre_result if 'mitre_result' in locals() else []
        )
        print(Fore.GREEN + f"  ✅ Pentest report saved: {pentest_filename}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"  [!] Pentest report error: {e}" + Style.RESET_ALL)

    print(Fore.CYAN + f"\n{'='*45}" + Style.RESET_ALL)
    print(Fore.GREEN + "  ✅ Recon Complete!" + Style.RESET_ALL)
    print(Fore.CYAN + f"{'='*45}\n" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
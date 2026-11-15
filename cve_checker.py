# modules/cve_checker.py

import requests
import urllib3
from colorama import Fore, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Known vulnerable versions database
VULNERABLE_VERSIONS = {
    "jquery": [
        {"version_max": "3.4.0", "cve": "CVE-2020-11022", "cvss": 6.1, "desc": "XSS via jQuery.htmlPrefilter"},
        {"version_max": "3.4.0", "cve": "CVE-2020-11023", "cvss": 6.1, "desc": "XSS passing HTML to manipulation methods"},
        {"version_max": "1.9.0", "cve": "CVE-2015-9251",  "cvss": 6.1, "desc": "XSS vulnerability in jQuery"},
        {"version_max": "3.0.0", "cve": "CVE-2019-11358", "cvss": 6.1, "desc": "Prototype pollution via Object.assign"},
    ],
    "bootstrap": [
        {"version_max": "3.4.0", "cve": "CVE-2019-8331",  "cvss": 6.1, "desc": "XSS in tooltip/popover data-template"},
        {"version_max": "4.1.2", "cve": "CVE-2018-14041", "cvss": 6.1, "desc": "XSS in data-target attribute"},
        {"version_max": "4.0.0", "cve": "CVE-2018-14042", "cvss": 6.1, "desc": "XSS in data-container attribute"},
    ],
    "angular": [
        {"version_max": "1.6.0", "cve": "CVE-2020-7676",  "cvss": 6.1, "desc": "XSS via ng-attr attribute"},
        {"version_max": "1.5.0", "cve": "CVE-2019-14863", "cvss": 6.1, "desc": "Prototype pollution"},
    ],
    "lodash": [
        {"version_max": "4.17.19", "cve": "CVE-2020-8203",  "cvss": 7.4, "desc": "Prototype pollution via zipObjectDeep"},
        {"version_max": "4.17.15", "cve": "CVE-2019-10744", "cvss": 9.1, "desc": "Prototype pollution via defaultsDeep"},
        {"version_max": "4.17.11", "cve": "CVE-2018-16487", "cvss": 9.8, "desc": "Prototype pollution via merge/mergeWith"},
    ],
    "moment": [
        {"version_max": "2.29.1", "cve": "CVE-2022-24785", "cvss": 7.5, "desc": "Path traversal in moment.locale()"},
        {"version_max": "2.29.3", "cve": "CVE-2022-31129", "cvss": 7.5, "desc": "ReDoS in rfc2822 regex"},
    ],
    "nginx": [
        {"version_max": "1.20.0", "cve": "CVE-2021-23017", "cvss": 9.4, "desc": "1-byte memory overwrite in DNS resolver"},
        {"version_max": "1.17.7", "cve": "CVE-2019-20372", "cvss": 5.3, "desc": "HTTP request smuggling"},
    ],
    "apache": [
        {"version_max": "2.4.49", "cve": "CVE-2021-41773", "cvss": 9.8, "desc": "Path traversal and RCE"},
        {"version_max": "2.4.50", "cve": "CVE-2021-42013", "cvss": 9.8, "desc": "Path traversal and RCE (bypass)"},
        {"version_max": "2.4.51", "cve": "CVE-2021-40438", "cvss": 9.0, "desc": "SSRF via mod_proxy"},
    ],
    "openssl": [
        {"version_max": "1.0.2", "cve": "CVE-2016-0800",  "cvss": 5.9, "desc": "DROWN attack - SSLv2"},
        {"version_max": "1.1.1", "cve": "CVE-2022-0778",  "cvss": 7.5, "desc": "Infinite loop in BN_mod_sqrt()"},
    ],
    "wordpress": [
        {"version_max": "5.8.2", "cve": "CVE-2022-21661", "cvss": 7.5, "desc": "SQL injection via WP_Query"},
        {"version_max": "5.8.2", "cve": "CVE-2022-21662", "cvss": 8.0, "desc": "XSS stored via post slugs"},
        {"version_max": "5.8.2", "cve": "CVE-2022-21663", "cvss": 7.2, "desc": "Object injection via Meta Data"},
    ],
    "drupal": [
        {"version_max": "8.6.9", "cve": "CVE-2019-6340",  "cvss": 9.8, "desc": "Remote code execution via REST API"},
        {"version_max": "7.57",  "cve": "CVE-2018-7600",  "cvss": 9.8, "desc": "Drupalgeddon2 - RCE"},
    ],
    "php": [
        {"version_max": "7.4.0", "cve": "CVE-2019-11043", "cvss": 9.8, "desc": "RCE in FPM/FastCGI"},
        {"version_max": "8.0.0", "cve": "CVE-2021-21703", "cvss": 7.0, "desc": "Local privilege escalation"},
    ],
}


def parse_version(version_str):
    """Parse version string to tuple for comparison"""
    try:
        parts = re.findall(r'\d+', version_str)
        return tuple(int(p) for p in parts[:3])
    except Exception:
        return (0, 0, 0)


def is_vulnerable(current_version, max_version):
    """Check if current version is <= max vulnerable version"""
    try:
        current = parse_version(current_version)
        maximum = parse_version(max_version)
        return current <= maximum
    except Exception:
        return False


def check_nvd_api(software, version):
    """Check NVD (National Vulnerability Database) for CVEs"""
    results = []
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={software}+{version}&resultsPerPage=5"
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            for vuln in vulns[:3]:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "N/A")
                desc = cve.get("descriptions", [{}])[0].get("value", "N/A")[:100]
                metrics = cve.get("metrics", {})
                cvss_score = 0
                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                results.append({
                    "cve": cve_id,
                    "cvss": cvss_score,
                    "desc": desc,
                    "source": "NVD"
                })
    except Exception:
        pass
    return results


def check_cves_for_tech(tech_stack):
    """Check CVEs for detected technology stack"""
    import re
    results = {
        "vulnerabilities": [],
        "checked": [],
        "total_vulns": 0,
        "critical": 0,
        "high": 0,
        "medium": 0
    }

    # Check JS libraries
    for lib in tech_stack.get("js_libraries", []):
        lib_lower = lib.lower()

        for tech_name, vuln_list in VULNERABLE_VERSIONS.items():
            if tech_name in lib_lower:
                # Extract version
                version_match = re.search(r'(\d+\.\d+\.?\d*)', lib)
                if version_match:
                    version = version_match.group(1)
                    results["checked"].append(f"{lib}")

                    for vuln in vuln_list:
                        if is_vulnerable(version, vuln["version_max"]):
                            cvss = vuln["cvss"]
                            if cvss >= 9.0:
                                severity = "CRITICAL"
                                results["critical"] += 1
                            elif cvss >= 7.0:
                                severity = "HIGH"
                                results["high"] += 1
                            else:
                                severity = "MEDIUM"
                                results["medium"] += 1

                            results["vulnerabilities"].append({
                                "software": lib,
                                "cve": vuln["cve"],
                                "cvss": cvss,
                                "severity": severity,
                                "desc": vuln["desc"],
                                "current_version": version,
                                "vulnerable_below": vuln["version_max"]
                            })

    # Check web server
    web_server = tech_stack.get("web_server", "")
    if web_server and web_server != "Unknown":
        server_lower = web_server.lower()
        for tech_name, vuln_list in VULNERABLE_VERSIONS.items():
            if tech_name in server_lower:
                version_match = re.search(r'(\d+\.\d+\.?\d*)', web_server)
                if version_match:
                    version = version_match.group(1)
                    results["checked"].append(f"{web_server}")

                    for vuln in vuln_list:
                        if is_vulnerable(version, vuln["version_max"]):
                            cvss = vuln["cvss"]
                            if cvss >= 9.0:
                                severity = "CRITICAL"
                                results["critical"] += 1
                            elif cvss >= 7.0:
                                severity = "HIGH"
                                results["high"] += 1
                            else:
                                severity = "MEDIUM"
                                results["medium"] += 1

                            results["vulnerabilities"].append({
                                "software": web_server,
                                "cve": vuln["cve"],
                                "cvss": cvss,
                                "severity": severity,
                                "desc": vuln["desc"],
                                "current_version": version,
                                "vulnerable_below": vuln["version_max"]
                            })

    # Check CMS
    cms = tech_stack.get("cms", "")
    if cms and cms not in ["None detected", "Unknown"]:
        cms_lower = cms.lower()
        for tech_name, vuln_list in VULNERABLE_VERSIONS.items():
            if tech_name in cms_lower:
                results["checked"].append(cms)
                # Add known CMS vulns without version check
                for vuln in vuln_list[:2]:
                    results["vulnerabilities"].append({
                        "software": cms,
                        "cve": vuln["cve"],
                        "cvss": vuln["cvss"],
                        "severity": "HIGH",
                        "desc": vuln["desc"],
                        "current_version": "Unknown",
                        "vulnerable_below": vuln["version_max"]
                    })

    # Also check NVD for web server
    if web_server and web_server != "Unknown" and len(web_server) > 3:
        nvd_results = check_nvd_api(web_server.split("/")[0], "")
        for nvd_vuln in nvd_results:
            cvss = nvd_vuln["cvss"]
            if cvss >= 9.0:
                severity = "CRITICAL"
                results["critical"] += 1
            elif cvss >= 7.0:
                severity = "HIGH"
                results["high"] += 1
            else:
                severity = "MEDIUM"
                results["medium"] += 1

            results["vulnerabilities"].append({
                "software": web_server,
                "cve": nvd_vuln["cve"],
                "cvss": cvss,
                "severity": severity,
                "desc": nvd_vuln["desc"],
                "current_version": "Detected",
                "vulnerable_below": "Check NVD",
                "source": "NVD Live"
            })

    # Sort by CVSS score
    results["vulnerabilities"].sort(key=lambda x: x["cvss"], reverse=True)
    results["total_vulns"] = len(results["vulnerabilities"])

    return results


def print_cve_results(cve_results):
    """Print CVE check results"""

    print(Fore.CYAN + "\n  ═══ CVE VULNERABILITY CHECKER ═══" + Style.RESET_ALL)

    if cve_results["checked"]:
        print(Fore.YELLOW + f"\n  🔍 Technologies checked:" + Style.RESET_ALL)
        for tech in cve_results["checked"]:
            print(f"    → {tech}")

    if cve_results["vulnerabilities"]:
        print(Fore.RED + f"\n  💀 CVEs FOUND: {cve_results['total_vulns']}" + Style.RESET_ALL)
        print(f"  🔴 Critical : {cve_results['critical']}")
        print(f"  🟠 High     : {cve_results['high']}")
        print(f"  🟡 Medium   : {cve_results['medium']}")
        print()

        for vuln in cve_results["vulnerabilities"]:
            cvss = vuln["cvss"]
            severity = vuln["severity"]

            if severity == "CRITICAL":
                color, icon = Fore.RED, "🔴"
            elif severity == "HIGH":
                color, icon = Fore.RED, "🟠"
            else:
                color, icon = Fore.YELLOW, "🟡"

            print(color + f"  {icon} {vuln['cve']:20} | CVSS: {cvss:4.1f} | {severity}" + Style.RESET_ALL)
            print(f"     Software : {vuln['software']}")
            print(f"     Detail   : {vuln['desc']}")
            if vuln.get("current_version") != "Detected":
                print(f"     Version  : {vuln['current_version']} (vulnerable below {vuln['vulnerable_below']})")
            print()

    else:
        print(Fore.GREEN + "\n  ✅ No known CVEs found for detected technologies" + Style.RESET_ALL)
        print(f"  [i] This may mean:")
        print(f"    → Technologies are up to date")
        print(f"    → Version info not exposed")
        print(f"    → Technologies not in our database")
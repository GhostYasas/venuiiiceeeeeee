# modules/web_app_scanner.py

import requests
import urllib3
import re
import json
import socket
import concurrent.futures
from colorama import Fore, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# ═══════════════════════════════
# 1. TECHNOLOGY STACK DETECTOR
# ═══════════════════════════════

def detect_technology_stack(domain):
    """Detect technologies used by the website"""
    results = {
        "web_server": "Unknown",
        "framework": [],
        "cms": "None detected",
        "cdn": "None detected",
        "analytics": [],
        "js_libraries": [],
        "security_tools": [],
        "programming_language": "Unknown",
        "database": "Unknown",
        "hosting": "Unknown"
    }

    try:
        url = f"https://{domain}"
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        headers = r.headers
        body = r.text.lower()
        header_keys = {k.lower(): v for k, v in headers.items()}

        # ── Web Server ──
        server = headers.get("Server", "")
        if server:
            results["web_server"] = server

        # ── Programming Language ──
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            results["programming_language"] = powered_by
        elif "x-aspnet-version" in header_keys:
            results["programming_language"] = f"ASP.NET {header_keys.get('x-aspnet-version', '')}"
        elif "php" in server.lower():
            results["programming_language"] = "PHP"

        # ── CDN Detection ──
        cdn_indicators = {
            "Cloudflare":  ["cf-ray", "cf-cache-status", "cloudflare"],
            "Akamai":      ["x-akamai-transformed", "akamai"],
            "Fastly":      ["x-fastly-request-id", "fastly"],
            "CloudFront":  ["x-amz-cf-id", "cloudfront"],
            "Incapsula":   ["x-iinfo", "incap_ses"],
            "Sucuri":      ["x-sucuri-id", "sucuri"],
            "MaxCDN":      ["x-cdn", "maxcdn"],
        }
        for cdn_name, indicators in cdn_indicators.items():
            for indicator in indicators:
                if indicator in header_keys or indicator in body[:500]:
                    results["cdn"] = cdn_name
                    break

        # ── CMS Detection ──
        cms_indicators = {
            "WordPress":  ["wp-content", "wp-includes", "wordpress"],
            "Joomla":     ["joomla", "/components/com_"],
            "Drupal":     ["drupal", "sites/default"],
            "Shopify":    ["shopify", "cdn.shopify.com"],
            "Magento":    ["magento", "mage/cookies"],
            "Wix":        ["wix.com", "_wix_browser_sess"],
            "Squarespace":["squarespace", "static.squarespace"],
            "Ghost":      ["ghost.io", "content/themes/ghost"],
            "Django":     ["csrfmiddlewaretoken", "django"],
            "Laravel":    ["laravel_session", "laravel"],
        }
        for cms_name, indicators in cms_indicators.items():
            for indicator in indicators:
                if indicator in body:
                    results["cms"] = cms_name
                    break

        # ── Framework Detection ──
        framework_indicators = {
            "React":      ["react", "__react", "reactroot"],
            "Angular":    ["ng-version", "angular", "ng-app"],
            "Vue.js":     ["vue.js", "__vue__", "v-app"],
            "Next.js":    ["__next", "_next/static"],
            "Nuxt.js":    ["__nuxt", "_nuxt/"],
            "Bootstrap":  ["bootstrap.min.css", "bootstrap.js"],
            "jQuery":     ["jquery.min.js", "jquery-"],
            "Tailwind":   ["tailwind", "tw-"],
            "Express":    ["x-powered-by: express"],
            "Flask":      ["werkzeug", "flask"],
            "Spring":     ["x-application-context"],
        }
        for fw_name, indicators in framework_indicators.items():
            for indicator in indicators:
                if indicator in body or indicator in str(headers).lower():
                    if fw_name not in results["framework"]:
                        results["framework"].append(fw_name)

        # ── JS Libraries ──
        js_patterns = {
            "jQuery":       r'jquery[/-](\d+\.\d+\.?\d*)',
            "Bootstrap":    r'bootstrap[/-](\d+\.\d+\.?\d*)',
            "React":        r'react[/-](\d+\.\d+\.?\d*)',
            "Angular":      r'angular[/-](\d+\.\d+\.?\d*)',
            "Vue":          r'vue[/-](\d+\.\d+\.?\d*)',
            "Lodash":       r'lodash[/-](\d+\.\d+\.?\d*)',
            "Moment.js":    r'moment[/-](\d+\.\d+\.?\d*)',
            "D3.js":        r'd3[/-](\d+\.\d+\.?\d*)',
            "Chart.js":     r'chart[.-]js',
        }
        for lib_name, pattern in js_patterns.items():
            match = re.search(pattern, body)
            if match:
                version = match.group(1) if match.lastindex else ""
                entry = f"{lib_name} {version}".strip()
                if entry not in results["js_libraries"]:
                    results["js_libraries"].append(entry)

        # ── Analytics ──
        analytics_indicators = {
            "Google Analytics":  ["google-analytics.com", "gtag(", "ga("],
            "Google Tag Manager":["googletagmanager.com", "gtm.js"],
            "Facebook Pixel":    ["connect.facebook.net", "fbq("],
            "Hotjar":            ["hotjar.com", "hjid"],
            "Mixpanel":          ["mixpanel.com", "mixpanel.track"],
            "Segment":           ["segment.com", "analytics.js"],
            "Matomo":            ["matomo.js", "piwik.js"],
            "Cloudflare Insights":["static.cloudflareinsights.com"],
        }
        for analytics_name, indicators in analytics_indicators.items():
            for indicator in indicators:
                if indicator in body:
                    if analytics_name not in results["analytics"]:
                        results["analytics"].append(analytics_name)

        # ── Security Tools ──
        security_indicators = {
            "reCAPTCHA":    ["recaptcha", "google.com/recaptcha"],
            "hCaptcha":     ["hcaptcha.com"],
            "Cloudflare":   ["cloudflare.com/cdn-cgi"],
            "Sucuri WAF":   ["sucuri.net"],
            "Wordfence":    ["wordfence"],
            "ModSecurity":  ["mod_security", "modsecurity"],
        }
        for tool_name, indicators in security_indicators.items():
            for indicator in indicators:
                if indicator in body or indicator in str(headers).lower():
                    if tool_name not in results["security_tools"]:
                        results["security_tools"].append(tool_name)

        # ── Hosting ──
        hosting_indicators = {
            "AWS":          ["amazonaws.com", "aws", "amazon"],
            "Google Cloud": ["googleapis.com", "google cloud"],
            "Azure":        ["azure", "azurewebsites"],
            "Heroku":       ["heroku", "herokuapp"],
            "Netlify":      ["netlify"],
            "Vercel":       ["vercel", "now.sh"],
            "DigitalOcean": ["digitalocean"],
            "Linode":       ["linode"],
        }
        for host_name, indicators in hosting_indicators.items():
            for indicator in indicators:
                if indicator in body[:1000] or indicator in str(headers).lower():
                    results["hosting"] = host_name
                    break

    except Exception as e:
        results["error"] = str(e)

    return results


# ═══════════════════════════════
# 2. JWT TOKEN ANALYZER
# ═══════════════════════════════

def analyze_jwt_tokens(domain):
    """Find and analyze JWT tokens in responses"""
    results = {
        "tokens_found": [],
        "vulnerabilities": []
    }

    try:
        url = f"https://{domain}"
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)

        # Search in headers
        for header_name, header_value in r.headers.items():
            jwt_matches = re.findall(
                r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
                header_value
            )
            for token in jwt_matches:
                results["tokens_found"].append({
                    "location": f"Header: {header_name}",
                    "token": token[:50] + "..."
                })

        # Search in cookies
        for cookie in r.cookies:
            jwt_matches = re.findall(
                r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
                cookie.value
            )
            for token in jwt_matches:
                results["tokens_found"].append({
                    "location": f"Cookie: {cookie.name}",
                    "token": token[:50] + "..."
                })

        # Search in body
        jwt_matches = re.findall(
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
            r.text
        )
        for token in jwt_matches[:3]:
            results["tokens_found"].append({
                "location": "Response body",
                "token": token[:50] + "..."
            })

        # Analyze each token
        for token_info in results["tokens_found"]:
            token = token_info["token"].replace("...", "")
            parts = token.split(".")
            if len(parts) >= 2:
                try:
                    import base64
                    # Decode header
                    header_pad = parts[0] + "=" * (4 - len(parts[0]) % 4)
                    header_decoded = base64.urlsafe_b64decode(header_pad).decode()
                    header_json = json.loads(header_decoded)

                    alg = header_json.get("alg", "unknown")

                    if alg.lower() == "none":
                        results["vulnerabilities"].append({
                            "severity": "CRITICAL",
                            "detail": f"JWT uses 'none' algorithm! Signature bypass possible!",
                            "location": token_info["location"]
                        })
                    elif alg.lower() in ["hs256", "hs384", "hs512"]:
                        results["vulnerabilities"].append({
                            "severity": "MEDIUM",
                            "detail": f"JWT uses symmetric {alg} - weak secret possible",
                            "location": token_info["location"]
                        })

                    token_info["algorithm"] = alg
                    token_info["type"] = header_json.get("typ", "JWT")

                except Exception:
                    pass

    except Exception as e:
        results["error"] = str(e)

    return results


# ═══════════════════════════════
# 3. GRAPHQL SECURITY TESTER
# ═══════════════════════════════

def test_graphql_security(domain):
    """Test GraphQL endpoint security"""
    results = {
        "found": False,
        "endpoint": None,
        "introspection_enabled": False,
        "schema": [],
        "vulnerabilities": []
    }

    graphql_paths = [
        "/graphql", "/api/graphql", "/graphql/v1",
        "/v1/graphql", "/api/v1/graphql", "/query",
        "/gql", "/graphiql", "/playground"
    ]

    # Find GraphQL endpoint
    for path in graphql_paths:
        try:
            url = f"https://{domain}{path}"
            r = requests.get(url, headers=HEADERS, timeout=5, verify=False)
            if r.status_code in [200, 400, 405]:
                content = r.text.lower()
                if any(x in content for x in ["graphql", "query", "mutation", "__schema"]):
                    results["found"] = True
                    results["endpoint"] = path
                    break
        except Exception:
            pass

    if results["found"]:
        # Test introspection
        try:
            introspection_query = {
                "query": "{ __schema { queryType { name } types { name kind } } }"
            }
            url = f"https://{domain}{results['endpoint']}"
            r = requests.post(
                url,
                json=introspection_query,
                headers={**HEADERS, "Content-Type": "application/json"},
                timeout=10,
                verify=False
            )

            if r.status_code == 200:
                data = r.json()
                if "data" in data and "__schema" in str(data):
                    results["introspection_enabled"] = True
                    results["vulnerabilities"].append({
                        "severity": "HIGH",
                        "detail": "GraphQL introspection enabled! Full schema exposed!"
                    })

                    # Extract type names
                    schema = data.get("data", {}).get("__schema", {})
                    types = schema.get("types", [])
                    for t in types:
                        name = t.get("name", "")
                        if name and not name.startswith("__"):
                            results["schema"].append(name)

        except Exception:
            pass

        # Test for batch queries (DoS risk)
        try:
            batch_query = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
                {"query": "{ __typename }"}
            ]
            url = f"https://{domain}{results['endpoint']}"
            r = requests.post(
                url,
                json=batch_query,
                headers={**HEADERS, "Content-Type": "application/json"},
                timeout=10,
                verify=False
            )
            if r.status_code == 200 and isinstance(r.json(), list):
                results["vulnerabilities"].append({
                    "severity": "MEDIUM",
                    "detail": "Batch queries enabled! DoS attack possible!"
                })
        except Exception:
            pass

    return results


# ═══════════════════════════════
# 4. WEBSOCKET SECURITY
# ═══════════════════════════════

def check_websocket_security(domain):
    """Check for WebSocket endpoints and security"""
    results = {
        "found": False,
        "endpoints": [],
        "vulnerabilities": []
    }

    try:
        url = f"https://{domain}"
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        body = r.text

        # Search for WebSocket in source
        ws_patterns = [
            r'new WebSocket\(["\']([^"\']+)["\']',
            r'ws://([^\'">\s]+)',
            r'wss://([^\'">\s]+)',
            r'socket\.connect\(["\']([^"\']+)["\']',
            r'io\.connect\(["\']([^"\']+)["\']',
        ]

        found_endpoints = set()
        for pattern in ws_patterns:
            matches = re.findall(pattern, body)
            for match in matches:
                found_endpoints.add(match)

        if found_endpoints:
            results["found"] = True
            for endpoint in list(found_endpoints)[:5]:
                is_secure = endpoint.startswith("wss://") or "wss" in endpoint
                results["endpoints"].append({
                    "url": endpoint,
                    "secure": is_secure
                })

                if not is_secure and not endpoint.startswith("/"):
                    results["vulnerabilities"].append({
                        "severity": "HIGH",
                        "detail": f"Unencrypted WebSocket (ws://) found: {endpoint[:50]}"
                    })

        # Check for Socket.io
        if "socket.io" in body or "socket.io.js" in body:
            results["found"] = True
            results["endpoints"].append({
                "url": "/socket.io",
                "secure": True,
                "type": "Socket.io"
            })

            # Test if socket.io endpoint is accessible without auth
            try:
                sio_url = f"https://{domain}/socket.io/?EIO=4&transport=polling"
                sr = requests.get(sio_url, headers=HEADERS, timeout=5, verify=False)
                if sr.status_code == 200:
                    results["vulnerabilities"].append({
                        "severity": "MEDIUM",
                        "detail": "Socket.io endpoint accessible without authentication!"
                    })
            except Exception:
                pass

    except Exception as e:
        results["error"] = str(e)

    return results


# ═══════════════════════════════
# PRINT ALL RESULTS
# ═══════════════════════════════

def print_web_app_results(tech_stack, jwt_results, graphql_results, ws_results):
    """Print all web application scan results"""

    # ── Technology Stack ──
    print(Fore.CYAN + "\n  ═══ TECHNOLOGY STACK DETECTOR ═══" + Style.RESET_ALL)

    print(Fore.YELLOW + "\n  🖥️  SERVER & LANGUAGE:" + Style.RESET_ALL)
    print(f"  Web Server    : {tech_stack.get('web_server', 'Unknown')}")
    print(f"  Language      : {tech_stack.get('programming_language', 'Unknown')}")
    print(f"  Hosting       : {tech_stack.get('hosting', 'Unknown')}")
    print(f"  CDN           : {tech_stack.get('cdn', 'None')}")
    print(f"  CMS           : {tech_stack.get('cms', 'None')}")

    if tech_stack.get("framework"):
        print(Fore.YELLOW + "\n  🔧 FRAMEWORKS DETECTED:" + Style.RESET_ALL)
        for fw in tech_stack["framework"]:
            print(Fore.GREEN + f"  ✅ {fw}" + Style.RESET_ALL)

    if tech_stack.get("js_libraries"):
        print(Fore.YELLOW + "\n  📚 JS LIBRARIES:" + Style.RESET_ALL)
        for lib in tech_stack["js_libraries"]:
            print(f"  → {lib}")

    if tech_stack.get("analytics"):
        print(Fore.YELLOW + "\n  📊 ANALYTICS & TRACKING:" + Style.RESET_ALL)
        for analytics in tech_stack["analytics"]:
            print(f"  → {analytics}")

    if tech_stack.get("security_tools"):
        print(Fore.YELLOW + "\n  🛡️  SECURITY TOOLS:" + Style.RESET_ALL)
        for tool in tech_stack["security_tools"]:
            print(Fore.GREEN + f"  ✅ {tool}" + Style.RESET_ALL)

    # ── JWT Analysis ──
    print(Fore.CYAN + "\n  ═══ JWT TOKEN ANALYZER ═══" + Style.RESET_ALL)

    if jwt_results.get("tokens_found"):
        print(Fore.YELLOW + f"\n  🔑 JWT TOKENS FOUND: {len(jwt_results['tokens_found'])}" + Style.RESET_ALL)
        for token in jwt_results["tokens_found"]:
            print(f"  → Location  : {token['location']}")
            print(f"    Algorithm : {token.get('algorithm', 'Unknown')}")
            print(f"    Token     : {token['token']}")

        if jwt_results.get("vulnerabilities"):
            print(Fore.RED + "\n  ⚠️  JWT VULNERABILITIES:" + Style.RESET_ALL)
            for vuln in jwt_results["vulnerabilities"]:
                color = Fore.RED if vuln["severity"] == "CRITICAL" else Fore.YELLOW
                icon  = "🔴" if vuln["severity"] == "CRITICAL" else "🟡"
                print(color + f"  {icon} [{vuln['severity']}] {vuln['detail']}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "\n  ✅ No JWT tokens found in responses" + Style.RESET_ALL)

    # ── GraphQL ──
    print(Fore.CYAN + "\n  ═══ GRAPHQL SECURITY TESTER ═══" + Style.RESET_ALL)

    if graphql_results["found"]:
        print(Fore.YELLOW + f"\n  ⚡ GraphQL endpoint found: {graphql_results['endpoint']}" + Style.RESET_ALL)

        if graphql_results["introspection_enabled"]:
            print(Fore.RED + "  🔴 INTROSPECTION ENABLED! Schema exposed!" + Style.RESET_ALL)
            if graphql_results["schema"]:
                print(f"\n  Exposed types ({len(graphql_results['schema'])}):")
                for type_name in graphql_results["schema"][:10]:
                    print(f"    → {type_name}")

        if graphql_results["vulnerabilities"]:
            for vuln in graphql_results["vulnerabilities"]:
                color = Fore.RED if vuln["severity"] == "HIGH" else Fore.YELLOW
                print(color + f"  ⚠️  [{vuln['severity']}] {vuln['detail']}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "\n  ✅ No GraphQL endpoints found" + Style.RESET_ALL)

    # ── WebSocket ──
    print(Fore.CYAN + "\n  ═══ WEBSOCKET SECURITY ═══" + Style.RESET_ALL)

    if ws_results["found"]:
        print(Fore.YELLOW + f"\n  🔌 WebSocket endpoints found: {len(ws_results['endpoints'])}" + Style.RESET_ALL)
        for ep in ws_results["endpoints"]:
            secure_icon = "✅" if ep.get("secure") else "🔴"
            print(f"  {secure_icon} {ep['url'][:60]}")

        if ws_results["vulnerabilities"]:
            print(Fore.RED + "\n  ⚠️  WEBSOCKET VULNERABILITIES:" + Style.RESET_ALL)
            for vuln in ws_results["vulnerabilities"]:
                color = Fore.RED if vuln["severity"] == "HIGH" else Fore.YELLOW
                print(color + f"  🔴 [{vuln['severity']}] {vuln['detail']}" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "  ✅ No WebSocket vulnerabilities found" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "\n  ✅ No WebSocket endpoints found" + Style.RESET_ALL)
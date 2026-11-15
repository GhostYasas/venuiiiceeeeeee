# modules/port_scanner.py

import socket
import concurrent.futures
from datetime import datetime

# Common ports with service names and risk levels
COMMON_PORTS = {
    21:   {"service": "FTP",        "risk": "HIGH",   "reason": "File transfer - often exploited"},
    22:   {"service": "SSH",        "risk": "MEDIUM", "reason": "Remote access - brute force target"},
    23:   {"service": "Telnet",     "risk": "HIGH",   "reason": "Unencrypted remote access"},
    25:   {"service": "SMTP",       "risk": "MEDIUM", "reason": "Email server"},
    53:   {"service": "DNS",        "risk": "LOW",    "reason": "Domain name resolution"},
    80:   {"service": "HTTP",       "risk": "LOW",    "reason": "Web server (unencrypted)"},
    110:  {"service": "POP3",       "risk": "MEDIUM", "reason": "Email retrieval"},
    135:  {"service": "RPC",        "risk": "HIGH",   "reason": "Windows RPC - common attack vector"},
    139:  {"service": "NetBIOS",    "risk": "HIGH",   "reason": "Windows file sharing vulnerability"},
    143:  {"service": "IMAP",       "risk": "MEDIUM", "reason": "Email retrieval"},
    443:  {"service": "HTTPS",      "risk": "LOW",    "reason": "Secure web server"},
    445:  {"service": "SMB",        "risk": "HIGH",   "reason": "EternalBlue/WannaCry target"},
    1433: {"service": "MSSQL",      "risk": "HIGH",   "reason": "Microsoft SQL Server exposed"},
    1521: {"service": "Oracle DB",  "risk": "HIGH",   "reason": "Oracle database exposed"},
    3306: {"service": "MySQL",      "risk": "HIGH",   "reason": "Database exposed to internet"},
    3389: {"service": "RDP",        "risk": "HIGH",   "reason": "Remote desktop - ransomware target"},
    5432: {"service": "PostgreSQL", "risk": "HIGH",   "reason": "Database exposed to internet"},
    5900: {"service": "VNC",        "risk": "HIGH",   "reason": "Remote desktop unencrypted"},
    6379: {"service": "Redis",      "risk": "HIGH",   "reason": "Often misconfigured, no auth"},
    8080: {"service": "HTTP-Alt",   "risk": "MEDIUM", "reason": "Alternative web server port"},
    8443: {"service": "HTTPS-Alt",  "risk": "LOW",    "reason": "Alternative secure web port"},
    9200: {"service": "Elasticsearch", "risk": "HIGH","reason": "Often exposed without auth"},
    27017:{"service": "MongoDB",    "risk": "HIGH",   "reason": "Database often left open"},
}

def scan_port(ip, port, timeout=1):
    """Scan a single port - returns True if open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def scan_ports(ip, ports=None, timeout=1):
    """
    Scan multiple ports using threading for speed
    Returns list of open ports with service info
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    start_time = datetime.now()

    # Use threading to scan multiple ports simultaneously
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
                if is_open:
                    port_info = COMMON_PORTS.get(port, {
                        "service": "Unknown",
                        "risk": "MEDIUM",
                        "reason": "Unknown service"
                    })
                    open_ports.append({
                        "port": port,
                        "service": port_info["service"],
                        "risk": port_info["risk"],
                        "reason": port_info["reason"]
                    })
            except Exception:
                pass

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])

    scan_time = (datetime.now() - start_time).seconds

    return {
        "ip": ip,
        "total_scanned": len(ports),
        "open_count": len(open_ports),
        "scan_time": scan_time,
        "open_ports": open_ports
    }

def get_risk_summary(scan_results):
    """Summarize risk levels from scan"""
    high = 0
    medium = 0
    low = 0

    for port in scan_results["open_ports"]:
        if port["risk"] == "HIGH":
            high += 1
        elif port["risk"] == "MEDIUM":
            medium += 1
        else:
            low += 1

    if high > 0:
        overall = "HIGH"
    elif medium > 0:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    return {
        "overall": overall,
        "high": high,
        "medium": medium,
        "low": low
    }
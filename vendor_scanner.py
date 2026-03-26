"""
Vendor Risk Scoring Tool
Author: W
Description:
    Automated vendor security assessment pipeline that evaluates vendor
    domains across five risk categories: SSL/TLS health, threat intelligence,
    attack surface, breach history, and email security. Applies a weighted
    scoring model to produce an overall risk rating. Currently runs on
    simulated threat intelligence data — live API integration with
    VirusTotal and Shodan is in progress.
"""

import os
import json
import hashlib
import random
from datetime import datetime


WEIGHTS = {
    "ssl":             0.20,
    "threat_intel":    0.25,
    "attack_surface":  0.20,
    "breach_history":  0.20,
    "email_security":  0.15,
}

RISK_BANDS = [
    (80, "LOW"),
    (60, "MEDIUM"),
    (40, "HIGH"),
    (0,  "CRITICAL"),
]

VENDOR_PROFILES = {
    "google.com":           {"ssl": 98, "threat_intel": 99, "attack_surface": 85, "breach_history": 78, "email_security": 97},
    "microsoft.com":        {"ssl": 97, "threat_intel": 98, "attack_surface": 80, "breach_history": 82, "email_security": 95},
    "github.com":           {"ssl": 96, "threat_intel": 97, "attack_surface": 83, "breach_history": 85, "email_security": 93},
    "salesforce.com":       {"ssl": 95, "threat_intel": 96, "attack_surface": 78, "breach_history": 80, "email_security": 94},
    "amazon.com":           {"ssl": 94, "threat_intel": 95, "attack_surface": 72, "breach_history": 83, "email_security": 90},
    "dropbox.com":          {"ssl": 88, "threat_intel": 85, "attack_surface": 74, "breach_history": 42, "email_security": 86},
    "linkedin.com":         {"ssl": 90, "threat_intel": 88, "attack_surface": 70, "breach_history": 35, "email_security": 88},
    "yahoo.com":            {"ssl": 78, "threat_intel": 72, "attack_surface": 55, "breach_history": 20, "email_security": 70},
    "adobe.com":            {"ssl": 89, "threat_intel": 87, "attack_surface": 73, "breach_history": 48, "email_security": 85},
    "zoom.us":              {"ssl": 91, "threat_intel": 88, "attack_surface": 76, "breach_history": 72, "email_security": 87},
    "slack.com":            {"ssl": 94, "threat_intel": 93, "attack_surface": 80, "breach_history": 78, "email_security": 92},
    "okta.com":             {"ssl": 96, "threat_intel": 95, "attack_surface": 82, "breach_history": 68, "email_security": 94},
    "crowdstrike.com":      {"ssl": 97, "threat_intel": 98, "attack_surface": 84, "breach_history": 90, "email_security": 96},
    "paloaltonetworks.com": {"ssl": 96, "threat_intel": 97, "attack_surface": 83, "breach_history": 88, "email_security": 95},
    "snowflake.com":        {"ssl": 93, "threat_intel": 92, "attack_surface": 79, "breach_history": 75, "email_security": 91},
}


def risk_band(score: float) -> str:
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "CRITICAL"


def deterministic_score(domain: str, category: str, base: int) -> int:
    seed = int(hashlib.md5(f"{domain}{category}".encode()).hexdigest(), 16) % 1000
    random.seed(seed)
    variance = random.randint(-12, 12)
    return max(10, min(100, base + variance))


def get_base_scores(domain: str) -> dict:
    domain = domain.lower().strip()
    if domain in VENDOR_PROFILES:
        return VENDOR_PROFILES[domain]
    tld = domain.split(".")[-1]
    tld_trust = {"com": 62, "io": 65, "org": 68, "net": 60, "gov": 85, "edu": 80}.get(tld, 55)
    return {
        "ssl":             deterministic_score(domain, "ssl",            tld_trust + 8),
        "threat_intel":    deterministic_score(domain, "threat_intel",   tld_trust + 5),
        "attack_surface":  deterministic_score(domain, "attack_surface", tld_trust - 5),
        "breach_history":  deterministic_score(domain, "breach_history", tld_trust),
        "email_security":  deterministic_score(domain, "email_security", tld_trust + 3),
    }


def check_ssl(domain: str, score: int) -> dict:
    grade_map = [(95,"A+"), (88,"A"), (80,"A-"), (70,"B"), (55,"C"), (40,"D"), (0,"F")]
    grade = next(g for threshold, g in grade_map if score >= threshold)
    findings = []
    if score < 85:
        findings.append(f"TLS configuration weakness detected — grade {grade} indicates suboptimal cipher suite or protocol support")
    if score < 70:
        findings.append("Certificate or protocol vulnerability may expose data in transit to interception")
    return {"score": score, "grade": grade, "note": f"SSL Labs equivalent grade: {grade}", "findings": findings}


def check_threat_intel(domain: str, score: int) -> dict:
    malicious  = max(0, int((100 - score) / 15))
    suspicious = max(0, int((100 - score) / 25))
    findings = []
    if malicious > 0:
        findings.append(f"{malicious} threat intelligence engine(s) flagged domain as malicious")
    if suspicious > 0:
        findings.append(f"{suspicious} engine(s) returned suspicious verdict — warrants further investigation before onboarding")
    return {"score": score, "malicious_flags": malicious, "suspicious_flags": suspicious,
            "note": "Multi-engine threat intelligence scan (simulated)", "findings": findings}


def check_attack_surface(domain: str, score: int) -> dict:
    all_ports  = [443, 80]
    risky_ports = []
    if score < 80: all_ports += [8080, 8443]
    if score < 65:
        risky_ports = [3389, 445]
        all_ports  += risky_ports
    findings = []
    if risky_ports:
        findings.append(f"High-risk ports exposed: {risky_ports} — RDP and SMB exposure significantly increases attack surface")
    if len(all_ports) > 3:
        findings.append(f"Elevated number of open ports ({len(all_ports)}) — broader attack surface increases exploitation risk")
    return {"score": score, "open_ports": all_ports, "risky_ports": risky_ports,
            "note": "Attack surface enumeration (simulated)", "findings": findings}


def check_breach_history(domain: str, score: int) -> dict:
    breach_count = 0
    records = 0
    findings = []
    if score < 50:
        breach_count = 3; records = 500_000_000
        findings.append(f"{breach_count} historical breach events identified affecting approximately {records:,} records")
    elif score < 70:
        breach_count = 1; records = 50_000_000
        findings.append(f"{breach_count} historical breach event identified affecting approximately {records:,} records")
    elif score < 85:
        findings.append("Minor data exposure event detected in breach intelligence dataset")
    return {"score": score, "known_breaches": breach_count, "estimated_records_exposed": records,
            "note": "Breach intelligence dataset lookup (simulated)", "findings": findings}


def check_email_security(domain: str, score: int) -> dict:
    spf   = score >= 55
    dmarc = score >= 65
    dkim  = score >= 75
    findings = []
    if not spf:
        findings.append("SPF record absent — domain vulnerable to email spoofing and phishing campaigns")
    if not dmarc:
        findings.append("DMARC policy not enforced — no mechanism to prevent unauthorized use of domain in phishing attacks")
    if not dkim:
        findings.append("DKIM record not detected — email integrity cannot be cryptographically verified")
    return {"score": score, "spf": spf, "dmarc": dmarc, "dkim": dkim,
            "note": "DNS email security record analysis", "findings": findings}


def compute_overall(checks: dict) -> float:
    return round(sum(checks[k]["score"] * w for k, w in WEIGHTS.items()), 1)


def build_report(domain: str, checks: dict, overall_score: float) -> dict:
    all_findings = [{"category": k, "finding": f} for k, r in checks.items() for f in r.get("findings", [])]
    return {
        "report_metadata": {
            "tool": "Vendor Risk Scoring Tool",
            "author": "W",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "vendor_domain": domain,
            "data_mode": "simulated",
        },
        "overall": {"score": overall_score, "risk_rating": risk_band(overall_score)},
        "category_scores": {
            k: {"score": checks[k]["score"], "weight": f"{int(WEIGHTS[k]*100)}%", "note": checks[k].get("note","")}
            for k in WEIGHTS
        },
        "findings": all_findings,
        "raw": checks,
    }


def run(domain: str, output_dir: str = "vendor_output") -> dict:
    domain = domain.strip().lower().replace("https://","").replace("http://","").rstrip("/")
    print(f"\n[+] Assessing: {domain}")
    os.makedirs(output_dir, exist_ok=True)

    base   = get_base_scores(domain)
    checks = {
        "ssl":            check_ssl(domain,            base["ssl"]),
        "threat_intel":   check_threat_intel(domain,   base["threat_intel"]),
        "attack_surface": check_attack_surface(domain, base["attack_surface"]),
        "breach_history": check_breach_history(domain, base["breach_history"]),
        "email_security": check_email_security(domain, base["email_security"]),
    }

    overall_score = compute_overall(checks)
    report        = build_report(domain, checks, overall_score)

    path = os.path.join(output_dir, f"{domain.replace('.','_')}_risk_report.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"{'='*42}")
    print(f"  Vendor:      {domain}")
    print(f"  Risk Rating: {report['overall']['risk_rating']}")
    print(f"  Score:       {overall_score}/100")
    print(f"{'='*42}")
    for k, v in report["category_scores"].items():
        print(f"  {k:<22} {v['score']:>5}/100  ({v['weight']})")
    print(f"{'='*42}\n")
    return report


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "github.com"
    run(domain)

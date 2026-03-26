# Vendor Risk Scoring Tool

I built this because a lot of my work doing third-party vendor risk assessments involves manually pulling security signals from different sources and piecing together a risk picture. I wanted to see if I could automate that process and actually understand how the scoring works under the hood rather than just using a commercial tool.

You give it a vendor domain, it runs five security checks, and spits out a risk rating with a breakdown of findings.

## What it checks

**SSL/TLS** grades the certificate and TLS configuration strength.

**Threat Intelligence** checks for malicious or suspicious flags across security engine data.

**Attack Surface** looks at open port exposure and risky services.

**Breach History** checks for known historical data breach events.

**Email Security** verifies SPF, DMARC, and DKIM DNS records.

Each category gets a score out of 100. They're weighted into an overall rating of Low, Medium, High, or Critical.

## Scoring weights

| Category | Weight |
|----------|--------|
| Threat Intelligence | 25% |
| SSL/TLS Health | 20% |
| Attack Surface | 20% |
| Breach History | 20% |
| Email Security | 15% |

Threat intel is weighted highest because active malicious classification is the strongest signal. Breach history and attack surface are weighted equally because both reflect systemic security gaps that compound over time.

## Stack

Python, Flask, deterministic scoring engine, JSON report output. Currently runs on simulated threat intelligence data with realistic domain profiles. Live VirusTotal and Shodan integration is next.

## Running it

```bash
git clone https://github.com/yourusername/vendor-risk-scanner
cd vendor-risk-scanner
pip install flask
```

CLI:
```bash
python vendor_scanner.py github.com
```

Web UI:
```bash
python vendor_app.py
```
Then open http://localhost:5001

## What's next

Adding live API calls to VirusTotal and Shodan, batch scanning for multiple vendors at once, and historical score tracking so you can see how a vendor's posture changes over time.

Security+ | ISC2 CC | AZ-900

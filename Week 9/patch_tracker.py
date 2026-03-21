import json
from datetime import datetime
from collections import Counter

# -----------------------------
# Load Inventory
# -----------------------------
def load_inventory(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

# -----------------------------
# Date Calculation
# -----------------------------
def calculate_days_since_patch(host):
    patch_date = datetime.strptime(host['last_patch_date'], '%Y-%m-%d')
    return (datetime.now() - patch_date).days

# -----------------------------
# Filters
# -----------------------------
def filter_by_os(hosts, os_type):
    return [h for h in hosts if os_type.lower() in h['os'].lower()]

def filter_by_criticality(hosts, level):
    return [h for h in hosts if h['criticality'] == level]

def filter_by_environment(hosts, env):
    return [h for h in hosts if h['environment'] == env]

def filter_critical_production(hosts):
    return [
        h for h in hosts
        if h['criticality'] == 'critical' and h['environment'] == 'production'
    ]

# -----------------------------
# Risk Scoring
# -----------------------------
def calculate_risk_score(host):
    score = 0

    # Criticality
    criticality_points = {
        "critical": 40,
        "high": 25,
        "medium": 10,
        "low": 5
    }
    score += criticality_points.get(host['criticality'], 0)

    # Patch Age (ORDER MATTERS)
    days = host.get('days_since_patch', 0)
    if days > 90:
        score += 30
    elif days > 60:
        score += 20
    elif days > 30:
        score += 10

    # Environment
    env_points = {
        "production": 15,
        "staging": 8,
        "development": 3
    }
    score += env_points.get(host['environment'], 0)

    # Tags
    tags = host.get('tags', [])
    if 'pci-scope' in tags:
        score += 10
    if 'hipaa' in tags:
        score += 10
    if 'internet-facing' in tags:
        score += 15

    return min(score, 100)

def get_risk_level(score):
    if score >= 70:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"

# -----------------------------
# Analysis Pipeline
# -----------------------------
def analyze_inventory(hosts):
    for host in hosts:
        host['days_since_patch'] = calculate_days_since_patch(host)
        host['risk_score'] = calculate_risk_score(host)
        host['risk_level'] = get_risk_level(host['risk_score'])
    return hosts

# -----------------------------
# High Risk Filter
# -----------------------------
def get_high_risk_hosts(hosts, threshold=50):
    high_risk = [h for h in hosts if h['risk_score'] >= threshold]
    return sorted(high_risk, key=lambda h: h['risk_score'], reverse=True)

# -----------------------------
# JSON Report
# -----------------------------
def generate_json_report(hosts, high_risk_hosts):
    risk_dist = Counter(h['risk_level'] for h in hosts)

    report = {
        "report_date": datetime.now().isoformat(),
        "total_hosts": len(hosts),
        "high_risk_count": len(high_risk_hosts),
        "risk_distribution": dict(risk_dist),
        "high_risk_hosts": [
            {
                "hostname": h['hostname'],
                "risk_score": h['risk_score'],
                "risk_level": h['risk_level'],
                "days_since_patch": h['days_since_patch'],
                "environment": h['environment'],
                "tags": h.get('tags', [])
            }
            for h in high_risk_hosts
        ]
    }

    with open('high_risk_report.json', 'w') as f:
        json.dump(report, f, indent=2)

# -----------------------------
# Text Summary
# -----------------------------
def generate_text_summary(hosts, high_risk_hosts):
    risk_dist = Counter(h['risk_level'] for h in hosts)
    very_old = sum(1 for h in hosts if h['days_since_patch'] > 90)

    lines = []
    lines.append("=" * 60)
    lines.append("WEEKLY PATCH COMPLIANCE REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now()}")
    lines.append("")

    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 60)
    lines.append(f"Total Systems: {len(hosts)}")
    lines.append(f"High Risk Systems: {len(high_risk_hosts)}")
    lines.append(f"Critical Systems: {risk_dist.get('critical', 0)}")
    lines.append(f">90 Days Unpatched: {very_old}")
    lines.append("")

    lines.append("RISK DISTRIBUTION")
    lines.append("-" * 60)
    for level in ['critical', 'high', 'medium', 'low']:
        lines.append(f"{level.title()}: {risk_dist.get(level, 0)}")
    lines.append("")

    lines.append("TOP RISK SYSTEMS")
    lines.append("-" * 60)
    for h in high_risk_hosts[:5]:
        lines.append(f"{h['hostname']} - Score: {h['risk_score']} ({h['risk_level']})")
    lines.append("")

    lines.append("RECOMMENDED ACTIONS")
    lines.append("-" * 60)
    if high_risk_hosts:
        lines.append("Patch critical systems immediately (within 48 hours).")
        lines.append("Schedule high-risk systems this week.")
    else:
        lines.append("No immediate patching required. Continue normal cycle.")

    output = "\n".join(lines)

    with open('patch_summary.txt', 'w') as f:
        f.write(output)

    print(output)

# -----------------------------
# MAIN
# -----------------------------
def main():
    hosts = load_inventory('host_inventory.json')
    hosts = analyze_inventory(hosts)
    high_risk = get_high_risk_hosts(hosts)

    generate_json_report(hosts, high_risk)
    generate_text_summary(hosts, high_risk)

if __name__ == "__main__":
    main()
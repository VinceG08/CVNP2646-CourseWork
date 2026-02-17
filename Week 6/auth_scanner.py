#!/usr/bin/env python3
"""
Authentication Log Scanner
CVNP2646 - Week 6 Project

Parses authentication logs, detects brute force attack patterns,
aggregates failed login attempts, and generates SOC intelligence reports.
"""

import sys
import json
from collections import Counter
from datetime import datetime, timezone


# -------------------------------------------------------------
# LOG PARSING
# -------------------------------------------------------------
def parse_log_line(line):
    """
    Parse a single authentication log line.
    Returns structured dict or None if malformed.
    """
    try:
        line = line.strip()
        if not line:
            return None

        parts = line.split()

        # Must contain at least timestamp (2 parts)
        if len(parts) < 2:
            return None

        timestamp = f"{parts[0]} {parts[1]}"

        data = {}
        for item in parts[2:]:
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            data[key] = value

        status = data.get("status")
        if status not in {"SUCCESS", "FAIL"}:
            return None

        return {
            "timestamp": timestamp,
            "event": data.get("event", "UNKNOWN"),
            "status": status,
            "user": data.get("user", "UNKNOWN"),
            "ip": data.get("ip", "UNKNOWN"),
            "method": data.get("method", "UNKNOWN"),
        }

    except Exception:
        return None


# -------------------------------------------------------------
# ANALYSIS
# -------------------------------------------------------------
def analyze_logs(filename):
    failed_by_user = Counter()
    failed_by_ip = Counter()

    total_success = 0
    total_fail = 0
    parse_errors = 0
    total_lines = 0

    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            parsed = parse_log_line(line)

            if not parsed:
                parse_errors += 1
                continue

            if parsed["status"] == "SUCCESS":
                total_success += 1
            else:
                total_fail += 1
                failed_by_user[parsed["user"]] += 1
                failed_by_ip[parsed["ip"]] += 1

    total_events = total_success + total_fail

    failure_rate = (
        (total_fail / total_events) * 100
        if total_events > 0
        else 0.0
    )

    return {
        "total_lines": total_lines,
        "total_events": total_events,
        "total_success": total_success,
        "total_fail": total_fail,
        "failure_rate": failure_rate,
        "parse_errors": parse_errors,
        "failed_by_user": failed_by_user,
        "failed_by_ip": failed_by_ip,
    }


# -------------------------------------------------------------
# JSON REPORT
# -------------------------------------------------------------
def generate_json_report(results):
    report = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            "analyst": "Vincent Gatlin",
            "classification": "INTERNAL"
        },
        "summary": {
            "total_events": results["total_events"],
            "total_success": results["total_success"],
            "total_fail": results["total_fail"],
            "failure_rate": round(results["failure_rate"], 1),
            "parse_errors": results["parse_errors"]
        },
        "top_targeted_users": [
            {
                "username": user,
                "failed_attempts": count
            }
            for user, count in results["failed_by_user"].most_common(5)
        ],
        "top_attacking_ips": [
            {
                "ip_address": ip,
                "failed_attempts": count
            }
            for ip, count in results["failed_by_ip"].most_common(5)
        ]
    }

    return json.dumps(report, indent=2)


# -------------------------------------------------------------
# TEXT REPORT
# -------------------------------------------------------------
def generate_text_report(results):
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines.append("=" * 70)
    lines.append("            AUTHENTICATION FAILURE ANALYSIS REPORT")
    lines.append(f"            Generated: {now}")
    lines.append("=" * 70)
    lines.append("")

    if results["failure_rate"] > 50:
        lines.append(
            f"ALERT: High failure rate detected: "
            f"{results['failure_rate']:.1f}% (baseline: 2-5%)"
        )
        lines.append("Potential BRUTE FORCE ATTACK in progress.")
        lines.append("")

    lines.append("-" * 70)
    lines.append("SUMMARY STATISTICS")
    lines.append("-" * 70)
    lines.append(f"Total Events:        {results['total_events']}")
    lines.append(
        f"Successful Logins:   {results['total_success']} "
        f"({(results['total_success']/results['total_events']*100 if results['total_events'] else 0):.1f}%)"
    )
    lines.append(
        f"Failed Attempts:     {results['total_fail']} "
        f"({results['failure_rate']:.1f}%)"
    )
    lines.append(f"Parse Errors:        {results['parse_errors']}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("TOP 5 TARGETED ACCOUNTS")
    lines.append("-" * 70)

    for i, (user, count) in enumerate(results["failed_by_user"].most_common(5), 1):
        lines.append(f"{i}. {user:18} {count} failed attempts")

    lines.append("")
    lines.append("-" * 70)
    lines.append("TOP 5 ATTACKING SOURCE IPs")
    lines.append("-" * 70)

    for i, (ip, count) in enumerate(results["failed_by_ip"].most_common(5), 1):
        lines.append(f"{i}. {ip:18} {count} failed attempts")

    lines.append("")
    lines.append("=" * 70)
    lines.append("Report generated by: SOC Automation Platform")
    lines.append("=" * 70)

    return "\n".join(lines)


# -------------------------------------------------------------
# MAIN
# -------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python auth_scanner.py <logfile>")
        sys.exit(1)

    logfile = sys.argv[1]

    print("Authentication Log Scanner")
    print("=" * 50)
    print(f"Processing: {logfile}")

    results = analyze_logs(logfile)

    print("\nParsing Statistics:")
    print(f"Total lines: {results['total_lines']}")
    print(f"Successfully parsed: {results['total_events']}")
    print(f"Parse failures: {results['parse_errors']}")

    print("\nAnalysis Complete:")
    print(f"Total events: {results['total_events']}")
    print(f"Failed logins: {results['total_fail']} ({results['failure_rate']:.1f}%)")

    if results["failure_rate"] > 50:
        print("⚠ ALERT: High failure rate detected")

    with open("incident_report.json", "w", encoding="utf-8") as f:
        f.write(generate_json_report(results))

    with open("incident_report.txt", "w", encoding="utf-8") as f:
        f.write(generate_text_report(results))

    print("\nReports generated:")
    print("✓ incident_report.json")
    print("✓ incident_report.txt")
    print("=" * 50)


if __name__ == "__main__":
    main()
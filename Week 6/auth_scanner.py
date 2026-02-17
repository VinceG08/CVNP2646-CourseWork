#!/usr/bin/env python3
"""
Authentication Log Scanner
Analyzes authentication logs for security incidents
"""

import sys
import json
from collections import Counter
from datetime import datetime


def parse_log_line(line):
    """
    Parse a single authentication log line.

    Returns:
        dict with parsed fields, or None if malformed
    """
    try:
        line = line.strip()
        if not line:
            return None

        parts = line.split()
        if len(parts) < 2:
            return None

        # Combine date + time
        timestamp = f"{parts[0]} {parts[1]}"

        data = {}
        for item in parts[2:]:
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            data[key] = value

        # Required fields
        if "status" not in data:
            return None
        if data["status"] not in {"SUCCESS", "FAIL"}:
            return None

        return {
            "timestamp": timestamp,
            "event": data.get("event", "UNKNOWN"),
            "status": data["status"],
            "user": data.get("user", "UNKNOWN"),
            "ip": data.get("ip", "UNKNOWN"),
            "method": data.get("method", "UNKNOWN"),
        }

    except Exception:
        return None


def analyze_logs(filename):
    """
    Analyze authentication logs from a file.
    """
    failed_by_user = Counter()
    failed_by_ip = Counter()

    total_events = 0
    total_success = 0
    total_fail = 0
    parse_errors = 0

    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_log_line(line)

            if not parsed:
                parse_errors += 1
                continue

            total_events += 1

            if parsed["status"] == "SUCCESS":
                total_success += 1
            else:
                total_fail += 1
                failed_by_user[parsed["user"]] += 1
                failed_by_ip[parsed["ip"]] += 1

    failure_rate = (
        total_fail / (total_success + total_fail)
        if (total_success + total_fail) > 0
        else 0.0
    )

    return {
        "total_events": total_events,
        "total_success": total_success,
        "total_fail": total_fail,
        "failure_rate": failure_rate,
        "parse_errors": parse_errors,
        "failed_by_user": failed_by_user,
        "failed_by_ip": failed_by_ip,
    }


def generate_json_report(results):
    """
    Generate JSON report from analysis results.
    """
    report = {
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "analyst": "SOC Analyst",
        },
        "summary": {
            "total_events": results["total_events"],
            "successful_logins": results["total_success"],
            "failed_logins": results["total_fail"],
            "failure_rate": round(results["failure_rate"], 3),
            "parse_errors": results["parse_errors"],
        },
        "top_targeted_users": [
            {"username": user, "failures": count}
            for user, count in results["failed_by_user"].most_common(5)
        ],
        "top_attacking_ips": [
            {"ip": ip, "attempts": count}
            for ip, count in results["failed_by_ip"].most_common(5)
        ],
    }

    return json.dumps(report, indent=2)


def generate_text_report(results):
    """
    Generate human-readable text report.
    """
    lines = []
    lines.append("Authentication Log Analysis Report")
    lines.append("=" * 70)

    lines.append(f"Total Events Processed: {results['total_events']}")
    lines.append(f"Successful Logins: {results['total_success']}")
    lines.append(f"Failed Logins: {results['total_fail']}")
    lines.append(f"Failure Rate: {results['failure_rate']:.1%}")
    lines.append(f"Parse Errors: {results['parse_errors']}")
    lines.append("")

    lines.append("Top Targeted Users:")
    for user, count in results["failed_by_user"].most_common(5):
        lines.append(f"  {user:20} {count:>5}")

    lines.append("")
    lines.append("Top Attacking IP Addresses:")
    for ip, count in results["failed_by_ip"].most_common(5):
        lines.append(f"  {ip:20} {count:>5}")

    return "\n".join(lines)


def main():
    """Main execution function."""
    if len(sys.argv) < 2:
        print("Usage: python auth_scanner.py <logfile>")
        sys.exit(1)

    logfile = sys.argv[1]

    print("Authentication Log Scanner")
    print("=" * 50)
    print(f"Processing: {logfile}")

    results = analyze_logs(logfile)

    total_lines = results["total_events"] + results["parse_errors"]
    success_rate = (
        results["total_events"] / total_lines * 100 if total_lines else 0
    )

    print("\nParsing Statistics:")
    print(f"Total lines: {total_lines}")
    print(
        f"Successfully parsed: {results['total_events']} ({success_rate:.1f}%)"
    )
    print(f"Parse failures: {results['parse_errors']}")

    print("\nAnalysis Complete:")
    print(f"Total events: {results['total_events']}")
    success_percent = (
    results["total_success"] / results["total_events"] * 100
    if results["total_events"] > 0
    else 0.0
)
    print(
        f"Failed logins: {results['total_fail']} "
        f"({results['failure_rate']:.1%})"
    )

    if results["failure_rate"] > 0.5:
        print(
            f"⚠ ALERT: High failure rate detected "
            f"({results['failure_rate']:.1%})"
        )

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
import os
import json
from datetime import datetime
from collections import Counter
import requests
from dotenv import load_dotenv

# -------------------------------
# Configuration and API Key Loader
# -------------------------------
class Config:
    def __init__(self):
        load_dotenv()
        self.ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
        if not self.ABUSEIPDB_KEY:
            raise ValueError("ABUSEIPDB_API_KEY not set in .env")

config = Config()

# -------------------------------
# Load JSON Feed from File
# -------------------------------
def load_feed(filepath):
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
            return data.get("indicators", [])
    except Exception as e:
        print(f"Failed to load {filepath}: {e}")
        return []

# -------------------------------
# Normalize Indicator from Any Vendor
# -------------------------------
def normalize_indicator(raw, source_name):
    type_val = raw.get("type") or raw.get("indicator_type") or raw.get("category")
    value_val = raw.get("value") or raw.get("indicator_value") or raw.get("ioc")
    confidence_val = raw.get("confidence") or raw.get("score") or raw.get("reliability") or 0
    threat_val = raw.get("threat") or raw.get("severity") or raw.get("risk") or "low"
    first_seen_val = raw.get("first_seen") or raw.get("date") or None
    return {
        "id": raw.get("id") or raw.get("ioc_id") or f"{source_name}-{value_val}",
        "type": type_val,
        "value": value_val,
        "confidence": confidence_val,
        "threat_level": threat_val,
        "first_seen": first_seen_val,
        "sources": [source_name]
    }

# -------------------------------
# Validate Indicators
# -------------------------------
def validate_indicators(indicators):
    valid = []
    errors = []
    for idx, ind in enumerate(indicators):
        if not all(field in ind for field in ["id", "type", "value", "confidence"]):
            errors.append(f"Indicator {idx} missing required field")
            continue
        if not (0 <= ind["confidence"] <= 100):
            errors.append(f"Indicator {idx} confidence out of range")
            continue
        if ind["type"] not in ["ip", "domain", "hash", "url"]:
            errors.append(f"Indicator {idx} invalid type")
            continue
        if not ind["value"]:
            errors.append(f"Indicator {idx} empty value")
            continue
        valid.append(ind)
    return valid, len(errors), errors

# -------------------------------
# Deduplicate Indicators
# -------------------------------
def deduplicate_indicators(indicators):
    unique = {}
    duplicate_count = 0
    for ind in indicators:
        key = (ind["type"], ind["value"])
        if key not in unique:
            unique[key] = ind
        else:
            duplicate_count += 1
            existing = unique[key]
            if ind["confidence"] > existing["confidence"]:
                ind["sources"].extend(existing["sources"])
                unique[key] = ind
            else:
                existing["sources"].extend(ind["sources"])
    return list(unique.values()), duplicate_count

# -------------------------------
# Filter Indicators
# -------------------------------
def filter_indicators(indicators, min_conf=85, levels=None, types=None):
    if levels is None:
        levels = ["high", "critical"]
    if types is None:
        types = ["ip", "domain"]
    return [
        ind for ind in indicators
        if ind["confidence"] >= min_conf
        and ind["threat_level"] in levels
        and ind["type"] in types
    ]

# -------------------------------
# Transform to Firewall Format
# -------------------------------
def transform_to_firewall(indicators):
    entries = []
    for ind in indicators:
        entries.append({
            "address": ind["value"],
            "action": "block",
            "priority": "high" if ind["threat_level"] == "critical" else "medium",
            "reason": f"Threat level: {ind['threat_level']}, Confidence: {ind['confidence']}%",
            "sources": ind["sources"]
        })
    return {
        "generated_at": datetime.now().isoformat(),
        "total_entries": len(entries),
        "blocklist": entries
    }

# -------------------------------
# Transform to SIEM Format
# -------------------------------
def transform_to_siem(indicators):
    entries = []
    for ind in indicators:
        entries.append({
            "id": ind["id"],
            "type": ind["type"],
            "indicator": ind["value"],
            "confidence": ind["confidence"],
            "threat_level": ind["threat_level"],
            "first_seen": ind["first_seen"],
            "sources": ind["sources"]
        })
    return entries

# -------------------------------
# Generate Text Report
# -------------------------------
def generate_report(indicators, stats):
    report = [
        f"Total loaded: {stats['total_loaded']}",
        f"Valid indicators: {stats['valid_count']}",
        f"Unique indicators: {stats['unique_count']}",
        f"Filtered indicators: {stats['filtered_count']}",
        f"Duplicates removed: {stats['duplicates_removed']}",
        f"Type distribution: {stats['type_distribution']}",
        f"Severity distribution: {stats['severity_distribution']}",
        f"Source contribution: {stats['source_contribution']}",
        "\nSample indicators:"
    ]
    for ind in indicators[:10]:
        report.append(f"{ind['type']} {ind['value']} ({ind['confidence']}%) sources: {ind['sources']}")
    return "\n".join(report)

# -------------------------------
# Generate Statistics
# -------------------------------
def generate_statistics(loaded, valid, deduped, filtered):
    type_counts = Counter(ind["type"] for ind in filtered)
    severity_counts = Counter(ind["threat_level"] for ind in filtered)
    source_counts = Counter()
    for ind in deduped:
        for source in ind["sources"]:
            source_counts[source] += 1
    return {
        "total_loaded": loaded,
        "valid_count": valid,
        "unique_count": len(deduped),
        "filtered_count": len(filtered),
        "duplicates_removed": loaded - len(deduped),
        "type_distribution": dict(type_counts),
        "severity_distribution": dict(severity_counts),
        "source_contribution": dict(source_counts)
    }

# -------------------------------
# Main Orchestration
# -------------------------------
def main():
    all_indicators = []

    # Load and normalize feeds
    for vendor_file, vendor_name in [("vendor_a.json", "VendorA"),
                                     ("vendor_b.json", "VendorB"),
                                     ("vendor_c.json", "VendorC")]:
        raw_feed = load_feed(vendor_file)
        print(f"Loaded {len(raw_feed)} indicators from {vendor_file}")
        for ind in raw_feed:
            normalized = normalize_indicator(ind, vendor_name)
            all_indicators.append(normalized)

    # Validation
    valid_inds, err_count, errors = validate_indicators(all_indicators)
    print(f"Validation errors: {err_count}")

    # Deduplication
    deduped_inds, dup_count = deduplicate_indicators(valid_inds)
    print(f"Removed {dup_count} duplicates")

    # Filtering
    filtered_inds = filter_indicators(deduped_inds)
    print(f"{len(filtered_inds)} indicators after filtering")

    # Statistics
    stats = generate_statistics(len(all_indicators), len(valid_inds), deduped_inds, filtered_inds)
    print(stats)

    # Outputs
    firewall_data = transform_to_firewall(filtered_inds)
    with open("firewall_blocklist.json", "w") as f:
        json.dump(firewall_data, f, indent=2)

    siem_data = transform_to_siem(filtered_inds)
    with open("siem_feed.json", "w") as f:
        json.dump(siem_data, f, indent=2)

    report_text = generate_report(filtered_inds, stats)
    with open("summary_report.txt", "w") as f:
        f.write(report_text)

    print("Output files generated: firewall_blocklist.json, siem_feed.json, summary_report.txt")

if __name__ == "__main__":
    main()
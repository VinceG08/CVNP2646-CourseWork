import os
import json
from datetime import datetime
from collections import Counter
from dotenv import load_dotenv

# --------------------------
# Load API key from .env
# --------------------------
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
if not API_KEY:
    print("Warning: ABUSEIPDB_API_KEY not set. Using simulator key or offline mode.")
    API_KEY = "valid_key_123"  # safe simulator key for testing

# --------------------------
# Load feed function
# --------------------------
def load_feed(filepath):
    with open(filepath, "r") as f:
        data = json.load(f)
    indicators = data.get("indicators", [])
    print(f"Loaded {len(indicators)} indicators from {filepath}")
    return indicators

# --------------------------
# Normalize indicators
# --------------------------
def normalize_indicator(raw, source_name):
    # Flexible field mapping using .get() fallbacks
    type_val = raw.get("type") or raw.get("indicator_type") or raw.get("category")
    value_val = raw.get("value") or raw.get("indicator_value") or raw.get("ioc")
    confidence_val = raw.get("confidence") or raw.get("score") or raw.get("reliability") or 0
    threat_level_val = raw.get("threat") or raw.get("severity") or raw.get("risk") or "low"
    first_seen_val = raw.get("first_seen") or raw.get("date") or datetime.now().isoformat()
    indicator_id = raw.get("id") or raw.get("ioc_id") or f"{source_name}-{value_val}"

    return {
        "id": indicator_id,
        "type": type_val,
        "value": value_val,
        "confidence": confidence_val,
        "threat_level": threat_level_val,
        "first_seen": first_seen_val,
        "sources": [source_name]
    }

# --------------------------
# Validation
# --------------------------
def validate_indicators(indicators):
    valid = []
    errors = []
    for idx, ind in enumerate(indicators):
        if not all(field in ind for field in ["id", "type", "value", "confidence"]):
            errors.append(f"Indicator {idx}: missing required field")
            continue
        if not (0 <= ind["confidence"] <= 100):
            errors.append(f"Indicator {idx}: confidence out of range")
            continue
        if not ind["type"] in ["ip", "domain", "hash", "url"]:
            errors.append(f"Indicator {idx}: invalid type")
            continue
        if not isinstance(ind["value"], str) or not ind["value"]:
            errors.append(f"Indicator {idx}: empty value")
            continue
        valid.append(ind)
    return valid, len(errors), errors

# --------------------------
# Deduplication
# --------------------------
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

# --------------------------
# Filtering
# --------------------------
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

# --------------------------
# Output functions
# --------------------------
def write_firewall_blocklist(indicators, filename="firewall_blocklist.json"):
    entries = []
    for ind in indicators:
        entry = {
            "address": ind["value"],
            "action": "block",
            "priority": "high" if ind["threat_level"] == "critical" else "medium",
            "reason": f"Threat level: {ind['threat_level']}, Confidence: {ind['confidence']}%",
            "sources": ind["sources"]
        }
        entries.append(entry)
    output = {
        "generated_at": datetime.now().isoformat(),
        "total_entries": len(entries),
        "blocklist": entries
    }
    with open(filename, "w") as f:
        json.dump(output, f, indent=2)

def write_siem_feed(indicators, filename="siem_feed.json"):
    output = []
    for ind in indicators:
        output.append({
            "id": ind.get("id"),
            "type": ind.get("type"),
            "indicator": ind.get("value"),
            "confidence": ind.get("confidence"),
            "threat_level": ind.get("threat_level"),
            "first_seen": ind.get("first_seen"),
            "sources": ind.get("sources")
        })
    with open(filename, "w") as f:
        json.dump(output, f, indent=2)

def write_summary_report(stats, filename="summary_report.txt"):
    with open(filename, "w") as f:
        f.write(f"Total loaded: {stats['total_loaded']}\n")
        f.write(f"Valid indicators: {stats['valid_count']}\n")
        f.write(f"Unique indicators: {stats['unique_count']}\n")
        f.write(f"Filtered indicators: {stats['filtered_count']}\n")
        f.write(f"Duplicates removed: {stats['duplicates_removed']}\n")
        f.write(f"Type distribution: {stats['type_distribution']}\n")
        f.write(f"Severity distribution: {stats['severity_distribution']}\n")
        f.write(f"Source contribution: {stats['source_contribution']}\n")

# --------------------------
# Main pipeline
# --------------------------
def main():
    all_indicators = []
    
    # Load and normalize all vendors
    for file, source in [("vendor_a.json","VendorA"), ("vendor_b.json","VendorB"), ("vendor_c.json","VendorC")]:
        raw = load_feed(file)
        normalized = [normalize_indicator(ind, source) for ind in raw]
        all_indicators.extend(normalized)

    # Validation
    valid_indicators, errors_count, errors = validate_indicators(all_indicators)
    print(f"Validation errors: {errors_count}")

    # Deduplication
    deduped_indicators, dup_count = deduplicate_indicators(valid_indicators)
    print(f"Removed {dup_count} duplicates")

    # Filtering
    filtered_indicators = filter_indicators(deduped_indicators)

    # Statistics
    stats = {
        "total_loaded": len(all_indicators),
        "valid_count": len(valid_indicators),
        "unique_count": len(deduped_indicators),
        "filtered_count": len(filtered_indicators),
        "duplicates_removed": dup_count,
        "type_distribution": dict(Counter(ind["type"] for ind in filtered_indicators)),
        "severity_distribution": dict(Counter(ind["threat_level"] for ind in filtered_indicators)),
        "source_contribution": dict(Counter(src for ind in deduped_indicators for src in ind["sources"]))
    }
    print(stats)

    # Write output files
    write_firewall_blocklist(filtered_indicators)
    write_siem_feed(filtered_indicators)
    write_summary_report(stats)
    print("Output files generated: firewall_blocklist.json, siem_feed.json, summary_report.txt")

# --------------------------
# Run script
# --------------------------
if __name__ == "__main__":
    main()
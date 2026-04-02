import json

# -----------------------------
# DriftResult Class
# -----------------------------
CRITICAL_KEYWORDS = ['password', 'secret', 'admin', 'root', 'enabled']

class DriftResult:
    def __init__(self, path, drift_type, baseline_value, current_value):
        self.path = path
        self.drift_type = drift_type
        self.baseline_value = baseline_value
        self.current_value = current_value
        self.severity = self._calculate_severity()
    
    def _calculate_severity(self):
        # High if path contains critical keywords
        for keyword in CRITICAL_KEYWORDS:
            if keyword in self.path.lower():
                return "high"
        # Medium for missing configs
        if self.drift_type == "missing":
            return "medium"
        # Otherwise low
        return "low"
    
    def is_critical(self):
        return self.severity == "high"
    
    def __str__(self):
        symbol = {"changed": "~", "missing": "-", "extra": "+"}.get(self.drift_type, "?")
        return f"[{symbol}] {self.path} ({self.severity})"
    
    def to_dict(self):
        return {
            "path": self.path,
            "drift_type": self.drift_type,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "severity": self.severity
        }

# -----------------------------
# Recursive Comparison Function
# -----------------------------
def compare_configs(baseline, current, path=""):
    results = []

    # CASE 1: Both dicts
    if isinstance(baseline, dict) and isinstance(current, dict):
        baseline_keys = set(baseline.keys())
        current_keys = set(current.keys())

        # Missing keys
        for key in baseline_keys - current_keys:
            full_path = f"{path}.{key}" if path else key
            results.append(DriftResult(full_path, "missing", baseline[key], None))

        # Extra keys
        for key in current_keys - baseline_keys:
            full_path = f"{path}.{key}" if path else key
            results.append(DriftResult(full_path, "extra", None, current[key]))

        # Recurse on common keys
        for key in baseline_keys & current_keys:
            full_path = f"{path}.{key}" if path else key
            results.extend(compare_configs(baseline[key], current[key], full_path))

    # CASE 2: Both lists
    elif isinstance(baseline, list) and isinstance(current, list):
        max_len = max(len(baseline), len(current))
        for i in range(max_len):
            idx_path = f"{path}[{i}]"
            if i >= len(baseline):
                # Extra item in current
                results.append(DriftResult(idx_path, "extra", None, current[i]))
            elif i >= len(current):
                # Missing item in current
                results.append(DriftResult(idx_path, "missing", baseline[i], None))
            else:
                # Recurse on items
                results.extend(compare_configs(baseline[i], current[i], idx_path))

    # CASE 3: Leaf values
    else:
        if baseline != current:
            results.append(DriftResult(path, "changed", baseline, current))

    return results

# -----------------------------
# Load JSON Files
# -----------------------------
def load_json(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {filename}: {e}")
        return None

baseline = load_json('baseline.json')
current = load_json('current.json')

if baseline and current:
    results = compare_configs(baseline, current)
    
    print("\n--- Configuration Drift Findings ---")
    for r in results:
        print(r)

    # Summary counts
    counts = {"high": 0, "medium": 0, "low": 0}
    for r in results:
        counts[r.severity] += 1

    print("\n--- Severity Summary ---")
    print(f"High: {counts['high']}, Medium: {counts['medium']}, Low: {counts['low']}")
    
    # Optional: Export to JSON file
    output_file = "drift_report.json"
    with open(output_file, "w") as f:
        json.dump([r.to_dict() for r in results], f, indent=4)
    print(f"\nDrift report saved to {output_file}")
import json
import random
import sys
from datetime import datetime

# ----------------------------
# Function: Load JSON Config
# ----------------------------
def load_config(filepath):
    """
    Load and parse a JSON backup configuration file.

    Args:
        filepath (str): Path to the JSON config file

    Returns:
        dict: Parsed configuration, or None if loading fails
    """
    try:
        with open(filepath) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Config file '{filepath}' not found")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{filepath}': {e}")
        return None

# ----------------------------
# Function: Validate Config
# ----------------------------
def validate_config(config: dict) -> tuple[bool, list[str]]:
    """
    Validate backup configuration across 4 levels.

    Returns:
        tuple: (is_valid: bool, errors: list[str])
        Always returns ALL errors found, not just the first.
    """
    errors = []

    # Level 2: Required fields
    for field in ['plan_name', 'sources', 'destination']:
        if field not in config:
            errors.append(f"Missing required field: '{field}'")

    # Level 3: Type validation
    if 'plan_name' in config and not isinstance(config['plan_name'], str):
        errors.append(f"'plan_name' must be a string, got {type(config['plan_name']).__name__}")
    if 'sources' in config and not isinstance(config['sources'], list):
        errors.append(f"'sources' must be a list, got {type(config['sources']).__name__}")
    if 'destination' in config and not isinstance(config['destination'], dict):
        errors.append(f"'destination' must be a dict, got {type(config['destination']).__name__}")

    # Level 4: Value validation
    if isinstance(config.get('sources'), list):
        if len(config['sources']) == 0:
            errors.append("'sources' list cannot be empty")
        for i, source in enumerate(config['sources']):
            if 'path' not in source:
                errors.append(f"Source {i}: missing 'path' field")
            elif not source['path'].strip():
                errors.append(f"Source {i}: 'path' cannot be empty string")

    if isinstance(config.get('destination'), dict):
        dest = config['destination']
        if 'base_path' not in dest:
            errors.append("destination: missing 'base_path' field")
        elif not dest['base_path'].strip():
            errors.append("destination: 'base_path' cannot be empty string")

    return len(errors) == 0, errors

# ----------------------------
# Function: Simulate Backup
# ----------------------------
def simulate_backup(config):
    """
    Generate a dry-run backup simulation.

    Does NOT read real directories or copy any files.
    Uses random module to create realistic fake file data.

    Args:
        config (dict): Validated backup configuration

    Returns:
        dict: Simulation report with operations and summary statistics
    """
    operations = []

    for source in config['sources']:
        num_files = random.randint(5, 15)
        files = []

        for i in range(num_files):
            size_mb = round(random.uniform(1, 100), 1)
            name = f"{source['name'].lower().replace(' ', '_')}_{i+1:03d}.log"
            files.append({"name": name, "size_mb": size_mb})

        operations.append({
            "source_name": source['name'],
            "source_path": source['path'],
            "files": files
        })

    total_files = sum(len(op['files']) for op in operations)
    total_size = round(sum(f['size_mb'] for op in operations for f in op['files']), 1)

    return {
        "plan_name": config['plan_name'],
        "mode": "DRY-RUN",
        "summary": {
            "total_sources": len(operations),
            "total_files": total_files,
            "total_size_mb": total_size
        },
        "operations": operations
    }

# ----------------------------
# Function: Generate Report
# ----------------------------
def generate_report(report_data):
    """
    Print formatted dry-run simulation report.

    Args:
        report_data (dict): Output from simulate_backup()
    """
    sep = "=" * 70
    print(sep)
    print(f"{'BACKUP PLAN DRY-RUN SIMULATION':^70}")
    print(sep)
    print(f"Plan: {report_data['plan_name']}")
    print(f"Mode: {report_data['mode']} (no files will be copied)")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()

    s = report_data['summary']
    print("SUMMARY")
    print("-" * 70)
    print(f"Total Sources:  {s['total_sources']}")
    print(f"Total Files:    {s['total_files']}")
    print(f"Total Size:     {s['total_size_mb']} MB")
    print()

    for i, op in enumerate(report_data['operations'], 1):
        print(f"SOURCE {i}: {op['source_name']}")
        print(f"Path: {op['source_path']}")
        print(f"Files: {len(op['files'])}")
        for f in op['files'][:3]:
            print(f"  -> {f['name']} ({f['size_mb']} MB)")
        remaining = len(op['files']) - 3
        if remaining > 0:
            print(f"  ... and {remaining} more files")
        print()

    print(sep)
    print("DRY-RUN complete. No files were copied.")
    print(sep)

# ----------------------------
# Main Function
# ----------------------------
def main():
    """Orchestrate the backup planning pipeline."""
    if len(sys.argv) < 2:
        print("Usage: python backup_planner.py <config_file>")
        sys.exit(1)

    filepath = sys.argv[1]

    # Step 1: Load
    config = load_config(filepath)
    if config is None:
        sys.exit(1)

    # Step 2: Validate
    is_valid, errors = validate_config(config)
    if not is_valid:
        print(f"Validation FAILED. {len(errors)} error(s) found:")
        for i, err in enumerate(errors, 1):
            print(f"  [{i}] {err}")
        sys.exit(1)

    print("Validation PASSED.")

    # Step 3: Simulate
    report_data = simulate_backup(config)

    # Step 4: Report
    generate_report(report_data)

# ----------------------------
# Entry Point
# ----------------------------
if __name__ == "__main__":
    main()

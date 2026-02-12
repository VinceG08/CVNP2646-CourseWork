# log_processor.py
# Process security logs with line numbers using enumerate

from pathlib import Path

print("=== Security Log Processor ===\n")

# Create sample security log
log_file = Path('security_events.log')
log_file.write_text("""INFO: System startup completed
WARNING: Failed login attempt from 203.0.113.45
INFO: Database connection established
ERROR: Unauthorized access attempt on /admin
WARNING: Multiple failed authentication attempts
INFO: Backup completed successfully
CRITICAL: Malware signature detected in uploaded file
WARNING: Unusual network traffic pattern detected
""")

print(f"Processing: {log_file}\n")

# Track findings by severity
findings = {
    'WARNING': [],
    'ERROR': [],
    'CRITICAL': []
}

# Process log with line numbers
with log_file.open('r') as f:
    for line_num, line in enumerate(f, start=1):
        line = line.strip()

        # Check for severity levels
        for severity in findings.keys():
            if line.startswith(severity):
                findings[severity].append({
                    'line': line_num,
                    'message': line
                })

# Display findings
print("Security Findings:")
print("=" * 60)

for severity in ['CRITICAL', 'ERROR', 'WARNING']:
    if findings[severity]:
        print(f"\n{severity} ({len(findings[severity])} found):")
        for finding in findings[severity]:
            print(f"  Line {finding['line']:2d}: {finding['message']}")

# Generate summary report
total_issues = sum(len(items) for items in findings.values())

print(f"\n{'=' * 60}")
print(f"Total security issues found: {total_issues}")
print(f"  CRITICAL: {len(findings['CRITICAL'])}")
print(f"  ERROR: {len(findings['ERROR'])}")
print(f"  WARNING: {len(findings['WARNING'])}")
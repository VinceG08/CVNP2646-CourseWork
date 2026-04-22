# Authentication Log Threat Analyzer

A CLI tool that detects brute-force login attacks from JSON authentication logs.

## How to Run

python src/main.py --input data/auth_logs.json --output output/alert_report.json

## Features

- Parses JSON logs
- Detects brute-force attacks
- Generates alert report

## Example Output

See output/alert_report.json
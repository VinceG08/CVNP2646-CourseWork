# 🔐 Authentication Log Threat Analyzer

## 📌 Overview

The Authentication Log Threat Analyzer is a Python command-line tool that analyzes authentication logs to detect suspicious login behavior. It identifies brute-force attacks, anomalous login times, and logins from known malicious IP addresses, then assigns risk scores and generates structured JSON reports.

This project simulates core functionality of a simplified SIEM (Security Information and Event Management) system.

---

## 🚨 Problem Statement

Security teams handle large volumes of authentication logs daily. Manually reviewing these logs is time-consuming and can lead to missed threats such as brute-force attacks or unauthorized access.

This tool automates log analysis, detects suspicious patterns, and prioritizes high-risk events for investigation.

---

## ⚙️ Features

### ✅ Core Features

* Parse authentication logs from JSON
* Detect brute-force attacks (multiple failed logins → success)
* Detect anomalous login times (midnight–5 AM)
* Detect logins from known malicious IPs
* Assign risk scores (0–100 scale)
* Generate structured JSON alert reports
* CLI interface using argparse
* Logging and error handling

---

## 📁 Project Structure

```
CapStone/
│
├── src/
│   ├── main.py
│   ├── analyzer.py
│   ├── models.py
│   └── __init__.py
│
├── data/
│   ├── auth_logs.json
│   └── config.json
│
├── output/
│   └── alert_report.json
│
├── tests/
│   └── test_analyzer.py
│
├── requirements.txt
└── README.md
```

---

## 🧰 Installation

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd CapStone
```

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

---

## ▶️ Usage

Run the tool using:

```bash
python -m src.main --input data/auth_logs.json --config data/config.json --output output/alert_report.json
```

### CLI Arguments

* `--input` → Path to input JSON file (required)
* `--config` → Path to configuration file (required)
* `--output` → Path to output JSON file (required)

---

## 📥 Input Format (auth_logs.json)

```json
{
  "events": [
    {
      "timestamp": "2024-03-10T02:30:00Z",
      "username": "admin",
      "source_ip": "185.220.101.45",
      "event_type": "login_success"
    }
  ]
}
```

---

## 📤 Output Format (alert_report.json)

```json
{
  "alerts": [
    {
      "alert_type": "brute_force",
      "username": "admin",
      "source_ip": "192.168.1.10",
      "risk_score": 90,
      "details": "Multiple failed logins followed by success"
    }
  ]
}
```

---

## 🧪 Running Tests

Run the test suite with:

```bash
python -m pytest
```

Tests include:

* Brute-force detection
* Anomalous login detection
* Suspicious IP detection

---

## 🛡️ Error Handling & Logging

The application includes:

* File validation (missing files handled gracefully)
* JSON validation (invalid format detection)
* Skipping malformed events
* Logging using Python’s `logging` module

---

## ⚙️ Configuration (config.json)

```json
{
  "failed_login_threshold": 2,
  "risk_score": 90
}
```

---

## 🎯 Key Concepts Demonstrated

* JSON parsing and validation
* Object-Oriented Programming (OOP)
* CLI development with argparse
* Logging and error handling
* Unit testing with pytest
* Basic cybersecurity threat detection logic

---

## 👤 Author

Vincent Gatlin

---

## 📌 Notes

This project was developed as part of the CVNP2646 Cybersecurity Programming course capstone and is intended as a portfolio project demonstrating practical security automation skills.

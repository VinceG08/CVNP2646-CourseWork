🔐 Authentication Log Threat Analyzer (Week 14 MVP)

📌 Overview

This project is a Python command-line tool that analyzes authentication logs stored in JSON format. It detects suspicious login behavior, specifically brute-force attacks, and generates a JSON report of security alerts.

This is the **Week 14 MVP (Minimum Viable Product)**, meaning the core functionality is implemented and working end-to-end.



🚨 Problem Statement

Security teams often deal with large volumes of login data. Manually reviewing logs to identify attacks like brute-force attempts is time-consuming and inefficient.

This tool automates that process by identifying suspicious login patterns and generating alerts.



⚙️ Current Features (MVP)

* Read authentication logs from a JSON file
* Detect brute-force login behavior:

  * Multiple failed logins followed by a successful login
* Generate alert objects with:

  * Alert type
  * Username
  * Source IP
  * Risk score
  * Description
* Output alerts to a JSON report file
* Command-line interface (CLI) using argparse
* Basic logging for program execution



▶️ How to Run

Run the program from the project root:

```bash id="mvp_run"
python src/main.py --input auth_logs.json --output alert_report.json
```



📥 Input Example (auth_logs.json)

```json id="mvp_input"
{
  "events": [
    {
      "timestamp": "2024-03-10T14:20:00Z",
      "username": "admin",
      "source_ip": "192.168.1.10",
      "event_type": "login_failed"
    },
    {
      "timestamp": "2024-03-10T14:21:00Z",
      "username": "admin",
      "source_ip": "192.168.1.10",
      "event_type": "login_success"
    }
  ]
}
```



📤 Output Example (alert_report.json)

```json id="mvp_output"
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



🧱 Project Structure

```id="mvp_structure"
CapStone/
│
├── src/
│   ├── main.py
│   ├── analyzer.py
│   └── models.py
│
├── auth_logs.json
├── config.json
└── alert_report.json
```



⚠️ Known Limitations (Week 14)

* Only detects brute-force attacks
* No anomaly detection yet
* Config file not fully utilized
* Limited error handling
* No unit tests implemented yet



🔜 Planned Improvements (Week 15)

* Add anomaly detection (unusual login times)
* Add suspicious IP detection
* Implement unit testing with pytest
* Improve error handling and validation
* Add structured logging
* Use configuration file for thresholds and scoring



👤 Author

Vincent Gatlin

📌 Notes
Project improved and moved into seperate folder under "CapStone"
Authentication Log Threat Analyzer with Risk Scoring and Anomaly Detection
Vincent Gatlin
________________________________________
Project Description
This project is a command-line Python application that analyzes authentication logs in JSON format to detect suspicious login behavior. The system identifies patterns such as brute-force attacks, unusual login times, and suspicious IP activity.
The application assigns a dynamic risk score to each detected event and generates structured JSON reports for further investigation. This tool simulates functionality commonly found in Security Information and Event Management (SIEM) systems.
________________________________________
Problem Statement
Organizations generate large volumes of authentication logs daily, making it difficult to manually detect security threats. Critical events such as brute-force attacks or unauthorized logins may go unnoticed.
This project addresses the problem by automating log analysis, detecting suspicious patterns, and prioritizing threats using risk scoring.
________________________________________
Target Users / Use Case
•	Security Operations Center (SOC) analysts 
•	System administrators 
•	IT security teams 
Use Cases:
•	Detect brute-force attacks 
•	Identify anomalous login behavior (e.g., unusual times) 
•	Highlight high-risk login events 
•	Generate investigation-ready reports 
________________________________________
Inputs
JSON Input Files
auth_logs.json
•	timestamp 
•	username 
•	source_ip 
•	event_type 
config.json
•	failed login threshold 
•	time window 
•	risk scoring weights 
optional:
•	known_bad_ips.txt (flag high-risk IPs) 
________________________________________
Outputs
JSON Output Files
alert_report.json
•	Detailed alerts with: 
o	alert type 
o	risk score 
o	supporting evidence 
o	recommended action 
summary.json
•	Total events analyzed 
•	Suspicious events 
•	High-risk alerts 
•	Breakdown by alert type 
________________________________________
CLI Interface
Example Command
python main.py --input auth_logs.json --config config.json --output alerts.json --verbose
Arguments
•	--input (required) 
•	--config (required) 
•	--output (required) 
•	--threshold (optional) 
•	--verbose (optional) 
________________________________________
Features
Must-Have Features
•	Parse JSON authentication logs 
•	Detect brute-force attacks (repeated failures) 
•	Detect successful login after failures 
•	Assign risk scores (0–100 scale) 
•	Generate structured JSON reports 
•	CLI interface 
•	Logging and error handling 
•	Object-oriented design (classes) 
•	Unit testing 
________________________________________
 Enhanced Features
•	Detect anomalous login times (e.g., late night logins) 
•	Flag logins from known malicious IPs 
•	Risk scoring based on multiple factors: 
o	failed attempts 
o	time of login 
o	IP reputation 
•	Categorize alerts: 
o	brute_force 
o	anomalous_login 
o	suspicious_ip 
________________________________________
Technical Approach
Classes
class SecurityEvent:
    def __init__(self, timestamp, username, source_ip, event_type):
        self.timestamp = timestamp
        self.username = username
        self.source_ip = source_ip
        self.event_type = event_type


class Alert:
    def __init__(self, alert_type, risk_score, details):
        self.alert_type = alert_type
        self.risk_score = risk_score
        self.details = details


class LogAnalyzer:
    def __init__(self, config):
        self.config = config
        self.events = []
        self.alerts = []

    def detect_brute_force(self):
        pass

    def detect_anomalies(self):
        pass

    def check_ip_reputation(self):
        pass

    def calculate_risk_score(self, event):
        pass
________________________________________
Detection Logic
1. Brute Force Detection
•	Count failed logins per user/IP 
•	If threshold exceeded → flag as attack 
2. Anomalous Login Detection
•	Flag logins outside normal hours (e.g., 12AM–5AM) 
3. Suspicious IP Detection
•	Compare IPs against known_bad_ips.txt 
________________________________________
Risk Scoring Model
Risk score (0–100) based on:
•	Failed attempts → +40 
•	Successful login after failures → +30 
•	Login at unusual time → +20 
•	Known bad IP → +30 
Scores are capped at 100.
________________________________________
Testing Strategy
•	Unit tests for: 
o	brute-force detection 
o	anomaly detection 
o	risk scoring 
•	Edge cases: 
o	empty files 
o	invalid JSON 
o	no alerts generated 
________________________________________
Timeline
Week 13: Proposal + design
Week 14: Core classes + JSON parsing
Week 15: Detection logic + scoring
Week 16: Testing + polish + submission
________________________________________
📥 auth_logs.json 
{
  "events": [
    {
      "timestamp": "2024-03-10T02:30:00Z",
      "username": "admin",
      "source_ip": "185.220.101.45",
      "event_type": "login_success"
    },
    {
      "timestamp": "2024-03-10T14:20:00Z",
      "username": "admin",
      "source_ip": "192.168.1.10",
      "event_type": "login_failed"
    },
    {
      "timestamp": "2024-03-10T14:20:30Z",
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
________________________________________
known_bad_ips.txt
185.220.101.45
45.33.32.156
________________________________________
alert_report.json 
{
  "alerts": [
    {
      "alert_id": "ALT-001",
      "alert_type": "brute_force",
      "username": "admin",
      "source_ip": "192.168.1.10",
      "risk_score": 90,
      "details": "Multiple failed logins followed by success",
      "recommendation": "Reset password and review account"
    },
    {
      "alert_id": "ALT-002",
      "alert_type": "anomalous_login",
      "username": "admin",
      "source_ip": "185.220.101.45",
      "risk_score": 85,
      "details": "Login occurred at unusual time and from flagged IP",
      "recommendation": "Verify user activity and block IP if necessary"
    }
  ]
}


from collections import defaultdict
from models import Alert
import logging

logger = logging.getLogger(__name__)


class LogAnalyzer:
    def __init__(self, events, config=None):
        self.events = events
        self.alerts = []
        self.config = config or {}

        self.failed_threshold = self.config.get("failed_login_threshold", 2)
        self.risk_score = self.config.get("risk_score", 90)

    def detect_brute_force(self):
        attempts = defaultdict(list)

        for event in self.events:
            key = (event.username, event.source_ip)
            attempts[key].append(event)

        for (user, ip), events in attempts.items():
            failed_count = 0

            for e in events:
                if e.event_type == "login_failed":
                    failed_count += 1

                if e.event_type == "login_success" and failed_count >= self.failed_threshold:
                    logger.warning(f"Brute force detected for {user} from {ip}")

                    alert = Alert(
                        "brute_force",
                        user,
                        ip,
                        self.risk_score,
                        "Multiple failed logins followed by success"
                    )
                    self.alerts.append(alert)
                    break

    def detect_anomalous_logins(self):
        for event in self.events:
            try:
                hour = int(event.timestamp[11:13])
            except:
                continue

            if 0 <= hour <= 5:
                logger.info(f"Anomalous login detected for {event.username}")

                alert = Alert(
                    "anomalous_login",
                    event.username,
                    event.source_ip,
                    70,
                    "Login occurred at unusual hours"
                )
                self.alerts.append(alert)

    def detect_suspicious_ip(self):
        bad_ips = {"185.220.101.45"}

        for event in self.events:
            if event.source_ip in bad_ips:
                logger.info(f"Suspicious IP detected: {event.source_ip}")

                alert = Alert(
                    "suspicious_ip",
                    event.username,
                    event.source_ip,
                    85,
                    "Login from known malicious IP"
                )
                self.alerts.append(alert)

    def run(self):
        logger.info(f"Analyzing {len(self.events)} events")

        self.detect_brute_force()
        self.detect_anomalous_logins()
        self.detect_suspicious_ip()

        return self.alerts
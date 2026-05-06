from collections import defaultdict
from src.models import Alert
import logging

logger = logging.getLogger(__name__)


class LogAnalyzer:
    def __init__(self, events, config=None):
        self.events = events
        self.alerts = []
        self.config = config or {}

        self.failed_threshold = self.config.get("failed_login_threshold", 2)
        self.risk_score = self.config.get("risk_score", 90)
        self.bad_ips = set(self.config.get("bad_ips", []))

        # Prevent duplicate alerts
        self.generated_alerts = set()

    def _add_alert(self, alert):
        key = (alert.alert_type, alert.username, alert.source_ip)

        if key not in self.generated_alerts:
            self.generated_alerts.add(key)
            self.alerts.append(alert)

    def detect_brute_force(self):
        attempts = defaultdict(list)

        for event in self.events:
            key = (event.username, event.source_ip)
            attempts[key].append(event)

        for (user, ip), events in attempts.items():
            events.sort(key=lambda x: x.timestamp)

            failed_count = 0

            for e in events:
                if e.event_type == "login_failed":
                    failed_count += 1

                elif e.event_type == "login_success":
                    if failed_count >= self.failed_threshold:
                        logger.warning(f"Brute force detected for {user} from {ip}")

                        alert = Alert(
                            "brute_force",
                            user,
                            ip,
                            self.risk_score,
                            f"{failed_count} failed logins followed by success"
                        )
                        self._add_alert(alert)

                    failed_count = 0

    def detect_anomalous_logins(self):
        for event in self.events:
            try:
                hour = int(event.timestamp[11:13])
            except Exception:
                continue

            if event.event_type == "login_success" and 0 <= hour <= 5:
                logger.info(f"Anomalous login detected for {event.username}")

                alert = Alert(
                    "anomalous_login",
                    event.username,
                    event.source_ip,
                    70,
                    "Successful login occurred at unusual hours (00:00–05:00)"
                )
                self._add_alert(alert)

    def detect_suspicious_ip(self):
        for event in self.events:
            if event.source_ip in self.bad_ips:
                logger.info(f"Suspicious IP detected: {event.source_ip}")

                alert = Alert(
                    "suspicious_ip",
                    event.username,
                    event.source_ip,
                    85,
                    "Login from known malicious IP"
                )
                self._add_alert(alert)

    def detect_impossible_travel(self):
        from datetime import datetime

        user_logins = defaultdict(list)

        for event in self.events:
            if event.event_type == "login_success":
                user_logins[event.username].append(event)

        time_window = self.config.get("impossible_travel_window_minutes", 60)

        for user, events in user_logins.items():
            events.sort(key=lambda x: x.timestamp)

            for i in range(len(events) - 1):
                e1 = events[i]
                e2 = events[i + 1]

                try:
                    t1 = datetime.fromisoformat(e1.timestamp.replace("Z", ""))
                    t2 = datetime.fromisoformat(e2.timestamp.replace("Z", ""))
                except Exception:
                    continue

                delta_minutes = (t2 - t1).total_seconds() / 60

                if delta_minutes <= time_window:
                    net1 = ".".join(e1.source_ip.split(".")[:2])
                    net2 = ".".join(e2.source_ip.split(".")[:2])

                    if net1 != net2:
                        logger.warning(f"Impossible travel detected for {user}")

                        alert = Alert(
                            "impossible_travel",
                            user,
                            f"{e1.source_ip} → {e2.source_ip}",
                            95,
                            f"Logins from different networks within {int(delta_minutes)} minutes"
                        )
                        self._add_alert(alert)

    def run(self):
        logger.info(f"Analyzing {len(self.events)} events")

        self.events.sort(key=lambda x: x.timestamp)

        self.detect_brute_force()
        self.detect_anomalous_logins()
        self.detect_suspicious_ip()
        self.detect_impossible_travel()

        return self.alerts
from collections import defaultdict
from models import Alert

class LogAnalyzer:
    def __init__(self, events):
        self.events = events
        self.alerts = []

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

                if e.event_type == "login_success" and failed_count >= 2:
                    alert = Alert(
                        "brute_force",
                        user,
                        ip,
                        90,
                        "Multiple failed logins followed by success"
                    )
                    self.alerts.append(alert)
                    break

    def run(self):
        self.detect_brute_force()
        return self.alerts
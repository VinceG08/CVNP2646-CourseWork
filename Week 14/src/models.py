class SecurityEvent:
    def __init__(self, timestamp, username, source_ip, event_type):
        self.timestamp = timestamp
        self.username = username
        self.source_ip = source_ip
        self.event_type = event_type


class Alert:
    def __init__(self, alert_type, username, source_ip, risk_score, details):
        self.alert_type = alert_type
        self.username = username
        self.source_ip = source_ip
        self.risk_score = risk_score
        self.details = details

    def to_dict(self):
        return {
            "alert_type": self.alert_type,
            "username": self.username,
            "source_ip": self.source_ip,
            "risk_score": self.risk_score,
            "details": self.details
        }
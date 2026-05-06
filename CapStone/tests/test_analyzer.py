import pytest
from src.models import SecurityEvent
from src.analyzer import LogAnalyzer


def test_brute_force():
    events = [
        SecurityEvent("2024-01-01T10:00:00Z","user","1.1.1.1","login_failed"),
        SecurityEvent("2024-01-01T10:01:00Z","user","1.1.1.1","login_failed"),
        SecurityEvent("2024-01-01T10:02:00Z","user","1.1.1.1","login_success"),
    ]

    config = {"failed_login_threshold": 2, "risk_score": 90}

    analyzer = LogAnalyzer(events, config)
    alerts = analyzer.run()

    assert any(a.alert_type == "brute_force" for a in alerts)


def test_anomaly():
    events = [
        SecurityEvent("2024-01-01T02:00:00Z","user","1.1.1.1","login_success")
    ]

    analyzer = LogAnalyzer(events, {})
    alerts = analyzer.run()

    assert any(a.alert_type == "anomalous_login" for a in alerts)


def test_bad_ip():
    events = [
        SecurityEvent("2024-01-01T10:00:00Z","user","185.220.101.45","login_success")
    ]

    config = {"bad_ips": ["185.220.101.45"]}

    analyzer = LogAnalyzer(events, config)
    alerts = analyzer.run()

    assert any(a.alert_type == "suspicious_ip" for a in alerts)


def test_impossible_travel():
    events = [
        SecurityEvent("2024-01-01T10:00:00Z", "user", "10.0.0.1", "login_success"),
        SecurityEvent("2024-01-01T10:30:00Z", "user", "192.168.1.1", "login_success"),
    ]

    config = {"impossible_travel_window_minutes": 60}

    analyzer = LogAnalyzer(events, config)
    alerts = analyzer.run()

    assert any(a.alert_type == "impossible_travel" for a in alerts)
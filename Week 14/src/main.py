import json
import argparse
import logging
from models import SecurityEvent
from analyzer import LogAnalyzer

logging.basicConfig(level=logging.INFO)

def load_events(filepath):
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)

        events = []
        for e in data["events"]:
            events.append(SecurityEvent(
                e["timestamp"],
                e["username"],
                e["source_ip"],
                e["event_type"]
            ))
        return events

    except Exception as e:
        logging.error(f"Error loading file: {e}")
        return []


def save_output(alerts, output_path):
    data = {"alerts": [a.to_dict() for a in alerts]}

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=4)


def main():
    parser = argparse.ArgumentParser(description="Auth Log Analyzer")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)

    args = parser.parse_args()

    events = load_events(args.input)

    analyzer = LogAnalyzer(events)
    alerts = analyzer.run()

    save_output(alerts, args.output)

    print(f"Generated {len(alerts)} alerts")


if __name__ == "__main__":
    main()
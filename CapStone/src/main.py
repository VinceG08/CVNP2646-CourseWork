import json
import argparse
import logging
from models import SecurityEvent
from analyzer import LogAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


def load_config(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error("Config file not found")
        return {}
    except json.JSONDecodeError:
        logging.error("Invalid config JSON")
        return {}


def load_events(filepath):
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)

        if "events" not in data:
            raise ValueError("Missing 'events' key")

        events = []
        for e in data["events"]:
            try:
                events.append(SecurityEvent(
                    e["timestamp"],
                    e["username"],
                    e["source_ip"],
                    e["event_type"]
                ))
            except KeyError as err:
                logging.warning(f"Skipping bad event: missing {err}")

        return events

    except FileNotFoundError:
        logging.error("Input file not found")
        return []
    except json.JSONDecodeError:
        logging.error("Invalid JSON format")
        return []
    except Exception as e:
        logging.error(f"Error loading events: {e}")
        return []


def save_output(alerts, output_path):
    data = {"alerts": [a.to_dict() for a in alerts]}

    try:
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logging.error(f"Error saving output: {e}")


def main():
    parser = argparse.ArgumentParser(description="Auth Log Analyzer")
    parser.add_argument("--input", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)

    args = parser.parse_args()

    events = load_events(args.input)
    config = load_config(args.config)

    analyzer = LogAnalyzer(events, config)
    alerts = analyzer.run()

    save_output(alerts, args.output)

    print(f"Generated {len(alerts)} alerts")


if __name__ == "__main__":
    main()
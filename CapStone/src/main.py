import json
import argparse
import logging
from src.models import SecurityEvent
from src.analyzer import LogAnalyzer

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
    except json.JSONDecodeError:
        logging.error("Invalid JSON format")
    except Exception as e:
        logging.error(f"Error loading events: {e}")

    return []


def save_output(alerts, output_path):
    data = {"alerts": [a.to_dict() for a in alerts]}

    try:
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=4)
        logging.info(f"Saved {len(alerts)} alerts to {output_path}")
    except Exception as e:
        logging.error(f"Error saving output: {e}")


def main():
    parser = argparse.ArgumentParser(description="Auth Log Analyzer")

    parser.add_argument("--input", required=True, help="Path to input JSON file")
    parser.add_argument("--config", required=True, help="Path to config file")
    parser.add_argument("--output", required=True, help="Path to output JSON file")

    args = parser.parse_args()

    events = load_events(args.input)
    config = load_config(args.config)

    if not events:
        logging.warning("No valid events to process")
        return

    analyzer = LogAnalyzer(events, config)
    alerts = analyzer.run()

    save_output(alerts, args.output)

    print(f"Generated {len(alerts)} alerts")


if __name__ == "__main__":
    main()
import argparse
import json
import logging
from pathlib import Path
from typing import List, Dict


# =========================
# CONFIG
# =========================
class NetworkConfig:
    """Configuration for network analysis."""

    DEFAULT_PORT_SCAN_THRESHOLD = 25
    DEFAULT_SYN_FLOOD_THRESHOLD = 100

    def __init__(self, port_scan_threshold=None, syn_flood_threshold=None):
        self.port_scan_threshold = (
            port_scan_threshold or self.DEFAULT_PORT_SCAN_THRESHOLD
        )
        self.syn_flood_threshold = (
            syn_flood_threshold or self.DEFAULT_SYN_FLOOD_THRESHOLD
        )


# =========================
# LOGGING
# =========================
def setup_logging(log_file="network_monitor.log", log_level="INFO"):
    logger = logging.getLogger("network_monitor")
    logger.setLevel(logging.DEBUG)
    logger.handlers = []

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_formatter = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# =========================
# PURE FUNCTIONS
# =========================
def parse_packet_line(line: str) -> Dict:
    parts = line.strip().split(",")

    if len(parts) != 6:
        raise ValueError(f"Expected 6 fields, got {len(parts)}")

    return {
        "src_ip": parts[0],
        "dst_ip": parts[1],
        "src_port": int(parts[2]),
        "dst_port": int(parts[3]),
        "protocol": parts[4].upper(),
        "flags": parts[5].strip()
    }


def is_syn_packet(packet: Dict) -> bool:
    return packet["protocol"] == "TCP" and "SYN" in packet["flags"]


def detect_port_scan(packets: List[Dict], src_ip: str, threshold: int) -> Dict:
    ports = {p["dst_port"] for p in packets if p["src_ip"] == src_ip}

    if len(ports) > threshold:
        return {
            "src_ip": src_ip,
            "unique_ports": len(ports),
            "ports": list(ports)
        }
    return None


def detect_syn_flood(packets: List[Dict], src_ip: str, threshold: int) -> Dict:
    syn_count = sum(
        1 for p in packets if p["src_ip"] == src_ip and is_syn_packet(p)
    )

    if syn_count > threshold:
        return {
            "src_ip": src_ip,
            "syn_count": syn_count
        }
    return None


def analyze_traffic(packets: List[Dict], config: NetworkConfig, logger) -> Dict:
    results = {
        "total_packets": len(packets),
        "port_scans": [],
        "syn_floods": []
    }

    ips = {p["src_ip"] for p in packets}

    for ip in ips:
        scan = detect_port_scan(packets, ip, config.port_scan_threshold)
        if scan:
            logger.warning("Port scan detected from %s", ip)
            results["port_scans"].append(scan)

        flood = detect_syn_flood(packets, ip, config.syn_flood_threshold)
        if flood:
            logger.warning("SYN flood detected from %s", ip)
            results["syn_floods"].append(flood)

    return results


# =========================
# I/O
# =========================
def load_traffic_log(filepath: Path, logger) -> tuple[List[Dict], int]:
    packets = []
    errors = 0

    with open(filepath, "r") as f:
        for i, line in enumerate(f):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            try:
                packet = parse_packet_line(line)
                packets.append(packet)
                logger.debug("Parsed packet %d", i)
            except Exception as e:
                errors += 1
                logger.error("Parse error at line %d: %s", i, str(e))

    return packets, errors


# =========================
# CLI
# =========================
def create_parser():
    parser = argparse.ArgumentParser(
        description="Network Traffic Monitor"
    )

    parser.add_argument("input_file", type=Path)
    parser.add_argument("--output", "-o", type=Path, default=Path("results.json"))
    parser.add_argument("--port-scan-threshold", "-p", type=int, default=25)
    parser.add_argument("--syn-flood-threshold", "-s", type=int, default=100)
    parser.add_argument("--log-level", default="INFO")

    return parser


def validate_args(args):
    if not args.input_file.exists():
        raise FileNotFoundError(f"File not found: {args.input_file}")

    if args.port_scan_threshold < 1:
        raise ValueError("Port scan threshold must be >= 1")

    if args.syn_flood_threshold < 1:
        raise ValueError("SYN threshold must be >= 1")


# =========================
# MAIN
# =========================
def main():
    parser = create_parser()
    args = parser.parse_args()

    try:
        validate_args(args)

        logger = setup_logging(log_level=args.log_level)

        config = NetworkConfig(
            args.port_scan_threshold,
            args.syn_flood_threshold
        )

        logger.info("Loading traffic log...")
        packets, errors = load_traffic_log(args.input_file, logger)

        logger.info("Analyzing %d packets", len(packets))
        results = analyze_traffic(packets, config, logger)

        results["parse_errors"] = errors
        results["summary"] = (
            f"Scanned {len(packets)} packets. "
            f"Found {len(results['port_scans'])} port scans, "
            f"{len(results['syn_floods'])} SYN floods."
        )

        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

        print("\n✓ Analysis complete")
        print(f"Total packets: {len(packets)}")
        print(f"Port scans: {len(results['port_scans'])}")
        print(f"SYN floods: {len(results['syn_floods'])}")

        return 0

    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        return 1

    except ValueError as e:
        print(f"ERROR: {e}")
        return 1

    except Exception as e:
        print(f"FATAL: {e}")
        return 2


if __name__ == "__main__":
    exit(main())
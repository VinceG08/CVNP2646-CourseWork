import pytest
from network_monitor import (
    parse_packet_line,
    is_syn_packet,
    detect_port_scan,
    detect_syn_flood,
    analyze_traffic,
    NetworkConfig
)


@pytest.fixture
def sample_packet():
    return {
        "src_ip": "1.1.1.1",
        "dst_ip": "2.2.2.2",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP",
        "flags": "SYN"
    }


def test_parse_valid():
    line = "1.1.1.1,2.2.2.2,1234,80,TCP,SYN"
    result = parse_packet_line(line)
    assert result["src_port"] == 1234


def test_parse_invalid():
    with pytest.raises(ValueError):
        parse_packet_line("bad,data")


def test_syn_packet(sample_packet):
    assert is_syn_packet(sample_packet) is True


def test_port_scan_detection():
    packets = [
        {"src_ip": "1.1.1.1", "dst_port": p} for p in range(30)
    ]
    result = detect_port_scan(packets, "1.1.1.1", 25)
    assert result is not None


def test_syn_flood_detection():
    packets = [
        {
            "src_ip": "1.1.1.1",
            "protocol": "TCP",
            "flags": "SYN"
        } for _ in range(150)
    ]
    result = detect_syn_flood(packets, "1.1.1.1", 100)
    assert result is not None


def test_analyze_empty():
    config = NetworkConfig()
    result = analyze_traffic([], config, None)
    assert result["total_packets"] == 0
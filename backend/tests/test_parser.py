"""Packet extraction and limit handling."""

import time

from app.services.pcap_parser import PACKET_LIMIT_WARNING, extract_packet, parse_packets
from app.utils.files import validate_magic
from app.utils.synthetic_pcap import build_pcap, icmp_frame


class Layer:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class DummyPacket:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def test_extracts_tcp_and_ignores_unset_flags():
    record = extract_packet(
        DummyPacket(
            number="5",
            sniff_timestamp="1700000000.5",
            length="64",
            highest_layer="tcp",
            ip=Layer(src="1.1.1.1", dst="2.2.2.2"),
            tcp=Layer(srcport="123", dstport="80", flags_syn="1", flags_ack="0"),
        ),
        1,
    )
    assert record.packet_number == 5
    assert record.timestamp == 1700000000.5
    assert record.protocol == "TCP"
    assert record.src_ip == "1.1.1.1"
    assert record.dst_port == 80
    assert record.transport == "TCP"
    assert record.tcp_flags == "SYN"


def test_extracts_ipv6_udp_dns():
    record = extract_packet(
        DummyPacket(
            number="2",
            sniff_timestamp="10",
            length="90",
            highest_layer="DNS",
            ipv6=Layer(src="2001:db8::1", dst="2001:db8::2"),
            udp=Layer(srcport="53000", dstport="53"),
        ),
        1,
    )
    assert record.src_ip == "2001:db8::1"
    assert record.dst_port == 53
    assert record.transport == "UDP"
    assert record.protocol == "DNS"
    assert record.src_port == 53000


def test_extracts_icmp_without_ports():
    record = extract_packet(
        DummyPacket(
            number="3",
            sniff_timestamp="11",
            length="40",
            highest_layer="ICMP",
            ip=Layer(src="10.0.0.1", dst="10.0.0.2"),
            icmp=Layer(type="8", code="0"),
        ),
        1,
    )
    assert record.transport == "ICMP"
    assert record.src_port is None
    assert record.dst_port is None
    assert record.icmp_type == 8
    assert record.icmp_code == 0


def test_extracts_arp_addresses_without_ports():
    record = extract_packet(
        DummyPacket(
            number="4",
            sniff_timestamp="12",
            length="42",
            highest_layer="ARP",
            arp=Layer(src_proto_ipv4="10.0.0.5", dst_proto_ipv4="10.0.0.1"),
        ),
        9,
    )
    assert record.protocol == "ARP"
    assert record.src_ip == "10.0.0.5"
    assert record.dst_ip == "10.0.0.1"
    assert record.src_port is None
    assert record.transport is None


def test_hex_syn_ack_flags():
    record = extract_packet(
        DummyPacket(
            number="6",
            sniff_timestamp="1",
            length="60",
            highest_layer="TCP",
            ip=Layer(src="1.1.1.1", dst="2.2.2.2"),
            tcp=Layer(srcport="1", dstport="2", flags="0x12"),
        ),
        1,
    )
    assert record.tcp_flags == "SYN,ACK"


def test_malformed_packet_does_not_raise():
    class Exploding:
        @property
        def number(self):
            raise RuntimeError("broken packet")

    record = extract_packet(Exploding(), 11)
    assert record.packet_number == 11
    assert record.protocol == "UNKNOWN"


def test_packet_limit_stops_processing():
    packets = [
        DummyPacket(number=str(index), sniff_timestamp="1", length="10", highest_layer="TCP")
        for index in range(1, 6)
    ]
    result = parse_packets(packets, max_packets=2, max_seconds=5)
    assert len(result.packets) == 2
    assert result.warnings == [PACKET_LIMIT_WARNING.format(limit=2)]


def test_time_limit_stops_processing():
    class Slow:
        def __iter__(self):
            yield DummyPacket(number="1", sniff_timestamp="1", length="10", highest_layer="UDP")
            time.sleep(0.2)
            yield DummyPacket(number="2", sniff_timestamp="2", length="10", highest_layer="UDP")

    result = parse_packets(Slow(), max_packets=10, max_seconds=0.05)
    assert len(result.packets) == 1
    assert any("MAX_PROCESSING_SECONDS" in warning for warning in result.warnings)


def test_synthetic_pcap_has_classic_magic():
    content = build_pcap([icmp_frame("10.0.0.1", "10.0.0.2")])
    assert content[:4] == b"\xd4\xc3\xb2\xa1"
    validate_magic(content[:4], ".pcap")

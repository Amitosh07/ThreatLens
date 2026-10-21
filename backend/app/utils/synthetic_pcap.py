"""Build small classic PCAP fixtures for labs and tests.

These captures are synthetic. They are not recordings of real attacks.
"""

import ipaddress
import struct
from pathlib import Path


def ipv4_checksum(header: bytes) -> int:
    total = 0
    for index in range(0, len(header), 2):
        total += int.from_bytes(header[index : index + 2], "big")
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload: bytes, ethertype: int, src_mac: bytes | None = None, dst_mac: bytes | None = None) -> bytes:
    source = src_mac or b"\x02\x00\x00\x00\x00\x01"
    destination = dst_mac or b"\x02\x00\x00\x00\x00\x02"
    return destination + source + struct.pack("!H", ethertype) + payload


def ipv4_packet(src: str, dst: str, protocol: int, payload: bytes, identification: int = 1) -> bytes:
    source = ipaddress.IPv4Address(src).packed
    destination = ipaddress.IPv4Address(dst).packed
    total_length = 20 + len(payload)
    base = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification & 0xFFFF,
        0,
        64,
        protocol,
        0,
        source,
        destination,
    )
    checksum = ipv4_checksum(base)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification & 0xFFFF,
        0,
        64,
        protocol,
        checksum,
        source,
        destination,
    )
    return header + payload


def ipv6_packet(src: str, dst: str, next_header: int, payload: bytes) -> bytes:
    version_flow = 6 << 28
    return struct.pack(
        "!IHBB16s16s",
        version_flow,
        len(payload),
        next_header,
        64,
        ipaddress.IPv6Address(src).packed,
        ipaddress.IPv6Address(dst).packed,
    ) + payload


def tcp_segment(src_port: int, dst_port: int, flags: int, seq: int = 1, ack: int = 0) -> bytes:
    offset_flags = (5 << 12) | (flags & 0x1FF)
    return struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, 65535, 0, 0)


def udp_datagram(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def icmp_echo(identifier: int = 1, sequence: int = 1) -> bytes:
    return struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)


def arp_request(src_ip: str, dst_ip: str, src_mac: bytes | None = None) -> bytes:
    sender = src_mac or b"\x02\x00\x00\x00\x00\x01"
    target = b"\x00\x00\x00\x00\x00\x00"
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    body += sender + ipaddress.IPv4Address(src_ip).packed + target + ipaddress.IPv4Address(dst_ip).packed
    return ethernet(body, 0x0806, src_mac=sender)


def dns_query(name: str = "example.com") -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + labels + struct.pack("!HH", 1, 1)


def tcp_frame(src: str, dst: str, src_port: int, dst_port: int, flags: int, identification: int = 1) -> bytes:
    segment = tcp_segment(src_port, dst_port, flags)
    return ethernet(ipv4_packet(src, dst, 6, segment, identification), 0x0800)


def udp_frame(src: str, dst: str, src_port: int, dst_port: int, payload: bytes, identification: int = 1) -> bytes:
    datagram = udp_datagram(src_port, dst_port, payload)
    return ethernet(ipv4_packet(src, dst, 17, datagram, identification), 0x0800)


def icmp_frame(src: str, dst: str, identification: int = 1) -> bytes:
    return ethernet(ipv4_packet(src, dst, 1, icmp_echo(), identification), 0x0800)


def ipv6_tcp_frame(src: str, dst: str, src_port: int, dst_port: int, flags: int) -> bytes:
    segment = tcp_segment(src_port, dst_port, flags)
    return ethernet(ipv6_packet(src, dst, 6, segment), 0x86DD)


def build_pcap(frames: list[bytes], timestamps: list[float] | None = None) -> bytes:
    if timestamps is None:
        timestamps = [1_700_000_000 + index * 0.1 for index in range(len(frames))]
    if len(timestamps) != len(frames):
        raise ValueError("Each frame needs one timestamp.")
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    chunks = [global_header]
    for frame, timestamp in zip(frames, timestamps, strict=True):
        seconds = int(timestamp)
        microseconds = int(round((timestamp - seconds) * 1_000_000))
        if microseconds >= 1_000_000:
            seconds += 1
            microseconds -= 1_000_000
        chunks.append(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
        chunks.append(frame)
    return b"".join(chunks)


def demo_frames() -> tuple[list[bytes], list[float]]:
    """Synthetic lab traffic that exercises the default rules.

    Expected default alerts: a possible port scan, sensitive-port matches for
    ports touched by that scan, and repeated SYN attempts to TCP/443.
    The default traffic-burst threshold is intentionally higher than this file.
    """
    start = 1_700_000_000.0
    frames: list[bytes] = []
    timestamps: list[float] = []

    for offset, port in enumerate(range(1, 26)):
        frames.append(tcp_frame("10.10.1.5", "10.10.1.20", 40000 + port, port, 0x02, identification=offset + 1))
        timestamps.append(start + offset * 0.05)

    for offset in range(12):
        frames.append(tcp_frame("10.10.1.6", "10.10.1.30", 41000, 443, 0x02, identification=100 + offset))
        timestamps.append(start + 2 + offset * 0.2)

    frames.append(tcp_frame("10.10.1.30", "10.10.1.6", 443, 41000, 0x12, identification=200))
    timestamps.append(start + 2.05)

    frames.append(udp_frame("10.10.1.8", "10.10.1.53", 53000, 53, dns_query(), identification=300))
    timestamps.append(start + 5)
    frames.append(icmp_frame("10.10.1.8", "10.10.1.20", identification=301))
    timestamps.append(start + 5.1)
    frames.append(arp_request("10.10.1.8", "10.10.1.1"))
    timestamps.append(start + 5.2)
    frames.append(ipv6_tcp_frame("2001:db8::10", "2001:db8::20", 51515, 80, 0x02))
    timestamps.append(start + 5.3)
    return frames, timestamps


def build_demo_pcap() -> bytes:
    frames, timestamps = demo_frames()
    return build_pcap(frames, timestamps)


def write_demo_pcap(path: Path) -> None:
    path.write_bytes(build_demo_pcap())

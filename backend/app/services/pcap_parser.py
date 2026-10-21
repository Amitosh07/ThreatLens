"""Turn PyShark packets into compact records without keeping decoded objects."""

import asyncio
from dataclasses import dataclass, field
import logging
import time

from app.services.errors import CaptureParseError

logger = logging.getLogger("threatlens.parser")

PACKET_LIMIT_WARNING = (
    "Processing stopped after {limit} packets because THREATLENS_MAX_PACKETS was reached. "
    "Statistics and alerts cover only the packets that were processed."
)
TIME_LIMIT_WARNING = (
    "Processing stopped because THREATLENS_MAX_PROCESSING_SECONDS was reached. "
    "Statistics and alerts cover only the packets that were processed."
)

FLAG_ATTRIBUTES = (
    ("flags_fin", "FIN"),
    ("flags_syn", "SYN"),
    ("flags_reset", "RST"),
    ("flags_rst", "RST"),
    ("flags_push", "PSH"),
    ("flags_psh", "PSH"),
    ("flags_ack", "ACK"),
    ("flags_urg", "URG"),
    ("flags_ece", "ECE"),
    ("flags_cwr", "CWR"),
)
FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)


@dataclass(slots=True)
class PacketRecord:
    packet_number: int
    timestamp: float
    length: int
    protocol: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    transport: str | None = None
    tcp_flags: str | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None


@dataclass(slots=True)
class ParseResult:
    packets: list[PacketRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _text(value) -> str | None:
    if value is None:
        return None
    try:
        text = str(value).strip()
    except Exception:
        return None
    if not text or text.lower() in {"none", "null"}:
        return None
    return text


def _layer(packet, name: str):
    try:
        return getattr(packet, name)
    except Exception:
        return None


def _field(layer, *names: str) -> str | None:
    if layer is None:
        return None
    for name in names:
        try:
            text = _text(getattr(layer, name))
        except Exception:
            text = None
        if text is not None:
            return text
    return None


def _first_int(value: str | None) -> int | None:
    if value is None:
        return None
    token = value.split(",")[0].strip()
    try:
        return int(token, 10)
    except ValueError:
        try:
            return int(float(token))
        except ValueError:
            return None


def _first_float(value: str | None, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        return float(value.split(",")[0].strip())
    except ValueError:
        return default


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "set"}


def _hex_flags(value: str | None) -> list[str]:
    if value is None:
        return []
    text = value.strip().lower()
    try:
        if text.startswith("0x"):
            number = int(text, 16)
        else:
            number = int(text, 16) if all(character in "0123456789abcdef" for character in text) else int(text, 10)
    except ValueError:
        return []
    return [name for bit, name in FLAG_BITS if number & bit]


def _tcp_flags(tcp_layer) -> str | None:
    if tcp_layer is None:
        return None
    names: list[str] = []
    for attribute, name in FLAG_ATTRIBUTES:
        try:
            raw = _text(getattr(tcp_layer, attribute))
        except Exception:
            raw = None
        if _truthy(raw) and name not in names:
            names.append(name)
    if not names:
        try:
            raw_flags = _text(getattr(tcp_layer, "flags"))
        except Exception:
            raw_flags = None
        for name in _hex_flags(raw_flags):
            if name not in names:
                names.append(name)
    return ",".join(names) if names else None


def _protocol(packet) -> str:
    try:
        highest = _text(getattr(packet, "highest_layer", None))
    except Exception:
        highest = None
    if highest:
        return highest.upper()
    frame = _layer(packet, "frame_info")
    protocols = _field(frame, "protocols")
    if protocols:
        return protocols.split(":")[-1].strip().upper() or "UNKNOWN"
    return "UNKNOWN"


def extract_packet(packet, fallback_number: int) -> PacketRecord:
    """Read one decoded packet. A broken packet becomes an unknown record."""
    try:
        number = _first_int(_text(getattr(packet, "number", None))) or fallback_number
        timestamp = _first_float(_text(getattr(packet, "sniff_timestamp", None)))
        length = _first_int(_text(getattr(packet, "length", None)))
        if length is None:
            frame = _layer(packet, "frame_info")
            length = _first_int(_field(frame, "len", "cap_len")) or 0
        if length < 0:
            length = 0

        ip_layer = _layer(packet, "ip")
        ipv6_layer = _layer(packet, "ipv6")
        arp_layer = _layer(packet, "arp")
        tcp_layer = _layer(packet, "tcp")
        udp_layer = _layer(packet, "udp")
        icmp_layer = _layer(packet, "icmp")
        icmpv6_layer = _layer(packet, "icmpv6")

        src_ip = _field(ip_layer, "src") or _field(ipv6_layer, "src") or _field(arp_layer, "src_proto_ipv4")
        dst_ip = _field(ip_layer, "dst") or _field(ipv6_layer, "dst") or _field(arp_layer, "dst_proto_ipv4")
        src_port = _first_int(_field(tcp_layer, "srcport", "src_port") or _field(udp_layer, "srcport", "src_port"))
        dst_port = _first_int(_field(tcp_layer, "dstport", "dst_port") or _field(udp_layer, "dstport", "dst_port"))

        if tcp_layer is not None:
            transport = "TCP"
        elif udp_layer is not None:
            transport = "UDP"
        elif icmp_layer is not None or icmpv6_layer is not None:
            transport = "ICMP"
        else:
            transport = None

        icmp_source = icmp_layer if icmp_layer is not None else icmpv6_layer
        return PacketRecord(
            packet_number=number,
            timestamp=timestamp,
            length=length,
            protocol=_protocol(packet),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport=transport,
            tcp_flags=_tcp_flags(tcp_layer),
            icmp_type=_first_int(_field(icmp_source, "type", "icmp_type")),
            icmp_code=_first_int(_field(icmp_source, "code", "icmp_code")),
        )
    except Exception:
        logger.warning("Skipped an unreadable packet", exc_info=True)
        return PacketRecord(
            packet_number=fallback_number,
            timestamp=0.0,
            length=0,
            protocol="UNKNOWN",
        )


def parse_packets(packets, max_packets: int, max_seconds: int | float) -> ParseResult:
    records: list[PacketRecord] = []
    warnings: list[str] = []
    deadline = time.monotonic() + max_seconds
    for index, packet in enumerate(packets, start=1):
        if len(records) >= max_packets:
            warnings.append(PACKET_LIMIT_WARNING.format(limit=max_packets))
            break
        if time.monotonic() > deadline:
            warnings.append(TIME_LIMIT_WARNING)
            break
        records.append(extract_packet(packet, index))
    return ParseResult(packets=records, warnings=warnings)


def _ensure_capture_event_loop() -> None:
    """PyShark on Windows expects a loop, including inside a worker thread.

    Python 3.12+ does not create one automatically for non-main threads.
    """
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())


def parse_capture(path, tshark_path: str, max_packets: int, max_seconds: int) -> ParseResult:
    try:
        import pyshark
    except ImportError as exc:
        raise CaptureParseError(
            "PyShark is not installed in the backend environment. "
            "From the backend directory run: .\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt"
        ) from exc

    capture = None
    try:
        _ensure_capture_event_loop()
        capture = pyshark.FileCapture(
            str(path),
            tshark_path=tshark_path,
            keep_packets=False,
            include_raw=False,
            custom_parameters=["-n"],
        )
        return parse_packets(capture, max_packets=max_packets, max_seconds=max_seconds)
    except CaptureParseError:
        raise
    except Exception as exc:
        logger.exception("PyShark could not read %s", path)
        raise CaptureParseError(
            "TShark could not read this capture. The file may be truncated, corrupted, or not a packet capture."
        ) from exc
    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception:
                logger.warning("PyShark capture did not close cleanly", exc_info=True)

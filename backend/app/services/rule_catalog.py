"""Detection rule definitions, defaults, and parameter validation."""

from copy import deepcopy

SEVERITIES = ("info", "low", "medium", "high", "critical")

RULE_CATALOG: list[dict] = [
    {
        "rule_key": "port_scan",
        "name": "Possible Port Scan",
        "description": (
            "Flags a source host that contacts many distinct destination ports on one "
            "destination host inside a time window. The pattern can match scanning, "
            "asset inventory, or application behavior. It is not proof of compromise."
        ),
        "enabled": True,
        "severity": "high",
        "parameters": {"distinct_ports": 20, "window_seconds": 60},
        "parameter_schema": [
            {
                "name": "distinct_ports",
                "label": "Distinct destination ports",
                "type": "integer",
                "min": 2,
                "max": 10000,
                "help": "Alert when one source reaches this many different destination ports on the same host.",
            },
            {
                "name": "window_seconds",
                "label": "Time window (seconds)",
                "type": "integer",
                "min": 1,
                "max": 86400,
                "help": "Only ports contacted inside this window are counted together.",
            },
        ],
    },
    {
        "rule_key": "traffic_burst",
        "name": "Possible Traffic Burst",
        "description": (
            "Flags a source host or a communicating pair whose packet count or byte count "
            "inside a time window exceeds the configured thresholds. High volume can be a "
            "transfer, a backup, or a flood. The alert states which threshold was exceeded."
        ),
        "enabled": True,
        "severity": "medium",
        "parameters": {"packet_rate": 500, "byte_rate": 1_000_000, "window_seconds": 10},
        "parameter_schema": [
            {
                "name": "packet_rate",
                "label": "Packet threshold per window",
                "type": "integer",
                "min": 1,
                "max": 10_000_000,
                "help": "Alert when packets in one window reach this count.",
            },
            {
                "name": "byte_rate",
                "label": "Byte threshold per window",
                "type": "integer",
                "min": 1,
                "max": 1_000_000_000_000,
                "help": "Alert when bytes in one window reach this total.",
            },
            {
                "name": "window_seconds",
                "label": "Time window (seconds)",
                "type": "integer",
                "min": 1,
                "max": 86400,
                "help": "Length of each fixed window, measured from the start of the capture.",
            },
        ],
    },
    {
        "rule_key": "sensitive_port",
        "name": "Sensitive Port Access",
        "description": (
            "Flags traffic whose destination port is on your watchlist. Administrative ports "
            "are often legitimate. A match is a lead for review, not a finding that the "
            "traffic is an intrusion."
        ),
        "enabled": True,
        "severity": "low",
        "parameters": {
            "ports": [21, 22, 23, 25, 135, 139, 161, 389, 445, 636, 1433, 3306, 3389, 5432, 5900, 6379, 27017]
        },
        "parameter_schema": [
            {
                "name": "ports",
                "label": "Sensitive destination ports",
                "type": "port_list",
                "min": 1,
                "max": 65535,
                "max_items": 100,
                "help": "Destination ports to watch. A match is not treated as confirmed malicious activity.",
            }
        ],
    },
    {
        "rule_key": "unusual_protocol",
        "name": "Protocol Outside Baseline",
        "description": (
            "Flags decoded protocols that are outside the configured expected set. A protocol "
            "is not treated as suspicious merely because it is uncommon if it is listed in the baseline."
        ),
        "enabled": True,
        "severity": "low",
        "parameters": {
            "expected_protocols": [
                "TCP",
                "UDP",
                "ICMP",
                "ICMPV6",
                "ARP",
                "DNS",
                "MDNS",
                "LLMNR",
                "DHCP",
                "DHCPV6",
                "NTP",
                "HTTP",
                "HTTP2",
                "TLS",
                "SSL",
                "QUIC",
                "SSDP",
                "NBNS",
                "BROWSER",
                "LDAP",
                "SMB",
                "SMB2",
                "KRB5",
                "SYSLOG",
                "SNMP",
                "IGMP",
                "STP",
                "LLDP",
                "CDP",
                "OCSP",
                "DATA",
                "IP",
                "IPV6",
                "ETH",
            ]
        },
        "parameter_schema": [
            {
                "name": "expected_protocols",
                "label": "Expected protocols",
                "type": "protocol_list",
                "max_items": 60,
                "help": "Highest-layer protocol names that should not raise this alert. Matching is case-insensitive.",
            }
        ],
    },
    {
        "rule_key": "repeated_syn",
        "name": "Repeated Connection Attempts",
        "description": (
            "Flags repeated TCP SYN packets without the ACK flag from one source to one "
            "destination socket inside the time window. SYN-ACK responses are not counted. "
            "The rule does not claim that authentication failed or that a connection was refused."
        ),
        "enabled": True,
        "severity": "medium",
        "parameters": {"syn_count": 10, "window_seconds": 30},
        "parameter_schema": [
            {
                "name": "syn_count",
                "label": "SYN attempts",
                "type": "integer",
                "min": 2,
                "max": 1_000_000,
                "help": "Alert when SYN packets without ACK reach this count for one source and destination socket.",
            },
            {
                "name": "window_seconds",
                "label": "Time window (seconds)",
                "type": "integer",
                "min": 1,
                "max": 86400,
                "help": "Only SYN attempts inside this window are counted together.",
            },
        ],
    },
]


def get_rule_definition(rule_key: str) -> dict | None:
    for definition in RULE_CATALOG:
        if definition["rule_key"] == rule_key:
            return definition
    return None


def snapshot_from_rule(rule) -> dict:
    definition = get_rule_definition(rule.rule_key)
    return {
        "rule_key": rule.rule_key,
        "name": rule.name,
        "description": rule.description,
        "enabled": bool(rule.enabled),
        "severity": rule.severity,
        "parameters": deepcopy(rule.parameters or {}),
        "parameter_schema": deepcopy(definition["parameter_schema"]) if definition else [],
    }


def _as_int(field: dict, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field['label']} must be an integer.")
    minimum = field.get("min")
    maximum = field.get("max")
    if minimum is not None and value < minimum or maximum is not None and value > maximum:
        raise ValueError(f"{field['label']} must be between {minimum} and {maximum}.")
    return value


def _as_port_list(field: dict, value) -> list[int]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field['label']} must be a non-empty list of ports.")
    max_items = field.get("max_items", 100)
    if len(value) > max_items:
        raise ValueError(f"{field['label']} cannot contain more than {max_items} ports.")
    ports: list[int] = []
    for item in value:
        port = _as_int({**field, "label": "Each port"}, item)
        if port not in ports:
            ports.append(port)
    return ports


def _as_protocol_list(field: dict, value) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field['label']} must be a non-empty list.")
    max_items = field.get("max_items", 60)
    if len(value) > max_items:
        raise ValueError(f"{field['label']} cannot contain more than {max_items} entries.")
    protocols: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("Protocol names must be text.")
        name = item.strip().upper()
        if not name or len(name) > 40 or any(not (character.isalnum() or character in {"_", "-"}) for character in name):
            raise ValueError("Protocol names must be 1-40 characters and use letters, numbers, '_' or '-'.")
        if name not in protocols:
            protocols.append(name)
    if not protocols:
        raise ValueError(f"{field['label']} must contain at least one protocol.")
    return protocols


def validate_parameters(rule_key: str, parameters: dict) -> dict:
    definition = get_rule_definition(rule_key)
    if definition is None:
        raise ValueError("Unknown detection rule.")
    if not isinstance(parameters, dict):
        raise ValueError("Parameters must be an object.")
    schema = {field["name"]: field for field in definition["parameter_schema"]}
    unknown = sorted(set(parameters) - set(schema))
    if unknown:
        raise ValueError("Unknown parameters: " + ", ".join(unknown))
    missing = [name for name in schema if name not in parameters]
    if missing:
        raise ValueError("Missing parameters: " + ", ".join(missing))
    cleaned: dict = {}
    for name, field in schema.items():
        value = parameters[name]
        field_type = field["type"]
        if field_type == "integer":
            cleaned[name] = _as_int(field, value)
        elif field_type == "port_list":
            cleaned[name] = _as_port_list(field, value)
        elif field_type == "protocol_list":
            cleaned[name] = _as_protocol_list(field, value)
        else:
            raise ValueError(f"Unsupported parameter type for {name}.")
    return cleaned


def validate_severity(severity: str) -> str:
    if severity not in SEVERITIES:
        raise ValueError("Severity must be one of: info, low, medium, high, critical.")
    return severity

// UI payloads follow backend/app/schemas.py and serializers.py. No packet parser is run here.
export const analysisId = "11111111-1111-4111-8111-111111111111";
export const brief = {
  id: analysisId, original_filename: "synthetic-lab-fixture.pcap", file_size: 128,
  file_hash: "a".repeat(64), status: "queued", created_at: "2026-10-21T10:00:00Z",
  started_at: null, completed_at: null, duration_ms: null,
  packet_count: 0, total_bytes: 0, alert_count: 0, error_message: null,
};
export const completed = {
  ...brief, status: "completed", packet_count: 4, total_bytes: 256, alert_count: 1,
  duration_ms: 42, completed_at: "2026-10-21T10:00:01Z",
  summary: {
    unique_source_hosts: 2, unique_destination_hosts: 1, unique_hosts: 3,
    tcp_syn_attempts: 1, tcp_syn_ack_responses: 0, protocols: [], timeline: [],
    top_sources: [], top_destinations: [], top_pairs: [], transports: {},
    top_source_ports: [], top_destination_ports: [], warnings: [],
  },
  rule_snapshot: [{ rule_key: "sensitive_port", name: "Sensitive Port Access", enabled: true, severity: "low", parameters: { ports: [22] } }],
};
export const packet = {
  packet_number: 2, timestamp: 1792576800, timestamp_iso: "2026-10-21T10:00:00Z",
  length: 64, protocol: "TCP", transport: "TCP", src_ip: "192.0.2.10",
  dst_ip: "198.51.100.7", src_port: 51515, dst_port: 22, tcp_flags: "SYN",
  icmp_type: null, icmp_code: null,
};
export const alert = {
  id: 7, analysis_id: analysisId, rule_key: "sensitive_port", rule_name: "Sensitive Port Access",
  severity: "low", evidence_strength: "packet", description: "Port 22 observed",
  explanation: "Review the supporting packet.", src_ip: packet.src_ip, dst_ip: packet.dst_ip,
  src_port: packet.src_port, dst_port: 22, window_start: packet.timestamp,
  window_end: packet.timestamp, observed_value: "22", threshold_value: "22",
  packet_numbers: [2], evidence: {}, created_at: "2026-10-21T10:00:01Z",
};
export const rule = {
  id: 3, rule_key: "sensitive_port", name: "Sensitive Port Access",
  description: "Watch selected ports", enabled: true, severity: "low",
  parameters: { ports: [22, 3389] }, updated_at: "2026-10-21T10:00:00Z",
  parameter_schema: [{ name: "ports", label: "Sensitive destination ports", type: "port_list", min: 1, max: 65535, max_items: 100, help: "Ports to watch" }],
};
export const page = (items) => ({ items, total: items.length, page: 1, page_size: 20, pages: items.length ? 1 : 0 });

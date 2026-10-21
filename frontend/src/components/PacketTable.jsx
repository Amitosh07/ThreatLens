import { display, endpoint, formatBytes, formatNumber, formatTime } from "../utils/format";

export default function PacketTable({ packets }) {
  if (!packets?.length) {
    return <p className="text-sm text-slate-500">No packets match these filters.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-left text-sm">
        <caption className="sr-only">Packet metadata</caption>
        <thead className="text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th scope="col" className="px-3 py-2 font-medium">#</th>
            <th scope="col" className="px-3 py-2 font-medium">Time</th>
            <th scope="col" className="px-3 py-2 font-medium">Source</th>
            <th scope="col" className="px-3 py-2 font-medium">Destination</th>
            <th scope="col" className="px-3 py-2 font-medium">Protocol</th>
            <th scope="col" className="px-3 py-2 font-medium">Length</th>
            <th scope="col" className="px-3 py-2 font-medium">TCP / ICMP</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((packet) => (
            <tr key={packet.packet_number} className="border-t border-line/80">
              <td className="px-3 py-2 font-mono text-slate-300">{packet.packet_number}</td>
              <td className="px-3 py-2 text-slate-300">{formatTime(packet.timestamp)}</td>
              <td className="px-3 py-2 font-mono text-xs">{endpoint(packet.src_ip, packet.src_port)}</td>
              <td className="px-3 py-2 font-mono text-xs">{endpoint(packet.dst_ip, packet.dst_port)}</td>
              <td className="px-3 py-2">
                <div>{display(packet.protocol)}</div>
                {packet.transport && packet.transport !== packet.protocol ? (
                  <div className="text-xs text-slate-500">{packet.transport}</div>
                ) : null}
              </td>
              <td className="px-3 py-2 font-mono">{formatBytes(packet.length)}</td>
              <td className="px-3 py-2 text-xs text-slate-400">
                {packet.tcp_flags
                  ? packet.tcp_flags
                  : packet.icmp_type != null
                    ? `ICMP ${packet.icmp_type}/${display(packet.icmp_code)}`
                    : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="sr-only">{formatNumber(packets.length)} rows shown</p>
    </div>
  );
}

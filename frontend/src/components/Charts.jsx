import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, Area, AreaChart } from "recharts";
import { formatBytes, formatNumber, formatTime } from "../utils/format";

const tooltipStyle = {
  background: "#0d1828",
  border: "1px solid #1e3348",
  borderRadius: 8,
  color: "#e7eef7",
};

export function ProtocolChart({ protocols }) {
  const data = (protocols || []).slice(0, 8);
  if (!data.length) return <p className="text-sm text-slate-500">No protocol data for this analysis.</p>;
  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
          <CartesianGrid stroke="#1e3348" vertical={false} />
          <XAxis dataKey="protocol" stroke="#8ea3b8" fontSize={12} tickLine={false} />
          <YAxis stroke="#8ea3b8" fontSize={12} tickLine={false} allowDecimals={false} />
          <Tooltip
            contentStyle={tooltipStyle}
            formatter={(value, name) => [formatNumber(value), name === "packets" ? "Packets" : name]}
          />
          <Bar dataKey="packets" fill="#5eead4" radius={[3, 3, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function TimelineChart({ timeline }) {
  const data = (timeline || []).map((bucket) => ({
    ...bucket,
    label: formatTime(bucket.bucket_start),
  }));
  if (!data.length) return <p className="text-sm text-slate-500">No timeline for this analysis.</p>;
  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
          <CartesianGrid stroke="#1e3348" vertical={false} />
          <XAxis dataKey="label" stroke="#8ea3b8" fontSize={11} tickLine={false} minTickGap={24} />
          <YAxis stroke="#8ea3b8" fontSize={12} tickLine={false} allowDecimals={false} />
          <Tooltip
            contentStyle={tooltipStyle}
            formatter={(value, name) => [name === "bytes" ? formatBytes(value) : formatNumber(value), name === "bytes" ? "Bytes" : "Packets"]}
          />
          <Area type="monotone" dataKey="packets" stroke="#67e8f9" fill="#155e75" fillOpacity={0.45} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function HostsChart({ hosts }) {
  const data = (hosts || []).slice(0, 8).map((host) => ({ ...host, label: host.ip }));
  if (!data.length) return <p className="text-sm text-slate-500">No host addresses in this analysis.</p>;
  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 8, right: 12, left: 16, bottom: 8 }}>
          <CartesianGrid stroke="#1e3348" horizontal={false} />
          <XAxis type="number" stroke="#8ea3b8" fontSize={12} allowDecimals={false} />
          <YAxis type="category" dataKey="label" stroke="#8ea3b8" fontSize={11} width={120} />
          <Tooltip contentStyle={tooltipStyle} formatter={(value) => [formatNumber(value), "Packets"]} />
          <Bar dataKey="packets" fill="#38bdf8" radius={[0, 3, 3, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

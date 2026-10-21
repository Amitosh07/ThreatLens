import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { HostsChart, ProtocolChart, TimelineChart } from "../components/Charts";
import PacketTable from "../components/PacketTable";
import { ErrorNote, LoadingBlock, Pagination, Stat, StatusBadge } from "../components/ui";
import { api, errorMessage } from "../services/api";
import { formatBytes, formatDuration, formatNumber, formatTime } from "../utils/format";

export default function AnalysisPage() {
  const { analysisId } = useParams();
  const [analysis, setAnalysis] = useState(null);
  const [packets, setPackets] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [confirmRun, setConfirmRun] = useState(false);
  const [filters, setFilters] = useState({ protocol: "", src_ip: "", dst_ip: "", q: "", page: 1 });
  const [draft, setDraft] = useState(filters);

  useEffect(() => {
    let stop = false;
    async function load() {
      try {
        const response = await api.get(`/analyses/${analysisId}`);
        if (!stop) {
          setAnalysis(response.data);
          setError("");
        }
      } catch (err) {
        if (!stop) setError(errorMessage(err));
      } finally {
        if (!stop) setLoading(false);
      }
    }
    load();
    const timer = setInterval(() => {
      if (analysis && analysis.status !== "queued" && analysis.status !== "processing") return;
      load();
    }, 1500);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, [analysisId, analysis?.status]);

  useEffect(() => {
    if (analysis?.status !== "completed") {
      setPackets(null);
      return undefined;
    }
    let ignore = false;
    const params = { page: filters.page, page_size: 25 };
    ["protocol", "src_ip", "dst_ip", "q"].forEach((key) => {
      if (filters[key]) params[key] = filters[key];
    });
    api
      .get(`/analyses/${analysisId}/packets`, { params })
      .then((response) => {
        if (!ignore) setPackets(response.data);
      })
      .catch((err) => {
        if (!ignore) setError(errorMessage(err));
      });
    return () => {
      ignore = true;
    };
  }, [analysisId, analysis?.status, filters]);

  async function runAgain() {
    setError("");
    try {
      const response = await api.post(`/analyses/${analysisId}/run`);
      setAnalysis(response.data);
      setConfirmRun(false);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  if (loading && !analysis) return <LoadingBlock label="Loading analysis" />;
  if (!analysis) return <ErrorNote message={error || "Analysis not found."} />;

  const summary = analysis.summary;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-xs text-slate-500">{analysis.id}</p>
          <h1 className="mt-1 text-2xl font-semibold">{analysis.original_filename}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-slate-400">
            <StatusBadge value={analysis.status} />
            <span>Processing {formatDuration(analysis.duration_ms)}</span>
            <span>SHA-256 {analysis.file_hash.slice(0, 12)}…</span>
          </div>
        </div>
        <div className="flex gap-2">
          <Link className="btn-ghost" to={`/alerts?analysis=${analysis.id}`}>
            Alerts
          </Link>
          <Link className="btn-ghost" to={`/reports?analysis=${analysis.id}`}>
            Report
          </Link>
          {analysis.status !== "processing" ? (
            <button type="button" className="btn-ghost" onClick={() => setConfirmRun(true)}>
              Run again
            </button>
          ) : null}
        </div>
      </div>
      <ErrorNote message={error} />
      {confirmRun ? (
        <div className="card p-4 text-sm text-slate-300">
          <p>Run again clears packets, alerts, and the summary for this file, then applies the rules currently saved.</p>
          <div className="mt-3 flex gap-2">
            <button type="button" className="btn-primary" onClick={runAgain}>
              Replace results
            </button>
            <button type="button" className="btn-ghost" onClick={() => setConfirmRun(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}
      {analysis.status === "failed" ? <ErrorNote message={analysis.error_message} /> : null}
      {analysis.status !== "completed" ? (
        <p className="text-sm text-slate-400">Packet statistics are shown after analysis completes successfully.</p>
      ) : (
        <>
          <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Stat label="Packets" value={formatNumber(analysis.packet_count)} />
            <Stat label="Bytes" value={formatBytes(analysis.total_bytes)} />
            <Stat label="Unique source hosts" value={formatNumber(summary?.unique_source_hosts)} />
            <Stat label="Unique destination hosts" value={formatNumber(summary?.unique_destination_hosts)} hint={`${formatNumber(summary?.unique_hosts)} unique hosts in the union`} />
          </section>
          <p className="text-sm text-slate-400">
            Capture range {formatTime(summary?.capture_start)} – {formatTime(summary?.capture_end)} ({summary?.capture_span_seconds ?? 0}s). TCP SYN attempts {formatNumber(summary?.tcp_syn_attempts)}. SYN-ACK responses {formatNumber(summary?.tcp_syn_ack_responses)}.
          </p>
          {(summary?.warnings || []).map((warning) => (
            <p key={warning} className="rounded-md border border-amber-900/60 bg-amber-950/30 px-3 py-2 text-sm text-amber-100">
              {warning}
            </p>
          ))}
          <section className="grid gap-4 xl:grid-cols-2">
            <article className="card p-4">
              <h2 className="mb-3 text-sm font-medium">Protocols</h2>
              <ProtocolChart protocols={summary?.protocols} />
            </article>
            <article className="card p-4">
              <h2 className="mb-3 text-sm font-medium">Timeline</h2>
              <TimelineChart timeline={summary?.timeline} />
            </article>
          </section>
          <section className="grid gap-4 lg:grid-cols-2">
            <RankList title="Top sources" rows={summary?.top_sources} />
            <RankList title="Top destinations" rows={summary?.top_destinations} />
            <PairList pairs={summary?.top_pairs} />
            <article className="card p-4">
              <h2 className="mb-3 text-sm font-medium">Transports and ports</h2>
              <p className="text-sm text-slate-300">
                TCP {summary?.transports?.TCP || 0} · UDP {summary?.transports?.UDP || 0} · ICMP {summary?.transports?.ICMP || 0} · Other {summary?.transports?.Other || 0}
              </p>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <PortList title="Source ports" rows={summary?.top_source_ports} />
                <PortList title="Destination ports" rows={summary?.top_destination_ports} />
              </div>
            </article>
          </section>
          <section className="card p-4">
            <h2 className="mb-3 text-sm font-medium">Packets</h2>
            <form
              className="mb-4 grid gap-3 md:grid-cols-5"
              onSubmit={(event) => {
                event.preventDefault();
                setFilters({ ...draft, page: 1 });
              }}
            >
              <input className="field" placeholder="Protocol" aria-label="Protocol" value={draft.protocol} onChange={(event) => setDraft({ ...draft, protocol: event.target.value })} />
              <input className="field" placeholder="Source IP" aria-label="Source IP" value={draft.src_ip} onChange={(event) => setDraft({ ...draft, src_ip: event.target.value })} />
              <input className="field" placeholder="Destination IP" aria-label="Destination IP" value={draft.dst_ip} onChange={(event) => setDraft({ ...draft, dst_ip: event.target.value })} />
              <input className="field" placeholder="Search" aria-label="Search packets" value={draft.q} onChange={(event) => setDraft({ ...draft, q: event.target.value })} />
              <button className="btn-primary" type="submit">Filter</button>
            </form>
            <PacketTable packets={packets?.items || []} />
            <div className="mt-4">
              <Pagination
                page={packets?.page || 1}
                pages={packets?.pages || 0}
                total={packets?.total || 0}
                onPage={(page) => setFilters((current) => ({ ...current, page }))}
              />
            </div>
          </section>
          <article className="card p-4">
            <h2 className="mb-2 text-sm font-medium">Top communicating pairs</h2>
            <HostsChart hosts={(summary?.top_pairs || []).map((pair) => ({ ip: `${pair.src_ip} → ${pair.dst_ip}`, packets: pair.packets }))} />
          </article>
        </>
      )}
    </div>
  );
}

function RankList({ title, rows }) {
  return (
    <article className="card p-4">
      <h2 className="mb-3 text-sm font-medium">{title}</h2>
      {(rows || []).length === 0 ? (
        <p className="text-sm text-slate-500">None</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {rows.map((row) => (
            <li key={row.ip} className="flex justify-between gap-3 font-mono text-xs">
              <span>{row.ip}</span>
              <span className="text-slate-400">
                {formatNumber(row.packets)} pkts · {formatBytes(row.bytes)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

function PairList({ pairs }) {
  return (
    <article className="card p-4">
      <h2 className="mb-3 text-sm font-medium">Host pairs</h2>
      {(pairs || []).length === 0 ? (
        <p className="text-sm text-slate-500">No IP pairs.</p>
      ) : (
        <ul className="space-y-2 text-xs">
          {pairs.map((pair) => (
            <li key={`${pair.src_ip}-${pair.dst_ip}`} className="flex justify-between gap-3 font-mono">
              <span>
                {pair.src_ip} → {pair.dst_ip}
              </span>
              <span className="text-slate-400">{formatNumber(pair.packets)}</span>
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

function PortList({ title, rows }) {
  return (
    <div>
      <h3 className="mb-2 text-xs uppercase tracking-wide text-slate-500">{title}</h3>
      {(rows || []).length === 0 ? (
        <p className="text-sm text-slate-500">None</p>
      ) : (
        <ul className="space-y-1 font-mono text-xs">
          {rows.map((row) => (
            <li key={row.port} className="flex justify-between">
              <span>{row.port}</span>
              <span className="text-slate-500">{row.packets}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

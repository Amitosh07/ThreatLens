import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { HostsChart, ProtocolChart, TimelineChart } from "../components/Charts";
import { EmptyState, ErrorNote, LoadingBlock, SeverityBadge, Stat, StatusBadge } from "../components/ui";
import { api, errorMessage } from "../services/api";
import { formatBytes, formatNumber, formatTime } from "../utils/format";

export default function DashboardPage() {
  const [params, setParams] = useSearchParams();
  const [overview, setOverview] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const selectedId = params.get("analysis") || "";

  useEffect(() => {
    let ignore = false;
    setLoading(true);
    const query = selectedId ? `?analysis_id=${encodeURIComponent(selectedId)}` : "";
    api
      .get(`/overview${query}`)
      .then((response) => {
        if (!ignore) setOverview(response.data);
      })
      .catch((err) => {
        if (!ignore) setError(errorMessage(err));
      })
      .finally(() => {
        if (!ignore) setLoading(false);
      });
    return () => {
      ignore = true;
    };
  }, [selectedId]);

  if (loading && !overview) return <LoadingBlock label="Loading overview" />;
  if (!overview && error) return <ErrorNote message={error} />;
  if (!overview?.total_analyses) {
    return (
      <EmptyState
        title="No captures analyzed yet"
        body="Upload a PCAP or PCAPNG file from an authorized lab capture. ThreatLens will parse it with TShark and show statistics only after processing finishes."
        action={
          <Link className="btn-primary" to="/upload">
            Upload a capture
          </Link>
        }
      />
    );
  }

  const selected = overview.selected_analysis;
  const summary = selected?.summary;
  const counts = overview.alert_severity_counts || {};

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Overview</h1>
          <p className="mt-1 text-sm text-slate-400">Figures below come from stored analyses, not sample data.</p>
        </div>
        <label className="text-sm text-slate-400">
          Analysis
          <select
            className="field mt-1 min-w-64"
            value={selected?.id || ""}
            onChange={(event) => {
              const next = new URLSearchParams(params);
              if (event.target.value) next.set("analysis", event.target.value);
              else next.delete("analysis");
              setParams(next);
            }}
          >
            {(overview.recent_analyses.some((item) => item.id === selected?.id) || !selected
              ? overview.recent_analyses
              : [selected, ...overview.recent_analyses]
            ).map((analysis) => (
              <option key={analysis.id} value={analysis.id}>
                {analysis.original_filename}
              </option>
            ))}
          </select>
        </label>
      </div>
      <ErrorNote message={error} />
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Total analyses" value={formatNumber(overview.total_analyses)} />
        <Stat
          label="Packets in selection"
          value={formatNumber(selected?.packet_count)}
          hint={selected ? selected.original_filename : "No analysis selected"}
        />
        <Stat label="Captured bytes" value={formatBytes(selected?.total_bytes)} hint="Sum of parsed packet lengths" />
        <Stat
          label="Unique hosts"
          value={formatNumber(summary?.unique_hosts)}
          hint={
            summary
              ? `${formatNumber(summary.unique_source_hosts)} sources · ${formatNumber(summary.unique_destination_hosts)} destinations`
              : "Available after a completed analysis"
          }
        />
      </section>
      <section className="grid gap-3 sm:grid-cols-5">
        {["critical", "high", "medium", "low", "info"].map((severity) => (
          <div key={severity} className="card px-4 py-3">
            <SeverityBadge value={severity} />
            <p className="mt-2 font-mono text-xl">{formatNumber(counts[severity] || 0)}</p>
            <p className="text-xs text-slate-500">Alerts in the selected analysis</p>
          </div>
        ))}
      </section>
      {selected?.status !== "completed" ? (
        <div className="card p-4">
          <div className="flex items-center gap-2">
            <StatusBadge value={selected?.status} />
            <span className="text-sm text-slate-300">{selected?.original_filename}</span>
          </div>
          <p className="mt-2 text-sm text-slate-400">
            {selected?.error_message || "Statistics appear after this analysis completes."}
          </p>
        </div>
      ) : (
        <section className="grid gap-4 xl:grid-cols-2">
          <article className="card p-4">
            <h2 className="mb-3 text-sm font-medium text-slate-200">Protocol distribution</h2>
            <ProtocolChart protocols={summary?.protocols} />
          </article>
          <article className="card p-4">
            <h2 className="mb-3 text-sm font-medium text-slate-200">Traffic volume over time</h2>
            <TimelineChart timeline={summary?.timeline} />
          </article>
          <article className="card p-4 xl:col-span-2">
            <h2 className="mb-3 text-sm font-medium text-slate-200">Top source hosts by packets</h2>
            <HostsChart hosts={summary?.top_sources} />
          </article>
        </section>
      )}
      {(summary?.warnings || []).length ? (
        <ul className="space-y-2 text-sm text-amber-100">
          {summary.warnings.map((warning) => (
            <li key={warning} className="rounded-md border border-amber-900/60 bg-amber-950/30 px-3 py-2">
              {warning}
            </li>
          ))}
        </ul>
      ) : null}
      <section className="grid gap-4 lg:grid-cols-2">
        <article className="card p-4">
          <h2 className="mb-3 text-sm font-medium">Recent analyses</h2>
          <ul className="divide-y divide-line">
            {overview.recent_analyses.map((analysis) => (
              <li key={analysis.id} className="flex items-center justify-between gap-3 py-2">
                <div>
                  <Link className="text-sm text-teal-100 hover:underline" to={`/analyses/${analysis.id}`}>
                    {analysis.original_filename}
                  </Link>
                  <p className="text-xs text-slate-500">{formatTime(analysis.created_at)}</p>
                </div>
                <StatusBadge value={analysis.status} />
              </li>
            ))}
          </ul>
        </article>
        <article className="card p-4">
          <h2 className="mb-3 text-sm font-medium">Recent alerts</h2>
          {overview.recent_alerts.length === 0 ? (
            <p className="text-sm text-slate-500">No alerts stored yet.</p>
          ) : (
            <ul className="divide-y divide-line">
              {overview.recent_alerts.map((alert) => (
                <li key={alert.id} className="py-2">
                  <div className="flex items-center gap-2">
                    <SeverityBadge value={alert.severity} />
                    <Link className="text-sm hover:underline" to={`/alerts?analysis=${alert.analysis_id}`}>
                      {alert.rule_name}
                    </Link>
                  </div>
                  <p className="mt-1 text-xs text-slate-500">{alert.description}</p>
                </li>
              ))}
            </ul>
          )}
        </article>
      </section>
    </div>
  );
}

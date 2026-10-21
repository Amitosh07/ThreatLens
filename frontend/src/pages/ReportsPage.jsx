import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { EmptyState, ErrorNote, LoadingBlock, StatusBadge } from "../components/ui";
import { api, downloadReport, errorMessage } from "../services/api";
import { formatBytes, formatNumber } from "../utils/format";

export default function ReportsPage() {
  const [params, setParams] = useSearchParams();
  const [analyses, setAnalyses] = useState([]);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const requested = params.get("analysis") || "";

  useEffect(() => {
    api
      .get("/analyses", { params: { status: "completed", page_size: 100 } })
      .then((response) => setAnalyses(response.data.items))
      .catch((err) => setError(errorMessage(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const id = requested || analyses[0]?.id;
    if (!id) return undefined;
    let ignore = false;
    api
      .get(`/analyses/${id}`)
      .then((response) => {
        if (!ignore) setSelected(response.data);
      })
      .catch((err) => {
        if (!ignore) setError(errorMessage(err));
      });
    return () => {
      ignore = true;
    };
  }, [requested, analyses]);

  async function exportReport(format) {
    if (!selected) return;
    setBusy(format);
    setError("");
    setNotice("");
    try {
      await downloadReport(selected.id, format);
      setNotice(`${format.toUpperCase()} report downloaded.`);
    } catch (err) {
      setError(err.message || "Report export failed.");
      setNotice("");
    } finally {
      setBusy("");
    }
  }

  if (loading) return <LoadingBlock label="Loading reports" />;
  if (!analyses.length) {
    return <EmptyState title="No completed analyses" body="A report can be downloaded after a capture has been processed successfully." />;
  }

  const summary = selected?.summary;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold">Reports</h1>
        <p className="mt-1 text-sm text-slate-400">Downloads use the stored analysis. A failed export is shown as an error and is not described as a generated report.</p>
      </div>
      <label className="block max-w-xl text-sm">
        <span className="label">Completed analysis</span>
        <select
          className="field"
          value={selected?.id || ""}
          onChange={(event) => {
            const next = new URLSearchParams(params);
            next.set("analysis", event.target.value);
            setParams(next);
          }}
        >
          {analyses.map((analysis) => (
            <option key={analysis.id} value={analysis.id}>
              {analysis.original_filename}
            </option>
          ))}
        </select>
      </label>
      <ErrorNote message={error} />
      {notice ? <p className="text-sm text-emerald-200">{notice}</p> : null}
      {selected ? (
        <section className="card space-y-4 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge value={selected.status} />
            <h2 className="text-lg">{selected.original_filename}</h2>
          </div>
          <dl className="grid gap-3 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-slate-500">Packets</dt>
              <dd className="font-mono">{formatNumber(selected.packet_count)}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Bytes</dt>
              <dd className="font-mono">{formatBytes(selected.total_bytes)}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Alerts</dt>
              <dd className="font-mono">{formatNumber(selected.alert_count)}</dd>
            </div>
          </dl>
          <div>
            <h3 className="text-sm font-medium">Protocols</h3>
            <ul className="mt-2 space-y-1 text-sm text-slate-300">
              {(summary?.protocols || []).slice(0, 8).map((item) => (
                <li key={item.protocol}>
                  {item.protocol}: {item.packets} packets ({item.percentage}%)
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="text-sm font-medium">Rule snapshot</h3>
            <ul className="mt-2 space-y-1 text-xs text-slate-400">
              {(selected.rule_snapshot || []).map((rule) => (
                <li key={rule.rule_key}>
                  {rule.name}: {rule.enabled ? "enabled" : "disabled"}, {rule.severity}, {JSON.stringify(rule.parameters)}
                </li>
              ))}
            </ul>
          </div>
          <div className="flex gap-2">
            <button type="button" className="btn-primary" disabled={busy !== ""} onClick={() => exportReport("json")}>
              {busy === "json" ? "Preparing JSON…" : "Download JSON"}
            </button>
            <button type="button" className="btn-ghost" disabled={busy !== ""} onClick={() => exportReport("csv")}>
              {busy === "csv" ? "Preparing CSV…" : "Download CSV"}
            </button>
          </div>
        </section>
      ) : null}
    </div>
  );
}

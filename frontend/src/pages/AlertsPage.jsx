import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import AlertDetails from "../components/AlertDetails";
import { EmptyState, ErrorNote, LoadingBlock, Pagination, SeverityBadge } from "../components/ui";
import { api, errorMessage } from "../services/api";
import { display, formatTime } from "../utils/format";

export default function AlertsPage() {
  const [params, setParams] = useSearchParams();
  const [pageData, setPageData] = useState(null);
  const [analyses, setAnalyses] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState(null);
  const analysis = params.get("analysis") || "";
  const severity = params.get("severity") || "";
  const q = params.get("q") || "";
  const sort = params.get("sort") || "severity";
  const page = Number(params.get("page") || "1");

  useEffect(() => {
    api.get("/analyses", { params: { page_size: 100 } }).then((response) => setAnalyses(response.data.items)).catch(() => {});
  }, []);

  useEffect(() => {
    let ignore = false;
    setLoading(true);
    api
      .get("/alerts", {
        params: {
          page,
          page_size: 20,
          analysis_id: analysis || undefined,
          severity: severity || undefined,
          q: q || undefined,
          sort,
          order: sort === "rule_name" ? "asc" : "desc",
        },
      })
      .then((response) => {
        if (!ignore) setPageData(response.data);
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
  }, [analysis, severity, q, sort, page]);

  function update(next) {
    const updated = new URLSearchParams(params);
    Object.entries(next).forEach(([key, value]) => {
      if (value) updated.set(key, value);
      else updated.delete(key);
    });
    if (!("page" in next)) updated.delete("page");
    setParams(updated);
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold">Alerts</h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-400">
          These are potential anomalies from configurable rules. A row is evidence to review, not confirmation of malicious activity.
        </p>
      </div>
      <form
        className="card grid gap-3 p-4 md:grid-cols-4"
        onSubmit={(event) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          update({
            analysis: data.get("analysis"),
            severity: data.get("severity"),
            q: data.get("q"),
            sort: data.get("sort"),
          });
        }}
      >
        <label className="text-sm">
          <span className="label">Analysis</span>
          <select className="field" name="analysis" defaultValue={analysis}>
            <option value="">All analyses</option>
            {analyses.map((item) => (
              <option key={item.id} value={item.id}>
                {item.original_filename}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="label">Severity</span>
          <select className="field" name="severity" defaultValue={severity}>
            <option value="">All</option>
            {["critical", "high", "medium", "low", "info"].map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="label">Sort</span>
          <select className="field" name="sort" defaultValue={sort}>
            <option value="severity">Severity</option>
            <option value="window_start">Time window</option>
            <option value="rule_name">Rule name</option>
            <option value="id">Alert ID</option>
          </select>
        </label>
        <label className="text-sm">
          <span className="label">Search</span>
          <input className="field" name="q" defaultValue={q} placeholder="Rule, IP, or description" />
        </label>
        <div className="md:col-span-4">
          <button className="btn-primary" type="submit">
            Apply filters
          </button>
        </div>
      </form>
      <ErrorNote message={error} />
      {loading ? <LoadingBlock label="Loading alerts" /> : null}
      {!loading && pageData && pageData.total === 0 ? (
        <EmptyState title="No alerts match" body="Completed analyses with no matching rules show an empty list. That is not a malware-free certification." />
      ) : null}
      {pageData?.items?.length ? (
        <div className="card overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">Rule</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Evidence</th>
                <th className="px-3 py-2">Observed</th>
                <th className="px-3 py-2">Hosts</th>
                <th className="px-3 py-2">Window</th>
              </tr>
            </thead>
            <tbody>
              {pageData.items.map((alert) => (
                <tr key={alert.id} className="border-t border-line">
                  <td className="px-3 py-2">
                    <button type="button" className="font-mono text-teal-200 underline" onClick={() => setSelectedId(alert.id)}>
                      {alert.id}
                    </button>
                  </td>
                  <td className="px-3 py-2">{alert.rule_name}</td>
                  <td className="px-3 py-2">
                    <SeverityBadge value={alert.severity} />
                  </td>
                  <td className="px-3 py-2 capitalize">{alert.evidence_strength}</td>
                  <td className="px-3 py-2 text-xs">{display(alert.observed_value)}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {display(alert.src_ip)} → {display(alert.dst_ip)}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-400">{formatTime(alert.window_start)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {pageData ? (
        <Pagination
          page={pageData.page}
          pages={pageData.pages}
          total={pageData.total}
          onPage={(next) => update({ page: String(next), analysis, severity, q, sort })}
        />
      ) : null}
      {selectedId ? <AlertDetails alertId={selectedId} onClose={() => setSelectedId(null)} /> : null}
    </div>
  );
}

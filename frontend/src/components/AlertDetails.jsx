import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, errorMessage } from "../services/api";
import { display, formatTime } from "../utils/format";
import PacketTable from "./PacketTable";
import { ErrorNote, LoadingBlock, SeverityBadge } from "./ui";

export default function AlertDetails({ alertId, onClose }) {
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let ignore = false;
    setLoading(true);
    api
      .get(`/alerts/${alertId}`)
      .then((response) => {
        if (!ignore) setAlert(response.data);
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
  }, [alertId]);

  useEffect(() => {
    function onKey(event) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-slate-950/70" onClick={onClose}>
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Alert evidence"
        className="h-full w-full max-w-2xl overflow-y-auto border-l border-line bg-ink p-5 shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500">Potential anomaly</p>
            <h2 className="mt-1 text-lg font-semibold">{alert?.rule_name || "Alert"}</h2>
          </div>
          <button type="button" className="btn-ghost" onClick={onClose}>
            Close
          </button>
        </div>
        {loading ? <LoadingBlock label="Loading evidence" /> : null}
        <ErrorNote message={error} />
        {alert ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge value={alert.severity} />
              <span className="text-xs text-slate-400">Evidence strength: {alert.evidence_strength}</span>
              <span className="font-mono text-xs text-slate-500">#{alert.id}</span>
            </div>
            <p className="text-sm text-slate-200">{alert.description}</p>
            <p className="text-sm leading-6 text-slate-400">{alert.explanation}</p>
            <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-slate-500">Observed</dt>
                <dd>{display(alert.observed_value)}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Threshold</dt>
                <dd>{display(alert.threshold_value)}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Source</dt>
                <dd className="font-mono text-xs">{display(alert.src_ip)}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Destination</dt>
                <dd className="font-mono text-xs">
                  {display(alert.dst_ip)}
                  {alert.dst_port != null ? `:${alert.dst_port}` : ""}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Window</dt>
                <dd>
                  {formatTime(alert.window_start)} – {formatTime(alert.window_end)}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Packet numbers</dt>
                <dd className="font-mono text-xs">{(alert.packet_numbers || []).join(", ") || "—"}</dd>
              </div>
            </dl>
            <Link className="text-sm text-teal-200 underline" to={`/analyses/${alert.analysis_id}`}>
              Open analysis
            </Link>
            <div>
              <h3 className="mb-2 text-sm font-medium text-slate-200">Supporting packets</h3>
              <PacketTable packets={alert.packets || []} />
            </div>
          </div>
        ) : null}
      </aside>
    </div>
  );
}

const SEVERITY_STYLES = {
  critical: "bg-rose-500/15 text-rose-300 ring-rose-500/40",
  high: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  medium: "bg-amber-400/15 text-amber-200 ring-amber-400/40",
  low: "bg-sky-400/15 text-sky-200 ring-sky-400/40",
  info: "bg-slate-400/15 text-slate-300 ring-slate-400/30",
};

const STATUS_STYLES = {
  queued: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  processing: "bg-teal-400/15 text-teal-200 ring-teal-300/40",
  completed: "bg-emerald-400/15 text-emerald-200 ring-emerald-400/40",
  failed: "bg-rose-500/15 text-rose-200 ring-rose-500/40",
};

export function SeverityBadge({ value }) {
  const key = String(value || "info").toLowerCase();
  return (
    <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${SEVERITY_STYLES[key] || SEVERITY_STYLES.info}`}>
      {key}
    </span>
  );
}

export function StatusBadge({ value }) {
  const key = String(value || "queued").toLowerCase();
  return (
    <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset ${STATUS_STYLES[key] || STATUS_STYLES.queued}`}>
      {key}
    </span>
  );
}

export function Stat({ label, value, hint }) {
  return (
    <div className="card px-4 py-3">
      <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
      <p className="mt-2 font-mono text-2xl text-slate-50">{value}</p>
      {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
    </div>
  );
}

export function ErrorNote({ message }) {
  if (!message) return null;
  return (
    <div role="alert" className="rounded-md border border-rose-900 bg-rose-950/50 px-3 py-2 text-sm text-rose-100">
      {message}
    </div>
  );
}

export function LoadingBlock({ label = "Loading" }) {
  return (
    <p role="status" className="text-sm text-slate-400">
      {label}…
    </p>
  );
}

export function EmptyState({ title, body, action }) {
  return (
    <div className="card px-6 py-10 text-center">
      <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
      <p className="mx-auto mt-2 max-w-xl text-sm text-slate-400">{body}</p>
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  );
}

export function Pagination({ page, pages, total, onPage }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-slate-400">
      <p>
        {total.toLocaleString()} result{total === 1 ? "" : "s"}
      </p>
      <div className="flex items-center gap-2">
        <button type="button" className="btn-ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          Previous
        </button>
        <span className="font-mono text-slate-300">
          {pages === 0 ? "0 / 0" : `${page} / ${pages}`}
        </span>
        <button type="button" className="btn-ghost" disabled={pages === 0 || page >= pages} onClick={() => onPage(page + 1)}>
          Next
        </button>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import { Menu, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { Outlet } from "react-router-dom";
import Sidebar from "../components/Sidebar";
import { api, errorMessage } from "../services/api";

export default function AppLayout() {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("threatlens-sidebar") === "collapsed");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState("");

  useEffect(() => {
    localStorage.setItem("threatlens-sidebar", collapsed ? "collapsed" : "open");
  }, [collapsed]);

  useEffect(() => {
    let ignore = false;
    api
      .get("/health")
      .then((response) => {
        if (!ignore) setHealth(response.data);
      })
      .catch((error) => {
        if (!ignore) setHealthError(errorMessage(error));
      });
    return () => {
      ignore = true;
    };
  }, []);

  const tshark = health?.tshark;
  const showTshark = tshark && !tshark.available;

  return (
    <div className="min-h-screen md:grid md:grid-cols-[auto_1fr]">
      <aside
        className={`hidden border-r border-line bg-[#0b1628] md:block ${collapsed ? "w-16" : "w-60"}`}
      >
        <Sidebar collapsed={collapsed} />
      </aside>
      {mobileOpen ? (
        <div className="fixed inset-0 z-30 md:hidden">
          <button type="button" className="absolute inset-0 bg-slate-950/70" aria-label="Close menu" onClick={() => setMobileOpen(false)} />
          <aside className="relative h-full w-64 border-r border-line bg-[#0b1628]">
            <Sidebar onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      ) : null}
      <div className="min-w-0">
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          <div className="flex items-center gap-2">
            <button type="button" className="btn-ghost md:hidden" onClick={() => setMobileOpen(true)} aria-label="Open menu">
              <Menu size={16} />
            </button>
            <button
              type="button"
              className="btn-ghost hidden md:inline-flex"
              onClick={() => setCollapsed((value) => !value)}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
            </button>
            <p className="text-sm text-slate-400">Network traffic analysis and anomaly detection</p>
          </div>
          <p className="text-xs text-slate-400">
            {healthError
              ? "API offline"
              : tshark?.available
                ? `TShark ready`
                : health
                  ? "TShark missing"
                  : "Checking TShark"}
          </p>
        </header>
        {healthError ? (
          <div role="alert" className="border-b border-rose-900 bg-rose-950/40 px-4 py-2 text-sm text-rose-100">
            {healthError}
          </div>
        ) : null}
        {showTshark ? (
          <div role="status" className="border-b border-amber-900/70 bg-amber-950/30 px-4 py-2 text-sm text-amber-100">
            {tshark.message}
          </div>
        ) : null}
        <main className="mx-auto w-full max-w-7xl px-4 py-6">
          <Outlet />
        </main>
        <footer className="px-4 pb-6 text-xs leading-5 text-slate-500">
          {health?.disclaimer ||
            "Alerts are heuristic indicators for authorized captures. No alerts does not mean a capture is safe or malware-free."}
        </footer>
      </div>
    </div>
  );
}

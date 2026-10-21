import { NavLink } from "react-router-dom";
import { FileBarChart, LayoutDashboard, Radar, ScrollText, ShieldAlert, SlidersHorizontal, Upload } from "lucide-react";

const LINKS = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/upload", label: "Upload", icon: Upload },
  { to: "/alerts", label: "Alerts", icon: ShieldAlert },
  { to: "/rules", label: "Rules", icon: SlidersHorizontal },
  { to: "/reports", label: "Reports", icon: FileBarChart },
];

export default function Sidebar({ collapsed, onNavigate }) {
  return (
    <div className="flex h-full flex-col">
      <div className={`flex items-center gap-3 px-4 py-5 ${collapsed ? "justify-center" : ""}`}>
        <span className="grid h-9 w-9 place-items-center rounded-lg bg-teal-300/15 text-teal-200">
          <Radar size={18} />
        </span>
        {collapsed ? null : (
          <div>
            <p className="text-sm font-semibold tracking-wide">ThreatLens</p>
            <p className="text-xs text-slate-500">Traffic analysis</p>
          </div>
        )}
      </div>
      <nav className="flex-1 space-y-1 px-2" aria-label="Primary">
        {LINKS.map((link) => {
          const Icon = link.icon;
          return (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.end}
              title={link.label}
              onClick={onNavigate}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-md px-3 py-2 text-sm ${
                  isActive ? "bg-teal-300/10 text-teal-100" : "text-slate-300 hover:bg-slate-800/70"
                } ${collapsed ? "justify-center" : ""}`
              }
            >
              <Icon size={18} />
              {collapsed ? <span className="sr-only">{link.label}</span> : link.label}
            </NavLink>
          );
        })}
      </nav>
      {collapsed ? null : (
        <p className="px-4 py-4 text-xs leading-5 text-slate-500">
          <ScrollText className="mb-1 inline" size={14} /> Offline review of authorized captures. Alerts are leads, not verdicts.
        </p>
      )}
    </div>
  );
}

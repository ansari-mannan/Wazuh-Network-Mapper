"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import { Shield, LayoutDashboard, Network, ShieldAlert, Route, ListChecks, Settings, Moon, Sun } from "lucide-react";

const links = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/dashboard/topology", label: "Topology Map", icon: Network },
  { href: "/dashboard/vulnerability-report", label: "Vulnerability Report", icon: ShieldAlert },
  { href: "/dashboard/attack-path", label: "Attack Paths", icon: Route },
  { href: "/dashboard/recommendations", label: "Recommendations", icon: ListChecks },
  { href: "/dashboard/scan-configuration", label: "Scan Config", icon: Settings },
];

const lastScan = "2026-03-19 02:14:33 UTC";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { theme, setTheme } = useTheme();

  return (
    <div className="dashboard-shell">
      <aside className="dashboard-sidebar">
        <div>
          <div className="sidebar-header">
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Shield size={18} color="#3b82f6" />
              <span className="sidebar-title">Wazuh Mapper</span>
            </div>
            <div className="sidebar-version">v1.0</div>
          </div>

          <nav className="sidebar-nav">
            {links.map((item) => {
              const Icon = item.icon;
              const active = pathname === item.href;
              return (
                <Link key={item.href} href={item.href} className={`sidebar-link ${active ? "active" : ""}`}>
                  <Icon size={16} />
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>

        <div className="sidebar-bottom">
          <div className="sidebar-section">
            <div>
              <span className="sidebar-dot" /> Last scan
            </div>
            <div>{lastScan}</div>
          </div>
          
          <div className="theme-toggle-section">
            <span className="theme-label">{theme === "dark" ? "Dark Mode" : "Light Mode"}</span>
            <button
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              className={`theme-toggle-switch ${theme === "dark" ? "active" : ""}`}
              aria-label="Toggle dark mode"
            >
              <div className="toggle-circle" />
            </button>
          </div>
        </div>
      </aside>

      <main className="dashboard-main">{children}</main>
    </div>
  );
}

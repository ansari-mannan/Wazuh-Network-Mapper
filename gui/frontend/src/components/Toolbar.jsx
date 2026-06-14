import React from "react";
import { ArrowLeft, RefreshCw, Radar } from "lucide-react";

const SCAN_TEXT = {
  idle: "Run New Scan",
  running: "Scanning…",
  done: "Scan complete",
  error: "Run New Scan",
};

export default function Toolbar({
  community,
  setCommunity,
  onLoad,
  onScan,
  scanState,
  scanError,
  loadError,
  metadata,
  inDetail,
  onBack,
}) {
  const scanning = scanState === "running";
  const counts = metadata && metadata.counts;

  return (
    <header className="toolbar">
      <div className="toolbar__left">
        {inDetail ? (
          <button className="btn btn--ghost" onClick={onBack}>
            <ArrowLeft size={16} /> Back to topology
          </button>
        ) : (
          <span className="brand">
            <span className="brand__mark">vuln</span>mapper
          </span>
        )}
      </div>

      <div className="toolbar__right">
        <button className="btn" onClick={onLoad} disabled={scanning}>
          <RefreshCw size={15} /> Load Graph
        </button>

        <div className="scan">
          <input
            className="scan__input"
            value={community}
            onChange={(e) => setCommunity(e.target.value)}
            placeholder="community"
            disabled={scanning}
            aria-label="SNMP community string"
          />
          <button className="btn btn--primary" onClick={onScan} disabled={scanning}>
            <Radar size={15} className={scanning ? "spin" : ""} />
            {SCAN_TEXT[scanState]}
          </button>
        </div>
      </div>

      {/* Status / error strip (kept inline so the graph below never disappears). */}
      {(counts || loadError || scanError || scanState === "done") && (
        <div className="statusbar">
          {counts && !loadError && (
            <span className="statusbar__counts">
              {counts.nodes} nodes · {counts.devices} devices · {counts.endpoints} endpoints ·{" "}
              {counts.lldp_edges + counts.endpoint_edges} edges · {counts.unparented_endpoints} unparented
            </span>
          )}
          {scanState === "done" && <span className="pill pill--ok">scan complete</span>}
          {loadError && <span className="pill pill--err">load failed: {loadError}</span>}
          {scanError && <span className="pill pill--err">scan failed: {scanError}</span>}
        </div>
      )}
    </header>
  );
}

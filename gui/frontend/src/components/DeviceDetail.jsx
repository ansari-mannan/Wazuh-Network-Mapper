import React from "react";
import { iconForRole } from "../icons.jsx";
import { isOffline, riskColor, riskLabel } from "../nodeStyle.js";

function Field({ label, value }) {
  const empty = value === null || value === undefined || value === "";
  return (
    <div className="field">
      <span className="field__k">{label}</span>
      <span className={`field__v ${empty ? "field__v--empty" : ""}`}>
        {empty ? "—" : value}
      </span>
    </div>
  );
}

export default function DeviceDetail({ node }) {
  const isDevice = node.kind === "device";
  const Icon = iconForRole(node.role);
  const color = riskColor(node.risk_score);
  const offline = isOffline(node.status);
  const cves = node.top_cves || [];
  const ports = node.port_status ? Object.entries(node.port_status) : [];

  return (
    <div className="detail">
      <div className="detail__head">
        <div className={`detail__id ${offline ? "is-offline" : ""}`}>
          <span className="detail__icon" style={{ "--risk": color }}>
            <Icon size={28} strokeWidth={1.5} />
          </span>
          <div>
            <h2>{node.hostname || node.ip || node.node_id}</h2>
            <div className="detail__sub">
              {node.role || node.kind} · {node.discovery_method}
              {offline && <span className="tag tag--offline">offline</span>}
            </div>
          </div>
        </div>
        <span className="riskbadge" style={{ borderColor: color, color }}>
          <span className="node__dot" style={{ background: color }} />
          risk {riskLabel(node.risk_score)}
        </span>
      </div>

      <section className="card">
        <h3>Identity</h3>
        <div className="grid2">
          <Field label="Hostname" value={node.hostname} />
          <Field label="IP" value={node.ip} />
          <Field label="MAC" value={node.mac} />
          <Field label="Vendor" value={node.vendor} />
          <Field label="Model" value={node.model} />
          <Field label="Firmware" value={node.firmware} />
          <Field label="Serial" value={node.serial} />
          <Field label="Role" value={node.role} />
          <Field label="Discovery method" value={node.discovery_method} />
          <Field label="Status" value={node.status} />
        </div>
      </section>

      {!isDevice && (
        <section className="card">
          <h3>
            Vulnerabilities <span className="count">{cves.length}</span>
          </h3>
          {cves.length === 0 ? (
            <p className="muted">
              No CVEs reported{node.risk_score == null ? " (host is unscored)" : ""}.
            </p>
          ) : (
            <div className="cves">
              {cves.map((c, i) => (
                <article className="cve" key={c.cve || i}>
                  <div className="cve__top">
                    <span className="cve__id">{c.cve}</span>
                    <span className="cve__sev" data-sev={(c.severity || "").toLowerCase()}>
                      {c.severity}
                      {c.cvss != null && <> · {c.cvss}</>}
                      {c.cvss_version && <span className="cve__ver"> (v{c.cvss_version})</span>}
                    </span>
                  </div>
                  {(c.package || c.version) && (
                    <div className="cve__pkg">
                      {c.package} {c.version && <span className="muted">· {c.version}</span>}
                    </div>
                  )}
                  {c.description && <p className="cve__desc">{c.description}</p>}
                </article>
              ))}
            </div>
          )}
        </section>
      )}

      {isDevice && (
        <>
          <section className="card">
            <h3>
              Ports <span className="count">{ports.length}</span>
            </h3>
            {ports.length === 0 ? (
              <p className="muted">No port status reported.</p>
            ) : (
              <div className="ports">
                {ports.map(([name, state]) => (
                  <div className="port" key={name}>
                    <span
                      className={`presence ${
                        state === "up" ? "presence--up" : "presence--down"
                      }`}
                      title={state}
                    />
                    <span className="port__name">{name}</span>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="card">
            <h3>Topology ports</h3>
            <div className="grid2">
              <Field label="Neighbor ports" value={(node.neighbor_ports || []).join(", ")} />
              <Field label="Uplink ports" value={(node.uplink_ports || []).join(", ")} />
            </div>
          </section>
        </>
      )}
    </div>
  );
}
